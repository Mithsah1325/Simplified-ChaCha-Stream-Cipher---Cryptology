#!/usr/bin/env python3
"""
Simplified ChaCha Stream Cipher Implementation
Cryptology Class Project - Educational Version
"""

from typing import Tuple


class SimplifiedChaCha:
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        """
        Initialize ChaCha cipher with key, nonce, and counter

        Args:
            key: 256-bit key as bytes (32 bytes)
            nonce: 96-bit nonce as bytes (12 bytes)
            counter: 32-bit block counter
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes (256 bits), got {len(key)} bytes")
        if len(nonce) != 12:
            raise ValueError(f"Nonce must be 12 bytes (96 bits), got {len(nonce)} bytes")
        if not (0 <= counter <= 0xFFFFFFFF):
            raise ValueError("Counter must fit in 32 bits")

        self.key = key
        self.nonce = nonce
        self.counter = counter & 0xFFFFFFFF

        # ChaCha constants (16 bytes)
        self.constants = b"expand 32-byte k"

    @staticmethod
    def _rotl32(v: int, n: int) -> int:
        return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))

    @staticmethod
    def _quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
        """
        ChaCha quarter round operation (pure function, returns updated a,b,c,d)
        Steps:
          a += b; d ^= a; d <<< 16;
          c += d; b ^= c; b <<< 12;
          a += b; d ^= a; d <<< 8;
          c += d; b ^= c; b <<< 7;
        """
        a = (a + b) & 0xFFFFFFFF
        d ^= a
        d = SimplifiedChaCha._rotl32(d, 16)

        c = (c + d) & 0xFFFFFFFF
        b ^= c
        b = SimplifiedChaCha._rotl32(b, 12)

        a = (a + b) & 0xFFFFFFFF
        d ^= a
        d = SimplifiedChaCha._rotl32(d, 8)

        c = (c + d) & 0xFFFFFFFF
        b ^= c
        b = SimplifiedChaCha._rotl32(b, 7)

        return a, b, c, d

    def _create_initial_state(self, counter_override: int = None):
        """
        Create the initial 4x4 state matrix (16 little-endian 32-bit words)
        Layout:
           [ const0, const1, const2, const3 ]
           [ key0  , key1  , key2  , key3   ]
           [ key4  , key5  , key6  , key7   ]
           [ counter, nonce0, nonce1, nonce2 ]
        """
        state = [0] * 16

        # Constants (first row), each 4 bytes little-endian
        state[0] = int.from_bytes(self.constants[0:4], 'little')
        state[1] = int.from_bytes(self.constants[4:8], 'little')
        state[2] = int.from_bytes(self.constants[8:12], 'little')
        state[3] = int.from_bytes(self.constants[12:16], 'little')

        # Key (rows 2 and 3) - 8 words (32 bytes)
        for i in range(8):
            state[4 + i] = int.from_bytes(self.key[i * 4:(i + 1) * 4], 'little')

        # Counter and nonce (row 4)
        ctr = self.counter if counter_override is None else (counter_override & 0xFFFFFFFF)
        state[12] = ctr
        state[13] = int.from_bytes(self.nonce[0:4], 'little')
        state[14] = int.from_bytes(self.nonce[4:8], 'little')
        state[15] = int.from_bytes(self.nonce[8:12], 'little')

        return state

    def _double_round(self, state: list):
        """
        Perform one double round (column rounds + diagonal rounds) in-place on state list.
        This mutates the `state` list.
        """
        # Column rounds
        for i in range(4):
            a, b, c, d = state[0 + i], state[4 + i], state[8 + i], state[12 + i]
            state[0 + i], state[4 + i], state[8 + i], state[12 + i] = \
                self._quarter_round(a, b, c, d)

        # Diagonal rounds
        diagonals = [(0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
        for (i0, i1, i2, i3) in diagonals:
            a, b, c, d = state[i0], state[i1], state[i2], state[i3]
            state[i0], state[i1], state[i2], state[i3] = \
                self._quarter_round(a, b, c, d)

    def _generate_key_stream_block(self, counter_for_block: int) -> bytes:
        """
        Generate one 64-byte key stream block for a given block counter.
        This does NOT modify self.counter; it uses the provided counter parameter.
        """
        initial_state = self._create_initial_state(counter_override=counter_for_block)
        working_state = initial_state.copy()

        # Apply 10 double rounds (20 rounds total)
        for _ in range(10):
            self._double_round(working_state)

        # Add initial state to working state (word-wise)
        for i in range(16):
            working_state[i] = (working_state[i] + initial_state[i]) & 0xFFFFFFFF

        # Convert state to byte stream (little-endian words)
        key_stream = bytearray()
        for word in working_state:
            key_stream.extend(word.to_bytes(4, 'little'))

        return bytes(key_stream)  # 64 bytes

    @staticmethod
    def _xor_bytes(data: bytes, key_stream: bytes) -> bytes:
        """XOR data with key stream (truncates to min length)"""
        return bytes(a ^ b for a, b in zip(data, key_stream))

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using simplified ChaCha stream cipher.
        The object's counter is advanced by the number of blocks processed.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext must be bytes or bytearray")

        ciphertext = bytearray()
        local_counter = self.counter
        blocks = 0

        for i in range(0, len(plaintext), 64):
            block = plaintext[i:i + 64]
            key_stream = self._generate_key_stream_block(local_counter)
            encrypted_block = self._xor_bytes(block, key_stream[:len(block)])
            ciphertext.extend(encrypted_block)
            local_counter = (local_counter + 1) & 0xFFFFFFFF
            blocks += 1

        # Advance the object's counter to reflect used blocks (keeps object state consistent)
        self.counter = local_counter

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext (same as encryption for stream ciphers).
        Uses the same algorithm and updates the counter as encryption does.
        """
        # Decryption is XOR with same keystream; use same encrypt implementation
        return self.encrypt(ciphertext)


def demonstrate_cha_cha_operations():
    """Demonstrate core ChaCha operations for educational purposes"""
    print("=" * 60)
    print("CHA-CHA STREAM CIPHER DEMONSTRATION")
    print("=" * 60)

    # Demonstrate quarter round
    print("\n1. QUARTER ROUND OPERATION:")
    print("   Input: a=0x11111111, b=0x01020304, c=0x9b8d6f43, d=0x01234567")
    a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
    result = SimplifiedChaCha._quarter_round(a, b, c, d)
    print(f"   Output: a={hex(result[0])}, b={hex(result[1])}, c={hex(result[2])}, d={hex(result[3])}")

    # Demonstrate state creation with proper key and nonce
    print("\n2. INITIAL STATE MATRIX (with test key):")
    key = (b'0123456789abcdef' * 2)[:32]  # 32-byte key
    nonce = b'TestNonce0123'[:12]  # exactly 12 bytes
    chacha = SimplifiedChaCha(key, nonce)
    state = chacha._create_initial_state()
    for i in range(0, 16, 4):
        row = [f"0x{state[i + j]:08x}" for j in range(4)]
        print(f"   Row {i // 4}: {', '.join(row)}")


def generate_proper_test_vectors():
    """Generate properly sized test vectors"""
    # Key: exactly 32 bytes
    key = b'ChaChaTestKey1234567890ABCDEF!!'  # 32 bytes (make sure length)
    key = key.ljust(32, b'\0')[:32]

    # Nonce: exactly 12 bytes
    nonce = b'TestNonce012'  # 12 bytes

    print(f"Test Key: {key} (length: {len(key)} bytes)")
    print(f"Test Nonce: {nonce} (length: {len(nonce)} bytes)")

    return key, nonce


def main():
    """Main demonstration function"""
    print("=" * 60)
    print("SIMPLIFIED CHACHA STREAM CIPHER")
    print("Cryptology Class Project - Educational Implementation")
    print("=" * 60)

    # Generate proper test vectors first
    print("\nGENERATING TEST VECTORS:")
    key, nonce = generate_proper_test_vectors()

    # Now demonstrate operations with proper vectors
    demonstrate_cha_cha_operations()

    print("\n" + "=" * 60)
    print("ENCRYPTION/DECRYPTION DEMONSTRATION")
    print("=" * 60)

    # Test messages
    message1 = b"Hello, ChaCha! This is a test message for our cryptology project."
    message2 = b"Short test"

    print(f"\nTest Key: {key}")
    print(f"Test Nonce: {nonce}")

    # Test 1: Long message, start counter 0
    print(f"\n--- TEST 1: LONG MESSAGE ---")
    print(f"Original: {message1.decode()}")
    print(f"Length: {len(message1)} bytes")

    cipher1 = SimplifiedChaCha(key, nonce, counter=0)
    encrypted1 = cipher1.encrypt(message1)
    print(f"Encrypted (hex): {encrypted1.hex()}")

    # For decryption create a new instance with the same starting counter (0)
    cipher1_decrypt = SimplifiedChaCha(key, nonce, counter=0)
    decrypted1 = cipher1_decrypt.decrypt(encrypted1)
    print(f"Decrypted: {decrypted1.decode()}")
    print(f"✓ Success: {message1 == decrypted1}")

    # Test 2: Short message with counter=1
    print(f"\n--- TEST 2: SHORT MESSAGE ---")
    print(f"Original: {message2.decode()}")
    print(f"Length: {len(message2)} bytes")

    cipher2 = SimplifiedChaCha(key, nonce, counter=1)  # Different counter
    encrypted2 = cipher2.encrypt(message2)
    print(f"Encrypted (hex): {encrypted2.hex()}")

    cipher2_decrypt = SimplifiedChaCha(key, nonce, counter=1)
    decrypted2 = cipher2_decrypt.decrypt(encrypted2)
    print(f"Decrypted: {decrypted2.decode()}")
    print(f"✓ Success: {message2 == decrypted2}")

    # Test 3: Demonstrate that same key+nonce+counter produces same stream
    print(f"\n--- TEST 3: KEY STREAM CONSISTENCY ---")
    test_message = b"AAAA"  # 4 A's
    cipher3a = SimplifiedChaCha(key, nonce, counter=10)
    cipher3b = SimplifiedChaCha(key, nonce, counter=10)

    encrypted3a = cipher3a.encrypt(test_message)
    encrypted3b = cipher3b.encrypt(test_message)

    print(f"Same inputs produce same output: {encrypted3a == encrypted3b}")
    print(f"Encrypted (both identical): {encrypted3a.hex()}")

    print("\n" + "=" * 60)
    print("EDUCATIONAL SUMMARY")
    print("=" * 60)
    print("""
CHA-CHA STREAM CIPHER KEY CONCEPTS:

1. STREAM CIPHER PRINCIPLES:
   • Generates pseudorandom key stream from (key, nonce, counter)
   • XOR with plaintext → ciphertext (same for decryption)
   • Security depends on never reusing (key, nonce) pairs

2. CHACHA CORE OPERATIONS:
   • Quarter Round: 4-word non-linear mixing function
   • Double Rounds: Column + diagonal rounds for full diffusion
   • State Matrix: 16 words (512 bits) organized in 4x4 grid

3. SECURITY PROPERTIES:
   • 256-bit key strength
   • 96-bit nonce for uniqueness
   • 20 rounds provide strong cryptographic security
   • Resistance to timing attacks (when implemented constant-time)

4. IMPLEMENTATION DETAILS:
   • Key: 32 bytes (256 bits)
   • Nonce: 12 bytes (96 bits)
   • Counter: 32 bits
   • Block size: 64 bytes
   • Constants: "expand 32-byte k"

5. EDUCATIONAL VALUE:
   • Modern stream cipher design principles
   • Importance of proper nonce management
   • Diffusion and confusion in practice
   • Symmetric cryptography fundamentals
    """)


if __name__ == "__main__":
    main()
