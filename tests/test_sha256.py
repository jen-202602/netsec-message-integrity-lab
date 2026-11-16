"""Fixed SHA-256 vectors and independent hashlib comparisons."""

import hashlib
import random
import unittest

from lab.crypto import sha256


class Sha256Tests(unittest.TestCase):
    def test_known_vectors(self) -> None:
        # Empty input plus RFC 6234 section 8.5 SHA-256 test messages.
        vectors = (
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        )
        for data, expected in vectors:
            with self.subTest(length=len(data)):
                self.assertEqual(sha256(data).hex(), expected)

    def test_padding_and_block_boundaries(self) -> None:
        for length in (0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256):
            data = bytes(index % 256 for index in range(length))
            with self.subTest(length=length):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_binary_and_utf8_messages(self) -> None:
        for data in (bytes(range(256)), b"\x00\xff\x80" * 100, '你好，Bob！\n"消息" 🔒'.encode("utf-8")):
            with self.subTest(data=data):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_reproducible_random_inputs(self) -> None:
        generator = random.Random(256)
        for index in range(40):
            data = generator.randbytes(generator.randrange(2049))
            with self.subTest(index=index, length=len(data)):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_calls_have_independent_state(self) -> None:
        first = sha256(b"first")
        sha256(b"other" * 100)
        self.assertEqual(sha256(b"first"), first)
        self.assertEqual(len(first), 32)

    def test_rejects_non_bytes(self) -> None:
        for data in ("abc", None, 3, bytearray(b"abc"), memoryview(b"abc")):
            with self.subTest(data=data), self.assertRaises(TypeError):
                sha256(data)


if __name__ == "__main__":
    unittest.main()
