"""RFC 4231 vectors, independent comparisons, and tag rejection tests."""

from dataclasses import replace
import hashlib
import hmac
import random
import unittest

from lab.crypto import hmac_sha256, verify_hmac_sha256
from lab.protocol import Message


class HmacSha256Tests(unittest.TestCase):
    def test_rfc4231_full_length_vectors(self) -> None:
        # RFC 4231 sections 4.2-4.5 and 4.7-4.8, cases 1-4 and 6-7.
        vectors = (
            (1, b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (2, b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (3, b"\xaa" * 20, b"\xdd" * 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (4, bytes(range(1, 26)), b"\xcd" * 50, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            (
                6, b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                7, b"\xaa" * 131,
                b"This is a test using a larger than block-size key and a larger than block-size data. "
                b"The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        )
        for case, key, data, expected in vectors:
            with self.subTest(case=case):
                actual = hmac_sha256(key, data)
                self.assertEqual(actual.hex(), expected)
                self.assertTrue(verify_hmac_sha256(key, data, bytes.fromhex(expected)))

    def test_rfc4231_truncated_vector(self) -> None:
        # Case 5 publishes only the first 128 bits. The API returns all 256.
        tag = hmac_sha256(b"\x0c" * 20, b"Test With Truncation")
        self.assertEqual(tag[:16].hex(), "a3b6167473100ee06e0c796c2955552b")
        self.assertEqual(len(tag), 32)
        self.assertFalse(verify_hmac_sha256(b"\x0c" * 20, b"Test With Truncation", tag[:16]))

    def test_key_and_message_boundaries(self) -> None:
        for key_length in (0, 1, 32, 63, 64, 65, 128, 131):
            key = bytes(index % 256 for index in range(key_length))
            for message_length in (0, 1, 55, 56, 63, 64, 65, 120, 128, 256):
                data = bytes(index % 256 for index in range(message_length))
                with self.subTest(key_length=key_length, message_length=message_length):
                    self.assertEqual(hmac_sha256(key, data), hmac.digest(key, data, "sha256"))

    def test_reproducible_random_inputs(self) -> None:
        generator = random.Random(4231)
        for index in range(30):
            key = generator.randbytes(generator.randrange(200))
            data = generator.randbytes(generator.randrange(1025))
            with self.subTest(index=index):
                self.assertEqual(hmac_sha256(key, data), hmac.new(key, data, hashlib.sha256).digest())

    def test_rejects_modified_tags_data_and_keys(self) -> None:
        key, data = b"shared lab key", b"transfer 100"
        tag = hmac.digest(key, data, "sha256")
        self.assertTrue(verify_hmac_sha256(key, data, tag))
        self.assertFalse(verify_hmac_sha256(key, b"transfer 900", tag))
        self.assertFalse(verify_hmac_sha256(b"other key", data, tag))
        for index in range(len(tag)):
            modified = bytearray(tag)
            modified[index] ^= 1
            with self.subTest(position=index):
                self.assertFalse(verify_hmac_sha256(key, data, bytes(modified)))
        for invalid in (b"", tag[:-1], tag + b"\x00"):
            with self.subTest(length=len(invalid)):
                self.assertFalse(verify_hmac_sha256(key, data, invalid))

    def test_protocol_fields_are_authenticated(self) -> None:
        message = Message("demo", "Alice", "Bob", 1, "转账 100 元")
        key = b"shared lab key"
        data = message.to_bytes()
        tag = hmac.digest(key, data, "sha256")
        self.assertEqual(hmac_sha256(key, data), tag)
        self.assertTrue(verify_hmac_sha256(key, data, tag))
        changed_messages = (
            replace(message, session_id="other"),
            replace(message, sender="Bob", recipient="Alice"),
            replace(message, sequence=2),
            replace(message, content="转账 900 元"),
        )
        for changed in changed_messages:
            with self.subTest(message=changed):
                self.assertFalse(verify_hmac_sha256(key, changed.to_bytes(), tag))

    def test_rejects_non_bytes(self) -> None:
        for invalid in ("text", None, 42, bytearray(b"abc"), memoryview(b"abc")):
            with self.subTest(value=invalid):
                with self.assertRaises(TypeError):
                    hmac_sha256(invalid, b"data")
                with self.assertRaises(TypeError):
                    hmac_sha256(b"key", invalid)
                with self.assertRaises(TypeError):
                    verify_hmac_sha256(b"key", b"data", invalid)


if __name__ == "__main__":
    unittest.main()
