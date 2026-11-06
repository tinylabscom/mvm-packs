import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ed25519  # noqa: E402


def sign(secret, message):
    """RFC 8032 signing, test-only."""
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = ed25519.compress(ed25519._mul(a, ed25519.BASE))
    r = ed25519.challenge(h[32:], message)
    big_r = ed25519.compress(ed25519._mul(r, ed25519.BASE))
    s = (r + ed25519.challenge(big_r, public, message) * a) % ed25519.Q
    return public, big_r + int.to_bytes(s, 32, "little")


# RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2 (one byte).
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


class Ed25519Tests(unittest.TestCase):
    def test_rfc_8032_vectors_verify_and_match_our_signer(self):
        for secret, public, message, signature in VECTORS:
            public, message, signature = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
            with self.subTest(message=message.hex()):
                self.assertTrue(ed25519.verify(public, message, signature))
                self.assertEqual(sign(bytes.fromhex(secret), message), (public, signature))

    def test_tampering_and_malformed_inputs_are_refused(self):
        secret, public, message, signature = (bytes.fromhex(x) for x in VECTORS[1])
        self.assertFalse(ed25519.verify(public, message + b"x", signature))
        self.assertFalse(ed25519.verify(public, message, signature[:-1] + bytes([signature[-1] ^ 1])))
        self.assertFalse(ed25519.verify(public[:-1], message, signature))
        self.assertFalse(ed25519.verify(public, message, signature[:63]))
        self.assertFalse(ed25519.verify(bytes(32), message, signature))
        bad_s = signature[:32] + int.to_bytes(ed25519.Q, 32, "little")
        self.assertFalse(ed25519.verify(public, message, bad_s))
