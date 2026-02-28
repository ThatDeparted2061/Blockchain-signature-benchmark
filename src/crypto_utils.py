from __future__ import annotations

from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding


@dataclass
class CryptoScheme:
    name: str
    private_key: object
    public_key: object

    def sign(self, message: bytes) -> bytes:
        if self.name.startswith("RSA"):
            return self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            if self.name.startswith("RSA"):
                self.public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:
                self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def public_key_size(self) -> int:
        if self.name.startswith("RSA"):
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        return len(pub_bytes)


def generate_rsa(bits: int) -> CryptoScheme:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return CryptoScheme(name=f"RSA-{bits}", private_key=private_key, public_key=public_key)


def generate_ecdsa_secp256k1() -> CryptoScheme:
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return CryptoScheme(name="ECDSA-secp256k1", private_key=private_key, public_key=public_key)
