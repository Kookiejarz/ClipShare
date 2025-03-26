from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class SecurityManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_key = None

    def generate_key_pair(self):
        """Generate new ECDH key pair"""
        try:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            self.public_key = self.private_key.public_key()
            return self.public_key
        except Exception as e:
            print(f"密钥对生成失败: {e}")
            raise

    def has_shared_key(self):
        """Check if shared key exists"""
        return self.shared_key is not None

    # For testing purposes only
    def generate_temporary_shared_key(self):
        """Generate a temporary shared key for testing"""
        try:
            self.shared_key = os.urandom(32)
            return self.shared_key
        except Exception as e:
            print(f"临时密钥生成失败: {e}")
            raise

    def generate_shared_key(self, peer_public_key):
        """Generate shared key using ECDH."""
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return self.shared_key

    def encrypt_message(self, message: bytes) -> bytes:
        """Encrypt a message using AES-256-GCM."""
        if not self.shared_key:
            raise ValueError("Shared key not established")
        try:
            aesgcm = AESGCM(self.shared_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, message, None)
            return nonce + ciphertext
        except Exception as e:
            print(f"加密失败: {e}")
            raise
