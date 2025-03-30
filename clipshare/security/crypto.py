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
            # 使用固定的种子生成相同的密钥（仅测试用）
            import hashlib
            # 两端使用完全相同的固定字符串
            seed = "clipshare-test-key-2023"
            self.shared_key = hashlib.sha256(seed.encode()).digest()
            print(f"🔑 临时密钥生成成功，前8字节: {self.shared_key[:8].hex()}")
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

    def set_shared_key_from_password(self, password: str):
        """Set shared key from a password (for testing)"""
        import hashlib
        self.shared_key = hashlib.sha256(password.encode()).digest()
        print(f"🔑 从密码设置密钥，前8字节: {self.shared_key[:8].hex()}")
        return self.shared_key

    def encrypt_message(self, message: bytes) -> bytes:
        """Encrypt a message using AES-256-GCM."""
        if not self.shared_key:
            raise ValueError("Shared key not established")
        
        # 显示密钥信息
        print(f"🔑 使用密钥 ({len(self.shared_key)} 字节) 加密，前8字节: {self.shared_key[:8].hex()}")
        
        print(f"🔒 正在加密 {len(message)} 字节数据...")
        
        try:
            aesgcm = AESGCM(self.shared_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, message, None)
            encrypted = nonce + ciphertext
            print(f"✅ 加密成功! 加密后 {len(encrypted)} 字节")
            return encrypted
        except Exception as e:
            print(f"❌ 加密失败: {e}")
            raise

    def decrypt_message(self, encrypted_data):
        """Decrypt a message using AES-256-GCM."""
        if not self.shared_key:
            raise ValueError("Shared key not established")
        
        # 显示密钥信息
        print(f"🔑 使用密钥 ({len(self.shared_key)} 字节) 解密，前8字节: {self.shared_key[:8].hex()}")
        
        # 确保数据是二进制格式
        if not isinstance(encrypted_data, bytes):
            print(f"⚠️ 将 {type(encrypted_data)} 转换为 bytes")
            try:
                if isinstance(encrypted_data, str):
                    if encrypted_data.startswith('{'):
                        print("⚠️ 跳过JSON格式数据，不尝试解密")
                        raise ValueError("JSON string cannot be decrypted directly")
                    
                    encrypted_data = encrypted_data.encode('utf-8')
                else:
                    raise TypeError(f"无法处理的数据类型: {type(encrypted_data)}")
            except Exception as e:
                print(f"❌ 数据类型转换失败: {e}")
                raise
        
        try:
            # 检查数据格式
            if len(encrypted_data) <= 12:
                raise ValueError(f"数据太短: {len(encrypted_data)} 字节")
                
            # 打印详细的nonce和密文信息用于调试
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            print(f"🔍 Nonce ({len(nonce)} 字节): {nonce.hex()[:24]}...")
            print(f"🔍 密文 ({len(ciphertext)} 字节): {ciphertext.hex()[:24] if len(ciphertext) >= 12 else ciphertext.hex()}...")
            
            aesgcm = AESGCM(self.shared_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            
            # 打印解密成功信息
            print(f"✅ 解密成功! 数据长度: {len(decrypted_data)} 字节")
            return decrypted_data
        except Exception as e:
            print(f"❌ 解密失败: {e}")
            print(f"数据长度: {len(encrypted_data)} 字节")
            print(f"数据预览 (十六进制): {encrypted_data[:20].hex()}")
            raise
