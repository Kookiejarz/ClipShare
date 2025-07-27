from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

class SecurityManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_key = None

    def generate_key_pair(self):
        """Generate ECDH key pair"""
        try:
            self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.public_key = self.private_key.public_key()
            print("🔑 密钥对生成成功")
        except Exception as e:
            print(f"❌ 密钥对生成失败: {e}")
            raise

    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        if not self.public_key:
            raise ValueError("Public key not available")
        
        # Fixed: Use public_bytes() instead of public_key_bytes()
        pem_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')

    def set_peer_public_key(self, peer_public_key_pem: str) -> bool:
        """Set the peer's public key and establish shared key"""
        try:
            print(f"🔧 设置对等方公钥 ({len(peer_public_key_pem)} 字符)")
            
            # Load peer's public key
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            self.peer_public_key = peer_public_key
            print("✅ 对等方公钥加载成功")
            
            # Establish shared key using ECDH
            if self.private_key and self.peer_public_key:
                print("🔑 正在建立共享密钥...")
                shared_secret = self.private_key.exchange(ec.ECDH(), self.peer_public_key)
                print(f"🔧 共享秘密生成成功 ({len(shared_secret)} 字节)")
                
                # Derive a key from the shared secret using HKDF
                self.shared_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,  # 256 bits for AES-256
                    salt=None,
                    info=b'clipshare-v1',
                    backend=default_backend()
                ).derive(shared_secret)
                
                print(f"🔑 共享密钥已建立 ({len(self.shared_key)} 字节)")
                print(f"🔍 共享密钥前16字节: {self.shared_key[:16].hex()}")
                return True
            else:
                print(f"❌ 无法建立共享密钥：private_key={self.private_key is not None}, peer_public_key={self.peer_public_key is not None}")
                return False
                
        except Exception as e:
            print(f"❌ 设置对等方公钥失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def encrypt_message(self, message: bytes, return_base64: bool = False) -> bytes:
        """Encrypt message using shared key"""
        if not self.shared_key:
            print(f"❌ 加密失败：shared_key={self.shared_key is not None}")
            raise ValueError("Shared key not established")
        
        try:
            # Use AES-GCM for authenticated encryption
            iv = os.urandom(12)  # 96-bit IV for GCM
            cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            # Return IV + tag + ciphertext
            encrypted_data = iv + encryptor.tag + ciphertext
            
            # Debug info removed to avoid clipboard pollution
            
            if return_base64:
                encrypted_data = base64.b64encode(encrypted_data)
                
            print(f"🔒 消息加密成功 ({len(message)} -> {len(encrypted_data)} 字节)")
            return encrypted_data
            
        except Exception as e:
            print(f"❌ 消息加密失败: {e}")
            raise

    def decrypt_message(self, encrypted_data) -> bytes:
        """Decrypt message using shared key"""
        if not self.shared_key:
            print(f"❌ 解密失败：shared_key={self.shared_key is not None}")
            raise ValueError("Shared key not established")
        
        try:
            # Handle string input by encoding to bytes (WebSocket text mode)
            if isinstance(encrypted_data, str):
                # Check if this looks like unencrypted JSON
                if encrypted_data.startswith('{') and 'type' in encrypted_data:
                    raise ValueError("Received unencrypted JSON data instead of encrypted data")
                # Convert string to bytes using latin1 to preserve binary data
                encrypted_data = encrypted_data.encode('latin1')
            elif isinstance(encrypted_data, bytes):
                # Check if bytes look like JSON
                if encrypted_data.startswith(b'{') and b'type' in encrypted_data:
                    raise ValueError("Received unencrypted JSON bytes instead of encrypted data")
            else:
                raise ValueError(f"encrypted_data must be bytes or string, got {type(encrypted_data)}")
            
            if len(encrypted_data) < 28:  # 12 (IV) + 16 (tag) minimum
                raise ValueError(f"Encrypted data too short: {len(encrypted_data)} bytes")
            
            # Extract IV, tag, and ciphertext
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Debug info removed to avoid clipboard pollution
            
            cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"🔓 消息解密成功 ({len(encrypted_data)} -> {len(decrypted_data)} 字节)")
            return decrypted_data
            
        except Exception as e:
            print(f"❌ 消息解密失败: {e}")
            print(f"   数据类型: {type(encrypted_data)}")
            if hasattr(encrypted_data, '__len__'):
                print(f"   数据长度: {len(encrypted_data)}")
            if isinstance(encrypted_data, str):
                print(f"   原始字符串前50字符: {repr(encrypted_data[:50])}")
            else:
                print(f"   数据hex前100字符: {encrypted_data[:50].hex()}")
            raise

    async def perform_key_exchange(self, send_data_func, receive_data_func):
        """
        Perform key exchange using provided send and receive functions
        
        Args:
            send_data_func: async function to send data
            receive_data_func: async function to receive data
            
        Returns:
            bool: True if key exchange was successful
        """
        try:
            # Generate our key pair if needed
            if not self.public_key:
                self.generate_key_pair()
            
            # Serialize and send our public key
            server_public_key = self.serialize_public_key()
            key_message = json.dumps({
                "type": "key_exchange",
                "public_key": server_public_key
            })
            await send_data_func(key_message)
            print("📤 已发送公钥")
            
            # Receive peer's public key
            response = await receive_data_func()
            peer_data = json.loads(response)
            
            if peer_data.get("type") == "key_exchange":
                peer_key_data = peer_data.get("public_key")
                peer_public_key = self.deserialize_public_key(peer_key_data)
                
                # Generate shared key
                self.generate_shared_key(peer_public_key)
                print("🔒 密钥交换完成，已建立共享密钥")
                
                # Send confirmation
                await send_data_func(json.dumps({
                    "type": "key_exchange_complete",
                    "status": "success"
                }))
                return True
            else:
                print("❌ 对方未发送公钥")
                return False
                
        except Exception as e:
            print(f"❌ 密钥交换失败: {e}")
            return False
