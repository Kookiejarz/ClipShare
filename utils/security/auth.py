import json
import os
import secrets
import hmac
import hashlib
import time
from pathlib import Path

class DeviceAuthManager:
    def __init__(self, auth_file_path=None):
        # 默认存储在用户主目录下
        if auth_file_path is None:
            home_dir = Path.home()
            self.auth_file = home_dir / ".clipshare" / "auth_devices.json"
        else:
            self.auth_file = Path(auth_file_path)
            
        # 确保目录存在
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 加载授权设备列表
        self.authorized_devices = self._load_devices()
        
        # 生成服务器密钥（如果不存在）
        self.server_key = self._load_or_create_server_key()
        
    def _load_or_create_server_key(self):
        key_file = self.auth_file.parent / "server_key.txt"
        if key_file.exists():
            with open(key_file, "r") as f:
                return f.read().strip()
        else:
            # 生成32字节随机密钥
            new_key = secrets.token_hex(32)
            with open(key_file, "w") as f:
                f.write(new_key)
            return new_key
            
    def _load_devices(self):
        if not self.auth_file.exists():
            return {}
            
        try:
            with open(self.auth_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
            
    def _save_devices(self):
        with open(self.auth_file, "w") as f:
            json.dump(self.authorized_devices, f, indent=2)
            
    def authorize_device(self, device_id, device_info=None):
        """授权新设备并生成令牌"""
        token = secrets.token_hex(16)
        timestamp = int(time.time())
        
        self.authorized_devices[device_id] = {
            "token": token,
            "created_at": timestamp,
            "last_seen": timestamp,
            "info": device_info or {}
        }
        
        self._save_devices()
        return token
        
    def validate_device(self, device_id, signature):
        """验证设备签名"""
        if device_id not in self.authorized_devices:
            print(f"❌ 设备 {device_id} 未授权")
            return False
            
        device_data = self.authorized_devices[device_id]
        device_token = device_data["token"]
        
        # 验证签名
        expected_signature = hmac.new(
            device_token.encode(), 
            device_id.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        is_valid = hmac.compare_digest(signature, expected_signature)
        
        if is_valid:
            # 更新最后活动时间
            device_data["last_seen"] = int(time.time())
            self._save_devices()
            
        return is_valid
        
    def revoke_device(self, device_id):
        """撤销设备授权"""
        if device_id in self.authorized_devices:
            del self.authorized_devices[device_id]
            self._save_devices()
            return True
        return False
        
    def list_devices(self):
        """列出所有授权设备"""
        return self.authorized_devices