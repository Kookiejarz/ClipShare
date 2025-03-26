import asyncio
import websockets
import pyperclip
from clipshare.security.crypto import SecurityManager
from clipshare.network.discovery import ServiceDiscovery

class WindowsClipboardClient:
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = ServiceDiscovery()
        self._init_encryption()
        self.ws_url = None

    def _init_encryption(self):
        try:
            self.security_mgr.generate_key_pair()
            self.security_mgr.generate_temporary_shared_key()
            print("✅ 加密系统初始化成功")
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")

    def on_service_found(self, ws_url):
        print(f"发现剪贴板服务: {ws_url}")
        self.ws_url = ws_url
        
    async def receive_clipboard(self):
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)
        
        while not self.ws_url:
            await asyncio.sleep(1)
            
        print(f"🔌 连接到服务器: {self.ws_url}")
        
        async with websockets.connect(self.ws_url) as websocket:
            while True:
                try:
                    encrypted_data = await websocket.recv()
                    # 解密数据
                    decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
                    # 写入剪贴板
                    pyperclip.copy(decrypted_data.decode('utf-8'))
                    print("📋 已更新剪贴板内容")
                except Exception as e:
                    print(f"❌ 错误: {e}")

def main():
    client = WindowsClipboardClient()
    asyncio.get_event_loop().run_until_complete(client.receive_clipboard())

if __name__ == "__main__":
    main()