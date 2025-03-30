import asyncio
import websockets
import pyperclip
import time
from clipshare.security.crypto import SecurityManager
from clipshare.network.discovery import ServiceDiscovery

class WindowsClipboardClient:
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = ServiceDiscovery()
        self._init_encryption()
        self.ws_url = None
        self.last_clipboard_content = pyperclip.paste()
        self.is_receiving = False  # Flag to avoid clipboard loops

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
        
    async def sync_clipboard(self):
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)
        
        while not self.ws_url:
            await asyncio.sleep(1)
            
        print(f"🔌 连接到服务器: {self.ws_url}")
        
        async with websockets.connect(self.ws_url) as websocket:
            # Start tasks for both sending and receiving
            send_task = asyncio.create_task(self.send_clipboard_changes(websocket))
            receive_task = asyncio.create_task(self.receive_clipboard_changes(websocket))
            
            # Wait for either task to complete (or be cancelled)
            await asyncio.gather(send_task, receive_task)
    
    async def send_clipboard_changes(self, websocket):
        """Monitor and send clipboard changes to Mac"""
        while True:
            try:
                current_content = pyperclip.paste()
                if current_content != self.last_clipboard_content and not self.is_receiving:
                    print("📤 发送剪贴板内容...")
                    # Encrypt and send content
                    encrypted_data = self.security_mgr.encrypt_message(current_content.encode('utf-8'))
                    await websocket.send(encrypted_data)
                    self.last_clipboard_content = current_content
                await asyncio.sleep(0.3)
            except Exception as e:
                print(f"❌ 发送错误: {e}")
                await asyncio.sleep(1)  # Wait before retrying
    
    async def receive_clipboard_changes(self, websocket):
        """Receive clipboard changes from Mac"""
        while True:
            try:
                encrypted_data = await websocket.recv()
                # Set flag to prevent loop
                self.is_receiving = True
                
                # Decrypt data
                decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
                content = decrypted_data.decode('utf-8')
                
                # Update clipboard
                pyperclip.copy(content)
                self.last_clipboard_content = content
                print("📋 已更新剪贴板内容")
                
                # Reset flag after a short delay
                await asyncio.sleep(0.5)
                self.is_receiving = False
            except Exception as e:
                print(f"❌ 接收错误: {e}")

def main():
    client = WindowsClipboardClient()
    asyncio.run(client.sync_clipboard())

if __name__ == "__main__":
    main()