import AppKit
import time
import asyncio
import websockets
from clipshare.security.crypto import SecurityManager
from clipshare.network.discovery import DeviceDiscovery

class ClipboardListener:
    def __init__(self):
        self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
        self.last_change_count = self.pasteboard.changeCount()
        self.security_mgr = SecurityManager()
        self.connected_clients = set()
        self.discovery = DeviceDiscovery()
        self._init_encryption()
        self.is_receiving = False  # Flag to avoid clipboard loops

    def _init_encryption(self):
        """初始化加密系统"""
        try:
            self.security_mgr.generate_key_pair()
            self.security_mgr.generate_temporary_shared_key()
            print("✅ 加密系统初始化成功")
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")

    async def handle_client(self, websocket):
        """处理 WebSocket 客户端连接"""
        self.connected_clients.add(websocket)
        try:
            # Receive and process messages from this client
            while True:
                encrypted_data = await websocket.recv()
                await self.process_received_data(encrypted_data)
        except websockets.exceptions.ConnectionClosed:
            print("📴 客户端断开连接")
        finally:
            self.connected_clients.remove(websocket)

    async def process_received_data(self, encrypted_data):
        """处理从 Windows 接收到的加密数据"""
        try:
            self.is_receiving = True
            decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
            content = decrypted_data.decode('utf-8')
            
            # Set to Mac clipboard
            pasteboard = AppKit.NSPasteboard.generalPasteboard()
            pasteboard.clearContents()
            pasteboard.setString_forType_(content, AppKit.NSPasteboardTypeString)
            self.last_change_count = pasteboard.changeCount()
            print("📋 已从 Windows 更新剪贴板")
            
            # Reset flag after a short delay
            await asyncio.sleep(0.5)
            self.is_receiving = False
        except Exception as e:
            print(f"❌ 接收数据处理错误: {e}")

    async def broadcast_encrypted_data(self, encrypted_data):
        """广播加密数据到所有连接的客户端"""
        if self.connected_clients:
            websockets.broadcast(self.connected_clients, encrypted_data)

    async def start_server(self, port=8765):
        """启动 WebSocket 服务器"""
        server = await websockets.serve(self.handle_client, "0.0.0.0", port)
        self.discovery.start_advertising(port)
        print(f"🌐 WebSocket 服务器启动在端口 {port}")
        await server.wait_closed()

    async def check_clipboard(self):
        """轮询检查剪贴板内容变化"""
        print("🔐 加密剪贴板监听已启动...")
        while True:
            if not self.is_receiving:  # Only check if not currently receiving
                new_change_count = self.pasteboard.changeCount()
                if new_change_count != self.last_change_count:
                    self.last_change_count = new_change_count
                    await self.process_clipboard()
            await asyncio.sleep(.3)

    async def process_clipboard(self):
        """处理并加密剪贴板内容"""
        types = self.pasteboard.types()
        try:
            if AppKit.NSPasteboardTypeString in types:
                text = self.pasteboard.stringForType_(AppKit.NSPasteboardTypeString)
                encrypted_data = self.security_mgr.encrypt_message(text.encode('utf-8'))
                print("🔐 加密后的文本", encrypted_data)
                await self.broadcast_encrypted_data(encrypted_data)

            if AppKit.NSPasteboardTypeFileURL in types:
                file_urls = self.pasteboard.propertyListForType_(AppKit.NSPasteboardTypeFileURL)
                encrypted_data = self.security_mgr.encrypt_message(str(file_urls).encode('utf-8'))
                print("🔐 加密后的文件路径")
                await self.broadcast_encrypted_data(encrypted_data)

            if AppKit.NSPasteboardTypePNG in types:
                print("⚠️ 图片加密暂不支持")

        except Exception as e:
            print(f"❌ 加密错误: {e}")

async def main():
    listener = ClipboardListener()
    try:
        await asyncio.gather(
            listener.start_server(),
            listener.check_clipboard()
        )
    except KeyboardInterrupt:
        print("\n👋 正在关闭服务...")
    finally:
        listener.discovery.close()

if __name__ == '__main__':
    asyncio.run(main())
