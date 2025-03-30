import AppKit
import asyncio
import websockets
import json 
import signal
from utils.security.crypto import SecurityManager
from utils.security.auth import DeviceAuthManager
from utils.network.discovery import DeviceDiscovery

class ClipboardListener:
    def __init__(self):
        self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
        self.last_change_count = self.pasteboard.changeCount()
        self.security_mgr = SecurityManager()
        self.auth_mgr = DeviceAuthManager()
        self.connected_clients = set()
        self.discovery = DeviceDiscovery()
        self._init_encryption()
        self.is_receiving = False  # Flag to avoid clipboard loops
        self.running = True  # 控制运行状态的标志
        self.server = None  # 保存WebSocket服务器引用，用于关闭

    def _init_encryption(self):
        """初始化加密系统"""
        try:
            # 只生成密钥对，不使用临时共享密钥
            self.security_mgr.generate_key_pair()
            print("✅ 加密系统初始化成功")
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")
    
    def stop(self):
        """停止服务器运行"""
        print("\n⏹️ 正在停止服务器...")
        self.running = False
        
        # 关闭服务发现
        if hasattr(self, 'discovery'):
            self.discovery.close()
        
        # 关闭WebSocket服务器
        if self.server:
            self.server.close()
        
        print("👋 感谢使用 ClipShare 服务器!")

    async def handle_client(self, websocket):
        """处理 WebSocket 客户端连接"""
        device_id = None
        try:
            # 首先接收身份验证信息
            auth_message = await websocket.recv()
            
            # 解析身份验证信息
            try:
                if isinstance(auth_message, str):
                    auth_info = json.loads(auth_message)
                else:
                    auth_info = json.loads(auth_message.decode('utf-8'))
                    
                device_id = auth_info.get('identity', 'unknown-device')
                signature = auth_info.get('signature', '')
                is_first_time = auth_info.get('first_time', False)
                
                print(f"📱 设备 {device_id} 尝试连接")
                
                # 处理首次连接的设备
                if is_first_time:
                    print(f"🆕 设备 {device_id} 首次连接，授权中...")
                    token = self.auth_mgr.authorize_device(device_id, {
                        "name": auth_info.get("device_name", "未命名设备"),
                        "platform": auth_info.get("platform", "未知平台")
                    })
                    
                    # 发送授权令牌给客户端
                    await websocket.send(json.dumps({
                        'status': 'first_authorized',
                        'server_id': 'mac-server',
                        'token': token
                    }))
                    print(f"✅ 已授权设备 {device_id} 并发送令牌")
                    
                else:
                    # 验证现有设备
                    print(f"🔐 验证设备 {device_id} 的签名")
                    is_valid = self.auth_mgr.validate_device(device_id, signature)
                    if not is_valid:
                        print(f"❌ 设备 {device_id} 验证失败")
                        await websocket.send(json.dumps({
                            'status': 'unauthorized',
                            'reason': 'Invalid signature or unknown device'
                        }))
                        return
                        
                    # 发送授权成功响应
                    await websocket.send(json.dumps({
                        'status': 'authorized',
                        'server_id': 'mac-server'
                    }))
                    print(f"✅ 设备 {device_id} 验证成功")
                
            except json.JSONDecodeError:
                print("❌ 无效的身份验证信息")
                await websocket.send(json.dumps({
                    'status': 'error',
                    'reason': 'Invalid authentication format'
                }))
                return
            
            # 执行密钥交换
            if not await self.perform_key_exchange(websocket):
                print("❌ 密钥交换失败，断开连接")
                return
            
            # 身份验证和密钥交换都通过，添加到客户端列表
            self.connected_clients.add(websocket)
            print(f"✅ 设备 {device_id} 已连接并完成密钥交换")
            
            # 之后接收的都是二进制加密数据
            while self.running:
                try:
                    encrypted_data = await asyncio.wait_for(
                        websocket.recv(), 
                        timeout=1.0  # 设置较短的超时，以便可以定期检查running标志
                    )
                    await self.process_received_data(encrypted_data)
                except asyncio.TimeoutError:
                    # 超时只是用来检查running标志，不是错误
                    continue
                except asyncio.CancelledError:
                    print(f"⏹️ {device_id} 的连接处理已取消")
                    break
                
        except websockets.exceptions.ConnectionClosed:
            print(f"📴 设备 {device_id or '未知设备'} 断开连接")
        finally:
            if websocket in self.connected_clients:
                self.connected_clients.remove(websocket)

    async def process_received_data(self, encrypted_data):
        """处理从客户端接收到的加密数据"""
        try:
            self.is_receiving = True
            decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
            content = decrypted_data.decode('utf-8')
            
            # 显示收到的内容（限制字符数以防内容过长）
            max_display_len = 100
            display_content = content if len(content) <= max_display_len else content[:max_display_len] + "..."
            print(f"📥 收到内容: \"{display_content}\"")
            
            # Set to Mac clipboard
            pasteboard = AppKit.NSPasteboard.generalPasteboard()
            pasteboard.clearContents()
            pasteboard.setString_forType_(content, AppKit.NSPasteboardTypeString)
            self.last_change_count = pasteboard.changeCount()
            print("📋 已从客户端更新剪贴板")
            
            # Reset flag after a short delay
            await asyncio.sleep(0.5)
            self.is_receiving = False
        except Exception as e:
            print(f"❌ 接收数据处理错误: {e}")
            self.is_receiving = False

    async def broadcast_encrypted_data(self, encrypted_data):
        """广播加密数据到所有连接的客户端"""
        if not self.connected_clients:
            return
        
        print(f"📢 广播数据 ({len(encrypted_data)} 字节) 到 {len(self.connected_clients)} 个客户端")
        
        # 复制客户端集合以避免在迭代过程中修改
        clients = self.connected_clients.copy()
        
        for client in clients:
            try:
                # 确保以二进制格式发送
                await client.send(encrypted_data)
            except Exception as e:
                print(f"❌ 发送到客户端失败: {e}")
                # 如果发送失败，尝试从集合中移除客户端
                if client in self.connected_clients:
                    self.connected_clients.remove(client)

    async def start_server(self, port=8765):
        """启动 WebSocket 服务器"""
        try:
            # 指定 websockets 使用二进制模式
            self.server = await websockets.serve(
                self.handle_client, 
                "0.0.0.0", 
                port,
                # 设置为二进制模式
                subprotocols=["binary"]
            )
            await self.discovery.start_advertising(port)
            print(f"🌐 WebSocket 服务器启动在端口 {port}")
            
            # 等待服务器关闭
            while self.running:
                await asyncio.sleep(0.5)
                
            # 主动关闭服务器
            if self.server:
                self.server.close()
                await self.server.wait_closed()
                print("✅ WebSocket 服务器已关闭")
                
        except Exception as e:
            print(f"❌ 服务器错误: {e}")
        finally:
            # 停止服务发现
            self.discovery.close()

    async def check_clipboard(self):
        """轮询检查剪贴板内容变化"""
        print("🔐 加密剪贴板监听已启动...")
        while self.running:
            try:
                if not self.is_receiving:  # Only check if not currently receiving
                    new_change_count = self.pasteboard.changeCount()
                    if new_change_count != self.last_change_count:
                        self.last_change_count = new_change_count
                        await self.process_clipboard()
                await asyncio.sleep(.3)
            except asyncio.CancelledError:
                print("⏹️ 剪贴板监听已停止")
                break
            except Exception as e:
                print(f"❌ 剪贴板监听错误: {e}")
                await asyncio.sleep(1)

    async def process_clipboard(self):
        """处理并加密剪贴板内容"""
        types = self.pasteboard.types()
        try:
            if AppKit.NSPasteboardTypeString in types:
                text = self.pasteboard.stringForType_(AppKit.NSPasteboardTypeString)
                
                # 显示发送的内容（限制字符数）
                max_display_len = 100
                display_content = text if len(text) <= max_display_len else text[:max_display_len] + "..."
                print(f"📤 发送内容: \"{display_content}\"")
                
                encrypted_data = self.security_mgr.encrypt_message(text.encode('utf-8'))
                print("🔐 加密后的文本")
                await self.broadcast_encrypted_data(encrypted_data)

            if AppKit.NSPasteboardTypeFileURL in types:
                file_urls = self.pasteboard.propertyListForType_(AppKit.NSPasteboardTypeFileURL)
                
                # 显示发送的文件路径
                print(f"📤 发送文件路径: {file_urls}")
                
                encrypted_data = self.security_mgr.encrypt_message(str(file_urls).encode('utf-8'))
                print("🔐 加密后的文件路径")
                await self.broadcast_encrypted_data(encrypted_data)

            if AppKit.NSPasteboardTypePNG in types:
                print("⚠️ 图片加密暂不支持")

        except Exception as e:
            print(f"❌ 加密错误: {e}")

    async def perform_key_exchange(self, websocket):
        """Perform key exchange with client"""
        try:
            # Generate and send our public key
            if not self.security_mgr.public_key:
                self.security_mgr.generate_key_pair()
            
            server_public_key = self.security_mgr.serialize_public_key()
            key_message = json.dumps({
                "type": "key_exchange",
                "public_key": server_public_key
            })
            await websocket.send(key_message)
            print("📤 已发送服务器公钥")
            
            # Receive client's public key
            response = await websocket.recv()
            client_data = json.loads(response)
            
            if client_data.get("type") == "key_exchange":
                client_key_data = client_data.get("public_key")
                client_public_key = self.security_mgr.deserialize_public_key(client_key_data)
                
                # Generate shared key
                self.security_mgr.generate_shared_key(client_public_key)
                print("🔒 密钥交换完成，已建立共享密钥")
                
                # Send confirmation
                await websocket.send(json.dumps({
                    "type": "key_exchange_complete",
                    "status": "success"
                }))
                return True
            else:
                print("❌ 客户端未发送公钥")
                return False
                
        except Exception as e:
            print(f"❌ 密钥交换失败: {e}")
            return False

async def main():
    listener = ClipboardListener()
    
    # 设置信号处理
    def signal_handler():
        print("\n⚠️ 接收到关闭信号...")
        listener.stop()
    
    # 捕获Ctrl+C信号
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        print("🚀 ClipShare Mac 服务器已启动")
        print("📋 按 Ctrl+C 退出程序")
        
        # 创建任务
        server_task = asyncio.create_task(listener.start_server())
        clipboard_task = asyncio.create_task(listener.check_clipboard())
        
        # 等待任务完成或被取消
        await asyncio.gather(server_task, clipboard_task)
    except asyncio.CancelledError:
        print("\n⏹️ 任务已取消")
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
    finally:
        # 确保资源被清理
        listener.stop()

if __name__ == '__main__':
    asyncio.run(main())
