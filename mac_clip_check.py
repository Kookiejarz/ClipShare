import AppKit
import asyncio
import websockets
import json 
import signal
import time
import base64
import os
from utils.security.crypto import SecurityManager
from utils.security.auth import DeviceAuthManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
import tempfile
from pathlib import Path
import hashlib
from handlers.file_handler import FileHandler

class ClipboardListener:
    """剪贴板监听和同步服务器"""
    
    def __init__(self):
        self._init_basic_components()
        self._init_state_flags()
        self._init_file_handling()
        self._init_encryption()
        
    def _init_basic_components(self):
        try:
            self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
            self.security_mgr = SecurityManager()
            self.auth_mgr = DeviceAuthManager()
            self.discovery = DeviceDiscovery()
            self.connected_clients = set()
        except Exception as e:
            print(f"❌ 基础组件初始化失败: {e}")
            raise
        
    def _init_state_flags(self):
        self.last_change_count = self.pasteboard.changeCount()
        self.last_content_hash = None
        self.is_receiving = False
        self.last_update_time = 0
        self.running = True
        self.server = None
        self.ignore_clipboard_until = 2  # 新增
        
    def _init_file_handling(self):
        try:
            self.temp_dir = Path(tempfile.gettempdir()) / "unipaste_files"
            self.file_handler = FileHandler(self.temp_dir, self.security_mgr)
        except Exception as e:
            print(f"❌ 文件处理初始化失败: {e}")
            raise

    def _init_encryption(self):
        try:
            self.security_mgr.generate_key_pair()
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")
            raise
        
    def load_file_cache(self):
        """加载文件缓存信息"""
        cache_path = self.temp_dir / "filecache.json"
        try:
            if cache_path.exists():
                with open(cache_path, "r") as f:
                    self.file_cache = json.load(f)
                print(f"📚 已加载 {len(self.file_cache)} 个文件缓存条目")
            else:
                self.file_cache = {}
                print("📝 创建新的文件缓存")
        except Exception as e:
            print(f"⚠️ 加载文件缓存失败: {e}，将使用空缓存")
            self.file_cache = {}
    

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
                        timeout=0.5  # 设置较短的超时，以便可以定期检查running标志
                    )
                    # 传递发送者的WebSocket连接对象
                    await self.process_received_data(encrypted_data, sender_websocket=websocket)
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

    async def process_received_data(self, encrypted_data, sender_websocket=None):
        """处理从客户端接收到的加密数据"""
        try:
            self.is_receiving = True
            decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
            message_json = decrypted_data.decode('utf-8')
            message = ClipMessage.deserialize(message_json)
            
            if message["type"] == MessageType.TEXT:
                text = message.get("content", "")
                if not text:
                    print("⚠️ 收到空文本消息")
                    return
                
                # 检查是否是临时文件路径
                if self._looks_like_temp_file_path(text):
                    return

                # 通过 FileHandler 设置剪贴板文本
                self.file_handler.set_clipboard_text(text)
                self.last_change_count = self.pasteboard.changeCount()
                self.last_update_time = time.time()
                self.last_content_hash = hashlib.md5(text.encode()).hexdigest()
                
                # 显示接收到的文本(限制长度)
                max_display = 50
                display_text = text[:max_display] + ("..." if len(text) > max_display else "")
                print(f"📥 已复制文本: \"{display_text}\"")
                
            elif message["type"] == MessageType.FILE:
                # 处理文件消息
                files = message.get("files", [])
                if files:
                    await self.file_handler.handle_received_files(
                        message, 
                        sender_websocket,
                        self.broadcast_encrypted_data
                    )
                    
            elif message["type"] == MessageType.FILE_RESPONSE:
                if self.file_handler.handle_received_chunk(message):
                    filename = message.get("filename")
                    if filename in self.file_handler.file_transfers:
                        file_path = self.file_handler.file_transfers[filename]["path"]
                        self.file_handler.set_clipboard_file(file_path)
                        print(f"✅ 文件已添加到剪贴板: {filename}")
                        # 新增：同步last_content_hash，防止回环
                        self.last_content_hash = hashlib.md5(str(file_path).encode()).hexdigest()
                        self.last_update_time = time.time()
                    
        except Exception as e:
            print(f"❌ 接收数据处理错误: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_receiving = False

    async def broadcast_encrypted_data(self, encrypted_data, exclude_client=None):
        """广播加密数据到所有连接的客户端，可选择排除特定客户端"""
        if not self.connected_clients:
            return
 
        # 计算要广播的客户端数
        broadcast_count = len(self.connected_clients) - (1 if exclude_client in self.connected_clients else 0)
        if broadcast_count == 0:
            return
            
        print(f"📢 广播数据 ({len(encrypted_data)} 字节) 到 {broadcast_count} 个客户端")
        
        # 复制客户端集合以避免在迭代过程中修改
        clients = self.connected_clients.copy()
        
        for client in clients:
            try:
                # 排除指定的客户端
                if client == exclude_client:
                    continue
                    
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
        last_processed_time = 0  # 上次处理内容的时间
        min_process_interval = 0.8  # 最小处理时间间隔
        
        while self.running:
            try:
                current_time = time.time()
                if current_time < self.ignore_clipboard_until:
                    await asyncio.sleep(0.3)
                    continue
                time_since_update = current_time - self.last_update_time
                time_since_process = current_time - last_processed_time
                
                # 三重防护: 1) 确保不是接收状态 2) 确保与上次更新间隔充足 3) 确保处理频率不会太高
                if (not self.is_receiving and 
                    time_since_update > 1.0 and  # 墛大阈值
                    time_since_process > min_process_interval):
                    
                    new_change_count = self.pasteboard.changeCount()
                    if new_change_count != self.last_change_count:
                        self.last_change_count = new_change_count
                        await self.process_clipboard()
                        last_processed_time = time.time()  # 更新处理时间
                        
                await asyncio.sleep(0.3)
            except asyncio.CancelledError:
                print("⏹️ 剪贴板监听已停止")
                break
            except Exception as e:
                print(f"❌ 剪贴板监听错误: {e}")
                await asyncio.sleep(1)

    async def process_clipboard(self):
        """处理并加密剪贴板内容"""
        try:
            # 通过 FileHandler 获取剪贴板文本
            text = self.file_handler.get_clipboard_text()
            if text:
                current_time = time.time()
                new_hash, new_time = await self.file_handler.process_clipboard_content(
                    text, 
                    current_time,
                    self.last_content_hash,
                    self.last_update_time,
                    self.broadcast_encrypted_data
                )
                self.last_content_hash = new_hash
                self.last_update_time = new_time

            # 通过 FileHandler 获取剪贴板文件列表
            file_urls = self.file_handler.get_clipboard_files()
            if file_urls:
                self.last_content_hash = await self.file_handler.handle_clipboard_files(
                    file_urls, 
                    self.last_content_hash,
                    self.broadcast_encrypted_data
                )
                self.last_update_time = time.time()

            # 图片等其它类型可后续扩展
        except Exception as e:
            print(f"❌ 加密错误: {e}")

    async def perform_key_exchange(self, websocket):
        """Perform key exchange with client"""
        # Create wrapper functions for sending/receiving through websocket
        async def send_to_websocket(data):
            await websocket.send(data)
            
        async def receive_from_websocket():
            return await websocket.recv()
        
        # Use the SecurityManager's key exchange implementation
        return await self.security_mgr.perform_key_exchange(
            send_to_websocket,
            receive_from_websocket
        )

    def _looks_like_temp_file_path(self, text):
        """检查文本是否看起来像临时文件路径"""
        # 检查是否有常见的临时目录路径
        temp_indicators = [
            "\\AppData\\Local\\Temp\\clipshare_files\\",
            "/var/folders/",
            "/tmp/clipshare_files/",
            "C:\\Users\\\\AppData\\Local\\Temp\\clipshare_files\\"
        ]
        
        for indicator in temp_indicators:
            if indicator in text:
                print(f"⏭️ 跳过临时文件路径: \"{text[:40]}...\"")
                return True
                
        return False
    
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
        
        print("👋 感谢使用 UniPaste 服务器!")

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
