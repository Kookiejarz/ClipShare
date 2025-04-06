import asyncio
import websockets
import pyperclip
import json
import os
import hmac
import hashlib
import sys
import base64
import time
from pathlib import Path
from utils.security.crypto import SecurityManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
from handlers.file_handler import FileHandler
from utils.platform_config import verify_platform, IS_WINDOWS
from config import ClipboardConfig
import tempfile

# Verify platform at startup
verify_platform('windows')

if IS_WINDOWS:
    import win32clipboard
    import win32con
else:
    raise RuntimeError("This script requires Windows")

class ConnectionStatus:
    """连接状态枚举"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2

class WindowsClipboardClient:
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = DeviceDiscovery()
        self.ws_url = None
        self.last_clipboard_content = pyperclip.paste()
        self.is_receiving = False
        self.device_id = self._get_device_id()
        self.device_token = self._load_device_token()
        self.running = True
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.reconnect_delay = 3
        self.max_reconnect_delay = 30
        self.last_discovery_time = 0
        self.last_content_hash = None
        self.last_update_time = 0
        self.last_format_log = set()
        
        # Initialize file handler
        self.file_handler = FileHandler(
            Path(tempfile.gettempdir()) / "clipshare_files",
            self.security_mgr
        )
    
    def _get_device_id(self):
        """获取唯一设备ID"""
        import socket
        # 使用主机名和MAC地址组合作为设备ID
        try:
            hostname = socket.gethostname()
            # 获取第一个网络接口的MAC地址
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 8*6, 8)][::-1])
            return f"{hostname}-{mac}"
        except:
            # 如果获取失败，生成一个随机ID
            import random
            return f"windows-{random.randint(10000, 99999)}"
    
    def _get_token_path(self):
        """获取令牌存储路径"""
        home_dir = Path.home()
        token_dir = home_dir / ".clipshare"
        token_dir.mkdir(parents=True, exist_ok=True)
        return token_dir / "device_token.txt"
    
    def _load_device_token(self):
        """加载设备令牌"""
        token_path = self._get_token_path()
        if (token_path.exists()):
            with open(token_path, "r") as f:
                return f.read().strip()
        return None
    
    def _save_device_token(self, token):
        """保存设备令牌"""
        token_path = self._get_token_path()
        with open(token_path, "w") as f:
            f.write(token)
        print(f"💾 设备令牌已保存到 {token_path}")
    
    def _generate_signature(self):
        """生成签名"""
        if not self.device_token:
            return ""
        
        return hmac.new(
            self.device_token.encode(), 
            self.device_id.encode(), 
            hashlib.sha256
        ).hexdigest()

    def _init_encryption(self):
        try:
            self.security_mgr.generate_key_pair()
            print("✅ 加密系统初始化成功")
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")
            
    def stop(self):
        """停止客户端运行"""
        print("\n⏹️ 正在停止客户端...")
        self.running = False
        # 关闭发现服务
        if hasattr(self, 'discovery'):
            self.discovery.close()
        print("👋 感谢使用 UniPaste!")

    def on_service_found(self, ws_url):
        """服务发现回调"""
        # 使用标准时间模块而非asyncio，避免线程问题
        self.last_discovery_time = time.time()
        print(f"发现剪贴板服务: {ws_url}")
        self.ws_url = ws_url
        
    async def sync_clipboard(self):
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)
        
        while self.running:
            try:
                if self.connection_status == ConnectionStatus.DISCONNECTED:
                    if not self.ws_url:
                        print("⏳ 等待发现剪贴板服务...")
                        await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                        continue
                    
                    self.connection_status = ConnectionStatus.CONNECTING
                    print(f"🔌 连接到服务器: {self.ws_url}")
                    
                    try:
                        await self.connect_and_sync()
                    except Exception as e:
                        print(f"❌ 连接失败: {e}")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        await self.wait_for_reconnect()
                else:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
            
            except asyncio.CancelledError:
                print("🛑 同步任务被取消")
                break
            except Exception as e:
                print(f"❌ 同步过程出错: {e}")
                await asyncio.sleep(1)
    
    async def wait_for_reconnect(self):
        """等待重连，使用指数退避策略"""
        # 修改这里，使用标准时间而非asyncio时间
        current_time = time.time()
        if current_time - self.last_discovery_time < 10:
            delay = self.reconnect_delay
        else:
            # 否则使用更长延迟
            delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
            self.reconnect_delay = delay
            
        print(f"⏱️ {delay}秒后重新尝试连接...")
        
        # 分段等待，以便能响应停止命令
        for _ in range(int(delay * 2)):
            if not self.running:
                break
            await asyncio.sleep(0.5)
        
        # 重新发现服务
        self.ws_url = None
        print("🔄 重新搜索剪贴板服务...")
    
    async def connect_and_sync(self):
        """连接到服务器并同步剪贴板"""
        # 指定二进制子协议
        async with websockets.connect(
            self.ws_url,
            subprotocols=["binary"]
        ) as websocket:
            try:
                # 身份验证
                if not await self.authenticate(websocket):
                    return
                
                # 密钥交换
                if not await self.perform_key_exchange(websocket):
                    print("❌ 密钥交换失败，断开连接")
                    return
                
                # 连接成功，重置重连延迟
                self.reconnect_delay = 3
                self.connection_status = ConnectionStatus.CONNECTED
                print("✅ 连接和密钥交换成功，开始同步剪贴板")
                
                # 创建可取消的任务
                send_task = asyncio.create_task(self.send_clipboard_changes(websocket))
                receive_task = asyncio.create_task(self.receive_clipboard_changes(websocket))
                
                # 等待任务完成或者程序关闭
                try:
                    while self.running and self.connection_status == ConnectionStatus.CONNECTED:
                        # 使用短超时来定期检查状态
                        await asyncio.sleep(0.5)
                        if not send_task.done() and not receive_task.done():
                            continue
                        break
                    
                    # 取消任务
                    if not send_task.done():
                        send_task.cancel()
                    if not receive_task.done():
                        receive_task.cancel()
                        
                    # 等待取消完成
                    await asyncio.gather(send_task, receive_task, return_exceptions=True)
                
                except asyncio.CancelledError:
                    print("🛑 连接任务被取消")
                    # 取消子任务
                    if not send_task.done():
                        send_task.cancel()
                    if not receive_task.done():
                        receive_task.cancel()
                    raise
                
            except websockets.exceptions.ConnectionClosed as e:
                print(f"📴 与服务器的连接已关闭: {e}")
                self.connection_status = ConnectionStatus.DISCONNECTED
            except Exception as e:
                print(f"❌ 连接过程中出错: {e}")
                self.connection_status = ConnectionStatus.DISCONNECTED
                raise
    
    async def authenticate(self, websocket):
        """与服务器进行身份验证"""
        try:
            is_first_time = self.device_token is None
            
            auth_info = {
                'identity': self.device_id,
                'signature': self._generate_signature(),
                'first_time': is_first_time,
                'device_name': os.environ.get('COMPUTERNAME', 'Windows设备'),
                'platform': 'windows'
            }
            
            print(f"🔑 {'首次连接' if is_first_time else '已注册设备'} ID: {self.device_id}")
            await websocket.send(json.dumps(auth_info))
            
            # 等待身份验证响应
            auth_response = await websocket.recv()
            if isinstance(auth_response, bytes):
                auth_response = auth_response.decode('utf-8')
            
            response_data = json.loads(auth_response)
            status = response_data.get('status')
            
            if status == 'authorized':
                print(f"✅ 身份验证成功! 服务器: {response_data.get('server_id', '未知')}")
                return True
            elif status == 'first_authorized':
                token = response_data.get('token')
                if (token):
                    self._save_device_token(token)
                    self.device_token = token
                    print(f"🆕 设备已授权并获取令牌")
                    return True
                else:
                    print(f"❌ 服务器未提供令牌")
                    return False
            else:
                print(f"❌ 身份验证失败: {response_data.get('reason', '未知原因')}")
                return False
        except Exception as e:
            print(f"❌ 身份验证过程出错: {e}")
            return False
    
    def _get_clipboard_file_paths(self):
        """从剪贴板获取文件路径列表"""
        try:
            # 使用 pywin32 获取文件路径
            import win32clipboard
            import win32con
            
            win32clipboard.OpenClipboard()
            try:
                # 首先尝试获取文件类型格式
                if (win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP)):
                    file_paths = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                    if file_paths:
                        paths = list(file_paths)
                        print(f"📎 剪贴板中包含 {len(paths)} 个文件")
                        return [str(path) for path in paths]
                else:
                    # 获取当前格式列表
                    available_formats = []
                    format_id = win32clipboard.EnumClipboardFormats(0)
                    while format_id:
                        try:
                            format_name = win32clipboard.GetClipboardFormatName(format_id)
                            available_formats.append(f"{format_id} ({format_name})")
                        except:
                            available_formats.append(f"{format_id}")
                        format_id = win32clipboard.EnumClipboardFormats(format_id)
                    
                    # 创建格式集合的哈希值
                    formats_hash = ','.join(sorted(available_formats))
                    
                    # 只有当格式组合发生变化时才打印
                    if formats_hash not in self.last_format_log:
                        print("🔍 剪贴板中没有文件格式数据")
                        if available_formats:
                            print(f"📋 当前剪贴板格式: {', '.join(available_formats[:5])}" + 
                                  (f"... 等{len(available_formats)-5}种" if len(available_formats) > 5 else ""))
                        # 更新已记录的格式
                        self.last_format_log.add(formats_hash)
                        # 保持集合大小在合理范围内
                        if len(self.last_format_log) > 100:
                            self.last_format_log.clear()
                    
            finally:
                win32clipboard.CloseClipboard()
        except Exception as e:
            print(f"❌ 读取剪贴板文件失败: {e}")
            # 打印详细错误信息以帮助调试
            import traceback
            traceback.print_exc()
        
        # 如果上面的方法失败，尝试解析剪贴板文本查找文件路径
        try:
            text = pyperclip.paste()
            # 检查是否像文件路径，包含 :\ 或开头有 / 等特征
            if text and (':\\' in text or text.strip().startswith('/')):
                # 按行分割，过滤掉空行
                lines = [line.strip() for line in text.split('\n') if line.strip()]
                # 检查每行是否可能是有效的文件路径
                valid_paths = []
                for line in lines:
                    path_obj = Path(line)
                    if path_obj.exists():
                        valid_paths.append(str(path_obj))
                
                if valid_paths:
                    print(f"📎 从剪贴板文本解析到 {len(valid_paths)} 个文件路径")
                    return valid_paths
        except Exception as e:
            print(f"❌ 解析剪贴板文本为文件路径失败: {e}")
        
        return None
    
    def _set_clipboard_file_paths(self, file_paths):
        """将文件路径设置到剪贴板"""
        try:
            # Windows需要特殊API将文件路径放入剪贴板
            # 这里我们使用简化的方法，将文件路径作为文本放入
            paths_text = "\n".join(file_paths)
            
            # 计算路径的哈希，用于防止回传
            self.last_content_hash = hashlib.md5(paths_text.encode()).hexdigest()
            
            # 设置更新时间标记，防止自动回传
            self.last_update_time = time.time()
            
            pyperclip.copy(paths_text)
            print(f"📋 已将文件路径复制到剪贴板")
        except Exception as e:
            print(f"❌ 设置剪贴板文件失败: {e}")
    
    def _normalize_path(self, path):
        """规范化不同平台的路径"""
        return str(Path(path))
    
    async def send_clipboard_changes(self, websocket):
        """监控并发送剪贴板变化"""
        last_send_attempt = 0
        last_processed_content = None
        min_interval = 0.5  # 最小检查间隔（秒）
        
        async def broadcast_fn(data):
            try:
                await websocket.send(data)
            except Exception as e:
                print(f"❌ 发送数据失败: {e}")
        
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                if self.is_receiving:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                    continue
                    
                current_time = time.time()
                
                # 检查是否达到最小间隔时间
                if current_time - last_send_attempt < min_interval:
                    await asyncio.sleep(0.1)
                    continue
                    
                current_content = pyperclip.paste()
                
                # 只有当内容真正发生变化时才处理
                if current_content and current_content != last_processed_content:
                    # 创建文本消息
                    text_msg = ClipMessage.text_message(current_content)
                    message_json = ClipMessage.serialize(text_msg)
                    
                    # 检查是否是自己刚刚设置的内容
                    content_hash = hashlib.md5(current_content.encode()).hexdigest()
                    if (content_hash != self.last_content_hash or 
                        current_time - self.last_update_time > 1.0):  # 1秒后允许重新发送相同内容
                        
                        # 加密并发送
                        encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
                        await broadcast_fn(encrypted_data)
                        
                        # 更新状态
                        self.last_content_hash = content_hash
                        self.last_update_time = current_time
                        last_processed_content = current_content
                        
                        # 显示发送的内容（限制长度）
                        max_display = 50
                        display_text = current_content[:max_display] + ("..." if len(current_content) > max_display else "")
                        print(f"📤 已发送文本: \"{display_text}\"")
                
                last_send_attempt = current_time
                await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.running and self.connection_status == ConnectionStatus.CONNECTED:
                    print(f"❌ 发送错误: {e}")
                    if "connection" in str(e).lower():
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                await asyncio.sleep(1)
    
    async def receive_clipboard_changes(self, websocket):
        """接收来自Mac的剪贴板变化"""
        async def broadcast_fn(data):
            await websocket.send(data)
            
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                received_data = await websocket.recv()
                self.is_receiving = True
                
                # 使用security_mgr解密数据
                decrypted_data = self.security_mgr.decrypt_message(received_data)
                message_json = decrypted_data.decode('utf-8')
                message = ClipMessage.deserialize(message_json)
                
                if message["type"] == MessageType.TEXT:
                    await self._handle_text_message(message)
                elif message["type"] == MessageType.FILE:
                    await self.file_handler.handle_received_files(message, websocket, broadcast_fn)
                elif message["type"] == MessageType.FILE_RESPONSE:
                    await self._handle_file_response(message)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.running and self.connection_status == ConnectionStatus.CONNECTED:
                    print(f"❌ 接收错误: {e}")
                    if "connection" in str(e).lower():
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                self.is_receiving = False
                await asyncio.sleep(1)

    async def perform_key_exchange(self, websocket):
        """Execute key exchange with server"""
        try:
            # Generate key pair if needed
            if not self.security_mgr.public_key:
                self.security_mgr.generate_key_pair()
            
            # Wait for server's public key
            server_key_message = await websocket.recv()
            server_data = json.loads(server_key_message)
            
            if server_data.get("type") != "key_exchange":
                print("❌ 服务器未发送公钥")
                return False
            
            # Deserialize server's public key
            server_key_data = server_data.get("public_key")
            server_public_key = self.security_mgr.deserialize_public_key(server_key_data)
            
            # Send our public key
            client_public_key = self.security_mgr.serialize_public_key()
            await websocket.send(json.dumps({
                "type": "key_exchange",
                "public_key": client_public_key
            }))
            print("📤 已发送客户端公钥")
            
            # Generate shared key
            self.security_mgr.generate_shared_key(server_public_key)
            print("🔒 密钥交换完成，已建立共享密钥")
            
            # Wait for confirmation
            confirmation = await websocket.recv()
            confirm_data = json.loads(confirmation)
            
            if confirm_data.get("type") == "key_exchange_complete":
                print("✅ 服务器确认密钥交换成功")
                return True
            else:
                print("⚠️ 没有收到服务器的密钥交换确认")
                return False
                
        except Exception as e:
            print(f"❌ 密钥交换失败: {e}")
            return False

    async def request_file_retry(self, websocket, file_path, filename):
        """请求重新传输文件"""
        print(f"🔄 请求重新传输文件: {filename}")
        file_req = ClipMessage.file_request_message(file_path)
        req_json = ClipMessage.serialize(file_req)
        encrypted_req = self.security_mgr.encrypt_message(req_json.encode('utf-8'))
        
        try:
            await websocket.send(encrypted_req)
            return True
        except Exception as e:
            print(f"❌ 重传请求失败: {e}")
            return False

    async def show_connection_status(self):
        """显示连接状态"""
        last_status = None
        status_messages = {
            ConnectionStatus.DISCONNECTED: "🔴 已断开连接 - 等待服务器",
            ConnectionStatus.CONNECTING: "🟡 正在连接...",
            ConnectionStatus.CONNECTED: "🟢 已连接 - 剪贴板同步已激活"
        }
        
        status_line = ""
        while self.running:
            try:
                # 只在状态变化时更新显示
                if self.connection_status != last_status:
                    # 清除上一行
                    if status_line:
                        sys.stdout.write("\r" + " " * len(status_line) + "\r")
                    
                    # 显示新状态
                    status_line = status_messages.get(self.connection_status, "⚪ 未知状态")
                    sys.stdout.write(f"\r{status_line}")
                    sys.stdout.flush()
                    last_status = self.connection_status
                
                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception:
                pass  # 状态显示不影响主要功能

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

    def _display_progress(self, current, total, length=30):
        """显示进度条"""
        if total == 0:
            return
        
        percent = float(current) / total
        filled_length = int(length * percent)
        bar = '█' * filled_length + '░' * (length - filled_length)
        percent_str = f"{int(percent*100):3}%"
        return f"|{bar}| {current}/{total} ({percent_str})"

    async def _handle_text_message(self, message):
        """处理收到的文本消息"""
        try:
            text = message.get("content", "")
            if not text:
                print("⚠️ 收到空文本消息")
                return
                
            # 检查是否是临时文件路径
            if self._looks_like_temp_file_path(text):
                return
                
            # 计算文本哈希用于防止循环
            content_hash = hashlib.md5(text.encode()).hexdigest()
            if content_hash == self.last_content_hash:
                print("⏭️ 跳过重复内容")
                return
                
            # 更新剪贴板
            pyperclip.copy(text)
            self.last_content_hash = content_hash
            self.last_update_time = time.time()
            
            # 显示收到的文本(限制长度)
            max_display = 50
            display_text = text[:max_display] + ("..." if len(text) > max_display else "")
            print(f"📥 已复制文本: \"{display_text}\"")
            
        except Exception as e:
            print(f"❌ 处理文本消息失败: {e}")
        finally:
            self.is_receiving = False

    async def _handle_file_response(self, message):
        """处理接收到的文件响应"""
        try:
            # 解析文件信息
            filename = message.get("filename")
            chunk_data = base64.b64decode(message.get("chunk_data", ""))
            chunk_index = message.get("chunk_index", 0)
            total_chunks = message.get("total_chunks", 1)
            
            if not filename or not chunk_data:
                print("⚠️ 收到的文件响应缺少必要信息")
                return
            
            # 通过FileHandler处理文件块
            is_complete = self.file_handler.handle_received_chunk(message)
            
            # 如果文件传输完成
            if is_complete:
                file_path = self.file_handler.file_transfers[filename]["path"]
                print(f"✅ 文件接收完成: {file_path}")
                
                # 将文件路径添加到Windows剪贴板
                try:
                    import win32clipboard
                    import win32con
                    from ctypes import sizeof, c_wchar_p, create_unicode_buffer
                    
                    # 准备文件路径
                    file_list = str(file_path) + '\0'  # 以null结尾
                    buffer = create_unicode_buffer(file_list)
                    
                    # 打开剪贴板
                    win32clipboard.OpenClipboard()
                    try:
                        win32clipboard.EmptyClipboard()
                        
                        # 使用 CF_HDROP 格式设置文件路径
                        win32clipboard.SetClipboardData(win32con.CF_HDROP, buffer)
                        print(f"📎 已将文件添加到剪贴板，可用于复制粘贴: {filename}")
                    finally:
                        win32clipboard.CloseClipboard()
                    
                    # 更新内容哈希以防止回传
                    self.last_content_hash = hashlib.md5(str(file_path).encode()).hexdigest()
                    self.last_update_time = time.time()
                    
                except Exception as e:
                    print(f"❌ 设置剪贴板文件失败: {e}")
                    import traceback
                    traceback.print_exc()
                    
                    # 作为备用方案，尝试使用文本方式设置路径
                    try:
                        win32clipboard.OpenClipboard()
                        try:
                            win32clipboard.EmptyClipboard()
                            win32clipboard.SetClipboardText(str(file_path))
                            print(f"📎 使用文本方式添加文件路径到剪贴板: {filename}")
                        finally:
                            win32clipboard.CloseClipboard()
                    except Exception as backup_err:
                        print(f"❌ 备用方法也失败了: {backup_err}")
        
        except Exception as e:
            print(f"❌ 处理文件响应失败: {e}")
        finally:
            self.is_receiving = False

    async def handle_file_transfer(self, file_path: str, broadcast_fn):
        """处理文件传输"""
        path_obj = Path(file_path)
        
        # 检查文件是否存在并且可读
        if not path_obj.exists():
            print(f"⚠️ 文件不存在: {file_path}")
            return False
            
        if not path_obj.is_file():
            print(f"⚠️ 不是有效的文件: {file_path}")
            return False
            
        try:
            # 确保文件可读
            with open(path_obj, 'rb') as f:
                pass
                
            file_size = path_obj.stat().st_size
            print(f"📤 正在处理文件: {path_obj.name} ({file_size} 字节)")
            
            # 创建文件响应消息
            response = {
                'type': MessageType.FILE_RESPONSE,
                'filename': path_obj.name,
                'exists': True,
                'path': str(path_obj)
            }
            
            # 加密并发送文件信息
            encrypted_resp = self.security_mgr.encrypt_message(
                json.dumps(response).encode('utf-8')
            )
            await broadcast_fn(encrypted_resp)
            
            # 发送文件内容
            with open(path_obj, 'rb') as f:
                chunk = f.read()
                chunk_data = base64.b64encode(chunk).decode('utf-8')
                
                file_msg = {
                    'type': MessageType.FILE_RESPONSE,
                    'filename': path_obj.name,
                    'exists': True,
                    'chunk_data': chunk_data,
                    'chunk_index': 0,
                    'total_chunks': 1
                }
                
                encrypted_data = self.security_mgr.encrypt_message(
                    json.dumps(file_msg).encode('utf-8')
                )
                await broadcast_fn(encrypted_data)
                
            return True
                
        except Exception as e:
            print(f"❌ 文件传输失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    client = WindowsClipboardClient()
    
    try:
        print("🚀 ClipShare Windows 客户端已启动")
        print("📋 按 Ctrl+C 退出程序")
        
        # 运行主任务和状态显示任务
        async def run_client():
            status_task = asyncio.create_task(client.show_connection_status())
            sync_task = asyncio.create_task(client.sync_clipboard())
            
            try:
                await asyncio.gather(sync_task, status_task)
            except asyncio.CancelledError:
                if not status_task.done():
                    status_task.cancel()
                if not sync_task.done():
                    sync_task.cancel()
                await asyncio.gather(status_task, sync_task, return_exceptions=True)
        
        # 使用asyncio.run运行主任务
        asyncio.run(run_client())
        
    except KeyboardInterrupt:
        print("\n👋 正在关闭 ClipShare...")
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
    finally:
        # 确保资源被清理
        client.stop()

if __name__ == "__main__":
    main()