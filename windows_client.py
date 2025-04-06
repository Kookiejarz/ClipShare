import asyncio
import websockets
import pyperclip
import json
import os
import hmac
import hashlib
import sys
import base64
import time  # 添加 time 模块
from pathlib import Path
from utils.security.crypto import SecurityManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
import win32clipboard
import tempfile

class ConnectionStatus:
    """连接状态枚举"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2

class WindowsClipboardClient:
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = DeviceDiscovery()
        self._init_encryption()
        self.ws_url = None
        self.last_clipboard_content = pyperclip.paste()
        self.is_receiving = False  # Flag to avoid clipboard loops
        self.device_id = self._get_device_id()
        self.device_token = self._load_device_token()
        self.running = True  # 控制运行状态的标志
        self.connection_status = ConnectionStatus.DISCONNECTED  # 连接状态
        self.reconnect_delay = 3  # 重连延迟秒数
        self.max_reconnect_delay = 30  # 最大重连延迟秒数
        self.last_discovery_time = 0  # 上次发现服务的时间，改为普通时间戳
        self.last_content_hash = None  # 添加内容哈希字段，用于防止重复发送
        self.last_update_time = 0  # 记录最后一次更新剪贴板的时间
    
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
        """同步剪贴板主循环"""
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)
        
        while self.running:
            try:
                if self.connection_status == ConnectionStatus.DISCONNECTED:
                    if not self.ws_url:
                        # 等待发现服务
                        print("⏳ 等待发现剪贴板服务...")
                        await asyncio.sleep(3)
                        continue
                    
                    # 发现服务后开始连接
                    self.connection_status = ConnectionStatus.CONNECTING
                    print(f"🔌 连接到服务器: {self.ws_url}")
                    
                    try:
                        await self.connect_and_sync()
                    except Exception as e:
                        print(f"❌ 连接失败: {e}")
                        # 连接失败，重置状态
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        # 如果连接失败，增加重连延迟，实现指数退避
                        await self.wait_for_reconnect()
                else:
                    # 已连接或正在连接，简单等待
                    await asyncio.sleep(0.5)
            
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
                if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                    file_paths = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                    if file_paths:
                        paths = list(file_paths)
                        print(f"📎 剪贴板中包含 {len(paths)} 个文件")
                        # 确保路径是字符串而非对象
                        return [str(path) for path in paths]
                else:
                    print("🔍 剪贴板中没有文件格式数据")
                    
                    # 调试: 显示当前可用的剪贴板格式
                    available_formats = []
                    format_id = win32clipboard.EnumClipboardFormats(0)
                    while format_id:
                        try:
                            format_name = win32clipboard.GetClipboardFormatName(format_id)
                            available_formats.append(f"{format_id} ({format_name})")
                        except:
                            available_formats.append(f"{format_id}")
                        format_id = win32clipboard.EnumClipboardFormats(format_id)
                    
                    if available_formats:
                        print(f"📋 当前剪贴板格式: {', '.join(available_formats[:5])}" + 
                              (f"... 等{len(available_formats)-5}种" if len(available_formats) > 5 else ""))
                    
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
        """监控并发送剪贴板变化到Mac"""
        last_send_attempt = 0  # 上次尝试发送的时间
        
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                # 检查当前状态
                if self.is_receiving:
                    # 正在接收中，不发送任何内容
                    await asyncio.sleep(0.5)
                    continue
                
                # 使用标准时间而非asyncio时间
                current_time = time.time()
                
                # 检查剪贴板中的文本
                current_content = pyperclip.paste()
                
                # 空内容不处理
                if not current_content or current_content.strip() == "":
                    await asyncio.sleep(0.3)
                    continue
                
                # 计算当前内容哈希
                content_hash = hashlib.md5(current_content.encode()).hexdigest()
                
                # 判断是否需要发送文本内容 - 增加更多条件和日志帮助调试
                should_send_text = (
                    current_content and 
                    content_hash != self.last_content_hash and  # 使用类变量
                    not self.is_receiving and 
                    current_time - last_send_attempt > 1.5 and  # 增加发送频率限制
                    current_time - self.last_update_time > 2.0 and  # 增加更新后保护期
                    not self._looks_like_temp_file_path(current_content)  # 避免发送临时文件路径
                )
                
                # 增加调试信息，帮助识别为什么未发送
                if current_content and content_hash != self.last_content_hash and not should_send_text:
                    reasons = []
                    if self.is_receiving:
                        reasons.append("正在接收中")
                    if current_time - last_send_attempt <= 1.5:
                        reasons.append(f"发送间隔过短 ({current_time - last_send_attempt:.1f}s < 1.5s)")
                    if current_time - self.last_update_time <= 2.0:
                        reasons.append(f"更新保护期内 ({current_time - self.last_update_time:.1f}s < 2.0s)")
                    
                    if reasons:
                        print(f"ℹ️ 剪贴板变化暂不发送: {', '.join(reasons)}")
                
                # 检查剪贴板中的文件
                file_paths = self._get_clipboard_file_paths()

                # 打印调试信息
                if file_paths:
                    print(f"🔍 检测到 {len(file_paths)} 个文件:")
                    for i, path in enumerate(file_paths[:3]):
                        print(f"  - {i+1}: {path}")
                    if len(file_paths) > 3:
                        print(f"  ... 共 {len(file_paths)} 个")

                should_send_files = (
                    file_paths and 
                    not self.is_receiving and 
                    current_time - last_send_attempt > 1.5 and
                    current_time - self.last_update_time > 2.0  # 确保距离上次更新有足够时间
                )

                if should_send_text:
                    # 记录发送尝试时间和内容哈希
                    last_send_attempt = current_time
                    self.last_content_hash = content_hash
                    
                    # 显示发送的内容（限制字符数）
                    max_display_len = 100
                    display_content = current_content if len(current_content) <= max_display_len else current_content[:max_display_len] + "..."
                    print(f"📤 发送文本内容: \"{display_content}\"")
                    
                    try:
                        # 创建文本消息
                        text_msg = ClipMessage.text_message(current_content)
                        message_json = ClipMessage.serialize(text_msg)
                        
                        # Encrypt and send content
                        encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
                        await websocket.send(encrypted_data)
                        self.last_clipboard_content = current_content
                        print("✅ 文本内容已发送")
                    except websockets.exceptions.ConnectionClosed:
                        print("❗ 服务器连接已断开，无法发送")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                
                elif should_send_files:
                    # 记录发送尝试时间
                    last_send_attempt = current_time
                    
                    # 显示发送的文件
                    file_names = []
                    file_sizes = []
                    for path in file_paths:
                        try:
                            path_obj = Path(path)
                            file_names.append(path_obj.name)
                            if path_obj.exists():
                                size_mb = path_obj.stat().st_size / (1024*1024)
                                file_sizes.append(f"{size_mb:.1f}MB")
                            else:
                                file_sizes.append("不存在")
                        except Exception as e:
                            file_names.append(os.path.basename(str(path)))
                            file_sizes.append(f"错误: {str(e)[:20]}...")
                    
                    paths_info = [f"{name} ({size})" for name, size in zip(file_names[:3], file_sizes[:3])]
                    print(f"📤 发送文件: {', '.join(paths_info)}{' 等' if len(file_names) > 3 else ''}")
                    
                    # 过滤掉不存在的文件
                    valid_paths = []
                    for path in file_paths:
                        if Path(path).exists():
                            valid_paths.append(str(path))
                        else:
                            print(f"⚠️ 跳过不存在的文件: {path}")
                    
                    if not valid_paths:
                        print("❌ 没有可发送的有效文件")
                        continue
                    
                    try:
                        # 创建文件消息
                        file_msg = ClipMessage.file_message(valid_paths)
                        message_json = ClipMessage.serialize(file_msg)
                        
                        # 打印一些调试信息
                        print(f"📋 文件消息长度: {len(message_json)} 字节")
                        
                        # Encrypt and send content
                        encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
                        await websocket.send(encrypted_data)
                        print(f"✅ 文件信息已发送 ({len(encrypted_data)} 字节)")
                        
                        # 更新哈希和时间，防止重复发送
                        paths_text = "\n".join(valid_paths)
                        self.last_content_hash = hashlib.md5(paths_text.encode()).hexdigest()
                        
                    except websockets.exceptions.ConnectionClosed:
                        print("❗ 服务器连接已断开，无法发送")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                    except Exception as e:
                        print(f"❌ 发送文件信息失败: {str(e)}")
                        import traceback
                        traceback.print_exc()
                    
                await asyncio.sleep(0.3)
                
            except asyncio.CancelledError:
                # 正常取消，不打印错误
                break
            except Exception as e:
                if self.running and self.connection_status == ConnectionStatus.CONNECTED:
                    print(f"❌ 发送错误: {e}")
                    # 如果是连接错误，切换到断开状态
                    if "connection" in str(e).lower() or "closed" in str(e).lower():
                        print("❗ 检测到连接问题，标记为已断开")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                await asyncio.sleep(1)
    
    async def receive_clipboard_changes(self, websocket):
        """接收来自Mac的剪贴板变化"""
        # 创建临时目录用于接收文件
        temp_dir = Path(tempfile.gettempdir()) / "clipshare_files"
        temp_dir.mkdir(exist_ok=True)
        
        # 文件接收状态跟踪
        file_transfers = {}
        
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                # 接收数据 - 可能是二进制或文本
                received_data = await websocket.recv()
                
                # 先设置接收标志，防止在处理过程中发送剪贴板内容
                self.is_receiving = True
                
                # 确保数据是二进制格式
                if isinstance(received_data, str):
                    # 如果是JSON字符串，可能需要解析
                    if received_data.startswith('{'):
                        try:
                            data_obj = json.loads(received_data)
                            if 'encrypted_data' in data_obj:
                                # 从JSON提取并转换为bytes
                                encrypted_data = base64.b64decode(data_obj['encrypted_data'])
                            else:
                                print("❌ 收到无效的JSON数据")
                                continue
                        except json.JSONDecodeError:
                            print("❌ 无效的JSON格式")
                            continue
                    else:
                        # 普通字符串，直接使用UTF-8编码转为bytes
                        encrypted_data = received_data.encode('utf-8')
                else:
                    # 已经是bytes类型
                    encrypted_data = received_data
                
                # 解密数据
                decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
                message_json = decrypted_data.decode('utf-8')
                
                # 解析消息
                message = ClipMessage.deserialize(message_json)
                if not message or "type" not in message:
                    print("❌ 收到无效的消息格式")
                    self.is_receiving = False
                    continue
                
                # 根据消息类型处理
                if message["type"] == MessageType.TEXT:
                    content = message["content"]
                    
                    # 计算内容哈希，用于防止循环
                    content_hash = hashlib.md5(content.encode()).hexdigest()
                    
                    # 如果和上次接收/发送的内容相同，则跳过
                    if content_hash == self.last_content_hash:
                        print(f"⏭️ 跳过重复内容: 哈希值 {content_hash[:8]}... 相同")
                        self.is_receiving = False
                        continue
                    
                    # 保存当前内容哈希 - 在更新剪贴板前记录
                    self.last_content_hash = content_hash
                    
                    # 显示收到的内容（限制字符数以防内容过长）
                    max_display_len = 100
                    display_content = content if len(content) <= max_display_len else content[:max_display_len] + "..."
                    print(f"📥 收到文本: \"{display_content}\"")
                    
                    # 更新剪贴板前，记录当前时间
                    self.last_update_time = time.time()
                    
                    # 更新剪贴板
                    pyperclip.copy(content)
                    self.last_clipboard_content = content
                    print("📋 已更新剪贴板")
                    
                    # 重要：在这里维持接收状态一段较长时间，而不是在通用循环结束处
                    # 这能确保接收后有足够时间防止回传
                    await asyncio.sleep(2.0)
                    print(f"⏱️ 剪贴板保护期结束")
                    self.is_receiving = False
                    
                elif message["type"] == MessageType.FILE:
                    # 收到文件列表信息
                    files = message.get("files", [])
                    if not files:
                        print("❌ 收到空的文件列表")
                        self.is_receiving = False
                        continue
                        
                    file_names = [f["filename"] for f in files]
                    print(f"📥 收到文件信息: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")
                    
                    # 对每个文件发送请求
                    for file_info in files:
                        file_path = file_info["path"]
                        filename = file_info["filename"]
                        file_size = file_info.get("size", 0)
                        
                        print(f"📥 准备接收文件: {filename} ({file_size / 1024 / 1024:.1f} MB)")
                        
                        # 创建文件请求消息
                        file_req = ClipMessage.file_request_message(file_path)
                        req_json = ClipMessage.serialize(file_req)
                        encrypted_req = self.security_mgr.encrypt_message(req_json.encode('utf-8'))
                        
                        try:
                            await websocket.send(encrypted_req)
                            print(f"📤 已请求文件: {filename}")
                        except Exception as e:
                            print(f"❌ 请求文件失败: {e}")
                    
                    # 文件列表处理完成，重置接收标志
                    self.is_receiving = False
                    
                elif message["type"] == MessageType.FILE_REQUEST:
                    # 收到文件请求
                    filename = message.get("filename", "未知文件")
                    file_path = message.get("path", "")
                    
                    if not file_path:
                        print(f"❌ 收到无效的文件请求: 缺少路径")
                        self.is_receiving = False
                        continue
                    
                    print(f"📥 收到文件请求: {filename} (路径: {file_path})")
                    
                    # 检查文件是否存在
                    path_obj = Path(file_path)
                    if not path_obj.exists():
                        print(f"❌ 请求的文件不存在: {file_path}")
                        
                        # 发送文件不存在响应
                        response = ClipMessage.file_response_message(file_path)  # exists=False by default
                        resp_json = ClipMessage.serialize(response)
                        encrypted_resp = self.security_mgr.encrypt_message(resp_json.encode('utf-8'))
                        await websocket.send(encrypted_resp)
                        
                        self.is_receiving = False
                        continue
                    
                    file_size = path_obj.stat().st_size
                    print(f"📤 开始发送文件: {filename} (大小: {file_size / 1024 / 1024:.2f} MB)")
                    
                    # 计算文件块数量
                    chunk_size = 1024 * 1024  # 1MB 块大小
                    total_chunks = (file_size + chunk_size - 1) // chunk_size
                    
                    # 计算文件哈希，用于验证
                    try:
                        file_hash = ClipMessage.calculate_file_hash(str(path_obj))
                        print(f"🔒 文件哈希: {file_hash[:8]}...")
                    except Exception as e:
                        print(f"⚠️ 计算文件哈希失败: {e}")
                        file_hash = ""
                    
                    # 逐块发送文件内容
                    for i in range(total_chunks):
                        try:
                            with open(path_obj, "rb") as f:
                                f.seek(i * chunk_size)
                                chunk_data = f.read(chunk_size)
                            
                            print(f"📤 发送文件块 {i+1}/{total_chunks} (大小: {len(chunk_data)/1024:.1f} KB)")
                            
                            # 创建文件响应消息
                            if i == 0:  # 只在第一个块中包含完整文件哈希
                                response = {
                                    "type": MessageType.FILE_RESPONSE,
                                    "filename": path_obj.name,
                                    "exists": True,
                                    "path": str(path_obj),
                                    "size": file_size,
                                    "chunk_index": i,
                                    "total_chunks": total_chunks,
                                    "chunk_data": base64.b64encode(chunk_data).decode('utf-8'),
                                    "file_hash": file_hash,
                                    "chunk_hash": hashlib.md5(chunk_data).hexdigest()
                                }
                            else:
                                response = {
                                    "type": MessageType.FILE_RESPONSE,
                                    "filename": path_obj.name,
                                    "exists": True,
                                    "path": str(path_obj),
                                    "size": file_size,
                                    "chunk_index": i,
                                    "total_chunks": total_chunks,
                                    "chunk_data": base64.b64encode(chunk_data).decode('utf-8'),
                                    "chunk_hash": hashlib.md5(chunk_data).hexdigest()
                                }
                            
                            resp_json = json.dumps(response)
                            encrypted_resp = self.security_mgr.encrypt_message(resp_json.encode('utf-8'))
                            await websocket.send(encrypted_resp)
                            
                            # 短暂延迟，避免网络拥塞
                            await asyncio.sleep(0.05)
                        except Exception as e:
                            print(f"❌ 发送文件块失败: {e}")
                            import traceback
                            traceback.print_exc()
                            break
                    
                    print(f"✅ 文件 {filename} 发送完成")
                    self.is_receiving = False
                    
                elif message["type"] == MessageType.FILE_RESPONSE:
                    # 收到文件内容响应
                    filename = message["filename"]
                    exists = message.get("exists", False)
                    
                    if not exists:
                        print(f"⚠️ 文件 {filename} 在源设备上不存在")
                        self.is_receiving = False
                        continue
                    
                    # 解析文件块信息
                    chunk_index = message.get("chunk_index", 0)
                    total_chunks = message.get("total_chunks", 1)
                    chunk_data = base64.b64decode(message["chunk_data"])
                    chunk_hash = message.get("chunk_hash", "")
                    
                    # 验证块哈希
                    calculated_chunk_hash = hashlib.md5(chunk_data).hexdigest()
                    if chunk_hash and calculated_chunk_hash != chunk_hash:
                        print(f"⚠️ 文件块 {filename} ({chunk_index+1}/{total_chunks}) 哈希验证失败")
                        # 可以在此添加重试逻辑
                        self.is_receiving = False
                        continue
                    
                    # 保存文件块
                    save_path = temp_dir / filename
                    
                    # 如果是第一块，创建或清空文件
                    if chunk_index == 0:
                        # 记录完整文件哈希用于最终验证
                        file_hash = message.get("file_hash", "")
                        
                        with open(save_path, "wb") as f:
                            f.write(chunk_data)
                        file_transfers[filename] = {
                            "received_chunks": 1,
                            "total_chunks": total_chunks,
                            "path": save_path,
                            "file_hash": file_hash
                        }
                        print(f"📥 开始接收文件: {filename} (块 1/{total_chunks})")
                    else:
                        # 否则追加到文件
                        with open(save_path, "ab") as f:
                            f.write(chunk_data)
                        
                        # 更新接收状态
                        if filename in file_transfers:
                            file_transfers[filename]["received_chunks"] += 1
                            received = file_transfers[filename]["received_chunks"]
                            print(f"📥 接收文件块: {filename} (块 {chunk_index+1}/{total_chunks}, 进度: {received}/{total_chunks})")
                        else:
                            # 处理中间块先到达的情况
                            print(f"⚠️ 收到乱序的文件块: {filename} (块 {chunk_index+1}/{total_chunks})")
                            file_transfers[filename] = {
                                "received_chunks": 1,
                                "total_chunks": total_chunks,
                                "path": save_path
                            }
                    
                    # 检查文件是否接收完成
                    if (filename in file_transfers and 
                        file_transfers[filename]["received_chunks"] == total_chunks):
                        print(f"✅ 文件接收完成: {save_path}")
                        
                        # 验证完整文件哈希
                        expected_hash = file_transfers[filename].get("file_hash")
                        if expected_hash:
                            calculated_hash = ClipMessage.calculate_file_hash(str(save_path))
                            if calculated_hash == expected_hash:
                                print(f"✓ 文件哈希验证成功: {filename}")
                            else:
                                print(f"❌ 文件哈希验证失败: {filename}")
                                # 如果哈希不匹配，可以请求重传
                                await self.request_file_retry(websocket, message.get("path", ""), filename)
                                self.is_receiving = False
                                continue
                        
                        # 复制文件路径到剪贴板，但暂时防止发送回去
                        self.last_content_hash = hashlib.md5(str(save_path).encode()).hexdigest()
                        self._set_clipboard_file_paths([str(save_path)])
                        
                        # 设置一个特殊的长时间保护期
                        self.last_update_time = time.time()
                        print("⏱️ 设置延长保护期，防止文件路径被回传")
                    
                    # 完成处理这个块后，判断是否要重置接收状态
                    # 只有当文件接收完成或接收到最后一块时才重置状态
                    if (filename in file_transfers and 
                        (file_transfers[filename]["received_chunks"] == total_chunks or
                         chunk_index == total_chunks - 1)):
                        await asyncio.sleep(0.5)  # 短暂延迟
                        self.is_receiving = False
                    else:
                        # 如果还有更多块，保持接收状态
                        pass  # 不重置is_receiving
                    
                else:
                    # 未知消息类型，重置接收标志
                    self.is_receiving = False
                    
            except asyncio.CancelledError:
                # 正常取消，不打印错误
                break
            except websockets.exceptions.ConnectionClosed:
                print("❗ 接收时检测到连接已关闭")
                self.connection_status = ConnectionStatus.DISCONNECTED
                break
            except Exception as e:
                if self.running and self.connection_status == ConnectionStatus.CONNECTED:
                    print(f"❌ 接收错误: {e}")
                    # 如果是连接错误，切换到断开状态
                    if "connection" in str(e).lower() or "closed" in str(e).lower():
                        print("❗ 检测到连接问题，标记为已断开")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                self.is_receiving = False  # 确保重置接收标志
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