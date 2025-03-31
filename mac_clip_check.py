import AppKit
import asyncio
import websockets
import json 
import signal
import time
import base64
import os  # 添加 os 模块导入
from utils.security.crypto import SecurityManager
from utils.security.auth import DeviceAuthManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
import tempfile
from pathlib import Path
import hashlib

class ClipboardListener:
    def __init__(self):
        self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
        self.last_change_count = self.pasteboard.changeCount()
        self.last_content_hash = None  # 添加内容哈希来避免重复发送
        self.security_mgr = SecurityManager()
        self.auth_mgr = DeviceAuthManager()
        self.connected_clients = set()
        self.discovery = DeviceDiscovery()
        self._init_encryption()
        self.is_receiving = False  # Flag to avoid clipboard loops
        self.last_update_time = 0  # 记录最后一次更新剪贴板的时间
        self.running = True  # 控制运行状态的标志
        self.server = None  # 保存WebSocket服务器引用，用于关闭
        self.temp_dir = Path(tempfile.gettempdir()) / "unipaste_files"
        self.temp_dir.mkdir(exist_ok=True)
        self.file_transfers = {}  # 跟踪文件传输状态
        self.file_cache = {}  # 文件哈希缓存，格式: {hash: 路径}
        self.load_file_cache()  # 加载缓存信息

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
        
        print("👋 感谢使用 UniPaste 服务器!")

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
            
            # 解析消息
            message = ClipMessage.deserialize(message_json)
            if not message or "type" not in message:
                print("❌ 收到无效的消息格式")
                self.is_receiving = False
                return
            
            # 根据消息类型处理
            if message["type"] == MessageType.TEXT:
                content = message["content"]
                
                # 计算内容哈希，用于防止循环
                content_hash = hashlib.md5(content.encode()).hexdigest()
                
                # 如果和上次接收/发送的内容相同，则跳过
                if content_hash == self.last_content_hash:
                    print(f"⏭️ 跳过重复内容: 哈希值 {content_hash[:8]}... 相同")
                    self.is_receiving = False
                    return
                
                self.last_content_hash = content_hash
                
                # 显示收到的内容（限制字符数以防内容过长）
                max_display_len = 100
                display_content = content if len(content) <= max_display_len else content[:max_display_len] + "..."
                print(f"📥 收到文本: \"{display_content}\"")
                
                # Set to Mac clipboard
                pasteboard = AppKit.NSPasteboard.generalPasteboard()
                pasteboard.clearContents()
                pasteboard.setString_forType_(content, AppKit.NSPasteboardTypeString)
                self.last_change_count = pasteboard.changeCount()
                self.last_update_time = time.time()
                print("📋 已从客户端更新剪贴板")
            
            elif message["type"] == MessageType.FILE:
                # 收到文件信息
                files = message["files"]
                if not files:
                    print("❌ 收到空的文件列表")
                    self.is_receiving = False
                    return
                    
                file_names = [f["filename"] for f in files]
                print(f"📥 收到文件信息: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")
                
                # 计算文件信息的哈希值，防止重复接收
                file_info_hash = hashlib.md5(str(files).encode()).hexdigest()
                self.last_content_hash = file_info_hash
                
                # 对每个文件处理
                for file_info in files:
                    file_path = file_info.get("path", "")
                    if not file_path:
                        print("⚠️ 收到的文件信息中缺少路径")
                        continue
                        
                    file_hash = file_info.get("hash", "")
                    filename = file_info.get("filename", os.path.basename(file_path))
                    
                    print(f"📥 准备下载文件: {filename}")
                    
                    # 创建文件请求消息
                    file_req = ClipMessage.file_request_message(file_path)
                    req_json = ClipMessage.serialize(file_req)
                    encrypted_req = self.security_mgr.encrypt_message(req_json.encode('utf-8'))
                    
                    # 只向发送者请求文件
                    if sender_websocket and sender_websocket in self.connected_clients:
                        await sender_websocket.send(encrypted_req)
                        print(f"📤 向源设备请求文件: {filename}")
                    else:
                        # 如果不知道发送者，则广播请求（不理想但作为后备）
                        await self.broadcast_encrypted_data(encrypted_req)
                        print(f"📤 广播文件请求: {filename}")
                
                # 标记最后更新时间，防止重复发送
                self.last_update_time = time.time()
                
                # 重置接收标志
                self.is_receiving = False

            elif message["type"] == MessageType.FILE_RESPONSE:
                # 收到文件内容响应
                filename = message.get("filename", "未知文件")
                exists = message.get("exists", False)
                
                if not exists:
                    print(f"⚠️ 文件 {filename} 在源设备上不存在")
                    self.is_receiving = False
                    return
                
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
                    return
                
                # 保存文件块
                save_path = self.temp_dir / filename
                
                # 如果是第一块，创建或清空文件
                if chunk_index == 0:
                    # 记录完整文件哈希用于最终验证
                    file_hash = message.get("file_hash", "")
                    
                    with open(save_path, "wb") as f:
                        f.write(chunk_data)
                    self.file_transfers[filename] = {
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
                    if filename in self.file_transfers:
                        self.file_transfers[filename]["received_chunks"] += 1
                        received = self.file_transfers[filename]["received_chunks"]
                        total = self.file_transfers[filename]["total_chunks"]
                        print(f"📥 接收文件块: {filename} ({chunk_index+1}/{total_chunks}, 进度: {received}/{total})")
                    else:
                        # 处理中间块先到达的情况
                        print(f"⚠️ 收到乱序的文件块: {filename} (块 {chunk_index+1}/{total_chunks})")
                        self.file_transfers[filename] = {
                            "received_chunks": 1,
                            "total_chunks": total_chunks,
                            "path": save_path
                        }
                
                # 检查文件是否接收完成
                if (filename in self.file_transfers and 
                    self.file_transfers[filename]["received_chunks"] == total_chunks):
                    print(f"✅ 文件接收完成: {save_path}")
                    
                    # 验证完整文件哈希
                    expected_hash = self.file_transfers[filename].get("file_hash")
                    if expected_hash:
                        # 确保导入了 ClipMessage 的 calculate_file_hash
                        from utils.message_format import ClipMessage
                        
                        calculated_hash = ClipMessage.calculate_file_hash(str(save_path))
                        if calculated_hash == expected_hash:
                            print(f"✓ 文件哈希验证成功: {filename}")
                            # 添加到文件缓存
                            self.add_to_file_cache(calculated_hash, str(save_path))
                        else:
                            print(f"❌ 文件哈希验证失败: {filename}")
                            # 请求重传
                            if sender_websocket and sender_websocket in self.connected_clients:
                                file_req = ClipMessage.file_request_message(message["path"])
                                req_json = ClipMessage.serialize(file_req)
                                encrypted_req = self.security_mgr.encrypt_message(req_json.encode('utf-8'))
                                await sender_websocket.send(encrypted_req)
                                print(f"🔄 请求重新传输文件: {filename}")
                                self.is_receiving = False
                                return
                    
                    # 将文件路径放入剪贴板
                    try:
                        # 标记哈希以避免重复发送
                        path_str = str(save_path)
                        self.last_content_hash = hashlib.md5(path_str.encode()).hexdigest()
                        self.last_update_time = time.time()  # 设置时间戳，防止立即触发发送
                        
                        # 在Mac上设置文件URL剪贴板
                        pasteboard = AppKit.NSPasteboard.generalPasteboard()
                        pasteboard.clearContents()
                        url = AppKit.NSURL.fileURLWithPath_(path_str)
                        urls = AppKit.NSArray.arrayWithObject_(url)
                        pasteboard.writeObjects_(urls)
                        self.last_change_count = pasteboard.changeCount()
                        print(f"📋 已将文件 {filename} 添加到剪贴板")
                    except Exception as e:
                        print(f"❌ 设置剪贴板文件失败: {e}")
                
                # 重置接收标志
                self.is_receiving = False

            # 延长延迟时间以防止循环，重要修改: 先重置标志，再等待
            self.is_receiving = False
            await asyncio.sleep(1.5)  # 增加延迟时间
        except Exception as e:
            print(f"❌ 接收数据处理错误: {e}")
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
        types = self.pasteboard.types()
        try:
            if AppKit.NSPasteboardTypeString in types:
                text = self.pasteboard.stringForType_(AppKit.NSPasteboardTypeString)
                
                # 如果内容为空，不处理
                if not text or text.strip() == "":
                    return
                
                # 如果看起来像临时文件路径，跳过
                if self._looks_like_temp_file_path(text):
                    return
                
                # 计算内容哈希，用于防止重复发送
                content_hash = hashlib.md5(text.encode()).hexdigest()
                
                # 如果和上次接收/发送的内容相同，则跳过
                if content_hash == self.last_content_hash:
                    print(f"⏭️ 跳过重复内容: 哈希值 {content_hash[:8]}... 相同")
                    return
                
                # 添加延迟检查 - 如果距离上次更新剪贴板时间太短，可能是我们自己刚刚更新的
                current_time = time.time()
                if current_time - self.last_update_time < 1.0:  # 增加延迟阈值
                    print(f"⏱️ 延迟检查: 距离上次更新时间 {current_time - self.last_update_time:.2f}秒，可能是自己更新的内容")
                    return
                
                self.last_content_hash = content_hash
                
                # 显示发送的内容（限制字符数）
                max_display_len = 100
                display_content = text if len(text) <= max_display_len else text[:max_display_len] + "..."
                print(f"📤 发送文本: \"{display_content}\"")
                
                # 创建文本消息
                text_msg = ClipMessage.text_message(text)
                message_json = ClipMessage.serialize(text_msg)
                
                # 加密并广播
                encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
                print("🔐 加密后的文本")
                
                # 非常重要: 先设置上次更新时间，再广播，这样可以避免自己广播后自己又接收
                self.last_update_time = time.time()
                await self.broadcast_encrypted_data(encrypted_data)
            
            if AppKit.NSPasteboardTypeFileURL in types:
                # 获取文件URL
                file_urls = []
                for item in self.pasteboard.pasteboardItems():
                    if item.availableTypeFromArray_([AppKit.NSPasteboardTypeFileURL]):
                        file_url_data = item.dataForType_(AppKit.NSPasteboardTypeFileURL)
                        if file_url_data:
                            file_url = AppKit.NSURL.URLWithString_(
                                AppKit.NSString.alloc().initWithData_encoding_(
                                    file_url_data, AppKit.NSUTF8StringEncoding
                                )
                            )
                            if file_url:
                                file_path = file_url.path()
                                file_urls.append(file_path)
                
                if not file_urls:
                    return
                
                # 计算文件路径哈希
                file_str = str(file_urls)
                content_hash = hashlib.md5(file_str.encode()).hexdigest()
                
                # 如果和上次接收/发送的内容相同，则跳过
                if content_hash == self.last_content_hash:
                    print("⏭️ 跳过重复文件路径")
                    return
                
                self.last_content_hash = content_hash
                
                # 显示发送的文件路径
                file_names = [os.path.basename(p) for p in file_urls]
                print(f"📤 发送文件: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")
                
                # 创建文件消息
                file_msg = ClipMessage.file_message(file_urls)
                message_json = ClipMessage.serialize(file_msg)
                
                # 加密并广播文件元数据
                encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
                print("🔐 加密后的文件消息")
                await self.broadcast_encrypted_data(encrypted_data)

                # 直接开始传输文件内容，无需等待客户端请求
                # 在服务器自动传输小文件（小于10MB的文件），大文件仍然等待请求
                print("🔄 准备主动传输文件内容...")
                for file_path in file_urls:
                    path_obj = Path(file_path)
                    if not path_obj.exists():
                        print(f"⚠️ 文件不存在: {file_path}")
                        continue
                        
                    # 检查文件大小，如果小于10MB，自动传输
                    file_size = path_obj.stat().st_size
                    if file_size <= 10 * 1024 * 1024:  # 10MB
                        chunk_size = 1024 * 1024  # 1MB 块大小
                        total_chunks = (file_size + chunk_size - 1) // chunk_size
                        
                        print(f"📤 自动传输文件: {path_obj.name} (总大小: {file_size} 字节, {total_chunks} 块)")
                        
                        # 分块发送文件
                        for i in range(total_chunks):
                            response = ClipMessage.file_response_message(
                                file_path, 
                                chunk_index=i,
                                total_chunks=total_chunks
                            )
                            resp_json = ClipMessage.serialize(response)
                            encrypted_resp = self.security_mgr.encrypt_message(resp_json.encode('utf-8'))
                            
                            # 广播给所有客户端
                            await self.broadcast_encrypted_data(encrypted_resp)
                            print(f"📤 已自动发送文件块: {path_obj.name} ({i+1}/{total_chunks})")
                            # 短暂延迟，避免网络拥塞
                            await asyncio.sleep(0.05)
                    else:
                        print(f"ℹ️ 文件过大 ({file_size/1024/1024:.1f} MB)，等待客户端请求再传输: {path_obj.name}")

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

    def load_file_cache(self):
        """加载文件缓存信息"""
        cache_path = self.temp_dir / "filecache.json"
        if cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    self.file_cache = json.load(f)
                print(f"📚 已加载 {len(self.file_cache)} 个文件缓存条目")
            except:
                print("❌ 加载文件缓存失败，将使用空缓存")
                self.file_cache = {}

    def save_file_cache(self):
        """保存文件缓存信息"""
        cache_path = self.temp_dir / "filecache.json"
        try:
            with open(cache_path, "w") as f:
                json.dump(self.file_cache, f)
        except:
            print("❌ 保存文件缓存失败")

    def add_to_file_cache(self, file_hash, file_path):
        """添加文件到缓存"""
        if Path(file_path).exists():
            self.file_cache[file_hash] = str(file_path)
            self.save_file_cache()

    def get_from_file_cache(self, file_hash):
        """从缓存获取文件路径"""
        path = self.file_cache.get(file_hash)
        if path and Path(path).exists():
            return path
        return None

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
