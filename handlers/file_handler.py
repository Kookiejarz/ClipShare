from pathlib import Path
import hashlib
import json
import base64
import asyncio
import os
import time
from utils.platform_config import IS_MACOS, IS_WINDOWS
from utils.message_format import ClipMessage, MessageType
from config import ClipboardConfig

# Only import AppKit on macOS
if IS_MACOS:
    import AppKit

class FileHandler:
    """文件处理管理器"""
    
    def __init__(self, temp_dir: Path, security_mgr):
        self.temp_dir = temp_dir
        self.security_mgr = security_mgr
        self.file_transfers = {}
        self.file_cache = {}
        self._init_temp_dir()
        self.load_file_cache()
        self.chunk_size = 512 * 1024  # 512KB chunks for file transfer
        self.pending_transfers = {}  # Track ongoing chunked transfers

    def _init_temp_dir(self):
        """初始化临时目录"""
        self.temp_dir.mkdir(exist_ok=True)
        print(f"✅ 文件处理初始化成功，临时目录: {self.temp_dir}")

    async def handle_file_transfer(self, file_path: str, broadcast_fn):
        """处理文件传输"""
        path_obj = Path(file_path)
        
        # 增强文件存在性检查
        try:
            if not path_obj.exists():
                print(f"⚠️ 检查文件存在性: {file_path} -> 不存在")
                abs_path = path_obj.absolute()
                print(f"🔍 尝试绝对路径: {abs_path}")
                path_obj = abs_path
                
                if not path_obj.exists():
                    print(f"❌ 文件确实不存在: {file_path}")
                    return False

            print(f"✅ 文件已找到: {path_obj}")
            file_size = path_obj.stat().st_size
            print(f"📤 开始处理文件: {path_obj.name} ({file_size} 字节)")

            # 创建文件消息
            file_msg = ClipMessage.file_message([str(path_obj)])
            message_json = ClipMessage.serialize(file_msg)
            encrypted_data = self.security_mgr.encrypt_message(
                message_json.encode('utf-8')
            )
            await broadcast_fn(encrypted_data)
            
            # 读取并发送文件内容
            with open(path_obj, 'rb') as f:
                chunk_data = f.read()
                if chunk_data:
                    response = {
                        'type': MessageType.FILE_RESPONSE,
                        'filename': path_obj.name,
                        'exists': True,
                        'chunk_data': base64.b64encode(chunk_data).decode('utf-8'),
                        'chunk_index': 0,
                        'total_chunks': 1
                    }
                    
                    encrypted_resp = self.security_mgr.encrypt_message(
                        json.dumps(response).encode('utf-8')
                    )
                    await broadcast_fn(encrypted_resp)
                    print(f"📤 已发送文件内容: {path_obj.name}")
                    
                return True
                
        except Exception as e:
            print(f"❌ 文件传输失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def _transfer_small_file(self, path_obj: Path, file_size: int, broadcast_fn):
        """传输小文件"""
        try:
            chunk_size = 700 * 1024  # 1MB
            total_chunks = (file_size + chunk_size - 1) // chunk_size
            
            print(f"📤 自动传输文件: {path_obj.name} ({file_size} 字节, {total_chunks} 块)")
            
            with open(path_obj, 'rb') as f:
                for i in range(total_chunks):
                    chunk_data = f.read(chunk_size)
                    if not chunk_data:
                        print(f"⚠️ 读取文件块失败: {path_obj.name} 块 {i+1}/{total_chunks}")
                        break
                        
                    chunk_hash = hashlib.md5(chunk_data).hexdigest()
                    
                    response = {
                        'type': MessageType.FILE_RESPONSE,
                        'filename': path_obj.name,
                        'exists': True,
                        'chunk_index': i,
                        'total_chunks': total_chunks,
                        'chunk_data': base64.b64encode(chunk_data).decode('utf-8'),
                        'chunk_hash': chunk_hash
                    }
                    
                    # 加密并发送
                    encrypted_resp = self.security_mgr.encrypt_message(
                        json.dumps(response).encode('utf-8')
                    )
                    await broadcast_fn(encrypted_resp)
                    print(f"📤 已发送文件块: {path_obj.name} ({i+1}/{total_chunks})")
                    await asyncio.sleep(0.05)  # 避免网络拥塞
                    
            print(f"✅ 文件 {path_obj.name} 传输完成")
            return True
            
        except Exception as e:
            print(f"❌ 文件传输失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def send_large_file(self, file_path: str, broadcast_fn):
        """分块发送大文件"""
        path_obj = Path(file_path)
        if not path_obj.exists():
            print(f"❌ 文件不存在: {file_path}")
            return False

        file_size = path_obj.stat().st_size
        total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
        file_id = hashlib.md5(f"{path_obj.name}-{time.time()}".encode()).hexdigest()

        # Send file start message
        start_message = ClipMessage.create({
            "type": MessageType.FILE_START,
            "file_id": file_id,
            "filename": path_obj.name,
            "total_chunks": total_chunks,
            "total_size": file_size
        })

        try:
            # Send start message
            encrypted_start = self.security_mgr.encrypt_message(
                ClipMessage.serialize(start_message).encode('utf-8')
            )
            await broadcast_fn(encrypted_start)
            print(f"\n📤 开始发送文件: {path_obj.name} ({file_size/1024/1024:.1f}MB)")

            # Send chunks
            with open(file_path, 'rb') as f:
                for i in range(total_chunks):
                    chunk = f.read(self.chunk_size)
                    await self._send_file_chunk(
                        chunk, i, file_id, path_obj.name, 
                        total_chunks, broadcast_fn
                    )
                    
                    # Show progress
                    progress = self._format_progress(i + 1, total_chunks)
                    print(f"\r📤 发送文件 {path_obj.name}: {progress}", end="")

            print(f"\n✅ 文件 {path_obj.name} 发送完成")
            return True

        except Exception as e:
            print(f"\n❌ 发送文件失败: {e}")
            return False

    async def _send_file_chunk(self, chunk_data, chunk_number, file_id, filename, total_chunks, broadcast_fn):
        """发送单个文件块"""
        chunk_message = ClipMessage.create({
            "type": MessageType.FILE_CHUNK,
            "file_id": file_id,
            "chunk_number": chunk_number,
            "data": base64.b64encode(chunk_data).decode('utf-8'),
            "is_last": chunk_number == total_chunks - 1,
            "filename": filename
        })

        encrypted_chunk = self.security_mgr.encrypt_message(
            ClipMessage.serialize(chunk_message).encode('utf-8')
        )
        await broadcast_fn(encrypted_chunk)
        await asyncio.sleep(0.05)  # Prevent network congestion

    async def receive_file_chunk(self, message: dict) -> bool:
        """处理接收到的文件块"""
        file_id = message.get("file_id")
        if file_id not in self.pending_transfers:
            self.pending_transfers[file_id] = {
                "chunks": {},
                "total_chunks": message.get("total_chunks", 0),
                "filename": message.get("filename", "unknown"),
                "received_chunks": 0
            }

        transfer = self.pending_transfers[file_id]
        chunk_number = message.get("chunk_number")
        chunk_data = base64.b64decode(message.get("data"))
        
        # Store chunk
        transfer["chunks"][chunk_number] = chunk_data
        transfer["received_chunks"] += 1

        # Show progress
        progress = self._format_progress(
            transfer["received_chunks"],
            transfer["total_chunks"]
        )
        print(f"\r📥 接收文件 {transfer['filename']}: {progress}", end="")

        # Check if file is complete
        if transfer["received_chunks"] == transfer["total_chunks"]:
            await self._complete_file_transfer(file_id)
            return True
            
        return False

    async def _complete_file_transfer(self, file_id: str):
        """完成文件传输"""
        transfer = self.pending_transfers[file_id]
        
        # Combine all chunks
        complete_data = b"".join(
            transfer["chunks"][i] 
            for i in range(transfer["total_chunks"])
        )

        # Save file
        save_path = self.temp_dir / transfer["filename"]
        try:
            with open(save_path, 'wb') as f:
                f.write(complete_data)
            print(f"\n✅ 文件保存到: {save_path}")
            
            # Add to cache
            file_hash = hashlib.md5(complete_data).hexdigest()
            self.add_to_file_cache(file_hash, str(save_path))
            
            # Add to clipboard on Mac
            if IS_MACOS:
                pasteboard = AppKit.NSPasteboard.generalPasteboard()
                pasteboard.clearContents()
                url = AppKit.NSURL.fileURLWithPath_(str(save_path))
                urls = AppKit.NSArray.arrayWithObject_(url)
                success = pasteboard.writeObjects_(urls)
                if success:
                    print(f"📎 已将文件添加到Mac剪贴板: {transfer['filename']}")
                else:
                    print("❌ 添加文件到剪贴板失败")
            
        except Exception as e:
            print(f"\n❌ 保存文件失败: {e}")
            
        # Cleanup
        del self.pending_transfers[file_id]

    def _format_progress(self, current: int, total: int) -> str:
        """格式化进度显示"""
        percentage = (current * 100) // total
        bar_length = 20
        filled = (percentage * bar_length) // 100
        bar = '█' * filled + '░' * (bar_length - filled)
        return f"[{bar}] {percentage}% ({current}/{total})"

    def handle_received_chunk(self, message: dict) -> bool:
        """处理接收到的文件块"""
        try:
            filename = message.get("filename", "unknown")
            chunk_index = message.get("chunk_index", 0)
            total_chunks = message.get("total_chunks", 1)
            chunk_data = base64.b64decode(message.get("chunk_data", ""))
            chunk_hash = message.get("chunk_hash")
            
            if not chunk_data:
                return False
                
            # 验证块的完整性
            if chunk_hash and hashlib.md5(chunk_data).hexdigest() != chunk_hash:
                print(f"⚠️ 块 {chunk_index} 校验失败")
                return False
                
            save_path = self.temp_dir / filename
            
            # 使用 msvcrt 在 Windows 上进行文件锁定，或在 Unix 上使用 fcntl
            if IS_WINDOWS:
                import msvcrt
                with open(save_path, "ab") as f:
                    try:
                        # 锁定文件，使用self.chunk_size
                        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, self.chunk_size)
                        f.seek(chunk_index * self.chunk_size)  # 使用相同的chunk_size
                        f.write(chunk_data)
                    finally:
                        # 解锁文件
                        try:
                            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, self.chunk_size)
                        except:
                            pass  # Ignore unlock errors
            else:
                # Unix/Mac 系统使用 fcntl
                import fcntl
                with open(save_path, "ab") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    try:
                        f.seek(chunk_index * self.chunk_size)  # 使用相同的chunk_size
                        f.write(chunk_data)
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                
            # 更新传输状态
            if filename not in self.file_transfers:
                self.file_transfers[filename] = {
                    "received_chunks": set([chunk_index]),
                    "total_chunks": total_chunks,
                    "path": save_path
                }
            else:
                self.file_transfers[filename]["received_chunks"].add(chunk_index)
            
            # 检查是否完成
            transfer = self.file_transfers[filename]
            is_complete = len(transfer["received_chunks"]) == transfer["total_chunks"]
            
            if is_complete:
                # 验证文件完整性
                if self._verify_file_integrity(save_path):
                    return True
                else:
                    print(f"⚠️ 文件 {filename} 完整性验证失败")
                    return False
                    
            return False
            
        except Exception as e:
            print(f"❌ 处理文件块失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _verify_file_integrity(self, file_path: Path) -> bool:
        """验证文件的完整性"""
        try:
            # 检查文件是否存在
            if not file_path.exists():
                print(f"❌ 文件不存在: {file_path}")
                return False
                
            # 检查文件大小
            file_size = file_path.stat().st_size
            if file_size == 0:
                print(f"❌ 文件为空: {file_path}")
                return False
                
            # 尝试读取文件
            try:
                with open(file_path, 'rb') as f:
                    # 读取第一个块来验证文件可访问性
                    first_chunk = f.read(8192)  # 8KB
                    if first_chunk is None:
                        print(f"❌ 文件无法读取: {file_path}")
                        return False
            except Exception as e:
                print(f"❌ 文件读取失败: {e}")
                return False
                
            print(f"✅ 文件完整性验证通过: {file_path.name}")
            return True
            
        except Exception as e:
            print(f"❌ 文件验证失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    # 文件缓存相关方法
    def load_file_cache(self):
        """加载文件缓存"""
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
            print(f"⚠️ 加载文件缓存失败: {e}")
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

    async def handle_received_files(self, message, sender_websocket, broadcast_fn):
        """处理收到的文件信息"""
        files = message["files"]
        if not files:
            print("❌ 收到空的文件列表")
            return False

        file_paths = [f["path"] for f in files if "path" in f]
        content_hashes = [self._get_files_content_hash([p]) for p in file_paths]
        for h in content_hashes:
            if h and h in self.file_cache:
                print("⏭️ 跳过已存在的文件内容，不再请求")
                return h
        # ...后续请求文件内容...
        
        file_names = [f["filename"] for f in files]
        print(f"📥 收到文件信息: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")

        # 计算文件信息的哈希值
        file_info_hash = hashlib.md5(str(files).encode()).hexdigest()

        # 处理每个文件
        for file_info in files:
            file_path = file_info.get("path", "")
            if not file_path:
                print("⚠️ 收到的文件信息中缺少路径")
                continue

            filename = file_info.get("filename", os.path.basename(file_path))
            print(f"📥 准备下载文件: {filename}")

            # 创建文件请求消息
            file_req = ClipMessage.file_request_message(file_path)
            req_json = ClipMessage.serialize(file_req)
            encrypted_req = self.security_mgr.encrypt_message(req_json.encode('utf-8'))

            if sender_websocket:
                await sender_websocket.send(encrypted_req)
                print(f"📤 向源设备请求文件: {filename}")
            else:
                await broadcast_fn(encrypted_req)
                print(f"📤 广播文件请求: {filename}")

        return file_info_hash

    def set_clipboard_file(self, file_path):
        """将文件路径设置到剪贴板"""
        try:
            path_str = str(file_path)
            if IS_MACOS:
                pasteboard = AppKit.NSPasteboard.generalPasteboard()
                pasteboard.clearContents()
                url = AppKit.NSURL.fileURLWithPath_(path_str)
                urls = AppKit.NSArray.arrayWithObject_(url)
                success = pasteboard.writeObjects_(urls)
                if success:
                    print(f"📎 已将文件添加到Mac剪贴板: {os.path.basename(path_str)}")
                    return pasteboard.changeCount()
                else:
                    print("❌ 添加文件到剪贴板失败")
                    return None
            elif IS_WINDOWS:
                import win32clipboard
                import win32con
                try:
                    win32clipboard.OpenClipboard()
                    win32clipboard.EmptyClipboard()
                    # Use CF_HDROP for proper file handling
                    win32clipboard.SetClipboardData(win32con.CF_HDROP, tuple([path_str]))
                    win32clipboard.CloseClipboard()
                    print(f"📎 已将文件添加到Windows剪贴板: {os.path.basename(path_str)}")
                    return True
                except Exception as e:
                    print(f"❌ Windows剪贴板操作失败: {e}")
                    return None
        except Exception as e:
            print(f"❌ 设置剪贴板文件失败: {e}")
            return None

    async def handle_clipboard_files(self, file_urls, last_content_hash, broadcast_fn):
        """处理剪贴板中的文件"""
        # 计算文件路径哈希
        file_str = str(file_urls)
        content_hash = hashlib.md5(file_str.encode()).hexdigest()
        
        # 检查重复
        if content_hash == last_content_hash:
            print("⏭️ 跳过重复文件路径")
            return content_hash
            
        # 显示发送的文件路径
        file_names = [os.path.basename(p) for p in file_urls]
        print(f"📤 发送文件: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")
        
        # 创建并发送文件消息
        file_msg = ClipMessage.file_message(file_urls)
        message_json = ClipMessage.serialize(file_msg)
        encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
        print("🔐 加密后的文件消息")
        await broadcast_fn(encrypted_data)

        # 处理文件传输
        print("🔄 准备主动传输文件内容...")
        for file_path in file_urls:
            await self.handle_file_transfer(file_path, broadcast_fn)
            
        return content_hash

    async def process_clipboard_content(self, text: str, current_time: float, last_content_hash: str, 
                                     last_update_time: float, broadcast_fn) -> tuple:
        """处理剪贴板文本内容"""
        # 如果内容为空，不处理
        if not text or text.strip() == "":
            return last_content_hash, last_update_time
        
        # 如果看起来像临时文件路径，跳过
        if self._looks_like_temp_file_path(text):
            return last_content_hash, last_update_time
        
        # 计算内容哈希，用于防止重复发送
        content_hash = hashlib.md5(text.encode()).hexdigest()
        
        # 如果和上次接收/发送的内容相同，则跳过
        if content_hash == last_content_hash:
            print(f"⏭️ 跳过重复内容: 哈希值 {content_hash[:8]}... 相同")
            return last_content_hash, last_update_time
        
        # 添加延迟检查 - 如果距离上次更新剪贴板时间太短，可能是我们自己刚刚更新的
        if current_time - last_update_time < 1.0:  # 增加延迟阈值
            print(f"⏱️ 延迟检查: 距离上次更新时间 {current_time - last_update_time:.2f}秒，可能是自己更新的内容")
            return last_content_hash, last_update_time
        
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
        
        # 更新状态
        new_update_time = time.time()
        
        # 发送加密数据
        await broadcast_fn(encrypted_data)
        
        return content_hash, new_update_time

    def _looks_like_temp_file_path(self, text: str) -> bool:
        """检查文本是否看起来像临时文件路径"""
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