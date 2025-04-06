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

    def _init_temp_dir(self):
        """初始化临时目录"""
        self.temp_dir.mkdir(exist_ok=True)
        print(f"✅ 文件处理初始化成功，临时目录: {self.temp_dir}")

    async def handle_file_transfer(self, file_path: str, broadcast_fn):
        """处理文件传输"""
        path_obj = Path(file_path)
        
        # 增强文件存在性检查
        if not path_obj.exists() or not path_obj.is_file():
            print(f"⚠️ 文件不存在或不是普通文件: {file_path}")
            
            # 创建并发送文件不存在响应
            response = {
                "type": MessageType.FILE_RESPONSE,
                "filename": path_obj.name,
                "exists": False,
                "path": str(path_obj),
                "error": "File does not exist"
            }
            
            try:
                encrypted_resp = self.security_mgr.encrypt_message(
                    json.dumps(response).encode('utf-8')
                )
                await broadcast_fn(encrypted_resp)
                print(f"📤 已发送文件不存在响应: {path_obj.name}")
            except Exception as e:
                print(f"❌ 发送文件不存在响应失败: {e}")
            
            return False

        try:
            file_size = path_obj.stat().st_size
            if file_size <= 10 * 1024 * 1024:  # 10MB
                await self._transfer_small_file(path_obj, file_size, broadcast_fn)
            else:
                print(f"ℹ️ 文件过大 ({file_size/1024/1024:.1f} MB)，等待请求: {path_obj.name}")
            return True
        except Exception as e:
            print(f"❌ 文件传输错误: {e}")
            return False

    async def _transfer_small_file(self, path_obj: Path, file_size: int, broadcast_fn):
        """传输小文件"""
        chunk_size = 1024 * 1024  # 1MB
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        print(f"📤 自动传输文件: {path_obj.name} ({file_size} 字节, {total_chunks} 块)")
        
        with open(path_obj, 'rb') as f:
            for i in range(total_chunks):
                chunk_data = f.read(chunk_size)
                chunk_hash = hashlib.md5(chunk_data).hexdigest()
                
                response = {
                    'type': 'file_response',
                    'filename': path_obj.name,
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

    def handle_received_chunk(self, message: dict) -> bool:
        """处理接收到的文件块"""
        filename = message.get("filename", "unknown")
        chunk_index = message.get("chunk_index", 0)
        total_chunks = message.get("total_chunks", 1)
        chunk_data = base64.b64decode(message["chunk_data"])
        chunk_hash = message.get("chunk_hash", "")
        
        # 验证块哈希
        if chunk_hash:
            calculated_hash = hashlib.md5(chunk_data).hexdigest()
            if calculated_hash != chunk_hash:
                print(f"⚠️ 文件块 {filename} ({chunk_index+1}/{total_chunks}) 哈希验证失败")
                return False

        save_path = self.temp_dir / filename
        mode = "wb" if chunk_index == 0 else "ab"
        
        try:
            with open(save_path, mode) as f:
                f.write(chunk_data)
            
            self._update_transfer_status(filename, chunk_index, total_chunks, save_path)
            return self._check_transfer_complete(filename)
        except Exception as e:
            print(f"❌ 保存文件块失败: {e}")
            return False

    def _update_transfer_status(self, filename: str, chunk_index: int, total_chunks: int, save_path: Path):
        """更新文件传输状态"""
        if filename not in self.file_transfers:
            self.file_transfers[filename] = {
                "received_chunks": 1,
                "total_chunks": total_chunks,
                "path": save_path
            }
        else:
            self.file_transfers[filename]["received_chunks"] += 1
        
        received = self.file_transfers[filename]["received_chunks"]
        print(f"📥 接收文件块: {filename} ({chunk_index+1}/{total_chunks}, 进度: {received}/{total_chunks})")

    def _check_transfer_complete(self, filename: str) -> bool:
        """检查文件是否传输完成"""
        if filename not in self.file_transfers:
            return False
            
        transfer = self.file_transfers[filename]
        if transfer["received_chunks"] == transfer["total_chunks"]:
            print(f"✅ 文件接收完成: {transfer['path']}")
            return True
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
                pasteboard.writeObjects_(urls)
                print(f"📋 已将文件添加到剪贴板: {os.path.basename(path_str)}")
                return pasteboard.changeCount()
            elif IS_WINDOWS:
                # Use Windows specific clipboard API
                import win32clipboard
                import win32con
                try:
                    win32clipboard.OpenClipboard()
                    win32clipboard.EmptyClipboard()
                    win32clipboard.SetClipboardText(path_str)
                    win32clipboard.CloseClipboard()
                    print(f"📋 已将文件路径添加到剪贴板: {os.path.basename(path_str)}")
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