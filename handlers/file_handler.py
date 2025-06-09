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

# Only import AppKit and objc on macOS
if IS_MACOS:
    import AppKit
    import objc # Import objc

    # Helper class to perform pasteboard operations on the main thread
    class PasteboardSetter(AppKit.NSObject):
        @classmethod # Use standard Python classmethod decorator
        def setFileURL_(cls, path_str):
            try:
                pasteboard = AppKit.NSPasteboard.generalPasteboard()
                pasteboard.clearContents()
                url = AppKit.NSURL.fileURLWithPath_(path_str)
                if not url:
                    print(f"❌ [MainThread] 无法创建文件URL: {path_str}")
                    return "0|-1"
                urls = AppKit.NSArray.arrayWithObject_(url)
                success = pasteboard.writeObjects_(urls)
                if success:
                    change_count = pasteboard.changeCount()
                    print(f"📎 [MainThread] 已将文件添加到Mac剪贴板: {Path(path_str).name}")
                    return f"1|{change_count}"
                else:
                    print(f"❌ [MainThread] 添加文件到Mac剪贴板失败: {Path(path_str).name}")
                    return "0|-1"
            except Exception as e:
                print(f"❌ [MainThread] 设置剪贴板文件时出错: {e}")
                import traceback
                traceback.print_exc()
                return "0|-1"


class FileHandler:
    """文件处理管理器"""
    
    def __init__(self, temp_dir: Path, security_mgr):
        self.temp_dir = temp_dir
        self.security_mgr = security_mgr
        self.file_transfers = {}
        self.file_cache = {}
        self._init_temp_dir()
        self.load_file_cache()
        self.chunk_size = ClipboardConfig.CHUNK_SIZE # Use config
        self.pending_transfers = {}  # Track ongoing chunked transfers

    def _init_temp_dir(self):
        """初始化临时目录"""
        self.temp_dir.mkdir(exist_ok=True)
        print(f"✅ 文件处理初始化成功，临时目录: {self.temp_dir}")

    def _looks_like_temp_file_path(self, text: str) -> bool:
        """检查文本是否看起来像临时文件路径"""
        for indicator in ClipboardConfig.TEMP_PATH_INDICATORS:
            if indicator in text:
                print(f"⏭️ 跳过临时文件路径: \"{text[:40]}...\"")
                return True
        return False

    async def handle_file_transfer(self, file_path: str, send_encrypted_fn):
        """处理文件传输（自动分块大文件）"""
        path_obj = Path(file_path)
        MAX_CHUNK_SIZE = self.chunk_size # Use instance chunk size

        if not path_obj.exists() or not path_obj.is_file():
            print(f"⚠️ 文件不存在或无效: {file_path}")
            return False

        try:
            file_size = path_obj.stat().st_size
            total_chunks = (file_size + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
            print(f"📤 开始传输文件: {path_obj.name} ({file_size/1024/1024:.1f}MB, {total_chunks}块)")

            # 发送文件开始消息 (optional, could be part of the first chunk)
            # Consider if a separate start message is needed or if info can be in first chunk

            # 逐块读取并发送文件
            with open(path_obj, 'rb') as f:
                for chunk_index in range(total_chunks):
                    chunk_data = f.read(MAX_CHUNK_SIZE)
                    if not chunk_data:
                        break

                    chunk_msg = {
                        'type': MessageType.FILE_RESPONSE,
                        'filename': path_obj.name,
                        'exists': True,
                        'chunk_data': base64.b64encode(chunk_data).decode('utf-8'),
                        'chunk_index': chunk_index,
                        'total_chunks': total_chunks,
                        'chunk_hash': hashlib.md5(chunk_data).hexdigest(),
                        'file_hash': ClipMessage.calculate_file_hash(str(path_obj)) if chunk_index == 0 else None # Send full hash only once
                    }

                    # 显示进度
                    progress = self._format_progress(chunk_index + 1, total_chunks)
                    print(f"\r📤 传输文件 {path_obj.name}: {progress}", end="", flush=True)

                    # 加密并发送块
                    await send_encrypted_fn(json.dumps(chunk_msg).encode('utf-8'))
                    await asyncio.sleep(ClipboardConfig.NETWORK_DELAY) # Use config

            print(f"\n✅ 文件 {path_obj.name} 传输完成")
            return True

        except Exception as e:
            print(f"\n❌ 文件传输失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    # Removed _transfer_small_file as handle_file_transfer now handles chunking

    # Removed send_large_file and _send_file_chunk as handle_file_transfer covers this

    # Removed receive_file_chunk as handle_received_chunk covers this

    # Removed _complete_file_transfer as handle_received_chunk handles completion

    def _format_progress(self, current: int, total: int) -> str:
        """格式化进度显示"""
        if total <= 0: return "[░░░░░░░░░░░░░░░░░░░░] 0% (0/0)" # Avoid division by zero
        percentage = (current * 100) // total
        bar_length = 20
        filled = min(bar_length, (percentage * bar_length) // 100) # Ensure filled doesn't exceed bar_length
        bar = '█' * filled + '░' * (bar_length - filled)
        return f"[{bar}] {percentage}% ({current}/{total})"

    def handle_received_chunk(self, message: dict) -> tuple[bool, Path | None]:
        """
        处理接收到的文件块.
        Returns: (is_complete, file_path_if_complete)
        """
        try:
            filename = message.get("filename", "unknown")
            chunk_index = message.get("chunk_index", 0)
            total_chunks = message.get("total_chunks", 1)
            chunk_data = base64.b64decode(message.get("chunk_data", ""))
            chunk_hash = message.get("chunk_hash")
            file_hash = message.get("file_hash") # Full file hash (sent with first chunk)

            if not chunk_data:
                print("⚠️ 收到的文件块数据为空")
                return False, None

            # 验证块的完整性
            if chunk_hash and hashlib.md5(chunk_data).hexdigest() != chunk_hash:
                print(f"⚠️ 块 {chunk_index+1}/{total_chunks} 校验失败 for {filename}")
                # Optionally request retransmission here
                return False, None

            save_path = self.temp_dir / filename

            # Initialize transfer state if first chunk
            if filename not in self.file_transfers:
                self.file_transfers[filename] = {
                    "received_chunks": {}, # Store data by index
                    "total_chunks": total_chunks,
                    "path": save_path,
                    "file_hash": file_hash # Store the expected full hash
                }
                # Clear any old file with the same name
                if save_path.exists():
                    try:
                        save_path.unlink()
                    except OSError as e:
                        print(f"⚠️ 无法删除旧文件 {save_path}: {e}")


            transfer = self.file_transfers[filename]

            # Store chunk data if not already received
            if chunk_index not in transfer["received_chunks"]:
                 transfer["received_chunks"][chunk_index] = chunk_data
            else:
                 print(f"ℹ️ 收到重复块 {chunk_index+1}/{total_chunks} for {filename}")


            # Display progress
            progress = self._format_progress(len(transfer["received_chunks"]), transfer["total_chunks"])
            print(f"\r📥 接收文件 {filename}: {progress}", end="", flush=True)


            # 检查是否完成
            is_complete = len(transfer["received_chunks"]) == transfer["total_chunks"]

            if is_complete:
                print(f"\n✅ 文件 {filename} 所有块接收完成，开始组装...")
                # 组装文件
                try:
                    with open(save_path, "wb") as f:
                        for i in range(transfer["total_chunks"]):
                            if i in transfer["received_chunks"]:
                                f.write(transfer["received_chunks"][i])
                            else:
                                # This shouldn't happen if is_complete is true, but as a safeguard
                                print(f"❌ 组装文件 {filename} 时缺少块 {i+1}")
                                raise IOError(f"Missing chunk {i+1} for {filename}")

                    # 验证完整文件哈希
                    if transfer["file_hash"]:
                        actual_hash = ClipMessage.calculate_file_hash(str(save_path))
                        if actual_hash == transfer["file_hash"]:
                            print(f"✅ 文件 {filename} 哈希校验成功")
                        else:
                            print(f"❌ 文件 {filename} 哈希校验失败! Expected: {transfer['file_hash']}, Got: {actual_hash}")
                            # Optionally delete the corrupted file
                            # save_path.unlink()
                            del self.file_transfers[filename]
                            return False, None # Indicate failure
                    else:
                         print(f"⚠️ 未收到文件 {filename} 的完整哈希值，跳过校验")


                    # Add to cache (using the verified hash if available)
                    final_hash = transfer["file_hash"] or ClipMessage.calculate_file_hash(str(save_path))
                    self.add_to_file_cache(final_hash, str(save_path))

                    # 清理传输状态
                    completed_path = transfer["path"]
                    del self.file_transfers[filename]
                    return True, completed_path # Indicate completion and return path

                except Exception as e:
                    print(f"❌ 组装或校验文件 {filename} 失败: {e}")
                    # Clean up
                    if save_path.exists(): save_path.unlink(missing_ok=True)
                    if filename in self.file_transfers: del self.file_transfers[filename]
                    return False, None # Indicate failure

            return False, None # Indicate not yet complete

        except Exception as e:
            print(f"❌ 处理文件块失败: {e}")
            import traceback
            traceback.print_exc()
            return False, None # Indicate failure

    # Removed _verify_file_integrity as validation is now part of handle_received_chunk

    # --- File Cache Methods ---
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
        except Exception as e: # Catch specific exceptions if needed
            print(f"❌ 保存文件缓存失败: {e}")

    async def handle_text_message(self, message: dict, set_clipboard_func, 
                                 last_content_hash: str) -> tuple[str, float]:
        """处理接收到的文本消息"""
        try:
            text = message.get("content", "")
            if not text:
                print("⚠️ 收到空文本消息")
                return last_content_hash, 0
            
            if self._looks_like_temp_file_path(text):
                return last_content_hash, 0
            
            # Calculate hash before setting clipboard
            from utils.clipboard_utils import ClipboardUtils
            content_hash = ClipboardUtils.calculate_content_hash(text)
            
            # Check if duplicate
            if content_hash == last_content_hash:
                print("⏭️ 跳过重复内容")
                return last_content_hash, 0
            
            # Set clipboard using provided function
            if await set_clipboard_func(text):
                display_text = ClipboardUtils.format_display_content(text)
                print(f"📥 已复制文本: \"{display_text}\"")
                return content_hash, time.time()
            else:
                print("❌ 更新剪贴板失败")
                return last_content_hash, 0
                
        except Exception as e:
            print(f"❌ 处理文本消息时出错: {e}")
            traceback.print_exc()
            return last_content_hash, 0