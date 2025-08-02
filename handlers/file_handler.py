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

    def add_to_file_cache(self, file_hash, file_path):
        """添加文件到缓存"""
        if Path(file_path).exists():
            self.file_cache[file_hash] = str(file_path)
            self.save_file_cache()

    def get_from_file_cache(self, file_hash):
        """从缓存获取文件路径"""
        path = self.file_cache.get(file_hash)
        if path:
            path_obj = Path(path)
            if path_obj.exists():
                return str(path_obj)
            else:
                # Remove stale entry from cache
                print(f"🧹 清理无效缓存条目: {file_hash} -> {path}")
                del self.file_cache[file_hash]
                self.save_file_cache()
        return None

    def get_files_content_hash(self, file_paths):
        """计算多个文件内容的MD5哈希值，跳过不存在的文件"""
        # This is now an instance method, no need for @staticmethod
        md5 = hashlib.md5()
        valid_paths_found = False
        for path_str in file_paths:
            path = Path(path_str) # Ensure it's a Path object
            try:
                if not path.is_file(): # Check if it's a file
                    print(f"⚠️ 跳过非文件或不存在的路径: {path}")
                    continue

                with open(path, 'rb') as f:
                    valid_paths_found = True
                    while True:
                        # Read in larger chunks for potentially better performance
                        chunk = f.read(1024 * 1024) # 1MB chunks
                        if not chunk:
                            break
                        md5.update(chunk)
            except FileNotFoundError:
                print(f"⚠️ 文件不存在，跳过哈希: {path}")
                continue
            except PermissionError:
                 print(f"⚠️ 权限不足，无法读取文件: {path}")
                 continue
            except Exception as e:
                print(f"❌ 计算文件哈希失败: {path} - {e}")
                # Depending on desired behavior, you might want to return None here
                # or just skip the problematic file. Skipping for now.
                continue
        # Only return a hash if at least one valid file was processed
        return md5.hexdigest() if valid_paths_found else None

    async def handle_received_files(self, file_info_message, send_encrypted_func, sender_websocket=None):
        """
        Handles a received FILE message containing file metadata.
        Checks the cache and requests missing files from the sender.
        """
        files = file_info_message.get("files", [])
        if not files:
            print("❌ 收到空的文件列表")
            return False

        files_to_request = []
        file_names = []

        for file_info in files:
            file_hash = file_info.get("hash")
            filename = file_info.get("filename")
            file_path = file_info.get("path") # Original path from sender

            if not filename or not file_path:
                 print("⚠️ 收到的文件信息缺少名称或路径")
                 continue

            file_names.append(filename)

            # Check cache first
            if file_hash and self.get_from_file_cache(file_hash):
                print(f"✅ 文件 '{filename}' 在缓存中找到 (Hash: {file_hash[:8]}...)")
                # Optionally: Update clipboard here if only one file and it's cached?
                # For now, we just skip the request.
                continue
            else:
                if file_hash:
                    print(f"ℹ️ 文件 '{filename}' 不在缓存中或哈希缺失，请求传输。")
                files_to_request.append(file_path) # Use original path for request

        if not files_to_request:
            print("✅ 所有收到的文件都在缓存中，无需请求。")
            # If all files are cached, potentially update clipboard now?
            # Needs careful consideration if multiple files were sent.
            return True # Indicate success (all cached or no files)

        print(f"📥 收到文件信息: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")
        print(f"📤 请求 {len(files_to_request)} 个文件内容...")

        # Request each missing file
        for file_path in files_to_request:
            filename = Path(file_path).name # Extract filename for logging
            print(f"📤 请求文件: {filename}")
            file_req = ClipMessage.file_request_message(file_path) # Request using original path
            req_json = ClipMessage.serialize(file_req)

            # Encrypt and send the request
            # If sender_websocket is provided, send directly, otherwise broadcast
            try:
                await send_encrypted_func(req_json.encode('utf-8'))
            except Exception as e:
                print(f"❌ 发送文件请求失败 ({Path(file_path).name}): {e}")
                # Consider how to handle partial request failures

            await asyncio.sleep(ClipboardConfig.NETWORK_DELAY) # Small delay between requests

        return True # Indicate requests were sent

    async def set_clipboard_file(self, file_path: Path):
        """将文件路径设置到剪贴板 (Uses main thread for macOS)"""
        try:
            path_str = str(file_path)
            if IS_MACOS:
                objc.registerMetaDataForSelector(
                    b'PasteboardSetter', b'setFileURL_', {'retval': {'type': b'@'}}
                )
                # Use executor to run the blocking operation in a separate thread
                import asyncio
                import concurrent.futures
                
                loop = asyncio.get_event_loop()
                def blocking_clipboard_operation():
                    return PasteboardSetter.performSelectorOnMainThread_withObject_waitUntilDone_(
                        'setFileURL:', path_str, True
                    )
                
                # Run in thread pool to avoid blocking the async event loop
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    result = await loop.run_in_executor(executor, blocking_clipboard_operation)
                
                if result is None:
                    # print("⚠️ 主线程剪贴板操作未返回结果，可能未正确注册 PasteboardSetter 或方法未被调用。")
                    return None
                # 解析 result
                try:
                    success_str, change_count_str = result.split("|")
                    success = success_str == "1"
                    change_count = int(change_count_str)
                except Exception as e:
                    print(f"⚠️ 解析主线程返回值失败: {result} ({e})")
                    return None
                if success:
                    return change_count
                else:
                    return None

            elif IS_WINDOWS:
                # Windows specific logic will be called from windows_client.py
                # This method primarily handles the macOS part or acts as a placeholder
                print(f"ℹ️ Windows剪贴板设置应在客户端处理: {file_path.name}")
                # We return True here to indicate the file handler part is done,
                # but the actual clipboard setting happens in windows_client.py
                return True
            else:
                print("⚠️ 未知的操作系统，无法设置剪贴板文件")
                return None
        except Exception as e:
            print(f"❌ 设置剪贴板文件时出错 (Outer): {e}")
            import traceback
            traceback.print_exc()
            return None


    async def handle_clipboard_files(self, file_urls, last_content_hash, send_encrypted_fn):
        """处理剪贴板中的文件, 发送文件信息"""
        # Calculate hash based on the list of file paths
        file_paths_str = str(sorted(file_urls)) # Sort for consistent hashing
        content_hash = hashlib.md5(file_paths_str.encode()).hexdigest()

        # Check for duplicates based on the list of paths
        if content_hash == last_content_hash:
            # print("⏭️ 跳过重复文件路径列表") # Less verbose logging
            return content_hash, False # Return hash, indicate no change sent

        # Display sending file paths
        file_names = [os.path.basename(p) for p in file_urls]
        print(f"📤 发送文件信息: {', '.join(file_names[:3])}{' 等' if len(file_names) > 3 else ''}")

        # Create file message (includes hashes now)
        file_msg = ClipMessage.file_message(file_urls)
        message_json = ClipMessage.serialize(file_msg)

        # Encrypt and broadcast file info
        await send_encrypted_fn(message_json.encode('utf-8'))
        print("🔐 已发送加密的文件信息")

        # Return the new hash and indicate that a change was sent
        return content_hash, True


    async def process_clipboard_content(self, text: str, current_time: float, last_content_hash: str,
                                     last_update_time: float, send_encrypted_fn) -> tuple[str, float, bool]:
        """
        处理剪贴板文本内容, 发送文本消息.
        Returns: (new_hash, new_update_time, sent_update)
        """
        # If content is empty or looks like temp path, do nothing
        if not text or text.strip() == "" or self._looks_like_temp_file_path(text):
            return last_content_hash, last_update_time, False

        # Calculate content hash
        content_hash = hashlib.md5(text.encode()).hexdigest()

        # If same as last content, skip
        if content_hash == last_content_hash:
            # print(f"⏭️ 跳过重复文本内容: 哈希值 {content_hash[:8]}...") # Less verbose
            return last_content_hash, last_update_time, False

        # Anti-loop delay check (moved to client/server logic before calling this)
        # if current_time - last_update_time < ClipboardConfig.UPDATE_DELAY:
        #     print(f"⏱️ 延迟检查: 距离上次更新时间 {current_time - last_update_time:.2f}秒，可能是自己更新的内容")
        #     return last_content_hash, last_update_time, False

        # Display sending content (limited length)
        display_content = text[:ClipboardConfig.MAX_DISPLAY_LENGTH] + ("..." if len(text) > ClipboardConfig.MAX_DISPLAY_LENGTH else "")
        print(f"📤 发送文本: \"{display_content}\"")

        # Create text message
        text_msg = ClipMessage.text_message(text)
        message_json = ClipMessage.serialize(text_msg)

        # Encrypt and broadcast
        await send_encrypted_fn(message_json.encode('utf-8'))
        print("🔐 已发送加密的文本")

        # Return new state
        new_update_time = time.time()
        return content_hash, new_update_time, True