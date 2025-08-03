"""剪贴板通用工具函数"""
import hashlib
import time
from pathlib import Path
from utils.platform_config import IS_WINDOWS, IS_MACOS
from config import ClipboardConfig

if IS_WINDOWS:
    import win32clipboard
    import win32con
    from ctypes import Structure, c_uint, sizeof
    import pyperclip
elif IS_MACOS:
    import AppKit

class ClipboardUtils:
    """剪贴板工具类，提供跨平台的剪贴板操作"""
    
    @staticmethod
    def calculate_content_hash(content: str) -> str:
        """计算内容的哈希值"""
        return hashlib.md5(content.encode()).hexdigest()
    
    @staticmethod
    def should_ignore_content(content_hash: str, last_remote_hash: str, 
                            last_remote_time: float, delay_multiplier: float = 2) -> bool:
        """检查是否应该忽略内容（防止回环）"""
        current_time = time.time()
        return (last_remote_hash == content_hash and 
                current_time - last_remote_time < ClipboardConfig.UPDATE_DELAY * delay_multiplier)
    
    @staticmethod
    def format_display_content(content: str, max_length: int = None) -> str:
        """格式化显示内容"""
        if max_length is None:
            max_length = ClipboardConfig.MAX_DISPLAY_LENGTH
        return content[:max_length] + ("..." if len(content) > max_length else "")

    # Windows specific methods
    if IS_WINDOWS:
        @staticmethod
        def get_clipboard_files():
            """获取Windows剪贴板中的文件列表"""
            try:
                win32clipboard.OpenClipboard()
                try:
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                        data = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                        if data:
                            paths = [str(p) for p in data if Path(p).exists()]
                            return paths if paths else None
                finally:
                    win32clipboard.CloseClipboard()
            except Exception as e:
                if "OpenClipboard" in str(e):
                    print(f"⚠️ 无法访问剪贴板: {e} (可能被其他应用占用)")
                    time.sleep(0.5)
                else:
                    print(f"❌ 读取剪贴板文件失败: {e}")
            return None

        @staticmethod 
        def set_clipboard_file(file_path: Path) -> bool:
            """设置Windows剪贴板文件"""
            from windows_client import DROPFILES, HAS_WIN32COM
            try:
                path_str = str(file_path.resolve())
                files = path_str + '\0'
                file_bytes = files.encode('utf-16le') + b'\0\0'

                df = DROPFILES()
                df.pFiles = sizeof(df)
                df.pt[0] = df.pt[1] = 0
                df.fNC = 0
                df.fWide = 1

                data = bytes(df) + file_bytes

                win32clipboard.OpenClipboard()
                try:
                    win32clipboard.EmptyClipboard()
                    win32clipboard.SetClipboardData(win32con.CF_HDROP, data)
                    print(f"📎 已将文件添加到剪贴板: {file_path.name}")
                    return True
                finally:
                    win32clipboard.CloseClipboard()

            except Exception as e:
                print(f"❌ 使用 CF_HDROP 设置剪贴板文件失败: {e}")
                # Fallback to text
                try:
                    pyperclip.copy(str(file_path))
                    print(f"📎 已将文件路径作为文本复制到剪贴板: {file_path.name}")
                    return True
                except Exception:
                    return False
            return False

    # macOS specific methods  
    elif IS_MACOS:
        @staticmethod
        def get_clipboard_files():
            """获取macOS剪贴板中的文件列表"""
            pasteboard = AppKit.NSPasteboard.generalPasteboard()
            types = pasteboard.types()
            
            if AppKit.NSPasteboardTypeFileURL in types:
                file_urls = []
                for item in pasteboard.pasteboardItems():
                    url_str = item.stringForType_(AppKit.NSPasteboardTypeFileURL)
                    if url_str:
                        url = AppKit.NSURL.URLWithString_(url_str)
                        if url and url.isFileURL():
                            file_path = url.path()
                            if file_path and Path(file_path).exists():
                                file_urls.append(file_path)
                return file_urls if file_urls else None
            return None