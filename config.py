from pathlib import Path
import tempfile

class ClipboardConfig:
    """剪贴板配置类"""
    
    # 文件传输相关
    MAX_FILE_SIZE_AUTO = 100 * 1024 * 1024  # 100MB自动传输限制
    CHUNK_SIZE = 700 * 1024  # 1MB分块大小
    
    # 时间间隔配置
    MIN_PROCESS_INTERVAL = 0.8  # 最小处理间隔
    UPDATE_DELAY = 1.0  # 更新延迟
    NETWORK_DELAY = 0.05  # 网络传输延迟
    CLIPBOARD_CHECK_INTERVAL = 0.5  # 剪贴板检查间隔
    
    # 显示相关
    MAX_DISPLAY_LENGTH = 100  # 最大显示长度
    
    # WebSocket配置
    DEFAULT_PORT = 8765
    HOST = "0.0.0.0"
    
    # 文件存储配置
    @classmethod
    def get_temp_dir(cls):
        """获取临时文件目录"""
        temp_dir = Path(tempfile.gettempdir()) / "unipaste_files"
        temp_dir.mkdir(exist_ok=True)
        return temp_dir
    
    # 临时文件路径标识
    TEMP_PATH_INDICATORS = [
        "\\AppData\\Local\\Temp\\clipshare_files\\",
        "/var/folders/",
        "/tmp/clipshare_files/",
        "C:\\Users\\\\AppData\\Local\\Temp\\clipshare_files\\"
    ]