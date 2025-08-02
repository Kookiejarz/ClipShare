from pathlib import Path
import tempfile

class ClipboardConfig:
    """剪贴板配置类"""
    
    # 文件传输相关
    MAX_FILE_SIZE_AUTO = 100 * 1024 * 1024  # 100MB自动传输限制
    CHUNK_SIZE_SMALL = 1 * 1024 * 1024      # 1MB for small files
    CHUNK_SIZE_LARGE = 4 * 1024 * 1024      # 4MB for large files  
    LARGE_FILE_THRESHOLD = 10 * 1024 * 1024 # 10MB threshold
    MAX_CONCURRENT_CHUNKS = 3               # Parallel chunk processing
    
    # 时间间隔配置
    MIN_PROCESS_INTERVAL = 0.3  # 最小处理间隔 (减少延迟)
    UPDATE_DELAY = 0.5  # 更新延迟 (减少延迟)
    NETWORK_DELAY_SMALL = 0.005  # 小文件极小延迟
    NETWORK_DELAY_LARGE = 0.001  # 大文件几乎无延迟
    CLIPBOARD_CHECK_INTERVAL = 0.2  # 剪贴板检查间隔 (更频繁检查)
    
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