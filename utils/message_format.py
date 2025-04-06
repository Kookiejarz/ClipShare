import json
import base64
import os
from pathlib import Path
import hashlib

class MessageType:
    TEXT = "text"
    FILE = "file"
    FILE_REQUEST = "file_request"  # 请求文件
    FILE_RESPONSE = "file_response"  # 文件内容响应

class ClipMessage:
    """剪贴板消息格式化工具"""
    
    @staticmethod
    def text_message(text):
        """创建文本消息"""
        return {
            "type": MessageType.TEXT,
            "content": text
        }
    
    @staticmethod
    def file_message(file_paths):
        """创建文件路径消息
        
        file_paths 可以是单个路径或路径列表
        """
        if not isinstance(file_paths, list):
            file_paths = [file_paths]
            
        file_infos = []
        for path in file_paths:
            path_obj = Path(path)
            if path_obj.exists():
                # 计算文件哈希
                file_hash = ClipMessage.calculate_file_hash(str(path_obj))
                
                file_infos.append({
                    "filename": path_obj.name,
                    "path": str(path_obj),
                    "size": path_obj.stat().st_size,
                    "mtime": path_obj.stat().st_mtime,
                    "hash": file_hash  # 添加文件哈希
                })
        
        return {
            "type": MessageType.FILE,
            "files": file_infos
        }
    
    @staticmethod
    def file_request_message(file_path):
        """请求特定文件内容"""
        path_obj = Path(file_path)
        return {
            "type": MessageType.FILE_REQUEST,
            "filename": path_obj.name,
            "path": str(path_obj)
        }
    
    @staticmethod
    def file_response_message(file_path, chunk_index=0, total_chunks=1):
        """文件内容响应消息"""
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            return {
                "type": MessageType.FILE_RESPONSE,
                "filename": path_obj.name,
                "exists": False
            }
        
        # 计算文件分块
        file_size = path_obj.stat().st_size
        chunk_size = 1024 * 1024  # 1MB 块大小
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # 计算完整文件哈希（仅在第一块发送）
        file_hash = ""
        if chunk_index == 0:
            file_hash = ClipMessage.calculate_file_hash(file_path)
        
        # 读取对应块的内容
        with open(file_path, "rb") as f:
            f.seek(chunk_size * chunk_index)
            chunk_data = f.read(chunk_size)
            encoded_data = base64.b64encode(chunk_data).decode('utf-8')
        
        # 计算块哈希
        chunk_hash = hashlib.md5(chunk_data).hexdigest()
        
        return {
            "type": MessageType.FILE_RESPONSE,
            "filename": path_obj.name,
            "exists": True,
            "path": str(path_obj),
            "size": file_size,
            "chunk_index": chunk_index,
            "total_chunks": total_chunks,
            "chunk_data": encoded_data,
            "file_hash": file_hash,  # 完整文件哈希
            "chunk_hash": chunk_hash  # 当前块哈希
        }
    
    @staticmethod
    def calculate_file_hash(file_path):
        """计算文件的MD5哈希值"""
        hasher = hashlib.md5()
        with open(file_path, "rb") as f:
            # 读取文件块并更新哈希
            chunk = f.read(65536)  # 64KB 块
            while chunk:
                hasher.update(chunk)
                chunk = f.read(65536)
        return hasher.hexdigest()
    
    @staticmethod
    def serialize(message):
        """序列化消息为JSON字符串"""
        return json.dumps(message)
    
    @staticmethod
    def deserialize(json_str):
        """反序列化JSON字符串为消息"""
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None