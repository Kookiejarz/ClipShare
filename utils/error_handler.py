"""
Error handling utilities for UniPaste
Provides consistent error handling and logging
"""

import functools
import traceback
from typing import Callable, Optional


def handle_exceptions(
    default_return=None, 
    log_traceback: bool = True,
    error_message: Optional[str] = None
):
    """
    Decorator for consistent exception handling
    
    Args:
        default_return: Value to return if exception occurs
        log_traceback: Whether to print full traceback
        error_message: Custom error message prefix
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                prefix = error_message or f"❌ {func.__name__} 执行失败"
                print(f"{prefix}: {e}")
                if log_traceback:
                    traceback.print_exc()
                return default_return
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                prefix = error_message or f"❌ {func.__name__} 执行失败"
                print(f"{prefix}: {e}")
                if log_traceback:
                    traceback.print_exc()
                return default_return
        
        # Return appropriate wrapper based on function type
        if hasattr(func, '__code__') and func.__code__.co_flags & 0x80:  # CO_COROUTINE
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class ErrorHandler:
    """
    Centralized error handling for common operations
    """
    
    @staticmethod
    def log_connection_error(operation: str, error: Exception, client_info: str = ""):
        """Log connection-related errors"""
        print(f"🔌 连接错误 [{operation}] {client_info}: {error}")
    
    @staticmethod
    def log_encryption_error(operation: str, error: Exception):
        """Log encryption-related errors"""
        print(f"🔐 加密错误 [{operation}]: {error}")
    
    @staticmethod
    def log_file_error(operation: str, error: Exception, file_path: str = ""):
        """Log file operation errors"""
        print(f"📁 文件错误 [{operation}] {file_path}: {error}")
    
    @staticmethod
    def log_clipboard_error(operation: str, error: Exception):
        """Log clipboard operation errors"""
        print(f"📋 剪贴板错误 [{operation}]: {error}")
    
    @staticmethod
    def safe_execute(func: Callable, *args, **kwargs):
        """Safely execute a function with error handling"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"❌ 安全执行失败 [{func.__name__}]: {e}")
            return None