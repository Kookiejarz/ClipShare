import sys
import platform

IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'

# Platform specific imports
if IS_MACOS:
    import AppKit
else:
    AppKit = None

def get_platform_name():
    """Get current platform name"""
    if IS_WINDOWS:
        return 'windows'
    elif IS_MACOS:
        return 'macos'
    return 'unknown'

def verify_platform(required_platform):
    """Verify if current platform matches required platform"""
    if required_platform == 'windows' and not IS_WINDOWS:
        raise RuntimeError("This module requires Windows")
    elif required_platform == 'macos' and not IS_MACOS:
        raise RuntimeError("This module requires macOS")
