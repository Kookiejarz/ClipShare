import threading
from utils.core.clipboard_manager import ClipboardManager
from utils.network.discovery import DeviceDiscovery
from utils.security.crypto import SecurityManager

def main():
    # Initialize components
    clipboard_mgr = ClipboardManager()
    device_discovery = DeviceDiscovery()
    security_mgr = SecurityManager()

    # Start device discovery
    device_discovery.start_advertising(5000)

    # Start clipboard monitoring in a separate thread
    clipboard_thread = threading.Thread(
        target=clipboard_mgr.start_monitoring,
        daemon=True
    )
    clipboard_thread.start()

if __name__ == "__main__":
    main()
