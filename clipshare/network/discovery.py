import socket
import json
from zeroconf import ServiceBrowser, Zeroconf, ServiceInfo, ServiceListener
import netifaces
import asyncio
from concurrent.futures import ThreadPoolExecutor

class ClipboardServiceListener(ServiceListener):
    def __init__(self, callback):
        self.callback = callback
        
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            address = str(info.parsed_addresses()[0])
            port = info.port
            self.callback(f"ws://{address}:{port}")
            
    # Required methods for ServiceListener
    def remove_service(self, zeroconf, type_, name):
        pass

    def update_service(self, zeroconf, type_, name):
        pass

class DeviceDiscovery:
    def __init__(self, service_name="_clipshare._tcp.local."):
        self.zeroconf = Zeroconf()
        self.service_name = service_name
        self.discovered_devices = {}
        self._executor = ThreadPoolExecutor(max_workers=1)

    async def start_advertising(self, port):
        """Advertise this device on the network."""
        ip_addr = self._get_local_ip()
        print(f"🌐 使用IP地址 {ip_addr} 和端口 {port} 注册服务")
        
        info = ServiceInfo(
            self.service_name,
            f"Device_{socket.gethostname()}.{self.service_name}",
            addresses=[socket.inet_aton(ip_addr)],
            port=port,
            properties={},
        )
        
        print(f"📢 广播服务: {self.service_name}")
        print(f"📛 服务名称: Device_{socket.gethostname()}.{self.service_name}")
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self.zeroconf.register_service, info)
        print("✅ 服务注册成功")

    def start_discovery(self, callback):
        """Discover clipboard services on the network."""
        self.browser = ServiceBrowser(
            self.zeroconf, 
            self.service_name,
            ClipboardServiceListener(callback)
        )
        print("🔍 开始搜索剪贴板服务...")

    def _get_local_ip(self):
        """Get the local IP address."""
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if addr['addr'] != '127.0.0.1':
                        return addr['addr']
        return '127.0.0.1'

    def close(self):
        """Clean up resources."""
        if hasattr(self, 'zeroconf'):
            self.zeroconf.close()
        if hasattr(self, '_executor'):
            self._executor.shutdown()
