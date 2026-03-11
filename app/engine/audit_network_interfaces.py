from .platform_utils import get_os

def audit_network_interfaces():

    os_type = get_os()

    if os_type == "windows":
        from .network_interfaces.windows import run
    elif os_type == "macos":
        from .network_interfaces.macos import run
    elif os_type == "linux":
        from .network_interfaces.linux import run
    else:
        return {"items": [], "error": "unsupported platform"}

    return run()
