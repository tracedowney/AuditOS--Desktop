from .platform_utils import get_os

def audit_dns_settings():

    os_type = get_os()

    if os_type == "windows":
        from .dns_settings.windows import run
    elif os_type == "macos":
        from .dns_settings.macos import run
    elif os_type == "linux":
        from .dns_settings.linux import run
    else:
        return {"items": [], "error": "unsupported platform"}

    return run()
