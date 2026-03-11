from .platform_utils import get_os

def audit_browser_extensions():

    os_type = get_os()

    if os_type == "windows":
        from .browser_extensions.windows import run
    elif os_type == "macos":
        from .browser_extensions.macos import run
    elif os_type == "linux":
        from .browser_extensions.linux import run
    else:
        return {"items": [], "error": "unsupported platform"}

    return run()
