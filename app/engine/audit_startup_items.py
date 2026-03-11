from .platform_utils import get_os

def audit_startup_items():

    os_type = get_os()

    if os_type == "windows":
        from .startup_items.windows import run
    elif os_type == "macos":
        from .startup_items.macos import run
    elif os_type == "linux":
        from .startup_items.linux import run
    else:
        return {"items": [], "error": "unsupported platform"}

    return run()
