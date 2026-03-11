from .platform_utils import get_os

def audit_routes():

    os_type = get_os()

    if os_type == "windows":
        from .routes.windows import run
    elif os_type == "macos":
        from .routes.macos import run
    elif os_type == "linux":
        from .routes.linux import run
    else:
        return {"items": [], "error": "unsupported platform"}

    return run()
