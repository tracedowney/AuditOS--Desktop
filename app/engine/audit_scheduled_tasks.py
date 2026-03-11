from .platform_utils import get_os

def audit_scheduled_tasks():

    os_type = get_os()

    if os_type == "windows":
        from .scheduled_tasks.windows import run
    elif os_type == "macos":
        from .scheduled_tasks.macos import run
    elif os_type == "linux":
        from .scheduled_tasks.linux import run
    else:
        return {"items": [], "error": "unsupported platform"}

    return run()
