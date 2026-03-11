import platform

def get_os():

    os_name = platform.system()

    if os_name == "Windows":
        return "windows"

    if os_name == "Darwin":
        return "macos"

    if os_name == "Linux":
        return "linux"

    return "unknown"
