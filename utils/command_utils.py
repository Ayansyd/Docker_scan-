import subprocess
from config import SCAN_TIMEOUT

def run_command_with_timeout(command, timeout=SCAN_TIMEOUT):
    """
    Run a command with a timeout and return its output.
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode
    except subprocess.TimeoutExpired:
        process.kill()
        return "", "Command timed out", -1
