import logging
from utils.command_utils import run_command_with_timeout

logger = logging.getLogger(__name__)

def run_clamav_scan(directory):
    """
    Run ClamAV antivirus scan on the specified directory.
    """
    results = {
        "raw_output": "",
        "formatted_output": "No threats detected",
        "threats_detected": 0,
        "infected_files": [],
        "success": False
    }
    try:
        clamscan_command = [
            'clamscan',
            '--infected',
            '--recursive',
            '--allmatch',
            '--detect-pua=yes',
            '--heuristic-scan-precedence=yes',
            '--scan-archive=yes',
            '--stdout',
            directory
        ]
        stdout, stderr, return_code = run_command_with_timeout(clamscan_command)
        results["raw_output"] = stdout if stdout else stderr
        
        infected_files = [line.strip() for line in stdout.splitlines() if 'FOUND' in line]
        if infected_files:
            results["threats_detected"] = len(infected_files)
            results["infected_files"] = infected_files
            results["formatted_output"] = f"Found {len(infected_files)} threats:\n" + "\n".join(infected_files)
            
        results["success"] = return_code in [0, 1]
    except Exception as e:
        logger.exception(f"Error during ClamAV scan: {str(e)}")
        results["raw_output"] = f"Scan Error: {str(e)}"
    return results
