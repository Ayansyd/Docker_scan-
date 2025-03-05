import os
import glob
import logging
from utils.command_utils import run_command_with_timeout

logger = logging.getLogger(__name__)

def run_yara_scan(directory):
    """
    Run YARA malware scan using custom rules.
    """
    results = {
        "raw_output": "",
        "formatted_output": "No YARA matches detected",
        "matches": [],
        "success": False
    }
    
    yara_rules_dir = os.path.join(os.getcwd(), "yara_rules")
    if not os.path.exists(yara_rules_dir):
        results["raw_output"] = "YARA rules directory not found"
        return results

    # Use glob to collect all .yar files from the rules directory
    rule_files = glob.glob(os.path.join(yara_rules_dir, "*.yar"))
    if not rule_files:
        results["raw_output"] = "No YARA rule files found"
        return results

    try:
        # Build the command: add all rule files to the command list
        yara_command = ['yara', '-r', '-w'] + rule_files + [directory]
        stdout, stderr, return_code = run_command_with_timeout(yara_command)
        results["raw_output"] = stdout if stdout else stderr

        matches = [line.strip() for line in stdout.splitlines() if line.strip()]
        if matches:
            results["matches"] = matches
            results["formatted_output"] = f"Found {len(matches)} YARA matches:\n" + "\n".join(matches)
        results["success"] = return_code == 0
    except Exception as e:
        logger.exception(f"Error during YARA scan: {str(e)}")
        results["raw_output"] = f"Scan Error: {str(e)}"
        
    return results
