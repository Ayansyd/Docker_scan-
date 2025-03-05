import json
import logging
from config import SEVERITY_LEVELS
from utils.command_utils import run_command_with_timeout
from utils.format_utils import format_trivy_output

logger = logging.getLogger(__name__)

def run_trivy_vulnerability_scan(image_path):
    """
    Run Trivy vulnerability scan on the provided image tar file.
    """
    results = {
        "raw_output": "",
        "formatted_output": "",
        "vulnerabilities": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        },
        "success": False,
        "details": []
    }
    try:
        # Execute JSON output scan
        trivy_command = [
            'trivy', 'image',
            '--input', image_path,
            '--no-progress',
            '--security-checks', 'vuln,secret,config',
            '--vuln-type', 'os,library',
            '--format', 'json',
            '--severity', ','.join(SEVERITY_LEVELS)
        ]
        stdout, stderr, return_code = run_command_with_timeout(trivy_command)
        if return_code not in [0, 1]:
            results["raw_output"] = f"Error: {stderr}"
            logger.error(f"Trivy scan failed with code {return_code}: {stderr}")
            return results

        # Execute text output scan for formatting
        text_command = [
            'trivy', 'image',
            '--input', image_path,
            '--no-progress',
            '--security-checks', 'vuln,secret,config',
            '--vuln-type', 'os,library',
            '--severity', ','.join(SEVERITY_LEVELS)
        ]
        text_stdout, _, _ = run_command_with_timeout(text_command)
        
        # Parse the JSON output to count vulnerabilities
        if stdout:
            try:
                json_data = json.loads(stdout)
                for result in json_data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN").lower()
                        if severity in results["vulnerabilities"]:
                            results["vulnerabilities"][severity] += 1
                        results["details"].append({
                            "vulnerability_id": vuln.get("VulnerabilityID", "Unknown"),
                            "package_name": vuln.get("PkgName", "Unknown"),
                            "installed_version": vuln.get("InstalledVersion", "Unknown"),
                            "fixed_version": vuln.get("FixedVersion", "Not Available"),
                            "severity": vuln.get("Severity", "Unknown"),
                            "description": vuln.get("Description", "No description available"),
                            "references": vuln.get("References", [])
                        })
            except json.JSONDecodeError:
                logger.error("Failed to parse Trivy JSON output")
        
        results["raw_output"] = text_stdout
        results["formatted_output"] = format_trivy_output(text_stdout)
        results["success"] = True

        # Optionally, run filesystem scan
        fs_command = [
            'trivy', 'filesystem',
            '--security-checks', 'vuln,secret,config,license'
        ]
        fs_stdout, _, fs_return_code = run_command_with_timeout(fs_command)
        if fs_return_code in [0, 1]:
            results["filesystem_scan"] = format_trivy_output(fs_stdout)
            
    except Exception as e:
        logger.exception(f"Error during Trivy scan: {str(e)}")
        results["raw_output"] = f"Scan Error: {str(e)}"
    
    return results
