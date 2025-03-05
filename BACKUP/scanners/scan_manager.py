import os
import subprocess
import tempfile
import tarfile
import shutil
import hashlib
import time
import threading
import json
import logging
from datetime import datetime

from config import RESULTS_FOLDER
from utils.file_utils import create_file_hash, sanitize_filename
from scanners.trivy_scanner import run_trivy_vulnerability_scan
from scanners.clamav_scanner import run_clamav_scan
from scanners.yara_scanner import run_yara_scan

logger = logging.getLogger(__name__)
active_scans = {}

def save_results_to_file(image_name, scan_results):
    """
    Save both human-readable and JSON scan results to files.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_name = sanitize_filename(image_name)
    filename = f"{RESULTS_FOLDER}/{sanitized_name}_{timestamp}.txt"
    json_filename = f"{RESULTS_FOLDER}/{sanitized_name}_{timestamp}.json"
    
    # Save human-readable results
    with open(filename, "w") as file:
        file.write(f"Scan Results for Image: {image_name}\n")
        file.write(f"Timestamp: {datetime.now().isoformat()}\n")
        file.write("=" * 60 + "\n\n")
        file.write("SUMMARY\n")
        file.write("-" * 60 + "\n")
        vuln_count = scan_results.get("trivy", {}).get("vulnerabilities", {})
        file.write(f"Vulnerabilities: {sum(vuln_count.values())} total\n")
        for severity, count in vuln_count.items():
            file.write(f"  - {severity.upper()}: {count}\n")
        clamav = scan_results.get("clamav", {})
        file.write(f"Malware/Virus Threats: {clamav.get('threats_detected', 0)}\n")
        yara = scan_results.get("yara", {})
        file.write(f"YARA Rule Matches: {len(yara.get('matches', []))}\n\n")
        file.write("VULNERABILITY SCAN (Trivy)\n")
        file.write("-" * 60 + "\n")
        file.write(scan_results.get("trivy", {}).get("formatted_output", "No data") + "\n\n")
        file.write("VIRUS SCAN (ClamAV)\n")
        file.write("-" * 60 + "\n")
        file.write(scan_results.get("clamav", {}).get("formatted_output", "No data") + "\n\n")
        file.write("MALWARE SCAN (YARA)\n")
        file.write("-" * 60 + "\n")
        file.write(scan_results.get("yara", {}).get("formatted_output", "No data") + "\n\n")
        if "filesystem_scan" in scan_results.get("trivy", {}):
            file.write("FILESYSTEM SECURITY SCAN\n")
            file.write("-" * 60 + "\n")
            file.write(scan_results.get("trivy", {}).get("filesystem_scan", "No data") + "\n\n")
        # Write final status info
        file.write(f"FINAL STATUS: {scan_results.get('final_status')}\n")
    
    # Save JSON machine-readable results
    with open(json_filename, "w") as json_file:
        json.dump(scan_results, json_file, indent=2)
    
    return filename, json_filename

def update_scan_status(scan_id, status, progress, error=None):
    """
    Update the status of a scan in the active_scans dictionary.
    This function ensures that all status updates are done consistently.
    """
    if scan_id in active_scans:
        active_scans[scan_id]["status"] = status
        active_scans[scan_id]["progress"] = progress
        if error:
            active_scans[scan_id]["error"] = error
        
        # Log the status update for debugging
        logger.info(f"Scan {scan_id} status updated: {status} ({progress}%)")
        
    else:
        logger.warning(f"Attempted to update status for unknown scan ID: {scan_id}")

def perform_scan(image_name, scan_id, scan_semaphore):
    """
    Perform a comprehensive scan on a Docker image.
    """
    # Initialize scan status
    active_scans[scan_id] = {
        "status": "preparing",
        "image": image_name,
        "start_time": datetime.now().isoformat(),
        "progress": 0,
        "error": None
    }
    
    results = {
        "image": image_name,
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "status": "preparing",
        "final_status": None,
        "error": None,
        "trivy": {},
        "clamav": {},
        "yara": {},
        "result_files": {}
    }
    
    temp_files = []
    extracted_dir = None
    
    try:
        with scan_semaphore:
            # Update status to pulling image
            update_scan_status(scan_id, "pulling_image", 10)
            results["status"] = "pulling_image"
            
            # Check if the image is available locally; if not, pull it.
            try:
                subprocess.check_output(
                    ['docker', 'inspect', image_name], 
                    stderr=subprocess.STDOUT
                )
                logger.info(f"Image {image_name} already available locally")
            except subprocess.CalledProcessError:
                logger.info(f"Pulling image: {image_name}")
                try:
                    pull_process = subprocess.Popen(
                        ['docker', 'pull', image_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                    
                    # Monitor the pull progress
                    for line in pull_process.stdout:
                        if "Pulling fs layer" in line:
                            update_scan_status(scan_id, "pulling_image_layers", 12)
                        elif "Downloading" in line:
                            update_scan_status(scan_id, "downloading_image", 15)
                        elif "Download complete" in line:
                            update_scan_status(scan_id, "download_complete", 18)
                        elif "Pull complete" in line:
                            update_scan_status(scan_id, "pull_complete", 19)
                    
                    pull_process.wait()
                    if pull_process.returncode != 0:
                        error_msg = f"Failed to pull docker image with return code {pull_process.returncode}"
                        logger.error(error_msg)
                        update_scan_status(scan_id, "failed", 0, error_msg)
                        results["error"] = error_msg
                        results["status"] = "failed"
                        return results
                        
                except subprocess.CalledProcessError as e:
                    error_msg = e.output.decode('utf-8')
                    logger.error(f"Failed to pull docker image: {error_msg}")
                    update_scan_status(scan_id, "failed", 0, error_msg)
                    results["error"] = f"Failed to pull docker image: {error_msg}"
                    results["status"] = "failed"
                    return results
            
            # Update status to saving image
            update_scan_status(scan_id, "saving_image", 20)
            results["status"] = "saving_image"
            
            # Save the image as a tar file.
            temp_tar = tempfile.NamedTemporaryFile(delete=False, suffix='.tar')
            temp_tar_path = temp_tar.name
            temp_tar.close()
            temp_files.append(temp_tar_path)
            
            try:
                # Use Popen to monitor the save process
                save_process = subprocess.Popen(
                    ['docker', 'save', image_name, '-o', temp_tar_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                # Wait for the process to complete
                save_process.wait()
                if save_process.returncode != 0:
                    error_msg = f"Failed to save docker image with return code {save_process.returncode}"
                    logger.error(error_msg)
                    update_scan_status(scan_id, "failed", 0, error_msg)
                    results["error"] = error_msg
                    results["status"] = "failed"
                    return results
                    
            except subprocess.CalledProcessError as e:
                error_msg = e.output.decode('utf-8')
                logger.error(f"Failed to save docker image: {error_msg}")
                update_scan_status(scan_id, "failed", 0, error_msg)
                results["error"] = f"Failed to save docker image: {error_msg}"
                results["status"] = "failed"
                return results
            
            # Create hash for integrity checking.
            update_scan_status(scan_id, "creating_hash", 25)
            results["status"] = "creating_hash"
            results["image_hash"] = create_file_hash(temp_tar_path)
            
            if os.path.getsize(temp_tar_path) == 0:
                error_msg = "Empty image tar file created"
                logger.error(error_msg)
                update_scan_status(scan_id, "failed", 0, error_msg)
                results["error"] = error_msg
                results["status"] = "failed"
                return results
            
            os.chmod(temp_tar_path, 0o644)
            
            # Update status to extracting image
            update_scan_status(scan_id, "extracting_image", 30)
            results["status"] = "extracting_image"
            
            # Extract the tar file.
            extracted_dir = tempfile.mkdtemp(prefix="docker_image_extract_")
            try:
                with tarfile.open(temp_tar_path, "r") as tar:
                    total_members = len(tar.getmembers())
                    for index, member in enumerate(tar.getmembers()):
                        if member.name.startswith('/') or '..' in member.name:
                            logger.warning(f"Potentially malicious path in tar: {member.name}")
                            continue
                        tar.extract(member, path=extracted_dir)
                        
                        # Update progress every 10% of extraction
                        if index % max(1, total_members // 10) == 0:
                            extract_progress = 30 + int((index / total_members) * 10)
                            update_scan_status(scan_id, "extracting_image", extract_progress)
            except Exception as e:
                error_msg = f"Failed to extract docker image tar: {str(e)}"
                logger.error(error_msg)
                update_scan_status(scan_id, "failed", 0, error_msg)
                results["error"] = error_msg
                results["status"] = "failed"
                return results
            
            # Run Trivy vulnerability scan
            update_scan_status(scan_id, "vulnerability_scanning", 40)
            results["status"] = "vulnerability_scanning"
            results["trivy"] = run_trivy_vulnerability_scan(temp_tar_path)
            
            # Update progress after Trivy scan
            update_scan_status(scan_id, "trivy_scan_complete", 60)
            
            # Run ClamAV virus scan
            update_scan_status(scan_id, "virus_scanning", 60)
            results["status"] = "virus_scanning"
            results["clamav"] = run_clamav_scan(extracted_dir)
            
            # Update progress after ClamAV scan
            update_scan_status(scan_id, "clamav_scan_complete", 80)
            
            # Run YARA malware scan
            update_scan_status(scan_id, "malware_scanning", 80)
            results["status"] = "malware_scanning"
            results["yara"] = run_yara_scan(extracted_dir)
            
            # Update progress after YARA scan
            update_scan_status(scan_id, "yara_scan_complete", 90)
            
            # Determine final status based solely on Trivy and ClamAV results.
            vuln_count = sum(results["trivy"].get("vulnerabilities", {}).values())
            threat_count = results["clamav"].get("threats_detected", 0)
            
            if vuln_count == 0 and threat_count == 0:
                results["final_status"] = "safe"
            else:
                results["final_status"] = "unsafe"
            
            # Update status to saving results
            update_scan_status(scan_id, "saving_results", 95)
            results["status"] = "saving_results"
            
            # Save scan results to files
            text_file, json_file = save_results_to_file(image_name, results)
            results["result_files"] = {"text": text_file, "json": json_file}
            
            # Set the final status in the result and update active scan record
            results["status"] = results["final_status"]
            update_scan_status(scan_id, results["final_status"], 100)
                
    except Exception as e:
        error_msg = f"Error during scan: {str(e)}"
        logger.exception(error_msg)
        update_scan_status(scan_id, "failed", 0, error_msg)
        results["error"] = error_msg
        results["status"] = "failed"
    finally:
        # Record end time
        active_scans[scan_id]["end_time"] = datetime.now().isoformat()
        
        # Clean up temporary files
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception as e:
                    logger.warning(f"Failed to remove temp file {temp_file}: {str(e)}")
                    
        # Clean up extracted directory
        if extracted_dir and os.path.exists(extracted_dir):
            try:
                shutil.rmtree(extracted_dir)
            except Exception as e:
                logger.warning(f"Failed to remove temp directory {extracted_dir}: {str(e)}")
    
    return results

def get_active_scan(scan_id):
    """
    Retrieve the active scan information by scan_id.
    """
    if scan_id in active_scans:
        # Return a copy to prevent modification
        return dict(active_scans[scan_id])
    return None

def get_active_scans_count():
    """
    Get the count of currently active scans.
    """
    return len([scan for scan_id, scan in active_scans.items() 
                if scan["status"] not in ["safe", "unsafe", "failed"]])

def cleanup_old_scans(max_age_hours=24):
    """
    Remove old completed or failed scans from the active_scans dictionary.
    """
    current_time = datetime.now()
    scans_to_remove = []
    
    for scan_id, scan_info in active_scans.items():
        if scan_info["status"] in ["safe", "unsafe", "failed"]:
            end_time = datetime.fromisoformat(scan_info.get("end_time", scan_info["start_time"]))
            age = (current_time - end_time).total_seconds() / 3600
            if age > max_age_hours:
                scans_to_remove.append(scan_id)
    
    for scan_id in scans_to_remove:
        del active_scans[scan_id]
        
    return len(scans_to_remove)
