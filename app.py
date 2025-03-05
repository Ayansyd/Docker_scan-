import os
import json
import hashlib
import time
import threading
import subprocess
from flask import Flask, request, jsonify
from datetime import datetime

from config import MAX_CONCURRENT_SCANS, RESULTS_FOLDER
from utils.validation import validate_docker_image_name
from scanners.scan_manager import perform_scan, get_active_scan, get_active_scans_count, cleanup_old_scans
from logger_config import logger

app = Flask(__name__)

# Initialize semaphore to limit concurrent scans
from threading import Semaphore
scan_semaphore = Semaphore(MAX_CONCURRENT_SCANS)

@app.route('/scan/<path:image_name>', methods=['GET', 'POST'])
def scan_image(image_name):
    """
    API endpoint to scan a Docker image using the image name provided directly in the URL.
    """
    try:
        if not image_name:
            return jsonify({'error': 'No image name provided in URL'}), 400

        # Validate the image name format
        if not validate_docker_image_name(image_name):
            return jsonify({'error': 'Invalid docker image name format'}), 400

        # Check if we have capacity to run more scans
        active_scans = get_active_scans_count()
        if active_scans >= MAX_CONCURRENT_SCANS:
            return jsonify({
                'error': 'Maximum concurrent scan limit reached',
                'message': f'Currently running {active_scans} scans, please try again later',
                'max_concurrent_scans': MAX_CONCURRENT_SCANS
            }), 429

        # Generate a unique scan ID
        scan_id = hashlib.md5(f"{image_name}:{time.time()}".encode()).hexdigest()

        # Start scan in a separate thread to not block
        scan_thread = threading.Thread(
            target=perform_scan,
            args=(image_name, scan_id, scan_semaphore)
        )
        scan_thread.daemon = True
        scan_thread.start()

        # Return immediate response with scan ID
        return jsonify({
            'message': 'Scan started',
            'scan_id': scan_id,
            'status': 'started',
            'image': image_name,
            'timestamp': datetime.now().isoformat()
        }), 202

    except Exception as e:
        logger.exception(f"Error processing scan request: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/scan_status/<scan_id>', methods=['GET'])
def check_scan_status(scan_id):
    """
    API endpoint to check scan progress.
    """
    scan_info = get_active_scan(scan_id)
    if not scan_info:
        return jsonify({'error': 'Scan ID not found'}), 404
    
    # Format the response for Jenkins
    response = {
        'scan_id': scan_id,
        'status': scan_info['status'],
        'progress': scan_info['progress'],
        'image': scan_info['image'],
        'start_time': scan_info['start_time']
    }
    
    if 'end_time' in scan_info:
        response['end_time'] = scan_info['end_time']
    if 'error' in scan_info and scan_info['error']:
        response['error'] = scan_info['error']
        
    # Map final status to Jenkins status
    if scan_info['status'] == 'safe':
        response['jenkins_status'] = 'SUCCESS'
    elif scan_info['status'] in ['unsafe', 'failed']:
        response['jenkins_status'] = 'FAILURE'
    else:
        response['jenkins_status'] = 'IN_PROGRESS'
        
    return jsonify(response), 200

@app.route('/scan_results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """
    API endpoint to retrieve completed scan results.
    """
    scan_info = get_active_scan(scan_id)
    if not scan_info:
        return jsonify({'error': 'Scan ID not found'}), 404
    
    if scan_info["status"] not in ["safe", "unsafe", "failed"]:
        return jsonify({
            'message': 'Scan still in progress',
            'status': scan_info["status"],
            'progress': scan_info["progress"],
            'jenkins_status': 'IN_PROGRESS'
        }), 202
    
    # Try to find the results file
    image_name = scan_info["image"]
    sanitized_name = image_name.replace("/", "_").replace(":", "_")
    
    for filename in os.listdir(RESULTS_FOLDER):
        if filename.endswith(".json") and sanitized_name in filename:
            result_path = os.path.join(RESULTS_FOLDER, filename)
            with open(result_path, "r") as f:
                results = json.load(f)
                
                # Add Jenkins-specific status information based on final_status
                if results.get("final_status") == "safe":
                    results["jenkins_status"] = "SUCCESS"
                else:
                    results["jenkins_status"] = "FAILURE"
                
                # Add formatted details for Jenkins reporting
                jenkins_details = {
                    "vulnerabilities": sum(results.get("trivy", {}).get("vulnerabilities", {}).values()),
                    "malware": results.get("clamav", {}).get("threats_detected", 0),
                    "suspicious_patterns": len(results.get("yara", {}).get("matches", [])),
                    "scan_duration_seconds": 0  # Calculate if needed
                }
                
                if 'end_time' in scan_info and 'start_time' in scan_info:
                    start = datetime.fromisoformat(scan_info['start_time'])
                    end = datetime.fromisoformat(scan_info['end_time'])
                    jenkins_details["scan_duration_seconds"] = (end - start).total_seconds()
                
                results["jenkins_details"] = jenkins_details
                return jsonify(results), 200
    
    return jsonify({
        'error': 'Results not found',
        'scan_info': scan_info,
        'jenkins_status': 'FAILURE'
    }), 404

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    """
    docker_status = trivy_status = clamav_status = yara_status = False
    
    try:
        subprocess.check_output(['docker', '--version'])
        docker_status = True
        
        subprocess.check_output(['trivy', '--version'])
        trivy_status = True
        
        subprocess.check_output(['clamscan', '--version'])
        clamav_status = True
        
        try:
            subprocess.check_output(['yara', '--version'])
            yara_status = True
        except Exception:
            yara_status = False
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
    
    # Clean up old scans periodically during health checks
    removed_scans = cleanup_old_scans()
    if removed_scans > 0:
        logger.info(f"Cleaned up {removed_scans} old scan(s) during health check")
    
    return jsonify({
        'status': 'healthy' if docker_status and trivy_status and clamav_status else 'degraded',
        'docker': docker_status,
        'trivy': trivy_status,
        'clamav': clamav_status,
        'yara': yara_status,
        'message': 'Service is running',
        'active_scans': get_active_scans_count()
    })

if __name__ == '__main__':
    # Initialize YARA rules directory and add sample rule if needed
    yara_rules_dir = os.path.join(os.getcwd(), "yara_rules")
    if not os.path.exists(yara_rules_dir):
        os.makedirs(yara_rules_dir)
        logger.info(f"Created YARA rules directory: {yara_rules_dir}")
        sample_rule = '''
        rule suspicious_strings {
            meta:
                description = "Detect suspicious strings in container files"
                author = "Security Team"
                severity = "high"
            strings:
                $shell1 = "nc -e /bin/sh" nocase
                $shell2 = "bash -i >& /dev/tcp/" nocase
                $shell3 = "/bin/sh -i" nocase
                $miner1 = "xmrig" nocase
                $miner2 = "cpuminer" nocase
                $ssh_key = "ssh-rsa " 
            condition:
                any of them
        }
        '''
        with open(os.path.join(yara_rules_dir, "suspicious.yar"), "w") as f:
            f.write(sample_rule)
    
    logger.info("Starting Docker Image Security Scanner")
    app.run(host='0.0.0.0', port=5000, threaded=True)
