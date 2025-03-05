import os

RESULTS_FOLDER = "scan_results"
SCAN_TIMEOUT = 600  # 10 minutes timeout for scans
MAX_CONCURRENT_SCANS = 3
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Ensure results folder exists
os.makedirs(RESULTS_FOLDER, exist_ok=True)
