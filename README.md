# 🔍 Docker Image Security Scanner

A Flask-based REST API that scans Docker images for vulnerabilities, malware, and suspicious patterns using three independent scanning engines — Trivy, ClamAV, and YARA. Designed to integrate directly into Jenkins CI/CD pipelines.

---

## System Architecture
```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENTS                               │
│           Jenkins Pipeline  │  curl  │  Any HTTP client      │
└─────────────────┬────────────────────────────────────────────┘
                  │  HTTP REST
                  ▼
┌──────────────────────────────────────────────────────────────┐
│                     FLASK API  (app.py)                      │
│                                                              │
│  POST /scan          GET /scan_status/:id                    │
│  GET  /scan_results/:id   GET /health                        │
│  POST /scan-complete (webhook receiver)                      │
└─────────────────┬────────────────────────────────────────────┘
                  │  spawns background thread
                  ▼
┌──────────────────────────────────────────────────────────────┐
│                   SCAN MANAGER                               │
│              (scanners/scan_manager.py)                      │
│                                                              │
│   Semaphore ──► limits MAX_CONCURRENT_SCANS at once          │
│   scan_id   ──► MD5 hash of image + timestamp                │
│   state     ──► in-memory dict {started, running, done}      │
└────┬──────────────┬───────────────────┬──────────────────────┘
     │              │                   │
     ▼              ▼                   ▼
┌─────────┐  ┌─────────────┐  ┌──────────────┐
│  Trivy  │  │   ClamAV    │  │     YARA     │
│ Scanner │  │   Scanner   │  │   Scanner    │
└────┬────┘  └──────┬──────┘  └──────┬───────┘
     │              │                │
     ▼              ▼                ▼
 CVEs &         Malware &       Suspicious
 Vulns          Viruses         Patterns
     │              │                │
     └──────────────┴────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────────────────────┐
│                    OUTPUT LAYER                              │
│   scan_results/<image>_<timestamp>.json  (full report)       │
│   scan_results/<image>_<timestamp>.txt   (human readable)    │
│   Callback fired → callback_url (if provided)                │
└──────────────────────────────────────────────────────────────┘
```

---

## API Request / Response Lifecycle
```
Client                    Flask API              Scan Manager         Callback URL
  │                           │                       │                    │
  │  POST /scan               │                       │                    │
  │  {image, callback_url}    │                       │                    │
  │──────────────────────────►│                       │                    │
  │                           │ validate image name   │                    │
  │                           │ generate scan_id      │                    │
  │                           │ spawn thread ─────────►                    │
  │◄──────────────────────────│                       │                    │
  │  202 {scan_id, started}   │                       │ run Trivy          │
  │                           │                       │ run ClamAV         │
  │  GET /scan_status/:id     │                       │ run YARA           │
  │──────────────────────────►│                       │                    │
  │◄──────────────────────────│                       │                    │
  │  {status: running, 60%}   │                       │                    │
  │                           │                       │ save results       │
  │                           │                       │ fire callback ─────►
  │                           │                       │                    │ POST
  │                           │                       │                    │ {scan_id, status}
  │  GET /scan_results/:id    │                       │                    │
  │──────────────────────────►│                       │                    │
  │◄──────────────────────────│                       │                    │
  │  {trivy, clamav, yara,    │                       │                    │
  │   jenkins_status: SUCCESS}│                       │                    │
```

---

## Scanner Engine Breakdown
```
┌─────────────────────────────────────────────────────────────┐
│                    TRIVY SCANNER                            │
│                                                             │
│  Input : Docker image name                                  │
│  Action: Pull image → scan OS packages + app dependencies   │
│  Output: CVE list with severity (CRITICAL/HIGH/MEDIUM/LOW)  │
│                                                             │
│  nginx:latest ──► { CRITICAL: 2, HIGH: 5, MEDIUM: 12 }     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    CLAMAV SCANNER                           │
│                                                             │
│  Input : Docker image filesystem (extracted layers)         │
│  Action: Scan files against ClamAV signature database       │
│  Output: threats_detected count + infected file paths       │
│                                                             │
│  image layers ──► { threats_detected: 0, files_scanned: 847}│
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     YARA SCANNER                            │
│                                                             │
│  Input : Docker image filesystem + yara_rules/*.yar         │
│  Action: Pattern match against custom YARA rules            │
│  Output: list of rule matches + matched strings             │
│                                                             │
│  Detects:                                                   │
│  ├── Reverse shells  (nc -e /bin/sh, bash -i >& /dev/tcp/)  │
│  ├── Crypto miners   (xmrig, cpuminer)                      │
│  └── Hardcoded keys  (ssh-rsa)                              │
└─────────────────────────────────────────────────────────────┘

Final verdict:
  ALL clean  ──► final_status: "safe"  ──► jenkins_status: SUCCESS
  ANY threat ──► final_status: "unsafe"──► jenkins_status: FAILURE
```

---

## Concurrent Scan Handling
```
Request 1: nginx:latest  ──────────────────────────────► thread 1
Request 2: ubuntu:22.04  ───────────────────────────────► thread 2
Request 3: alpine:latest ────────────────────────────────► thread 3
Request 4: node:18       ─── SEMAPHORE FULL (blocks) ───► queued
Request 5: python:3.11   ─── SEMAPHORE FULL (blocks) ───► queued

                         MAX_CONCURRENT_SCANS = 3 (config.py)

When thread 1 finishes:
  semaphore.release() ──► Request 4 unblocks ──► thread 4 starts

State tracking (in-memory):
  scan_id_1: { status: "safe",    progress: 100, image: "nginx:latest"    }
  scan_id_2: { status: "running", progress:  60, image: "ubuntu:22.04"    }
  scan_id_3: { status: "running", progress:  30, image: "alpine:latest"   }
  scan_id_4: { status: "started", progress:   0, image: "node:18"         }

cleanup_old_scans() runs on every /health check to free memory
```

---

## Jenkins Pipeline Flow
```
Jenkinsfile
     │
     ▼
stage('Scan Image')
     │
     │  POST /scan {"image_name": "$IMAGE", "callback_url": "$JENKINS_URL/scan-complete"}
     │──────────────────────────────────────────────────────────────────────────────────►
     │                                                                  Scanner API
     │◄──────────────────────────────────────────────────────────────────────────────────
     │  {scan_id: "abc123", status: "started"}
     │
     ▼
stage('Poll Status')  ◄─────────────────────────────────┐
     │                                                   │
     │  GET /scan_status/abc123                          │
     │──────────────────────────────────────────────────►│
     │◄──────────────────────────────────────────────────│
     │  {status: "running", jenkins_status: "IN_PROGRESS"}
     │                                                   │
     │  sleep(10s) ──────────────────────────────────────┘
     │  (loop until jenkins_status != IN_PROGRESS)
     │
     ▼
stage('Get Results')
     │
     │  GET /scan_results/abc123
     │──────────────────────────────────────────────────►
     │◄──────────────────────────────────────────────────
     │  {jenkins_status: "SUCCESS" / "FAILURE",
     │   vulnerabilities: 3, malware: 0, suspicious: 0}
     │
     ▼
stage('Pass / Fail Build')
     │
     ├── jenkins_status: SUCCESS ──► ✅ Build continues
     └── jenkins_status: FAILURE ──► ❌ Build fails + report archived
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Start a scan — returns `scan_id` immediately |
| `GET` | `/scan_status/<scan_id>` | Poll scan progress and status |
| `GET` | `/scan_results/<scan_id>` | Get full results once complete |
| `POST/GET` | `/scan-complete` | Webhook callback receiver |
| `GET` | `/health` | Health check — verifies all tools available |

---

## Project Structure
```
scan_docker_image/
├── app.py                  # Flask API — endpoints and scan orchestration
├── config.py               # Configuration (concurrency limits, paths)
├── logger_config.py        # Logging setup
├── requirements.txt
├── scanners/
│   ├── scan_manager.py     # Scan lifecycle, concurrency, cleanup
│   ├── trivy_scanner.py    # Trivy wrapper
│   ├── clamav_scanner.py   # ClamAV wrapper
│   └── yara_scanner.py     # YARA wrapper
├── utils/
│   ├── validation.py       # Docker image name validation
│   ├── command_utils.py    # Shell command helpers
│   ├── file_utils.py       # File handling
│   └── format_utils.py     # Result formatting
└── yara_rules/
    └── suspicious.yar      # YARA detection rules (extend as needed)
```

---

## Setup

### Prerequisites
```bash
sudo apt install clamav trivy yara
sudo freshclam   # update ClamAV signatures
```

### Install & Run
```bash
git clone https://github.com/Ayansyd/Docker_scan-.git
cd Docker_scan-

python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

python app.py
# API runs on http://0.0.0.0:5000
```

### Verify
```bash
curl http://localhost:5000/health
```

---

## Tech Stack

- **Language** — Python 3.10
- **API** — Flask
- **Vulnerability scanning** — Trivy
- **Malware detection** — ClamAV
- **Pattern matching** — YARA
- **CI/CD** — Jenkins

---

## Status

✅ Trivy, ClamAV, YARA scanning — working  
✅ Concurrent scan support (semaphore-limited) — working  
✅ Jenkins callback and status mapping — working  
🔄 Extended YARA ruleset — in progress  

---

## Author

**Mohammed Ayan Syed**
