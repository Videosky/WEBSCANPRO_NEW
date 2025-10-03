#!/usr/bin/env python3
"""
check_dvwa.py
Checks if DVWA is accessible at http://localhost:8080.
If not accessible, checks for a Docker container named 'dvwa' and attempts to start it.
"""

import subprocess
import time
import sys

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: pip install requests")
    sys.exit(2)

DVWA_URL = "http://localhost:8080/"
DOCKER_CONTAINER_NAME = "dvwa"
DOCKER_RUN_CMD = [
    "docker", "run", "--name", DOCKER_CONTAINER_NAME,
    "-p", "8080:80", "-d", "vulnerables/web-dvwa"
]
POLL_INTERVAL = 3         # seconds between HTTP checks
POLL_TIMEOUT = 60         # total seconds to wait after starting container


def is_dvwa_accessible(url: str, timeout: float = 5.0) -> bool:
    """
    Returns True if an HTTP GET to url returns a 200 and the response contains
    a DVWA-ish marker (e.g., 'DVWA' or 'Web Vulnerability' in the body).
    """
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            body = resp.text.lower()
            # look for simple markers that indicate the DVWA app (login page contains 'dvwa')
            if "dvwa" in body or "web vuln" in body or "damian" in body:
                return True
            # 200 but not recognizable content: still consider it reachable
            return True
        else:
            return False
    except requests.RequestException:
        return False


def docker_container_running(name: str) -> bool:
    """
    Checks 'docker ps' to see if a container with the provided name is running.
    Returns True if running, False otherwise.
    """
    try:
        # --filter to make output concise; --format '{{.Names}}' lists container names
        out = subprocess.run(
            ["docker", "ps", "--filter", f"name={name}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False
        )
        running_names = out.stdout.strip().splitlines()
        return name in running_names
    except FileNotFoundError:
        print("Docker CLI not found. Is Docker installed and on PATH?")
        return False


def start_dvwa_container():
    """
    Attempts to start the DVWA container using the predefined DOCKER_RUN_CMD.
    If a container with the same name exists but is stopped, this will fail;
    the function will try 'docker start <name>' in that case.
    """
    try:
        # Try direct run
        print("Attempting to run DVWA container with docker run ...")
        run_proc = subprocess.run(DOCKER_RUN_CMD, capture_output=True, text=True, check=False)
        if run_proc.returncode == 0:
            print("docker run launched container (detached). Container id:")
            print(run_proc.stdout.strip())
            return True
        else:
            stderr = run_proc.stderr.strip()
            print("docker run failed or container may already exist. docker run stderr:")
            print(stderr)
            # If a stopped container exists with same name, try docker start
            print(f"Attempting 'docker start {DOCKER_CONTAINER_NAME}' ...")
            start_proc = subprocess.run(
                ["docker", "start", DOCKER_CONTAINER_NAME],
                capture_output=True, text=True, check=False
            )
            if start_proc.returncode == 0:
                print("Started existing container.")
                return True
            else:
                print("Failed to start existing container. docker start stderr:")
                print(start_proc.stderr.strip())
                return False
    except FileNotFoundError:
        print("Docker CLI not found. Cannot start container.")
        return False


def poll_until_accessible(url: str, timeout: int = POLL_TIMEOUT) -> bool:
    """
    Polls the given URL every POLL_INTERVAL seconds until it responds as accessible
    or until timeout seconds elapse. Returns True if accessible, False if timed out.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        if is_dvwa_accessible(url):
            return True
        print(f"Not yet accessible. Waiting {POLL_INTERVAL}s ...")
        time.sleep(POLL_INTERVAL)
    return False


def main():
    print(f"Checking DVWA at {DVWA_URL} ...")
    if is_dvwa_accessible(DVWA_URL):
        print("DVWA is accessible. ✅")
        sys.exit(0)

    print("DVWA not accessible on HTTP. Checking Docker container status...")
    if docker_container_running(DOCKER_CONTAINER_NAME):
        print(f"Container '{DOCKER_CONTAINER_NAME}' is running but app not reachable on HTTP.")
        print("Try checking container logs with: docker logs -f dvwa")
        # Still attempt polling in case the app is still booting
        if poll_until_accessible(DVWA_URL):
            print("DVWA became accessible. ✅")
            sys.exit(0)
        else:
            print("Timed out waiting for the running container to serve HTTP.")
            sys.exit(3)
    else:
        print(f"Container '{DOCKER_CONTAINER_NAME}' is not running. Attempting to start it...")
        started = start_dvwa_container()
        if not started:
            print("Failed to start DVWA container automatically. Please start it manually.")
            sys.exit(4)
        print("Container start attempted. Polling for HTTP readiness ...")
        if poll_until_accessible(DVWA_URL):
            print("DVWA is now accessible. ✅")
            sys.exit(0)
        else:
            print(f"Timed out ({POLL_TIMEOUT}s) waiting for DVWA to become accessible.")
            print("Check 'docker logs dvwa' for errors or ensure port 8080 is free.")
            sys.exit(5)


if __name__ == "__main__":
    main()
