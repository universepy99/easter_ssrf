#requirements.txt

import subprocess
import sys
import os

REQUIREMENTS_FILE = "requirements.txt"

def install_requirements():
    if os.path.exists(REQUIREMENTS_FILE):
        print("[+] Checking and installing dependencies from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS_FILE])
            print("[+] All dependencies are up to date.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to install some dependencies: {e}")
    else:
        print("[!] requirements.txt file not found. Skipping dependency installation.")

if __name__ == "__main__":
    install_requirements()
