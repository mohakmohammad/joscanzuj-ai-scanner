#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
joscanzuj.py - AI-Powered Vulnerability Scanner
جامعة الزيتونة الأردنية - مشروع التخرج
joscanzuj_full_gui_ai_enhanced.py
JOSCANZUJ - Full scanner + CustomTkinter GUI with enhanced AI Assistant
Features:
 - requests scanner + selenium fallback
 - default vulnerability payloads (XSS, SQLi, LFI, Command Injection, Dir Traversal, Open Redirect)
 - JSON / CSV / PDF outputs saved into reports/, previous outputs archived to reports/archive/
 - modern CustomTkinter GUI with progress, logs and colored highlights
 - ethical/legal disclaimer in generated PDF
 - Enhanced AI Assistant with multiple providers (DeepSeek, OpenAI, Ollama local, OpenRouter)
 - Auto-analysis buttons for quick insights
 - Chat session storage
 - Ollama local model support with installation guide
Author: Generated for user (Mohamed Hassan)
"""

import os
import re
import json
import csv
import time
import html
import queue
import threading
import traceback
import logging
import shutil
import pickle
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, quote_plus, urlparse, parse_qsl, urlencode, urlunparse
from pathlib import Path
import webbrowser
import tkinter.filedialog as fd
from tkinter import messagebox, scrolledtext

# third-party
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, WebDriverException, TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.utils import ImageReader

import customtkinter as ctk
from colorama import init as colorama_init, Fore, Style

# init / UI theming
colorama_init(autoreset=True)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ---------------- config ----------------
BASE_DIR = Path.cwd()
SCREENSHOT_DIR = BASE_DIR / "screenshots"
REPORTS_DIR = BASE_DIR / "reports"
ARCHIVE_DIR = REPORTS_DIR / "archive"
CHAT_SESSIONS_DIR = BASE_DIR / "chat_sessions"
SCREENSHOT_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
ARCHIVE_DIR.mkdir(exist_ok=True)
CHAT_SESSIONS_DIR.mkdir(exist_ok=True)

OUT_JSON_DEFAULT = "results.json"
HEADERS = {"User-Agent": "JOSCANZUJ/1.0"}
TIMEOUT = 10
SEL_PAGE_LOAD_TIMEOUT = 30
DEFAULT_DELAY = 0.5
LOG_FILE = "scanner.log"

# Ollama configuration
OLLAMA_HOST = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3.2"
OLLAMA_AVAILABLE_MODELS = ["llama3.2", "mistral", "codellama", "phi", "gemma:2b"]

# logging
logger = logging.getLogger("JOSCANZUJ")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

# ---------------- tests & payloads ----------------
VULN_TESTS = [
    {"name": "Reflected XSS", "payloads": ['<script>alert("XSS")</script>', '"><img src=x onerror=alert(1)>', "';alert(1);//"], "param": "q"},
    {"name": "SQL Injection", "payloads": ["' OR '1'='1' -- ", "' UNION SELECT NULL--", "' OR 1=1 -- "], "param": "q"},
    {"name": "Local File Inclusion (LFI)", "payloads": ["../../../../etc/passwd", "/etc/passwd"], "param": "file"},
    {"name": "Command Injection", "payloads": ["; ls", "&& whoami", "| dir"], "param": "q"},
    {"name": "Directory Traversal", "payloads": ["../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts"], "param": "path"},
    {"name": "Open Redirect", "payloads": ["http://evil.example.com", "https://attacker.example.com"], "param": "next"}
]

# ---------------- helpers ----------------
def sanitize_filename(s, max_len=120):
    s = (s or "").strip()
    s = s.replace("#", "hash")
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', s)
    if len(s) > max_len:
        s = s[:max_len]
    s = s.strip("._-")
    return s or "file"

def add_param_to_url(base_url, param, value):
    p = urlparse(base_url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    new_query = urlencode(q, doseq=True)
    new = p._replace(query=new_query)
    return urlunparse(new)

def make_requests_session(retries=2, backoff_factor=0.3, status_forcelist=(502,503,504), user_agent=None):
    s = requests.Session()
    try:
        retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist, allowed_methods=frozenset(["GET","POST","PUT","DELETE","OPTIONS"]))
    except TypeError:
        retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist, method_whitelist=frozenset(["GET","POST","PUT","DELETE","OPTIONS"]))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    headers = dict(HEADERS)
    if user_agent:
        headers["User-Agent"] = user_agent
    s.headers.update(headers)
    return s

def snippet_of(text, payload, ctx=160):
    """
    Find occurrences (variants) of payload in text and return a snippet with context.
    """
    if not text or not payload:
        return None
    txt = str(text)
    payload = str(payload)
    variants = [payload, html.escape(payload)]
    try:
        variants.append(quote_plus(payload))
    except Exception:
        pass
    variants.append(payload.replace('"', '\\"').replace("'", "\\'"))
    tokens = re.findall(r"[A-Za-z0-9]{4,}", payload)
    variants.extend(tokens)
    low_text = txt.lower()
    for v in variants:
        if not v:
            continue
        try:
            idx = low_text.find(v.lower())
        except Exception:
            continue
        if idx != -1:
            start = max(0, idx - ctx)
            end = idx + len(v) + ctx
            return txt[start:end].replace("\n", " ")
    safe = re.sub(r'\s+', r'\\s*', re.escape(payload))
    m = re.search(safe, txt, flags=re.IGNORECASE)
    if m:
        start = max(0, m.start() - ctx)
        end = m.end() + ctx
        return txt[start:end].replace("\n", " ")
    return None

# selenium helpers
def make_selenium_driver(headless=True, chromedriver_path=None):
    chrome_options = Options()
    if headless:
        try:
            chrome_options.add_argument("--headless=new")
        except Exception:
            chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1366,900")
    if chromedriver_path:
        service = Service(chromedriver_path)
    else:
        path = ChromeDriverManager().install()
        service = Service(path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

def get_selenium(full_url, driver, screenshot_path=None, wait_after=1.5):
    try:
        driver.set_page_load_timeout(SEL_PAGE_LOAD_TIMEOUT)
        try:
            driver.get(full_url)
        except TimeoutException:
            pass
        time.sleep(wait_after)
        alert_text = None
        try:
            alert = driver.switch_to.alert
            try:
                alert_text = alert.text
            except Exception:
                alert_text = None
            try:
                alert.accept()
            except Exception:
                pass
            time.sleep(0.4)
        except NoAlertPresentException:
            alert_text = None
        except Exception:
            try:
                alert = driver.switch_to.alert
                alert_text = getattr(alert, "text", None)
                try:
                    alert.accept()
                except Exception:
                    pass
            except Exception:
                alert_text = None
        page = ""
        try:
            page = driver.page_source or ""
        except Exception:
            page = ""
        if screenshot_path:
            try:
                os.makedirs(os.path.dirname(screenshot_path) or SCREENSHOT_DIR, exist_ok=True)
                driver.save_screenshot(screenshot_path)
            except Exception as e:
                logger.debug(f"Could not save screenshot {screenshot_path}: {e}")
        result = {"status": 200, "url": full_url, "page_source": page}
        if alert_text:
            result["alert_text"] = alert_text
        return result
    except UnexpectedAlertPresentException:
        alert_text = None
        try:
            alert = driver.switch_to.alert
            alert_text = getattr(alert, "text", None)
            try:
                alert.accept()
            except Exception:
                pass
        except Exception:
            pass
        page = ""
        try:
            page = driver.page_source or ""
        except Exception:
            page = ""
        res = {"status": 200, "url": full_url, "page_source": page}
        if alert_text:
            res["alert_text"] = alert_text
        return res
    except WebDriverException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

# ---------------- reporting helpers ----------------
SEVERITY_MAP = {
    'sql injection': 'High',
    'command injection': 'High',
    'local file inclusion': 'High',
    'lfi': 'High',
    'directory traversal': 'Medium',
    'reflected xss': 'Medium',
    'xss': 'Medium',
    'open redirect': 'Low'
}

def map_severity(vuln_type: str) -> str:
    if not vuln_type:
        return 'Unknown'
    t = vuln_type.lower()
    for k, sev in SEVERITY_MAP.items():
        if k in t:
            return sev
    return 'Low'

def make_image_flow_pdf(path, max_width_mm=160, max_height_mm=220):
    if not path or not os.path.exists(path):
        return None
    try:
        reader = ImageReader(path)
        iw, ih = reader.getSize()
        max_w = max_width_mm * mm
        max_h = max_height_mm * mm
        scale = min(1.0, max_w / iw, max_h / ih)
        w = iw * scale
        h = ih * scale
        img = Image(path, width=w, height=h)
        img.hAlign = 'LEFT'
        return img
    except Exception:
        return None

def prepare_vuln_rows(vulnerabilities: list):
    rows = []
    for v in vulnerabilities:
        vtype = v.get('type', 'Unknown')
        severity = v.get('severity') or map_severity(vtype)
        endpoint = v.get('endpoint', '-')
        method = v.get('method', '-')
        payload = str(v.get('payload', ''))
        snippet = v.get('evidence', {}).get('response_snippet', '') if isinstance(v.get('evidence'), dict) else ''
        screenshot = v.get('evidence', {}).get('screenshot') if isinstance(v.get('evidence'), dict) else None
        rows.append({'type': vtype,'severity': severity,'endpoint': endpoint,'method': method,'payload': payload,'snippet': snippet,'screenshot': screenshot})
    return rows

def generate_pdf_report(target: str, vulnerabilities: list, output_file: str):
    doc = SimpleDocTemplate(output_file, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    heading = styles['Heading1']; normal = styles['Normal']; heading4 = styles.get('Heading4', styles.get('Heading2')); h2 = styles['Heading2']
    story = []
    story.append(Paragraph('JOSCANZUJ - Vulnerability Scan Report', heading)); story.append(Spacer(1, 6))
    meta_lines = [f'Target: {target}', f'Scan ID / Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', f'Total vulnerabilities: {len(vulnerabilities)}']
    for ln in meta_lines: story.append(Paragraph(ln, normal))
    story.append(Spacer(1, 8))
    severities = {}
    for v in vulnerabilities: sev = v.get('severity') or map_severity(v.get('type', '')); severities[sev] = severities.get(sev,0)+1
    story.append(Paragraph('Severity Summary:', h2)); data = [['Severity','Count']]
    for sev in ['High','Medium','Low','Unknown']:
        if sev in severities: data.append([sev,str(severities[sev])])
    if len(data) == 1: data.append(['-','0'])
    t = Table(data, colWidths=[60*mm,30*mm]); t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#f2f2f2')),('GRID',(0,0),(-1,-1),0.5,colors.grey),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
    story.append(t); story.append(Spacer(1,12))
    story.append(Paragraph('Vulnerability Details:', h2)); story.append(Spacer(1,6))
    rows = prepare_vuln_rows(vulnerabilities)
    if not rows:
        story.append(Paragraph('No vulnerabilities were detected during the scan.', normal))
    else:
        for i, r in enumerate(rows,1):
            story.append(Paragraph(f"{i}. {r['type']} ({r['severity']})", heading4))
            story.append(Paragraph(f"Endpoint: {r['endpoint']}", normal))
            story.append(Paragraph(f"Method: {r['method']}", normal))
            if r['payload']: story.append(Paragraph(f"Payload: {r['payload']}", normal))
            if r['snippet']:
                story.append(Paragraph('<b>Evidence snippet:</b>', normal))
                story.append(Paragraph(r['snippet'].replace('<','&lt;').replace('>','&gt;'), normal))
            story.append(Spacer(1,6))
            img = make_image_flow_pdf(r['screenshot'])
            if img:
                story.append(img); story.append(Spacer(1,8))
            story.append(Spacer(1,8))
    story.append(PageBreak()); story.append(Paragraph('Ethical and Legal Disclaimer', heading)); story.append(Spacer(1,6))
    disclaimer_text = ("This tool has been developed strictly for educational and defensive purposes. It must be used only in environments where explicit authorization has been obtained from the system owner. Unauthorized use of this tool on public or private systems without consent is illegal and unethical. The author and contributors assume no liability for misuse of this program.")
    story.append(Paragraph(disclaimer_text, normal)); story.append(Spacer(1,12))
    story.append(Paragraph('Notes:', h2)); story.append(Paragraph(' - This report summarises automated findings. Manual validation is recommended before taking remediation actions.', normal)); story.append(Spacer(1,8))
    doc.build(story)
    logger.info(f"PDF saved: {output_file}")

def generate_pdf_report_from_results(results: dict, output_file: str):
    target = results.get('target','Unknown'); raw_vulns = results.get('vulnerabilities',[]) or []; processed=[]
    for v in raw_vulns:
        v_copy = dict(v); v_copy['severity'] = v_copy.get('severity') or map_severity(v_copy.get('type','')); processed.append(v_copy)
    generate_pdf_report(target, processed, output_file)

# ---------------- backup helper ----------------
def backup_file_if_exists(path: Path):
    try:
        if path.exists():
            ts = datetime.now().strftime("%Y%m%dT%H%M%S")
            new_name = f"{path.stem}_{ts}{path.suffix}"
            target = ARCHIVE_DIR / new_name
            path.rename(target)
            logger.info(f"Archived {path} -> {target}")
    except Exception as e:
        logger.debug(f"Archive error for {path}: {e}")

# ------------------- Main scanning flow -------------------
def normalize_target(url):
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme:
        return url
    return "https://" + url

def run_scan_for_target(target, endpoints=None, out_json=OUT_JSON_DEFAULT, no_screenshots=False,
                        scan_id_prefix=None, session=None, delay=DEFAULT_DELAY,
                        progress_callback=None, chromedriver_path=None, requests_only=False,
                        save_json=True, save_csv=True, save_pdf=True):
    """
    Core scanner routine. Returns (results_dict, json_path_or_None).
    """
    target = normalize_target(target)
    if not target:
        raise ValueError("Invalid target URL")
    endpoints = endpoints or ["/", "/#/search", "/#/product/1", "/rest/products/search"]
    host_tag = sanitize_filename(urlparse(target).netloc.replace(":", "_"))

    results = {"scan_id": (scan_id_prefix or "scan") + "-" + f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
               "target": target, "scanned_at": datetime.now(timezone.utc).isoformat(), "vulnerabilities": [], "notes": []}

    session = session or make_requests_session()
    driver = None
    total_tasks = sum(len(test.get("payloads", [])) for test in VULN_TESTS) * max(1, len(endpoints))
    current_task = 0

    try:
        for ep in endpoints:
            base_url = urljoin(target, ep)
            msg = f"Scanning endpoint: {ep}  -> {base_url}"
            logger.info(msg)
            if callable(progress_callback):
                progress_callback(current_task, total_tasks, msg)

            for test in VULN_TESTS:
                vuln_type = test["name"]
                param = test.get("param") or "q"
                for payload in test["payloads"]:
                    current_task += 1
                    if callable(progress_callback):
                        progress_callback(current_task, total_tasks, f"Testing {vuln_type} ({current_task}/{total_tasks}) on {ep}")

                    params = {param: payload}
                    if delay and delay > 0:
                        time.sleep(delay)

                    # requests check
                    req_res = get_requests(base_url, params=params, session=session)
                    if "error" in req_res:
                        results["notes"].append({"endpoint": ep, "method": "requests", "error": req_res.get("error")})
                        logger.debug(f"requests error: {req_res.get('error')}")
                    else:
                        snippet = snippet_of(req_res.get("text",""), payload)
                        if snippet:
                            vuln = {"type": vuln_type, "endpoint": ep, "params": params, "payload": payload, "method": "requests", "evidence": {"request_url": req_res.get("url"), "response_status": req_res.get("status"), "response_snippet": snippet, "screenshot": None}}
                            results["vulnerabilities"].append(vuln)
                            logger.warning(f"[+] requests => {vuln_type} at {ep}")
                            continue

                    if requests_only:
                        continue

                    # selenium fallback
                    if driver is None:
                        try:
                            driver = make_selenium_driver(headless=True, chromedriver_path=chromedriver_path)
                            logger.info("[*] Selenium started")
                        except Exception as e:
                            results["notes"].append({"endpoint": ep, "method": "selenium_init", "error": str(e)})
                            logger.debug(f"selenium init err: {e}")
                            continue

                    selenium_url = add_param_to_url(base_url, param, payload)
                    safe_endpoint = sanitize_filename(ep.strip("/") or "root")
                    filename = f"{host_tag}_{results['scan_id']}_{safe_endpoint}_{int(time.time())}.png"
                    screenshot_path = str(SCREENSHOT_DIR / filename)

                    sel_res = get_selenium(selenium_url, driver, screenshot_path=screenshot_path if not no_screenshots else None)
                    if "error" in sel_res:
                        results["notes"].append({"endpoint": ep, "method": "selenium", "error": sel_res.get("error")})
                        logger.debug(f"selenium err {sel_res.get('error')}")
                        continue
                    else:
                        page = sel_res.get("page_source","") or ""
                        alert_text = sel_res.get("alert_text")
                        if alert_text:
                            vuln = {"type": vuln_type if "xss" in vuln_type.lower() or "script" in (alert_text or "").lower() else f"{vuln_type} (alert)", "endpoint":ep, "params":params, "payload":payload, "method":"selenium", "evidence":{"request_url":selenium_url, "response_status":sel_res.get("status"), "response_snippet":f"ALERT: {alert_text}", "screenshot": screenshot_path if os.path.exists(screenshot_path) else None, "alert_text": alert_text}}
                            results["vulnerabilities"].append(vuln)
                            logger.warning(f"[+] selenium alert => {vuln_type} at {ep}")
                            continue

                        snippet = snippet_of(page, payload)
                        if snippet:
                            vuln = {"type": vuln_type, "endpoint":ep, "params":params, "payload":payload, "method":"selenium", "evidence":{"request_url":selenium_url, "response_status":sel_res.get("status"), "response_snippet":snippet, "screenshot": screenshot_path if os.path.exists(screenshot_path) else None}}
                            results["vulnerabilities"].append(vuln)
                            logger.warning(f"[+] selenium => {vuln_type} at {ep}")
                        else:
                            logger.debug(f"not found selenium {ep} payload")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    results["summary"] = {"total_vulns": len(results["vulnerabilities"])}

    # save outputs with archive backups
    host_tag = sanitize_filename(urlparse(target).netloc.replace(":", "_"))
    timestamp = int(time.time())
    json_name = REPORTS_DIR / f"{OUT_JSON_DEFAULT.replace('.json','')}_{host_tag}.json"
    csv_name = REPORTS_DIR / f"report_{host_tag}_{timestamp}.csv"
    pdf_name = REPORTS_DIR / f"report_{host_tag}.pdf"

    if save_json:
        try:
            backup_file_if_exists(json_name)
            with open(json_name, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Could not write JSON: {e}")

    if save_csv:
        try:
            backup_file_if_exists(csv_name)
            with open(csv_name, "w", newline='', encoding="utf-8") as cf:
                writer = csv.writer(cf)
                writer.writerow(["type","severity","endpoint","method","payload","snippet","screenshot"])
                for v in results.get("vulnerabilities", []):
                    sev = v.get("severity") or map_severity(v.get("type",""))
                    ev = v.get("evidence",{}) or {}
                    writer.writerow([v.get("type"), sev, v.get("endpoint"), v.get("method"), v.get("payload"), ev.get("response_snippet",""), ev.get("screenshot","")])
        except Exception as e:
            logger.error(f"Could not write CSV: {e}")

    if save_pdf:
        try:
            backup_file_if_exists(pdf_name)
            generate_pdf_report_from_results(results, str(pdf_name))
        except Exception as e:
            logger.debug(f"PDF gen failed: {e}")

    logger.info(f"Scan finished for {target} - JSON:{json_name if save_json else 'SKIPPED'} CSV:{csv_name if save_csv else 'SKIPPED'} PDF:{pdf_name if save_pdf else 'SKIPPED'}")
    return results, str(json_name) if save_json else None

def get_requests(full_url, params=None, session=None):
    sess = session or make_requests_session()
    try:
        r = sess.get(full_url, params=params, timeout=TIMEOUT)
        return {"status": r.status_code, "url": r.url, "text": r.text, "headers": dict(r.headers)}
    except requests.RequestException as e:
        logger.debug(f"requests error for {full_url} params={params}: {e}")
        return {"error": str(e), "exception_type": type(e).__name__}
    except Exception as e:
        logger.debug(f"unknown error for {full_url} params={params}: {e}")
        return {"error": str(e), "exception_type": type(e).__name__}

# ------------------- Ollama Helper Functions -------------------
def check_ollama_installed():
    """Check if Ollama is installed and running"""
    try:
        response = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        if response.status_code == 200:
            return True, "Ollama is running"
    except requests.ConnectionError:
        # Try to check if Ollama executable exists
        import platform
        system = platform.system()
        
        if system == "Windows":
            # Check in common installation paths
            paths = [
                os.path.expandvars("%LOCALAPPDATA%\\Programs\\Ollama\\ollama.exe"),
                os.path.expandvars("%ProgramFiles%\\Ollama\\ollama.exe"),
                "C:\\Program Files\\Ollama\\ollama.exe"
            ]
            for path in paths:
                if os.path.exists(path):
                    return False, "Ollama installed but not running"
        
        elif system == "Darwin":  # macOS
            if os.path.exists("/Applications/Ollama.app"):
                return False, "Ollama installed but not running"
            elif os.path.exists("/usr/local/bin/ollama"):
                return False, "Ollama installed but not running"
        
        elif system == "Linux":
            if os.path.exists("/usr/local/bin/ollama") or os.path.exists("/usr/bin/ollama"):
                return False, "Ollama installed but not running"
    
    return False, "Ollama not installed or not running"

def get_installed_ollama_models():
    """Get list of models installed in Ollama"""
    try:
        response = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
        if response.status_code == 200:
            data = response.json()
            models = [model['name'] for model in data.get('models', [])]
            return models
    except:
        pass
    return []

def install_ollama_model(model_name):
    """Install a model in Ollama"""
    try:
        # This is a simplified version - in practice, you'd run ollama pull in a subprocess
        response = requests.post(f"{OLLAMA_HOST}/api/pull", 
                                json={"name": model_name}, 
                                timeout=300)  # 5 minute timeout for large models
        return True, f"Model {model_name} installation started"
    except Exception as e:
        return False, f"Failed to install model: {str(e)}"

def start_ollama_service():
    """Try to start Ollama service"""
    import platform
    system = platform.system()
    
    try:
        if system == "Windows":
            subprocess.Popen(["ollama", "serve"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            return True, "Ollama service started"
        elif system in ["Darwin", "Linux"]:
            subprocess.Popen(["ollama", "serve"], start_new_session=True)
            return True, "Ollama service started"
    except Exception as e:
        return False, f"Failed to start Ollama: {str(e)}"
    
    return False, "Could not start Ollama service"

# ------------------- Chat Session Storage -------------------
class ChatStorage:
    """Manage chat session storage"""
    def __init__(self, storage_dir="chat_sessions"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
    
    def _generate_hash(self, target, scan_id):
        """Generate hash for session identification"""
        content = f"{target}_{scan_id}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def save_session(self, scan_hash, conversation):
        """Save conversation linked to specific scan"""
        try:
            filename = self.storage_dir / f"{scan_hash}.pkl"
            with open(filename, 'wb') as f:
                pickle.dump(conversation, f)
            return True
        except Exception as e:
            logger.error(f"Failed to save chat session: {e}")
            return False
    
    def load_session(self, scan_hash):
        """Load previous conversation"""
        try:
            filename = self.storage_dir / f"{scan_hash}.pkl"
            if filename.exists():
                with open(filename, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.error(f"Failed to load chat session: {e}")
        return []
    
    def delete_session(self, scan_hash):
        """Delete saved session"""
        try:
            filename = self.storage_dir / f"{scan_hash}.pkl"
            if filename.exists():
                filename.unlink()
                return True
        except Exception as e:
            logger.error(f"Failed to delete chat session: {e}")
        return False

# ------------------- AI Chat Assistant Class -------------------
class AIChatWindow(ctk.CTkToplevel):
    def __init__(self, parent, scan_results=None):
        super().__init__(parent)
        self.parent = parent
        self.title("🤖 JOSCANZUJ AI Assistant - Enhanced")
        self.geometry("1000x750")
        self.minsize(900, 650)
        
        # API Configuration
        self.api_provider = "ollama_local"
        self.api_key = ""
        self.temperature = 0.7
        self.max_tokens = 2000
        self.ollama_model = OLLAMA_DEFAULT_MODEL
        
        # Storage
        self.storage = ChatStorage()
        self.scan_hash = None
        self.attached_file_content = scan_results
        self.attached_file_path = None
        
        # Conversation
        self.conversation_history = []
        
        # Check Ollama status
        self.ollama_installed, self.ollama_status = check_ollama_installed()
        self.installed_models = get_installed_ollama_models() if self.ollama_installed else []
        
        self._build_ui()
        self._center_window()
        
        # Load existing session if scan results provided
        if scan_results:
            self._load_from_scan_results(scan_results)
    
    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def _load_from_scan_results(self, scan_results):
        """Load scan results and create session"""
        if scan_results:
            target = scan_results.get('target', 'Unknown')
            scan_id = scan_results.get('scan_id', 'Unknown')
            self.scan_hash = self.storage._generate_hash(target, scan_id)
            
            # Try to load existing session
            loaded = self.storage.load_session(self.scan_hash)
            if loaded:
                self.conversation_history = loaded
                self._restore_conversation()
                self._append_to_conversation(f"📂 Loaded existing session for scan: {scan_id}", "system")
            else:
                self._append_to_conversation(f"📋 New session for target: {target}", "system")
                
            # Attach the results
            self.attached_file_content = scan_results
            self._update_attachment_display()
    
    def _restore_conversation(self):
        """Restore conversation from history"""
        for entry in self.conversation_history:
            if entry['role'] == 'user':
                self._append_to_conversation(entry['content'], "user")
            elif entry['role'] == 'assistant':
                self._append_to_conversation(entry['content'], "ai")
    
    def _build_ui(self):
        # Main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=12, pady=12)
        
        # Top frame - Settings
        top_frame = ctk.CTkFrame(main_container)
        top_frame.pack(fill="x", padx=0, pady=(0, 12))
        
        # Provider selection
        provider_frame = ctk.CTkFrame(top_frame)
        provider_frame.pack(side="left", padx=(12, 6), pady=12)
        
        ctk.CTkLabel(provider_frame, text="Provider:").pack(side="left", padx=(0, 4))
        self.provider_var = ctk.StringVar(value="ollama_local")
        providers = ["ollama_local", "deepseek", "openai", "openrouter"]
        self.provider_menu = ctk.CTkOptionMenu(
            provider_frame, 
            values=providers, 
            variable=self.provider_var,
            command=self._on_provider_change,
            width=150
        )
        self.provider_menu.pack(side="left", padx=4)
        
        # Ollama model selection (only visible when Ollama is selected)
        self.model_frame = ctk.CTkFrame(top_frame)
        self.model_frame.pack(side="left", padx=6, pady=12)
        
        ctk.CTkLabel(self.model_frame, text="Model:").pack(side="left", padx=(0, 4))
        self.model_var = ctk.StringVar(value=self.ollama_model)
        
        # Get available models for dropdown
        model_options = self.installed_models if self.installed_models else [self.ollama_model]
        self.model_menu = ctk.CTkOptionMenu(
            self.model_frame,
            values=model_options,
            variable=self.model_var,
            command=self._on_model_change,
            width=120
        )
        self.model_menu.pack(side="left", padx=4)
        
        # Refresh models button
        ctk.CTkButton(
            self.model_frame,
            text="🔄",
            width=30,
            command=self._refresh_models
        ).pack(side="left", padx=4)
        
        # API Key frame (for non-Ollama providers)
        self.key_frame = ctk.CTkFrame(top_frame)
        self.key_frame.pack(side="left", padx=6, pady=12)
        
        ctk.CTkLabel(self.key_frame, text="API Key:").pack(side="left", padx=(0, 4))
        self.api_key_entry = ctk.CTkEntry(
            self.key_frame, 
            width=300, 
            placeholder_text="Enter API key for DeepSeek/OpenAI",
            show="•"
        )
        self.api_key_entry.pack(side="left", padx=4)
        
        # Ollama status indicator
        self.status_frame = ctk.CTkFrame(top_frame)
        self.status_frame.pack(side="right", padx=(6, 12), pady=12)
        
        status_color = "green" if self.ollama_installed else "red"
        status_text = "🟢 Running" if self.ollama_installed else "🔴 Not Running"
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text=f"Ollama: {status_text}",
            text_color=status_color
        )
        self.status_label.pack(side="left", padx=(0, 4))
        
        # Ollama setup button
        ctk.CTkButton(
            self.status_frame,
            text="Setup Ollama",
            width=100,
            command=self._show_ollama_setup
        ).pack(side="left", padx=4)
        
        # Update visibility based on provider
        self._update_provider_ui()
        
        # Attachments frame
        attach_frame = ctk.CTkFrame(main_container)
        attach_frame.pack(fill="x", padx=0, pady=(0, 12))
        
        attach_btn_frame = ctk.CTkFrame(attach_frame)
        attach_btn_frame.pack(side="left", padx=(12, 6), pady=6)
        
        ctk.CTkButton(
            attach_btn_frame, 
            text="📎 Attach Scan File", 
            command=self._attach_json_file,
            width=150
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            attach_btn_frame,
            text="📂 Load Recent Scan",
            command=self._load_recent_scan,
            width=150
        ).pack(side="left", padx=4)
        
        self.attach_label = ctk.CTkLabel(
            attach_frame, 
            text="No file attached", 
            text_color="gray",
            wraplength=400
        )
        self.attach_label.pack(side="left", padx=12, pady=6)
        
        # Auto-analysis buttons
        if self.attached_file_content:
            self._add_auto_analysis_buttons(main_container)
        
        # Conversation display
        conv_frame = ctk.CTkFrame(main_container)
        conv_frame.pack(fill="both", expand=True, padx=0, pady=(0, 12))
        
        self.conversation_text = scrolledtext.ScrolledText(
            conv_frame,
            wrap="word",
            font=("Segoe UI", 10),
            bg="#1e1e1e",
            fg="white",
            insertbackground="white"
        )
        self.conversation_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.conversation_text.config(state="disabled")
        
        # Text tags for formatting
        self.conversation_text.tag_config("user_tag", foreground="#4a9eff", font=("Segoe UI", 10, "bold"))
        self.conversation_text.tag_config("user_text", foreground="#ffffff")
        self.conversation_text.tag_config("ai_tag", foreground="#2d5aa0", font=("Segoe UI", 10, "bold"))
        self.conversation_text.tag_config("ai_text", foreground="#cccccc")
        self.conversation_text.tag_config("system_text", foreground="#aaaaaa", font=("Segoe UI", 9, "italic"))
        self.conversation_text.tag_config("warning", foreground="#ff6b6b", font=("Segoe UI", 9, "bold"))
        self.conversation_text.tag_config("success", foreground="#4CAF50", font=("Segoe UI", 9, "bold"))
        
        # Welcome message
        self._add_welcome_message()
        
        # Input frame
        input_frame = ctk.CTkFrame(main_container)
        input_frame.pack(fill="x", padx=0, pady=0)
        
        # Input text box
        self.user_input = ctk.CTkTextbox(input_frame, height=80)
        self.user_input.pack(side="left", fill="both", expand=True, padx=(12, 6), pady=12)
        self.user_input.insert("1.0", "Ask about vulnerabilities, risks, or remediation...")
        
        # Button frame
        btn_frame = ctk.CTkFrame(input_frame, width=140)
        btn_frame.pack(side="right", fill="y", padx=(0, 12), pady=12)
        
        ctk.CTkButton(
            btn_frame, 
            text="Send", 
            command=self._send_message,
            fg_color="#2d5aa0", 
            hover_color="#1e3d6d"
        ).pack(pady=4)
        
        ctk.CTkButton(
            btn_frame,
            text="Clear Chat",
            command=self._clear_chat,
            fg_color="#666666"
        ).pack(pady=4)
        
        ctk.CTkButton(
            btn_frame,
            text="Save Session",
            command=self._save_current_session,
            fg_color="#2e7d32"
        ).pack(pady=4)
        
        # Bind Ctrl+Enter to send
        self.user_input.bind("<Control-Return>", lambda e: self._send_message())
    
    def _update_provider_ui(self):
        """Update UI based on selected provider"""
        provider = self.provider_var.get()
        
        # Show/hide API key field
        if provider == "ollama_local":
            self.key_frame.pack_forget()
            self.model_frame.pack(side="left", padx=6, pady=12)
            self.status_frame.pack(side="right", padx=(6, 12), pady=12)
        else:
            self.key_frame.pack(side="left", padx=6, pady=12)
            self.model_frame.pack_forget()
            self.status_frame.pack_forget()
    
    def _on_provider_change(self, choice):
        self.api_provider = choice
        self._update_provider_ui()
        
        provider_info = {
            "ollama_local": "Using local Ollama (free, requires installation)",
            "deepseek": "Using DeepSeek API (free tier available)",
            "openai": "Using OpenAI GPT API (requires billing)",
            "openrouter": "Using OpenRouter API (multiple models)"
        }
        info = provider_info.get(choice, "Unknown provider")
        self._append_to_conversation(f"Switched to {choice}: {info}", "system")
        
        # If switching to Ollama, check status
        if choice == "ollama_local":
            self._check_ollama_status()
    
    def _on_model_change(self, model_name):
        self.ollama_model = model_name
        self._append_to_conversation(f"Switched to model: {model_name}", "system")
    
    def _refresh_models(self):
        """Refresh list of installed Ollama models"""
        self.installed_models = get_installed_ollama_models()
        if self.installed_models:
            self.model_menu.configure(values=self.installed_models)
            self._append_to_conversation(f"Refreshed models. Found: {', '.join(self.installed_models)}", "success")
        else:
            self._append_to_conversation("No Ollama models found. Please install a model first.", "warning")
    
    def _check_ollama_status(self):
        """Check and update Ollama status"""
        self.ollama_installed, self.ollama_status = check_ollama_installed()
        
        status_color = "green" if self.ollama_installed else "red"
        status_text = "🟢 Running" if self.ollama_installed else "🔴 Not Running"
        self.status_label.configure(
            text=f"Ollama: {status_text}",
            text_color=status_color
        )
        
        if not self.ollama_installed:
            self._append_to_conversation(
                "⚠️ Ollama is not running. Please start it or use a different provider.",
                "warning"
            )
    
    def _show_ollama_setup(self):
        """Show Ollama setup instructions"""
        setup_window = ctk.CTkToplevel(self)
        setup_window.title("Ollama Setup Guide")
        setup_window.geometry("700x500")
        
        # Create a scrolled text widget
        text_widget = scrolledtext.ScrolledText(
            setup_window,
            wrap="word",
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="white"
        )
        text_widget.pack(fill="both", expand=True, padx=12, pady=12)
        
        setup_guide = """
===========================================
OLLAMA SETUP GUIDE FOR JOSCANZUJ AI ASSISTANT
===========================================

📦 STEP 1: INSTALL OLLAMA
-------------------------
Download and install Ollama from: https://ollama.com/

Windows: Run the installer .exe file
macOS: Drag Ollama to Applications folder
Linux: Run: curl -fsSL https://ollama.com/install.sh | sh

🔧 STEP 2: START OLLAMA
----------------------
After installation:

Windows:
- Search for "Ollama" in Start Menu and run it
- Or run from command prompt: ollama serve

macOS:
- Open Applications folder → Double-click Ollama
- Or run in terminal: ollama serve

Linux:
- Run in terminal: ollama serve
- To run as service: sudo systemctl enable ollama

📥 STEP 3: DOWNLOAD A MODEL
--------------------------
Open a new terminal/command prompt and run:

For Llama 3.2 (3B parameters, recommended):
  ollama pull llama3.2

Other good options:
  ollama pull mistral        # 7B parameters
  ollama pull codellama      # Code-focused model
  ollama pull phi            # Small & fast (2.7B)
  ollama pull gemma:2b       # Google's lightweight model

✅ STEP 4: VERIFY INSTALLATION
-----------------------------
In terminal, run:
  ollama list

You should see your downloaded models.

🔄 STEP 5: RETURN TO JOSCANZUJ
------------------------------
1. Close this window
2. Click "Refresh" button next to Model dropdown
3. Select your downloaded model
4. Start chatting!

⚠️ TROUBLESHOOTING
-----------------
1. If Ollama won't start:
   - Windows: Check Task Manager for ollama.exe
   - macOS/Linux: Check if ollama process is running

2. If models won't download:
   - Check internet connection
   - Try a different model (llama3.2 is smallest)

3. Port conflict:
   - Ollama uses port 11434
   - Make sure nothing else is using this port

💡 TIPS
------
• llama3.2 is fastest for most vulnerability analysis tasks
• Models are stored in ~/.ollama/ (can be several GB)
• First model download may take 5-15 minutes depending on internet
        """
        
        text_widget.insert("1.0", setup_guide)
        text_widget.config(state="disabled")
        
        # Add buttons
        button_frame = ctk.CTkFrame(setup_window)
        button_frame.pack(fill="x", padx=12, pady=(0, 12))
        
        ctk.CTkButton(
            button_frame,
            text="Open Ollama Website",
            command=lambda: webbrowser.open("https://ollama.com/")
        ).pack(side="left", padx=6)
        
        ctk.CTkButton(
            button_frame,
            text="Test Ollama Connection",
            command=lambda: self._test_ollama_connection(setup_window)
        ).pack(side="left", padx=6)
        
        ctk.CTkButton(
            button_frame,
            text="Close",
            command=setup_window.destroy
        ).pack(side="right", padx=6)
    
    def _test_ollama_connection(self, parent_window):
        """Test Ollama connection"""
        self.ollama_installed, status = check_ollama_installed()
        
        if self.ollama_installed:
            models = get_installed_ollama_models()
            if models:
                messagebox.showinfo("Ollama Test", 
                    f"✅ Connection successful!\n\nInstalled models:\n" + "\n".join(models))
                self._refresh_models()
            else:
                messagebox.showwarning("Ollama Test", 
                    "✅ Ollama is running but no models installed.\n\nPlease download a model:\nollama pull llama3.2")
        else:
            messagebox.showerror("Ollama Test", 
                f"❌ Connection failed.\n\nStatus: {status}\n\nPlease ensure Ollama is installed and running.")
    
    def _add_auto_analysis_buttons(self, parent_frame):
        """Add quick analysis buttons"""
        analysis_frame = ctk.CTkFrame(parent_frame)
        analysis_frame.pack(fill="x", padx=0, pady=(0, 12))
        
        ctk.CTkLabel(
            analysis_frame, 
            text="Quick Analysis:", 
            font=("Segoe UI", 12, "bold")
        ).pack(side="left", padx=(12, 8), pady=8)
        
        questions = [
            ("🔍 Summary", "Provide a brief summary of the scan results"),
            ("⚠️ Top Risks", "What are the highest risk vulnerabilities?"),
            ("🛡️ Fixes", "Suggest fixes for each vulnerability type"),
            ("📊 Risk Score", "Rate overall risk 1-10 with justification"),
            ("🔧 Next Steps", "What should be done next?")
        ]
        
        for btn_text, question in questions:
            btn = ctk.CTkButton(
                analysis_frame,
                text=btn_text,
                width=120,
                command=lambda q=question: self._ask_predefined_question(q)
            )
            btn.pack(side="left", padx=4, pady=8)
    
    def _add_welcome_message(self):
        welcome_msg = """🤖 JOSCANZUJ AI Assistant - Enhanced
============================================
I specialize in cybersecurity vulnerability analysis.

I can help you:
• Analyze scan results and identify risks
• Explain vulnerability types and impacts
• Suggest remediation strategies
• Prioritize fixes based on severity
• Provide security best practices

🔧 RECOMMENDED SETUP:
1. Install Ollama from https://ollama.com/
2. Download a model: `ollama pull llama3.2`
3. Select "ollama_local" as provider
4. Start chatting - completely FREE and local!

============================================

"""
        self._append_to_conversation(welcome_msg, "system")
        
        # Add Ollama status
        if not self.ollama_installed:
            self._append_to_conversation(
                "⚠️ Ollama is not running. For free local AI, please install Ollama first.",
                "warning"
            )
    
    def _append_to_conversation(self, text, sender="user"):
        self.conversation_text.config(state="normal")
        
        if sender == "user":
            self.conversation_text.insert("end", "👤 You:\n", "user_tag")
            self.conversation_text.insert("end", f"{text}\n\n", "user_text")
            # Add to history
            self.conversation_history.append({"role": "user", "content": text})
            
        elif sender == "ai":
            self.conversation_text.insert("end", "🤖 AI:\n", "ai_tag")
            self.conversation_text.insert("end", f"{text}\n\n", "ai_text")
            # Add to history
            self.conversation_history.append({"role": "assistant", "content": text})
            
        elif sender == "system":
            self.conversation_text.insert("end", f"📢 {text}\n\n", "system_text")
        elif sender == "warning":
            self.conversation_text.insert("end", f"⚠️ {text}\n\n", "warning")
        elif sender == "success":
            self.conversation_text.insert("end", f"✅ {text}\n\n", "success")
        
        self.conversation_text.config(state="disabled")
        self.conversation_text.see("end")
    
    def _attach_json_file(self):
        file_path = fd.askopenfilename(
            title="Select Scan Results JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.attached_file_content = json.load(f)
                self.attached_file_path = file_path
                self._update_attachment_display()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")
    
    def _load_recent_scan(self):
        """Load most recent scan from reports directory"""
        json_files = list(REPORTS_DIR.glob("*.json"))
        if not json_files:
            self._append_to_conversation("No scan results found in reports directory", "system")
            return
        
        # Get most recent file
        latest_file = max(json_files, key=lambda f: f.stat().st_mtime)
        
        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                self.attached_file_content = json.load(f)
            self.attached_file_path = str(latest_file)
            self._update_attachment_display()
            
            # Create/load session
            target = self.attached_file_content.get('target', 'Unknown')
            scan_id = self.attached_file_content.get('scan_id', 'Unknown')
            self.scan_hash = self.storage._generate_hash(target, scan_id)
            
            self._append_to_conversation(f"Loaded latest scan: {latest_file.name}", "success")
            
        except Exception as e:
            self._append_to_conversation(f"Error loading scan: {str(e)}", "warning")
    
    def _update_attachment_display(self):
        """Update attachment display label"""
        if self.attached_file_content:
            target = self.attached_file_content.get('target', 'Unknown')
            vuln_count = self.attached_file_content.get('summary', {}).get('total_vulns', 0)
            
            filename = os.path.basename(self.attached_file_path) if self.attached_file_path else "Scan Results"
            self.attach_label.configure(
                text=f"📁 {filename}\nTarget: {target} | Vulns: {vuln_count}",
                text_color="lightgreen"
            )
            
            # Add auto-analysis buttons if not already present
            if not hasattr(self, 'analysis_added') or not self.analysis_added:
                self._add_auto_analysis_buttons(self)
                self.analysis_added = True
        else:
            self.attach_label.configure(text="No file attached", text_color="gray")
    
    def _ask_predefined_question(self, question):
        """Ask a predefined question"""
        self.user_input.delete("1.0", "end")
        self.user_input.insert("1.0", question)
        self._send_message()
    
    def _clear_chat(self):
        """Clear chat but keep attachment"""
        self.conversation_text.config(state="normal")
        self.conversation_text.delete(1.0, "end")
        self.conversation_text.config(state="disabled")
        self.conversation_history = []
        self._add_welcome_message()
        
        if self.scan_hash:
            self.storage.delete_session(self.scan_hash)
            self.scan_hash = None
    
    def _save_current_session(self):
        """Save current conversation session"""
        if self.scan_hash and self.conversation_history:
            success = self.storage.save_session(self.scan_hash, self.conversation_history)
            if success:
                self._append_to_conversation("💾 Chat session saved successfully", "success")
            else:
                self._append_to_conversation("❌ Failed to save session", "warning")
        else:
            self._append_to_conversation("No active scan session to save", "warning")
    
    def _send_message(self):
        user_text = self.user_input.get(1.0, "end-1c").strip()
        if not user_text or user_text == "Ask about vulnerabilities, risks, or remediation...":
            return
        
        # Check provider-specific requirements
        provider = self.provider_var.get()
        
        if provider in ["deepseek", "openai", "openrouter"]:
            self.api_key = self.api_key_entry.get().strip()
            if not self.api_key:
                self._append_to_conversation(
                    f"❌ API key required for {provider}. Please enter your API key above.",
                    "warning"
                )
                return
        
        elif provider == "ollama_local":
            # Check if Ollama is running
            self._check_ollama_status()
            if not self.ollama_installed:
                self._append_to_conversation(
                    "❌ Ollama is not running. Please start Ollama or use a different provider.",
                    "warning"
                )
                return
            
            # Check if model is installed
            if not self.installed_models:
                self._append_to_conversation(
                    "❌ No Ollama models found. Please install a model first (e.g., ollama pull llama3.2).",
                    "warning"
                )
                return
        
        # Add user message
        self._append_to_conversation(user_text, "user")
        self.user_input.delete(1.0, "end")
        
        # Start response thread
        threading.Thread(
            target=self._get_ai_response,
            args=(user_text,),
            daemon=True
        ).start()
    
    def _get_ai_response(self, user_question):
        try:
            # Prepare context
            context = self._prepare_context(user_question)
            
            # Build messages
            messages = self._build_messages(context, user_question)
            
            # Call API based on provider
            response_text = self._call_ai_api(messages)
            
            # Add response to conversation
            self.after(0, lambda: self._append_to_conversation(response_text, "ai"))
            
        except Exception as e:
            error_msg = f"""❌ Error getting AI response: {str(e)}

Troubleshooting tips:
1. Check your API key is valid (for cloud providers)
2. Verify internet connection (for cloud providers)
3. For Ollama: ensure it's running locally (http://localhost:11434)
4. Try a different provider or model"""
            self.after(0, lambda: self._append_to_conversation(error_msg, "warning"))
            logger.error(f"AI API error: {e}")
    
    def _prepare_context(self, user_question):
        """Prepare scan results context with better formatting"""
        context = ""
        
        if self.attached_file_content:
            target = self.attached_file_content.get('target', 'Unknown')
            scan_time = self.attached_file_content.get('scanned_at', 'Unknown')
            vuln_count = self.attached_file_content.get('summary', {}).get('total_vulns', 0)
            
            context += "📋 SCAN RESULTS OVERVIEW\n"
            context += f"• Target URL: {target}\n"
            context += f"• Scan Time: {scan_time}\n"
            context += f"• Total Vulnerabilities Found: {vuln_count}\n\n"
            
            if vuln_count > 0 and 'vulnerabilities' in self.attached_file_content:
                vulns = self.attached_file_content['vulnerabilities']
                
                # Group by severity
                severity_groups = {'High': [], 'Medium': [], 'Low': [], 'Unknown': []}
                for v in vulns:
                    sev = map_severity(v.get('type', ''))
                    severity_groups[sev].append(v)
                
                context += "📊 VULNERABILITY DISTRIBUTION BY SEVERITY\n"
                for sev in ['High', 'Medium', 'Low', 'Unknown']:
                    count = len(severity_groups[sev])
                    if count > 0:
                        context += f"• {sev}: {count} vulnerability(s)\n"
                
                context += "\n🔍 DETAILED FINDINGS (Top 10)\n"
                for i, v in enumerate(vulns[:10], 1):
                    v_type = v.get('type', 'Unknown')
                    endpoint = v.get('endpoint', 'N/A')
                    severity = map_severity(v_type)
                    method = v.get('method', 'N/A')
                    payload = v.get('payload', '')
                    
                    context += f"\n{i}. [{severity}] {v_type}\n"
                    context += f"   Endpoint: {endpoint}\n"
                    context += f"   Method: {method}\n"
                    if payload:
                        context += f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}\n"
                
                if vuln_count > 10:
                    context += f"\n... and {vuln_count - 10} more vulnerabilities\n"
            
            context += "\n📝 SCAN NOTES\n"
            for note in self.attached_file_content.get('notes', [])[:3]:
                context += f"• {note.get('method', 'Unknown')}: {note.get('error', 'No error details')}\n"
        
        return context
    
    def _build_messages(self, context, user_question):
        """Build messages for AI API"""
        
        system_prompt = """You are JOSCANZUJ AI Assistant, a cybersecurity expert specialized in web application security.
Your role is to help analyze vulnerability scan results and provide actionable insights.

Guidelines:
1. Be precise, technical, and professional
2. Focus on practical remediation advice
3. Prioritize vulnerabilities by risk level
4. Explain concepts clearly but technically
5. Reference specific findings when scan data is provided
6. Suggest concrete next steps
7. Consider OWASP best practices
8. Highlight critical risks first

Format responses with clear sections and use bullet points for readability."""
        
        messages = [{"role": "system", "content": system_prompt}]
        
        if context:
            messages.append({
                "role": "user",
                "content": f"""ANALYSIS REQUEST

SCAN DATA:
{context}

USER QUESTION: {user_question}

Please analyze the scan results and answer the question above."""
            })
        else:
            messages.append({
                "role": "user",
                "content": user_question
            })
        
        return messages
    
    def _call_ai_api(self, messages):
        """Call appropriate API based on provider"""
        
        provider = self.provider_var.get()
        
        if provider == "deepseek":
            return self._call_deepseek_api(messages)
        elif provider == "openai":
            return self._call_openai_api(messages)
        elif provider == "ollama_local":
            return self._call_ollama_api(messages)
        elif provider == "openrouter":
            return self._call_openrouter_api(messages)
        else:
            return f"Unknown provider: {provider}"
    
    def _call_deepseek_api(self, messages):
        """Call DeepSeek API"""
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": "deepseek-chat",
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            
            if response.status_code == 402:
                return """❌ Payment Required (Error 402)

Your DeepSeek API balance may be exhausted.

Options:
1. Add funds to your DeepSeek account
2. Use Ollama (FREE & local) - recommended
3. Try a different provider

To use Ollama:
1. Install from https://ollama.com/
2. Run: ollama pull llama3.2
3. Select "ollama_local" as provider"""
            
            data = response.json()
            return data['choices'][0]['message']['content']
            
        except requests.exceptions.RequestException as e:
            return f"API Error: {str(e)}"
    
    def _call_openai_api(self, messages):
        """Call OpenAI API"""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data['choices'][0]['message']['content']
        except requests.exceptions.RequestException as e:
            return f"OpenAI API Error: {str(e)}"
    
    def _call_ollama_api(self, messages):
        """Call local Ollama API"""
        url = f"{OLLAMA_HOST}/api/chat"
        
        # Convert to Ollama format
        ollama_messages = []
        for msg in messages:
            if msg['role'] == 'system':
                # Ollama doesn't have system role, prepend to first user message
                if ollama_messages and ollama_messages[-1]['role'] == 'user':
                    ollama_messages[-1]['content'] = msg['content'] + "\n\n" + ollama_messages[-1]['content']
            else:
                ollama_messages.append(msg)
        
        payload = {
            "model": self.ollama_model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens
            }
        }
        
        try:
            response = requests.post(url, json=payload, timeout=120)
            
            if response.status_code == 404:
                # Model not found, suggest pulling it
                return f"""❌ Model '{self.ollama_model}' not found.

Please install this model first:

1. Open terminal/command prompt
2. Run: ollama pull {self.ollama_model}
3. Wait for download to complete
4. Try again

Or select a different model from the dropdown."""
            
            response.raise_for_status()
            data = response.json()
            return data['message']['content']
            
        except requests.exceptions.ConnectionError:
            return """❌ Cannot connect to Ollama.

Please ensure:
1. Ollama is installed (https://ollama.com/)
2. Ollama is running (check system tray/task manager)
3. Pull a model first: `ollama pull llama3.2`
4. Try again or use a different provider

Click "Setup Ollama" button for detailed instructions."""
        except Exception as e:
            return f"Ollama Error: {str(e)}"
    
    def _call_openrouter_api(self, messages):
        """Call OpenRouter API"""
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://joscanzuj.local",
            "X-Title": "JOSCANZUJ Scanner"
        }
        
        payload = {
            "model": "openai/gpt-3.5-turbo",  # Default model
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data['choices'][0]['message']['content']
        except Exception as e:
            return f"OpenRouter Error: {str(e)}"

# ------------------- GUI -------------------
APP_WIDTH = 980
APP_HEIGHT = 700

class GUIApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("JOSCANZUJ - GUI (Full with AI Assistant)")
        self.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.minsize(900, 640)
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.latest_pdf = None
        self.latest_scan_results = None
        self._build_ui()
        self._start_poller()

    def _build_ui(self):
        header = ctk.CTkFrame(self); header.pack(fill="x", padx=12, pady=(12,6))
        ctk.CTkLabel(header, text="🛡️ JOSCANZUJ - Web Vulnerability Scanner with AI Assistant", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=6)

        opts = ctk.CTkFrame(self); opts.pack(fill="x", padx=12, pady=6)
        left = ctk.CTkFrame(opts); left.pack(side="left", fill="both", expand=True, padx=(6,12), pady=6)
        self.target_entry = ctk.CTkEntry(left, placeholder_text="Target URL (e.g. https://example.com)", width=620); self.target_entry.pack(padx=8, pady=(8,6))
        endpoints_frame = ctk.CTkFrame(left); endpoints_frame.pack(fill="x", padx=8, pady=(0,6))
        self.endpoints_entry = ctk.CTkEntry(endpoints_frame, placeholder_text="Endpoints (comma/semicolon sep) - optional", width=460); self.endpoints_entry.pack(side="left", padx=(6,4), pady=6)
        ctk.CTkButton(endpoints_frame, text="Load", width=110, command=self._load_endpoints).pack(side="left", padx=4)

        opts_row = ctk.CTkFrame(left); opts_row.pack(fill="x", padx=8, pady=(0,6))
        self.requests_only_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts_row, text="Requests-only (no Selenium)", variable=self.requests_only_var).pack(side="left", padx=8, pady=6)
        self.no_screenshots_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts_row, text="No screenshots", variable=self.no_screenshots_var).pack(side="left", padx=8, pady=6)

        ctk.CTkLabel(opts_row, text="Delay (s)").pack(side="left", padx=(12,4))
        self.delay_entry = ctk.CTkEntry(opts_row, width=80); self.delay_entry.insert(0,"0.5"); self.delay_entry.pack(side="left", padx=4)
        ctk.CTkLabel(opts_row, text="User-Agent").pack(side="left", padx=(12,4))
        self.ua_entry = ctk.CTkEntry(opts_row, width=260); self.ua_entry.pack(side="left", padx=4)

        export_row = ctk.CTkFrame(left); export_row.pack(fill="x", padx=8, pady=(0,6))
        ctk.CTkLabel(export_row, text="Save:").pack(side="left", padx=(6,4))
        self.save_json_var = ctk.BooleanVar(value=True)
        self.save_csv_var = ctk.BooleanVar(value=True)
        self.save_pdf_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(export_row, text="JSON", variable=self.save_json_var).pack(side="left", padx=6)
        ctk.CTkCheckBox(export_row, text="CSV", variable=self.save_csv_var).pack(side="left", padx=6)
        ctk.CTkCheckBox(export_row, text="PDF", variable=self.save_pdf_var).pack(side="left", padx=6)

        chromef = ctk.CTkFrame(left); chromef.pack(fill="x", padx=8, pady=(0,4))
        self.chromedriver_entry = ctk.CTkEntry(chromef, placeholder_text="Optional chromedriver path", width=560); self.chromedriver_entry.pack(side="left", padx=(6,4), pady=6)
        ctk.CTkButton(chromef, text="Browse", width=120, command=self._pick_chromedriver).pack(side="left", padx=6, pady=6)

        actions = ctk.CTkFrame(left); actions.pack(fill="x", padx=8, pady=(4,8))
        self.start_btn = ctk.CTkButton(actions, text="Start Scan", width=150, command=self.start_scan); self.start_btn.pack(side="left", padx=(6,8))
        self.stop_btn = ctk.CTkButton(actions, text="Stop", width=120, fg_color="#b22222", hover_color="#a11a1a", command=self.stop_scan, state="disabled"); self.stop_btn.pack(side="left", padx=(0,8))
        ctk.CTkButton(actions, text="Open reports folder", width=160, command=self._open_reports).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="Open last PDF", width=140, command=self._open_last_pdf).pack(side="left", padx=6)
        
        # Enhanced AI Assistant button
        ctk.CTkButton(actions, text="🤖 AI Assistant", width=140, 
                     command=self.open_ai_chat, fg_color="#2d5aa0", hover_color="#1e3d6d").pack(side="left", padx=6)
        
        # Load last scan for AI button
        ctk.CTkButton(actions, text="📂 AI Analyze Last", width=140,
                     command=self.open_ai_with_last_scan, fg_color="#2e7d32", hover_color="#1b5e20").pack(side="left", padx=6)

        right = ctk.CTkFrame(opts, width=320); right.pack(side="left", fill="y", padx=4, pady=6)
        ctk.CTkLabel(right, text="Progress", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(8,4))
        self.progress = ctk.CTkProgressBar(right, width=260); self.progress.set(0); self.progress.pack(padx=8, pady=6)
        self.status_label = ctk.CTkLabel(right, text="Ready.", wraplength=260); self.status_label.pack(padx=8, pady=6)
        ctk.CTkLabel(right, text="Summary:", font=ctk.CTkFont(size=12)).pack(pady=(10,2))
        self.summary_label = ctk.CTkLabel(right, text="—", wraplength=260, justify="left"); self.summary_label.pack(padx=8, pady=4)

        logs = ctk.CTkFrame(self); logs.pack(fill="both", expand=True, padx=12, pady=(4,12))
        ctk.CTkLabel(logs, text="Scan Log:").pack(anchor="w", padx=8, pady=(8,0))
        self.logbox = ctk.CTkTextbox(logs, width=940, height=360)
        self.logbox.pack(padx=8, pady=8, fill="both", expand=True)
        # initial content
        self.logbox.configure(state="normal")
        self.logbox.insert("end", "Logs will appear here...\n")
        self.logbox.configure(state="disabled")
        # access underlying tkinter Text for tagging
        try:
            self._tk_log_text = self.logbox.textbox
            self._tk_log_text.tag_config("vuln", foreground="red")
            self._tk_log_text.tag_config("success", foreground="green")
            self._tk_log_text.tag_config("note", foreground="orange")
        except Exception:
            self._tk_log_text = None

    # UI helpers
    def _load_endpoints(self):
        fp = fd.askopenfilename(title="Select endpoints file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if fp:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                self.endpoints_entry.delete(0, "end"); self.endpoints_entry.insert(0, ",".join(lines))
                self._enqueue_log(f"[+] loaded {len(lines)} endpoints from {fp}", level="success")
            except Exception as e:
                self._enqueue_log(f"[!] failed to load endpoints file: {e}", level="note")

    def _pick_chromedriver(self):
        fp = fd.askopenfilename(title="Select chromedriver", filetypes=[("Executables","*chromedriver*;*.exe;*"),("All files","*.*")])
        if fp:
            self.chromedriver_entry.delete(0, "end"); self.chromedriver_entry.insert(0, fp); self._enqueue_log(f"[+] chromedriver set: {fp}", level="success")

    def _open_reports(self):
        path = REPORTS_DIR.resolve(); path.mkdir(exist_ok=True); webbrowser.open(path.as_uri())

    def _open_last_pdf(self):
        if self.latest_pdf and Path(self.latest_pdf).exists():
            webbrowser.open(Path(self.latest_pdf).absolute().as_uri())
        else:
            self._enqueue_log("[!] No PDF available yet.", level="note")

    # AI Assistant functions
    def open_ai_chat(self):
        """Open AI Assistant window"""
        try:
            if not hasattr(self, 'ai_window') or not self.ai_window or not self.ai_window.winfo_exists():
                self.ai_window = AIChatWindow(self, self.latest_scan_results)
                self.ai_window.focus()
            else:
                self.ai_window.focus()
                self.ai_window.lift()
        except Exception as e:
            logger.error(f"Error opening AI window: {e}")
            self._enqueue_log(f"[!] Failed to open AI Assistant: {e}", level="note")

    def open_ai_with_last_scan(self):
        """Open AI Assistant with last scan results"""
        if not self.latest_scan_results:
            # Try to load the most recent scan
            json_files = list(REPORTS_DIR.glob("*.json"))
            if json_files:
                latest_file = max(json_files, key=lambda f: f.stat().st_mtime)
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        self.latest_scan_results = json.load(f)
                    self._enqueue_log(f"[+] Loaded latest scan: {latest_file.name}", level="success")
                except Exception as e:
                    self._enqueue_log(f"[!] Failed to load scan: {e}", level="note")
                    return
            else:
                self._enqueue_log("[!] No scan results found. Run a scan first.", level="note")
                return
        
        self.open_ai_chat()

    # queue helpers
    def _enqueue_log(self, text, level="info"):
        """
        Put a log message into the GUI queue.
        level: 'info' / 'success' / 'note' / 'vuln'
        """
        self.log_queue.put(("log", text, level))

    def _set_status(self, text): self.log_queue.put(("status", text))
    def _set_progress(self, fraction): self.log_queue.put(("progress", fraction))
    def _set_summary(self, text): self.log_queue.put(("summary", text))

    # control
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            self._enqueue_log("[!] Enter a target URL first.", level="note")
            return

        # CLEAR previous UI results (only UI)
        self.logbox.configure(state="normal"); self.logbox.delete("1.0", "end")
        self.logbox.insert("end", "Logs will appear here...\n"); self.logbox.configure(state="disabled")
        self.progress.set(0); self.status_label.configure(text="Ready."); self.summary_label.configure(text="—"); self.latest_pdf = None

        endpoints_raw = self.endpoints_entry.get().strip() or None
        endpoints = None
        if endpoints_raw:
            sep = ";" if ";" in endpoints_raw else ","
            endpoints = [p.strip() for p in endpoints_raw.split(sep) if p.strip()]
        no_screens = bool(self.no_screenshots_var.get())
        requests_only = bool(self.requests_only_var.get())
        save_json = bool(self.save_json_var.get()); save_csv = bool(self.save_csv_var.get()); save_pdf = bool(self.save_pdf_var.get())
        try:
            delay = float(self.delay_entry.get())
        except Exception:
            delay = DEFAULT_DELAY
        chromedriver_path = self.chromedriver_entry.get().strip() or None
        user_agent = self.ua_entry.get().strip() or None

        self.start_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self.progress.set(0); self.status_label.configure(text="Starting scan..."); self._enqueue_log(f"[+] Launching scan for: {target}", level="success")
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_scan, kwargs={"target": target, "endpoints": endpoints, "no_screenshots": no_screens, "delay": delay, "chromedriver_path": chromedriver_path, "user_agent": user_agent, "requests_only": requests_only, "save_json": save_json, "save_csv": save_csv, "save_pdf": save_pdf}, daemon=True)
        self.worker_thread.start()

    def stop_scan(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self._enqueue_log("[!] Stop requested — attempting to abort...", level="note")
            self.stop_event.set()
        else:
            self._enqueue_log("[!] No running scan.", level="note")

    def _worker_scan(self, target, endpoints, no_screenshots, delay, chromedriver_path, user_agent, requests_only, save_json, save_csv, save_pdf):
        try:
            session = make_requests_session(user_agent=user_agent) if make_requests_session else None
            def progress_callback(current, total, message):
                if total and total > 0:
                    frac = min(1.0, max(0.0, float(current) / float(total)))
                    self._set_progress(frac)
                # decide color by message content
                level = "info"
                if message.startswith("[+]") or "Launching" in message:
                    level = "success"
                if "Testing" in message:
                    level = "info"
                self._enqueue_log(message, level=level)
                self._set_status(message)
                if self.stop_event.is_set():
                    raise RuntimeError("Scan aborted by user")
            results, saved_json = run_scan_for_target(target, endpoints=endpoints, out_json=OUT_JSON_DEFAULT, no_screenshots=no_screenshots, scan_id_prefix="gui_scan", session=session, delay=delay, progress_callback=progress_callback, chromedriver_path=chromedriver_path, requests_only=requests_only, save_json=save_json, save_csv=save_csv, save_pdf=save_pdf)
            
            # Store results for AI Assistant
            self.latest_scan_results = results
            
            host_tag = sanitize_filename(urlparse(target).netloc.replace(":", "_"))
            pdf_path = REPORTS_DIR / f"report_{host_tag}.pdf"
            if pdf_path.exists():
                self.latest_pdf = str(pdf_path)
                self._enqueue_log(f"[+] PDF: {pdf_path}", level="success")
            total_vulns = results.get("summary", {}).get("total_vulns", 0)
            # print vulnerabilities specially (red)
            if total_vulns > 0:
                for v in results.get("vulnerabilities", []):
                    vmsg = f"[!] VULN: {v.get('type')} at {v.get('endpoint')} via {v.get('method')} payload={v.get('payload')}"
                    self._enqueue_log(vmsg, level="vuln")
            self._enqueue_log(f"[+] Scan completed. Total vulnerabilities: {total_vulns}", level="success")
            self._set_summary(f"Vulns: {total_vulns}")
            self._set_status("Scan finished.")
            self._set_progress(1.0)
            
            # Suggest AI analysis
            if total_vulns > 0:
                self._enqueue_log("[💡] Click '🤖 AI Assistant' to analyze these findings", level="success")
            
        except RuntimeError as re:
            self._enqueue_log(f"[!] Scan stopped: {re}", level="note"); self._set_status("Scan stopped by user.")
        except Exception as e:
            self._enqueue_log(f"[!] Scan error: {e}", level="note"); self._set_status("Error during scan."); logger.debug(traceback.format_exc())
        finally:
            self.start_btn.configure(state="normal"); self.stop_btn.configure(state="disabled")

    # poll queue
    def _start_poller(self): self.after(200, self._poll_queue)
    def _poll_queue(self):
        try:
            while not self.log_queue.empty():
                item = self.log_queue.get_nowait()
                if not item:
                    continue
                typ = item[0]
                if typ == "log":
                    _, text, level = item
                    self._append_log_colored(text, level=level)
                elif typ == "status":
                    _, text = item
                    self.status_label.configure(text=text)
                elif typ == "progress":
                    _, val = item
                    try: self.progress.set(float(val))
                    except: pass
                elif typ == "summary":
                    _, text = item
                    self.summary_label.configure(text=text)
        except queue.Empty:
            pass
        finally:
            self.after(200, self._poll_queue)

    def _append_log_colored(self, text, level="info"):
        """
        Add a line to the logbox and color it based on level. Also highlight vulnerability keywords within the whole log.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {text}\n"
        # append
        self.logbox.configure(state="normal")
        # insert and get index
        if self._tk_log_text:
            idx = self._tk_log_text.index("end-1c")
            self._tk_log_text.insert("end", line)
            end_idx = self._tk_log_text.index("end-1c")
            tag = None
            if level == "vuln":
                tag = "vuln"
            elif level == "success":
                tag = "success"
            elif level == "note":
                tag = "note"
            # apply tag to the newly inserted line
            if tag:
                try:
                    self._tk_log_text.tag_add(tag, idx, end_idx)
                except Exception:
                    pass
            # highlight known vulnerability keywords anywhere in the text
            vuln_keywords = ["XSS","SQL Injection","LFI","Command Injection","Directory Traversal","Open Redirect","VULN"]
            for keyword in vuln_keywords:
                start_idx = "1.0"
                while True:
                    pos = self._tk_log_text.search(keyword, start_idx, "end")
                    if not pos:
                        break
                    endpos = f"{pos}+{len(keyword)}c"
                    try:
                        self._tk_log_text.tag_add("vuln", pos, endpos)
                    except Exception:
                        pass
                    start_idx = endpos
        else:
            # fallback without tags
            self.logbox.insert("end", line)
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

# ------------------- run -------------------
if __name__ == "__main__":
    app = GUIApp()
    app.mainloop()