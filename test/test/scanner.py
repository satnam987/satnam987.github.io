# scanner.py

import requests
import hashlib
import os
import time
import logging


logging.basicConfig(filename='scanner.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')


API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '8ff438386c110160890004a447c0fd6e0135b7e505858f4ed9916ca713104346')


if not API_KEY:
    logging.error("VIRUSTOTAL_API_KEY environment variable is not set.")
    raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set.")

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        logging.info(f"SHA-256 hash berekend voor bestand: {file_path}")
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        logging.error(f"Bestand niet gevonden: {file_path}")
        return None

def get_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        logging.info(f"Rapport opgehaald voor hash: {file_hash}")
        return response.json()
    elif response.status_code == 401:
        logging.error("401 Unauthorized: Controleer je API-sleutel.")
        return None
    elif response.status_code == 404:
        logging.info(f"Geen rapport gevonden voor hash: {file_hash}")
        return None
    else:
        logging.error(f"Fout bij het ophalen van rapport: {response.status_code}")
        return None

def upload_and_scan(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": API_KEY
    }
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files)
        if response.status_code in [200, 202]:
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            logging.info(f"Bestand geüpload voor analyse. Analyse ID: {analysis_id}")
            return analysis_id
        elif response.status_code == 401:
            logging.error("401 Unauthorized: Controleer je API-sleutel.")
            return None
        else:
            logging.error(f"Fout bij uploaden: {response.status_code}")
            return None
    except FileNotFoundError:
        logging.error(f"Bestand niet gevonden: {file_path}")
        return None

def get_analysis_report(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        logging.info(f"Analyse rapport opgehaald voor analyse ID: {analysis_id}")
        return response.json()
    elif response.status_code == 401:
        logging.error("401 Unauthorized: Controleer je API-sleutel.")
        return None
    else:
        logging.error(f"Fout bij het ophalen van analyse: {response.status_code}")
        return None

def scan_file(file_path, timeout=300, interval=15):
    """
    Scant een bestand en wacht tot de scanresultaten beschikbaar zijn.

    Parameters:
    - file_path: Pad naar het te scannen bestand.
    - timeout: Maximale wachttijd in seconden.
    - interval: Interval tussen statuscontroles in seconden.

    Returns:
    - Een dictionary met scanresultaten of foutinformatie.
    """
    sha256 = calculate_sha256(file_path)
    if not sha256:
        return {"error": "Bestand niet gevonden."}

    report = get_report(sha256)
    if report:
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        analysis_results = report.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

        # Extract security vendors' analysis
        security_vendors = {}
        for vendor, details in analysis_results.items():
            security_vendors[vendor] = details.get('result', 'N/A')

        logging.debug(f"Security Vendors: {security_vendors}")

        return {
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "undetected": stats.get('undetected', 0),
            "detailed": {
                "security_vendors": security_vendors
            }
        }
    
    else:
        analysis_id = upload_and_scan(file_path)
        if not analysis_id:
            return {"error": "Fout bij het uploaden van het bestand."}

        # Poll de analyse status
        start_time = time.time()
        while time.time() - start_time < timeout:
            analysis_report = get_analysis_report(analysis_id)
            if analysis_report:
                status = analysis_report.get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    stats = analysis_report.get('data', {}).get('attributes', {}).get('stats', {})
                    analysis_results = analysis_report.get('data', {}).get('attributes', {}).get('results', {})

                    # Extract security vendors' analysis
                    security_vendors = {}
                    for vendor, details in analysis_results.items():
                        security_vendors[vendor] = details.get('result', 'N/A')

                    logging.debug(f"Security Vendors: {security_vendors}")

                    logging.info(f"Scan voltooid voor analyse ID: {analysis_id}")
                    return {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "undetected": stats.get('undetected', 0),
                        "detailed": {
                            "security_vendors": security_vendors
                        }
                    }
            time.sleep(interval)
            logging.debug(f"Wacht op voltooiing van scan. Tijd verstreken: {time.time() - start_time} seconden")

        logging.warning("Scan is nog niet voltooid binnen de timeout periode.")
        return {"info": "Scan is nog niet voltooid. Probeer het later opnieuw."}
