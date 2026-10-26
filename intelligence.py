import os
import re
import urllib.parse
from flask import Flask, render_template, request, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Default API keys from server environment if available
DEFAULT_VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
DEFAULT_OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")


def detect_indicator_type(target):
    """Auto-detect indicator type if not specified by user."""
    target = target.strip()
    
    # IPv4 regex
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ipv4_pattern, target):
        return "ip"
    
    # Hashes (MD5: 32 hex, SHA1: 40 hex, SHA256: 64 hex)
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", target):
        return "hash"
    
    # URL pattern
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    
    # Domain pattern
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, target):
        return "domain"
    
    return "unknown"


def query_virustotal(target, indicator_type, api_key):
    """Query VirusTotal v3 API."""
    if not api_key:
        return {"error": "VirusTotal API key not provided."}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    base_url = "https://www.virustotal.com/api/v3"
    endpoint = ""

    try:
        if indicator_type == "ip":
            endpoint = f"{base_url}/ip_addresses/{target}"
        elif indicator_type == "domain":
            endpoint = f"{base_url}/domains/{target}"
        elif indicator_type == "hash":
            endpoint = f"{base_url}/files/{target}"
        elif indicator_type == "url":
            # VT v3 URL endpoint requires base64 encoding without padding
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"{base_url}/urls/{url_id}"
        else:
            return {"error": f"Unsupported indicator type for VirusTotal: {indicator_type}"}

        response = requests.get(endpoint, headers=headers, timeout=12)

        if response.status_code == 404:
            return {"status": "not_found", "message": "Indicator not found in VirusTotal database."}
        if response.status_code == 401:
            return {"error": "Invalid VirusTotal API Key."}
        if response.status_code != 200:
            return {"error": f"VirusTotal API Error (HTTP {response.status_code})"}

        res_data = response.json().get("data", {}).get("attributes", {})
        stats = res_data.get("last_analysis_stats", {})
        results = res_data.get("last_analysis_results", {})

        # Process top engine detections
        engines_list = []
        for engine_name, engine_data in results.items():
            engines_list.append({
                "engine": engine_name,
                "category": engine_data.get("category", "unknown"),
                "result": engine_data.get("result") or "clean/unrated",
                "method": engine_data.get("method", "N/A")
            })

        return {
            "status": "success",
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            },
            "reputation": res_data.get("reputation", 0),
            "tags": res_data.get("tags", []),
            "asn": res_data.get("asn", "N/A"),
            "as_owner": res_data.get("as_owner", "N/A"),
            "country": res_data.get("country", "N/A"),
            "engines": engines_list
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal Network Error: {str(e)}"}


def query_alienvault_otx(target, indicator_type, api_key):
    """Query AlienVault OTX API."""
    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    base_url = "https://otx.alienvault.com/api/v1"
    
    # Map indicator types to OTX section endpoints
    otx_type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "hash": "file",
        "url": "url"
    }

    otx_type = otx_type_map.get(indicator_type)
    if not otx_type:
        return {"error": f"Unsupported indicator type for OTX: {indicator_type}"}

    try:
        # General general indicators endpoint
        general_url = f"{base_url}/indicators/{otx_type}/{target}/general"
        resp = requests.get(general_url, headers=headers, timeout=12)

        if resp.status_code == 404:
            return {"status": "not_found", "message": "Indicator not found in AlienVault OTX."}
        if resp.status_code != 200:
            return {"error": f"AlienVault OTX Error (HTTP {resp.status_code})"}

        data = resp.json()
        
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        # Extract tags and malware families from active pulses
        tags = set()
        malware_families = set()
        pulse_titles = []

        for p in pulses[:10]:  # Limit top 10 pulses for summary
            pulse_titles.append(p.get("name"))
            for t in p.get("tags", []):
                tags.add(t)
            for m in p.get("malware_families", []):
                if isinstance(m, dict):
                    malware_families.add(m.get("display_name", ""))
                elif isinstance(m, str):
                    malware_families.add(m)

        return {
            "status": "success",
            "pulse_count": pulse_count,
            "tags": list(tags)[:15],
            "malware_families": list(filter(None, list(malware_families))),
            "pulse_summary": pulse_titles[:5],
            "country_name": data.get("country_name", "N/A"),
            "asn": data.get("asn", "N/A")
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"AlienVault OTX Network Error: {str(e)}"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_indicator():
    data = request.get_json() or {}
    
    target = data.get("target", "").strip()
    indicator_type = data.get("type", "auto").lower()
    vt_key = data.get("vt_key", "").strip() or DEFAULT_VT_API_KEY
    otx_key = data.get("otx_key", "").strip() or DEFAULT_OTX_API_KEY

    if not target:
        return jsonify({"status": "error", "message": "Target indicator is required."}), 400

    # Handle auto-detection
    if indicator_type == "auto" or not indicator_type:
        indicator_type = detect_indicator_type(target)
        if indicator_type == "unknown":
            return jsonify({
                "status": "error", 
                "message": "Unable to auto-detect indicator type. Please select the type manually."
            }), 400

    # Query Intel APIs concurrently or sequentially
    vt_result = query_virustotal(target, indicator_type, vt_key)
    otx_result = query_alienvault_otx(target, indicator_type, otx_key)

    # Compute Threat Assessment
    vt_malicious = 0
    vt_suspicious = 0
    if vt_result.get("status") == "success":
        vt_malicious = vt_result.get("stats", {}).get("malicious", 0)
        vt_suspicious = vt_result.get("stats", {}).get("suspicious", 0)

    otx_pulses = 0
    if otx_result.get("status") == "success":
        otx_pulses = otx_result.get("pulse_count", 0)

    # Threat score & badge evaluation
    threat_level = "Clean"
    badge_class = "badge-clean"
    threat_score = 0

    if vt_malicious > 5 or otx_pulses > 10:
        threat_level = "Malicious"
        badge_class = "badge-malicious"
        threat_score = min(100, (vt_malicious * 10) + (otx_pulses * 2))
    elif vt_malicious > 0 or vt_suspicious > 0 or otx_pulses > 0:
        threat_level = "Suspicious"
        badge_class = "badge-suspicious"
        threat_score = min(60, (vt_malicious * 15) + (vt_suspicious * 10) + (otx_pulses * 3))

    response_payload = {
        "status": "success",
        "target": target,
        "type": indicator_type,
        "assessment": {
            "threat_level": threat_level,
            "badge_class": badge_class,
            "threat_score": threat_score,
            "total_detections": vt_malicious + vt_suspicious,
            "pulse_count": otx_pulses
        },
        "virustotal": vt_result,
        "alienvault_otx": otx_result
    }

    return jsonify(response_payload)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)