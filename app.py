from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from werkzeug.serving import run_simple


import requests
import re
import time
import asyncio
import threading



app = Flask(__name__)

# Mail configuration
app.config['MAIL_SERVER'] = '{Mail Server}'
app.config['MAIL_PORT'] = {Mail Server Port}
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '{Mail username}'
app.config['MAIL_PASSWORD'] = '{Mail password}'
app.config['MAIL_DEFAULT_SENDER'] = '{Sender Address}'

mail = Mail(app)
base_url = "https://{Nessus Server URL}:8834"

Nessus_Username = "{Nessus Username}"
Nessus_Password = "{Nessus Password}"

api_status = True

async def get_api_token():
    global api_status
    # Fetch the main page source code
    main_page = None
    try:
        main_page = requests.get(base_url, verify=False, timeout=5).text
    except requests.exceptions.Timeout:
        print("Timeout while fetching the main page source code")
        api_status = False
        return False
    # Extract the nessus6.js?v=xxxxxxx
    js_version = re.search(r"nessus6.js\?v=(\d+)", main_page)
    if js_version:
        js_url = f"{base_url}/nessus6.js?v={js_version.group(1)}"
    else:
        # raise ValueError("Failed to find nessus6.js version")
        return False
    # Fetch the nessus6.js source code
    js_source = requests.get(js_url, verify=False).text

    # Extract the X-API-Token
    api_token = re.search(
        r'key:"getApiToken",value:function\(\){return"([^"]+)"', js_source)
    if api_token:
        return api_token.group(1)
    else:
        api_status = False
        return False




async def get_token():
    global api_status, Nessus_Password, Nessus_Username
    url = base_url + '/session'

    data = {
        'username': Nessus_Username,
        'password': Nessus_Password
    }
    response = None
    try:
        response = requests.post(url, headers=headers, json=data, verify=False)
    except requests.exceptions.Timeout:
        print("Timeout while fetching the main page source code")
        api_status = False
        return False
    return response.json()['token']

@app.route('/status', methods=['GET'])
async def status():
    global api_status
    return jsonify({"status": "online" if api_status else "offline"})


@app.route('/create_scan', methods=['POST'])
async def create_scan():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email address is required"}), 400

    username = request.json.get("username")
    password = request.json.get("password")
    operating_system = request.json.get("operating_system", "Windows").capitalize()

    if operating_system not in ["Windows", "Linux", "Darwin"]:
        return jsonify({"error": "Invalid operating system"}), 400
    
    # Get the requester's IP address
    requester_ip = request.remote_addr
    
    
    data = {
        "uuid": "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65",
        "settings": {
            "patch_audit_over_telnet": "no",
            "patch_audit_over_rsh": "no",
            "patch_audit_over_rexec": "no",
            "snmp_port": "161",
            "additional_snmp_port1": "161",
            "additional_snmp_port2": "161",
            "additional_snmp_port3": "161",
            "http_login_method": "POST",
            "http_reauth_delay": "",
            "http_login_max_redir": "0",
            "http_login_invert_auth_regex": "no",
            "http_login_auth_regex_on_headers": "no",
            "http_login_auth_regex_nocase": "no",
            "never_send_win_creds_in_the_clear": "yes",
            "dont_use_ntlmv1": "yes",
            "start_remote_registry": "yes",
            "enable_admin_shares": "yes",
            "start_server_service": "yes",
            "ssh_known_hosts": "",
            "ssh_port": "22",
            "ssh_client_banner": "OpenSSH_5.0",
            "attempt_least_privilege": "no",
            "network_capture_enabled": "no",
            "log_whole_attack": "no",
            "always_report_ssh_cmds": "no",
            "enable_plugin_debugging": "no",
            "debug_level": "1",
            "enable_plugin_list": "no",
            "audit_trail": "use_scanner_default",
            "include_kb": "use_scanner_default",
            "windows_search_filepath_exclusions": "",
            "windows_search_filepath_inclusions": "",
            "custom_find_filepath_exclusions": "",
            "custom_find_filesystem_exclusions": "",
            "custom_find_filepath_inclusions": "",
            "reduce_connections_on_congestion": "no",
            "network_receive_timeout": "5",
            "max_checks_per_host": "5",
            "max_hosts_per_scan": "30",
            "max_simult_tcp_sessions_per_host": "",
            "max_simult_tcp_sessions_per_scan": "",
            "safe_checks": "yes",
            "stop_scan_on_disconnect": "no",
            "slice_network_addresses": "no",
            "auto_accept_disclaimer": "no",
            "scan.allow_multi_target": "no",
            "host_tagging": "yes",
            "trusted_cas": "",
            "advanced_mode": "Default",
            "allow_post_scan_editing": "yes",
            "reverse_lookup": "no",
            "log_live_hosts": "no",
            "display_unreachable_hosts": "no",
            "display_unicode_characters": "no",
            "report_verbosity": "Normal",
            "report_superseded_patches": "yes",
            "silent_dependencies": "yes",
            "oracle_database_use_detected_sids": "no",
            "samr_enumeration": "yes",
            "adsi_query": "yes",
            "wmi_query": "yes",
            "rid_brute_forcing": "no",
            "request_windows_domain_info": "no",
            "scan_webapps": "no",
            "test_default_oracle_accounts": "no",
            "provided_creds_only": "yes",
            "report_paranoia": "Normal",
            "thorough_tests": "no",
            "assessment_mode": "Scan for all web vulnerabilities (complex)",
            "collect_identity_data_from_ad": "",
            "svc_detection_on_all_ports": "yes",
            "detect_ssl": "yes",
            "ssl_prob_ports": "All ports",
            "dtls_prob_ports": "None",
            "cert_expiry_warning_days": "60",
            "enumerate_all_ciphers": "yes",
            "check_crl": "no",
            "tcp_scanner": "no",
            "tcp_firewall_detection": "Automatic (normal)",
            "syn_scanner": "yes",
            "syn_firewall_detection": "Automatic (normal)",
            "udp_scanner": "no",
            "ssh_netstat_scanner": "yes",
            "wmi_netstat_scanner": "yes",
            "snmp_scanner": "yes",
            "only_portscan_if_enum_failed": "yes",
            "verify_open_ports": "no",
            "unscanned_closed": "no",
            "portscan_range": "default",
            "wol_mac_addresses": "",
            "wol_wait_time": "5",
            "scan_network_printers": "no",
            "scan_netware_hosts": "no",
            "scan_ot_devices": "no",
            "ping_the_remote_host": "yes",
            "arp_ping": "yes",
            "tcp_ping": "yes",
            "tcp_ping_dest_ports": "built-in",
            "icmp_ping": "yes",
            "icmp_unreach_means_host_down": "no",
            "icmp_ping_retries": "2",
            "udp_ping": "no",
            "test_local_nessus_host": "yes",
            "fast_network_discovery": "no",
            "discovery_mode": "Port scan (all ports)",
            "attach_report": "yes",
            "attached_report_type": "pdf",
            "attached_report_maximum_size": "40",
            "filter_type": "and",
            "filters": [],
            "launch_now": False,
            "enabled": False,
            "live_results": "",
            "name": "SMB Defence Scan of " +str(requester_ip),
            "description": "basic scan of " +str(requester_ip),
            "folder_id": "3",
            "scanner_id": "1",
            "file_targets": ""
        }
    }
    # Add credentials only if both username and password are provided
    if username and password:
        if operating_system == "Windows":
            data["credentials"] = {
                "add": {
                    "Host": {
                        "Windows": [
                            {
                                "auth_method": "NTLM Hash",
                                "username": username,
                                "password": password,
                                "domain": ""
                            }
                        ]
                    },
                    "edit": {},
                    "delete": []
                }
            }
        else:
            data["credentials"] = {
                "add": {
                    "Host": {
                        "SSH": [
                            {
                                "auth_method": "password",
                                "username": username,
                                "password": password,
                                "elevate_privileges_with": "sudo",
                                "escalation_account": "",
                                "escalation_password": "",
                                "bin_directory": "",
                                "custom_password_prompt": ""
                            }
                        ]
                    }
                },
                "edit": {},
                "delete": []
            }
    data["settings"]["emails"] = email
    data["settings"]["text_targets"] = requester_ip
    url = base_url+'/scans'

    response = requests.post(url, headers=headers, json=data, verify=False)
    response_data = response.json()

    # Start the scan
    scan_id = response_data["scan"]["id"]
    start_scan_url = f"{base_url}/scans/{scan_id}/launch"
    start_scan_response = requests.post(
        start_scan_url, headers=headers, verify=False)

    return jsonify({"scan_id": scan_id, "start_scan_response": start_scan_response.json()})


@app.route('/scan_status/<int:scan_id>', methods=['GET'])
async def scan_status(scan_id, requester_ip=None):
    # scan_id = request.args.get("scan_id")
    
    if requester_ip is None:
       requester_ip = request.remote_addr
    url = f"{base_url}/scans/{scan_id}"

    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        return jsonify({"error": f"Failed to get scan status: {response.status_code} {response.text}"}), response.status_code

    scan_data = response.json()
    # scan_data["info"]["targets"] check if "targets" exists in scan_data["info"]
    if "targets" in scan_data["info"]:
        target_ip = scan_data["info"]["targets"]
    else:
        target_ip = None
    name = scan_data["info"]["name"]

    if requester_ip not in (target_ip, name):
        return jsonify({"error": f"Requester IP address {requester_ip} not found in targets or name field"}), 403
    
    return jsonify(scan_data), 200

@app.route('/export_report', methods=['POST'])
async def export_report():
    requester_ip = request.remote_addr
    scan_id = request.json.get("scan_id")
    response, status_code = await scan_status(scan_id, requester_ip)
    scan_data = response.get_json()
    if status_code != 200:
        return jsonify(scan_data), status_code
    
    email = request.json.get("email")
    limit = request.json.get("limit", 4000)
    url = f"{base_url}/scans/{scan_id}/export?limit={limit}"

    payload = {
        "format": "pdf",
        "template_id": 61,
        "csvColumns": {},
        "formattingOptions": {
            "page_breaks": True
        },
        "extraFilters": {
            "host_ids": [],
            "plugin_ids": []
        }
    }

    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code != 200:
        return jsonify({"error": f"Failed to export report: {response.status_code} {response.text}"}), response.status_code

    response_data = response.json()
    token = response_data["token"]

    # Check download status
    ready = False
    while not ready:
        time.sleep(5)  # Wait for 5 seconds before checking again
        url = f"{base_url}/tokens/{token}/status"
        download_status_response = requests.get(url, headers=headers, verify=False)
        if download_status_response.status_code != 200:
            return jsonify({"error": f"Failed to check download status: {download_status_response.status_code} {download_status_response.text}"}), download_status_response.status_code

        status_data = download_status_response.json()
        if status_data["status"] == "ready":
            ready = True

    # Download report
    url = f"{base_url}/tokens/{token}/download"
    download_response = requests.get(url, headers=headers, verify=False)
    if download_response.status_code != 200:
        return jsonify({"error": f"Failed to download report: {download_response.status_code} {download_response.text}"}), download_response.status_code

    # Send email with report attached
    subject = 'Your Nessus Scan Report'
    body = 'Please find the attached Nessus scan report.'

    msg = Message(subject, recipients=[email])
    msg.body = body
    msg.attach("report.pdf", "application/pdf", download_response.content)
    mail.send(msg)

    return jsonify({"message": "Report has been sent to the provided email address."})

@app.route('/stop_scan/<int:scan_id>', methods=['POST'])
def stop_scan(scan_id):
    url = f"{base_url}/scans/{scan_id}/stop"

    response = requests.post(url, headers=headers, verify=False)
    if response.status_code == 200:
        return jsonify({"message": f"Scan {scan_id} stopped successfully"}), 200
    else:
        return jsonify({"error": f"Failed to stop scan: {response.status_code} {response.text}"}), response.status_code

@app.route('/delete_scan/<int:scan_id>', methods=['DELETE'])
async def delete_scan(scan_id):
    requester_ip = request.remote_addr
    response, status_code = await scan_status(scan_id, requester_ip)
    scan_data = response.get_json()
    if status_code != 200:
        return jsonify(scan_data), status_code

    url = f'{base_url}/scans/{scan_id}'
    response = requests.delete(url, headers=headers, verify=False)

    if response.status_code == 200:
        return jsonify({"message": f"Scan {scan_id} deleted successfully"})
    else:
        return jsonify({"error": f"Failed to delete scan {scan_id}"}), response.status_code

async def update_tokens():
    
    print("Updating tokens")
    global cookie_token, api_token, headers, api_status
    while True:
        try:
            api_token= await get_api_token()
        except Exception as e:
            print("Failed to get API token:")
            api_status = False
            await asyncio.sleep(20)
            continue
        if not api_token:
            print("Failed to get API token")
            api_status = False
            await asyncio.sleep(20)
            continue
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': base_url,
            'Referer': base_url,
            'X-API-Token': api_token
        }
        try:
            cookie_token = await get_token()
        except Exception as e:
            print("Failed to get cookie token")
            api_status = False
            await asyncio.sleep(20)
            continue
        if not cookie_token:
            print("Failed to get cookie token")
            api_status = False
            await asyncio.sleep(20)
            continue
        headers['X-Cookie'] = 'token='+cookie_token

        print(f"Cookie Token: {cookie_token}")
        print("X-API-Token:", api_token)
        api_status = True
        await asyncio.sleep(600)


def run_flask_app():
    run_simple("0.0.0.0", 80, app, use_reloader=False, use_debugger=False, threaded=True)


if __name__ == '__main__':
    
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(update_tokens())
    except KeyboardInterrupt:
        print("Program stopped.")
    finally:
        loop.close()