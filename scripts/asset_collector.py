import argparse
import os
import re
import subprocess
import requests
from dotenv import load_dotenv

load_dotenv("tokenlar.env")

# ============================================================
# AYARLAR
# ============================================================
GLPI_URL = os.getenv("GLPI_URL", "http://localhost:8080")
NMAP_PATH = os.getenv("NMAP_PATH", r"C:\Program Files (x86)\Nmap\nmap.exe")
APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
USER_TOKEN = os.getenv("GLPI_USER_TOKEN")

DROPDOWN_CACHE = {}

# ============================================================
# GLPI SESSION YÖNETİMİ
# ============================================================
def init_session():
    if not APP_TOKEN or not USER_TOKEN:
        print("❌ Hata: tokenlar.env dosyasında GLPI_APP_TOKEN veya GLPI_USER_TOKEN bulunamadı!")
        return None
    url = f"{GLPI_URL}/apirest.php/initSession"
    headers = {"Content-Type": "application/json", "App-Token": APP_TOKEN, "Authorization": f"user_token {USER_TOKEN}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("session_token")
        else:
            print(f"❌ GLPI session başlatılamadı! HTTP {response.status_code}")
    except requests.RequestException as e:
        print("❌ GLPI API bağlantı hatası:", e)
    return None

def kill_session(session_token):
    requests.get(f"{GLPI_URL}/apirest.php/killSession", headers={"App-Token": APP_TOKEN, "Session-Token": session_token})

# ============================================================
# YARDIMCI VERİ ERİŞİM VE DROPDOWN YÖNETİCİSİ
# ============================================================
def safe_get_list(url, headers):
    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, list): return data
    except requests.RequestException:
        pass
    return []

def find_existing_computer(headers, serial_number):
    url = f"{GLPI_URL}/apirest.php/Computer"
    params = {"searchText[serial]": serial_number}
    try:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code == 200:
            items = res.json()
            if isinstance(items, list) and len(items) > 0:
                for item in items:
                    if item.get("serial") == serial_number: return item.get("id")
    except requests.RequestException:
        pass
    return None

def get_or_create_dropdown_id(headers, endpoint, name):
    global DROPDOWN_CACHE
    cache_key = f"{endpoint}_{name.lower()}"
    
    if cache_key in DROPDOWN_CACHE:
        return DROPDOWN_CACHE[cache_key]

    url = f"{GLPI_URL}/apirest.php/{endpoint}"
    items = safe_get_list(f"{url}?searchText[name]={name}", headers)
    for item in items:
        if item.get("name", "").lower() == name.lower():
            DROPDOWN_CACHE[cache_key] = item.get("id")
            return item.get("id")

    res = requests.post(url, headers=headers, json={"input": {"name": name}})
    if res.status_code in [200, 201]:
        new_id = res.json().get("id")
        DROPDOWN_CACHE[cache_key] = new_id
        return new_id
    return None

def guess_os_family(os_text):
    text = os_text.lower()
    if "linux" in text: return "Linux"
    if "windows" in text: return "Windows"
    if "bsd" in text: return "BSD"
    if "mac" in text or "apple" in text: return "macOS"
    if "bilinmiyor" in text or not text.strip(): return "Bilinmiyor"
    return "Diğer"

# ============================================================
# VARLIK TÜRÜ VE ROL SINIFLANDIRICI (GÜVENLİ ITIL STANDARDI)
# ============================================================
def determine_asset_type(open_ports, ip_address):
    port_numbers = [item["port"] for item in open_ports]
    
    if any(p in {3306, 5432, 27017, 1433} for p in port_numbers): 
        return "Database Server"
    if any(p in {80, 443, 8080, 8081} for p in port_numbers): 
        return "Web Server"
    if any(p in {22, 3389, 21} for p in port_numbers): 
        return "Server"
    if ip_address.endswith(".1") or any(p in {53, 67, 161} for p in port_numbers): 
        return "Network Device"
    if not port_numbers: 
        return "IoT / Other"
        
    return "Workstation"

# ============================================================
# NMAP ÇALIŞTIRMA VE AYRIŞTIRMA
# ============================================================
def run_nmap_scan(target):
    print(f"\n🔍 Nmap ile taranıyor: {target}")
    command = [NMAP_PATH, "-sV", "-O", "-F", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode == 0 or result.stdout: return result.stdout
    except FileNotFoundError:
        print(f"❌ Nmap bulunamadı: {NMAP_PATH}")
    return None

def calculate_criticality(open_ports):
    port_numbers = [item["port"] for item in open_ports]
    if any(p in {22, 23, 3306, 5432, 3389, 445} for p in port_numbers): return "Kritik", 4
    if any(p in {21, 25, 139, 8080, 8081} for p in port_numbers): return "Yüksek", 3
    if len(port_numbers) >= 2: return "Orta", 2
    return "Düşük", 1

def parse_nmap_output(nmap_output):
    hosts = []
    host_blocks = nmap_output.split("Nmap scan report for ")

    for block in host_blocks[1:]:
        lines = block.splitlines()
        report_match = re.search(r"^(?:(.+) \(([\d\.]+)\)|([\d\.]+))", lines[0])
        if not report_match: continue
        
        hostname = report_match.group(1) if report_match.group(1) else f"srv-{report_match.group(3).replace('.', '-')}"
        ip_address = report_match.group(2) if report_match.group(1) else report_match.group(3)
        open_ports, os_info, mac_address = [], "Bilinmiyor", "Bilinmiyor"

        for line in lines:
            port_match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
            if port_match: open_ports.append({"port": int(port_match.group(1)), "service": port_match.group(2)})

            mac_match = re.search(r"^MAC Address:\s+([0-9a-fA-F:]+)", line)
            if mac_match: mac_address = mac_match.group(1)

            if "OS details:" in line: os_info = line.split("OS details:")[1].strip()
            elif "Running:" in line and os_info == "Bilinmiyor": os_info = line.split("Running:")[1].strip()
            elif "Service Info: OS:" in line and os_info == "Bilinmiyor": os_info = line.split("Service Info: OS:")[1].split(";")[0].strip()

        criticality, score = calculate_criticality(open_ports)
        asset_type = determine_asset_type(open_ports, ip_address)

        hosts.append({
            "hostname": hostname, "ip_address": ip_address, "mac_address": mac_address,
            "os": os_info, "criticality": criticality, "criticality_score": score,
            "asset_type": asset_type, "open_ports": open_ports
        })
    return hosts

# ============================================================
# GLPI İLİŞKİSEL GÜNCELLEME ALGORİTMALARI
# ============================================================
def upsert_os_info(headers, computer_id, asset):
    if not asset["os"] or asset["os"] == "Bilinmiyor": return
    
    os_id = get_or_create_dropdown_id(headers, "OperatingSystem", guess_os_family(asset["os"]))
    if not os_id: return

    existing_links = safe_get_list(f"{GLPI_URL}/apirest.php/Computer/{computer_id}/Item_OperatingSystem", headers)
    
    if existing_links:
        link_id = existing_links[0]["id"]
        current_os_id = existing_links[0].get("operatingsystems_id")
        if str(current_os_id) != str(os_id):
            requests.put(f"{GLPI_URL}/apirest.php/Item_OperatingSystem/{link_id}", headers=headers, json={"input": {"id": link_id, "operatingsystems_id": os_id}})
    else:
        requests.post(f"{GLPI_URL}/apirest.php/Item_OperatingSystem", headers=headers, json={"input": {"itemtype": "Computer", "items_id": computer_id, "operatingsystems_id": os_id}})

def upsert_network_info(headers, computer_id, asset):
    port_id = None
    ports = safe_get_list(f"{GLPI_URL}/apirest.php/Computer/{computer_id}/NetworkPort", headers)
    
    if ports:
        port_id = ports[0]["id"]
        if asset["mac_address"] != "Bilinmiyor" and ports[0].get("mac") != asset["mac_address"]:
            requests.put(f"{GLPI_URL}/apirest.php/NetworkPort/{port_id}", headers=headers, json={"input": {"id": port_id, "mac": asset["mac_address"]}})
    else:
        res = requests.post(f"{GLPI_URL}/apirest.php/NetworkPort", headers=headers, json={"input": {"itemtype": "Computer", "items_id": computer_id, "name": "eth0", "instantiation_type": "NetworkPortEthernet", "mac": asset["mac_address"] if asset["mac_address"] != "Bilinmiyor" else ""}})
        if res.status_code in [200, 201]: port_id = res.json().get("id")

    if not port_id: return

    name_id = None
    names = safe_get_list(f"{GLPI_URL}/apirest.php/NetworkPort/{port_id}/NetworkName", headers)
    if names:
        name_id = names[0]["id"]
    else:
        res = requests.post(f"{GLPI_URL}/apirest.php/NetworkName", headers=headers, json={"input": {"itemtype": "NetworkPort", "items_id": port_id, "name": asset["hostname"]}})
        if res.status_code in [200, 201]: name_id = res.json().get("id")
        
    if not name_id: return

    ips = safe_get_list(f"{GLPI_URL}/apirest.php/NetworkName/{name_id}/IPAddress", headers)
    if ips:
        ip_id = ips[0]["id"]
        if ips[0].get("name") != asset["ip_address"]:
            requests.put(f"{GLPI_URL}/apirest.php/IPAddress/{ip_id}", headers=headers, json={"input": {"id": ip_id, "name": asset["ip_address"]}})
    else:
        requests.post(f"{GLPI_URL}/apirest.php/IPAddress", headers=headers, json={"input": {"itemtype": "NetworkName", "items_id": name_id, "name": asset["ip_address"]}})

# ============================================================
# ANA UPSERT AKIŞI
# ============================================================
def upsert_glpi_asset(session_token, asset):
    headers = {"Content-Type": "application/json", "App-Token": APP_TOKEN, "Session-Token": session_token}
    result = {"status": "Hata", "computer_id": None}
    
    serial_number = asset['mac_address'] if asset['mac_address'] != "Bilinmiyor" else f"NMAP-{asset['ip_address']}"
    port_summary = ", ".join(f"{item['port']}/{item['service']}" for item in asset["open_ports"])
    existing_id = find_existing_computer(headers, serial_number)

    # Dropdown Değerleri
    state_label = f"{asset['criticality']} ({asset['criticality_score']})"
    state_id = get_or_create_dropdown_id(headers, "State", state_label)
    type_id = get_or_create_dropdown_id(headers, "ComputerType", asset["asset_type"])

    computer_payload = {
        "input": {
            "name": asset["hostname"],
            "serial": serial_number,
            "states_id": state_id if state_id else 0,
            "computertypes_id": type_id if type_id else 0,
            "comment": f"[{asset['asset_type']}] Açık Portlar: {port_summary if port_summary else 'Yok'} | OS: {asset['os']}"
        }
    }

    if existing_id:
        computer_payload["input"]["id"] = existing_id
        res_comp = requests.put(f"{GLPI_URL}/apirest.php/Computer/{existing_id}", headers=headers, json=computer_payload)
        if res_comp.status_code in [200, 201]:
            computer_id = existing_id
            result["status"] = "Güncellendi"
        else:
            print(f"❌ {asset['hostname']} ana kaydı güncellenemedi! HTTP {res_comp.status_code}")
            return result
    else:
        res_comp = requests.post(f"{GLPI_URL}/apirest.php/Computer", headers=headers, json=computer_payload)
        if res_comp.status_code in [200, 201]:
            computer_id = res_comp.json().get("id")
            result["status"] = "Oluşturuldu"
        else:
            print(f"❌ {asset['ip_address']} eklenemedi! HTTP {res_comp.status_code}")
            return result

    result["computer_id"] = computer_id

    upsert_os_info(headers, computer_id, asset)
    upsert_network_info(headers, computer_id, asset)

    return result

# ============================================================
# CLI ÇALIŞTIRICI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="GLPI Bağımsız Ağ Varlık Tarayıcı")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Taranacak IP veya CIDR (Örn: 192.168.1.0/24)")
    args = parser.parse_args()

    print("====================================")
    print("   GLPI SMART ASSET SCANNER (CLI)")
    print("====================================")

    raw_output = run_nmap_scan(args.target)
    if not raw_output:
        print("⚠️ Tarama çıktısı alınamadı.")
        return

    assets = parse_nmap_output(raw_output)
    print(f"✅ {len(assets)} adet aktif varlık ayrıştırıldı.")
    if not assets: return

    session_token = init_session()
    if not session_token: return

    summary = []
    for asset in assets:
        res = upsert_glpi_asset(session_token, asset)
        summary.append((asset["hostname"], asset["ip_address"], asset["asset_type"], res["status"], res["computer_id"]))

    kill_session(session_token)

    print("\n====================================")
    print("          İŞLEM TAMAMLANDI")
    print("====================================")
    print(f"{'Hostname':<22}{'IP Adresi':<16}{'Varlık Türü':<20}{'Durum':<14}{'GLPI ID'}")
    for host, ip, atype, st, cid in summary:
        print(f"{host:<22}{ip:<16}{atype:<20}{st:<14}{cid if cid else '-'}")

if __name__ == "__main__":
    main()