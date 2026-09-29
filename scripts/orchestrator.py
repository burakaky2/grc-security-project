import os
import json
import socket
import subprocess
import requests
from dotenv import load_dotenv

import nmap_vulners_scanner
import trivy_scanner
import defectdojo_integrator

load_dotenv("tokenlar.env")

GLPI_URL = os.getenv("GLPI_URL", "http://localhost:8080")
APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
USER_TOKEN = os.getenv("GLPI_USER_TOKEN")

def get_local_ip_addresses():
    """Çalışılan makinenin tüm yerel IP adreslerini tespit eder."""
    ips = {"127.0.0.1", "localhost"}
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        ips.update(ip_list)
    except Exception:
        pass
    return ips

def get_running_docker_images():
    """Sistemde Docker aktifse sadece ÇALIŞAN konteynerlerin imaj listesini çeker."""
    try:
        cmd = ["docker", "ps", "--format", "{{.Image}}"]
        res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
        if res.returncode == 0:
            images = set(img.strip() for img in res.stdout.splitlines() if img.strip() and not img.endswith("<none>"))
            return list(images)
    except Exception:
        pass
    return []

def init_session():
    url = f"{GLPI_URL}/apirest.php/initSession"
    headers = {
        "Content-Type": "application/json",
        "App-Token": APP_TOKEN,
        "Authorization": f"user_token {USER_TOKEN}"
    }
    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            return res.json().get("session_token")
    except Exception as e:
        print("❌ GLPI bağlantı hatası:", e)
    return None

def kill_session(session_token):
    url = f"{GLPI_URL}/apirest.php/killSession"
    headers = {"App-Token": APP_TOKEN, "Session-Token": session_token}
    try:
        requests.get(url, headers=headers)
    except Exception:
        pass

def get_computer_ip(computer_id, headers):
    try:
        ports = requests.get(f"{GLPI_URL}/apirest.php/Computer/{computer_id}/NetworkPort", headers=headers).json()
        if isinstance(ports, list) and ports:
            port_id = ports[0].get("id")
            names = requests.get(f"{GLPI_URL}/apirest.php/NetworkPort/{port_id}/NetworkName", headers=headers).json()
            if isinstance(names, list) and names:
                name_id = names[0].get("id")
                ips = requests.get(f"{GLPI_URL}/apirest.php/NetworkName/{name_id}/IPAddress", headers=headers).json()
                if isinstance(ips, list) and ips:
                    return ips[0].get("name")
    except Exception:
        pass
    return None

def fetch_glpi_assets(session_token):
    headers = {
        "Content-Type": "application/json",
        "App-Token": APP_TOKEN,
        "Session-Token": session_token
    }
    url = f"{GLPI_URL}/apirest.php/Computer?expand_dropdowns=true"
    try:
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            return []
        
        raw_comps = res.json()
        asset_list = []
        for c in raw_comps:
            c_id = c.get("id")
            asset_list.append({
                "id": c_id,
                "name": c.get("name", f"Asset-{c_id}"),
                "type": c.get("computertypes_id", "Genel"),
                "criticality": c.get("states_id", "Düşük (1)"),
                "ip": get_computer_ip(c_id, headers)
            })
        return asset_list
    except Exception as e:
        print("❌ Asset çekme hatası:", e)
        return []

def main():
    print("==================================================")
    print(" 🚀 AKILLI GRC ORCHESTRATOR (HİBRİT MOTOR)")
    print("==================================================")

    local_ips = get_local_ip_addresses()
    docker_images = get_running_docker_images()

    print(f"[*] Yerel Host IP'leri: {', '.join(local_ips)}")
    print(f"[*] Aktif Çalışan Konteyner İmajları ({len(docker_images)} adet): {', '.join(docker_images) if docker_images else 'Yok'}\n")

    session_token = init_session()
    if not session_token:
        return

    assets = fetch_glpi_assets(session_token)
    kill_session(session_token)

    print(f"[*] GLPI'den {len(assets)} varlık alındı.\n")

    all_mapped_findings = []

    for asset in assets:
        asset_id = asset["id"]
        ip = asset["ip"]
        name = asset["name"]
        criticality = asset["criticality"]

        print(f"🎯 Hedef: {name} | ID: {asset_id} | IP: {ip} | Kritiklik: {criticality}")

        asset_findings = []

        if ip and ip != "IP Yok / Bilinmiyor":
            print("   🌐 [NMAP] Ağ zafiyet taraması başlatılıyor...")
            nmap_res = nmap_vulners_scanner.scan(ip_address=ip, asset_id=asset_id)
            asset_findings.extend(nmap_res)
        else:
            print("   ⚠️ IP bulunamadı, Nmap atlandı.")

        if ip in local_ips and docker_images:
            print(f"   🐳 [TRIVY] Hedef yerel Docker Host olarak tespit edildi ({len(docker_images)} çalışan imaj taranıyor)...")
            for img in docker_images:
                trivy_res = trivy_scanner.scan(image_name=img, asset_id=asset_id, ip_address=ip)
                asset_findings.extend(trivy_res)

        all_mapped_findings.extend(asset_findings)

        if asset_findings:
            print(f"   📤 Toplam {len(asset_findings)} bulgu DefectDojo'ya iletiliyor...")
            defectdojo_integrator.push_findings_to_dojo(asset_data=asset, findings=asset_findings)
        else:
            print("   ℹ️ Bu varlık için zafiyet bulunamadı.")

        print("-" * 50)

    if all_mapped_findings:
        with open("mapped_scan_results.json", "w", encoding="utf-8") as f:
            json.dump(all_mapped_findings, f, indent=4, ensure_ascii=False)
        print("💾 Tüm tarama sonuçları 'mapped_scan_results.json' dosyasına kaydedildi.")

    print("\n🎉 TÜM SÜREÇ BAŞARIYLA TAMAMLANDI!")

if __name__ == "__main__":
    main()