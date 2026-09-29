import os
import re
import json
import subprocess
from datetime import datetime
from dotenv import load_dotenv

load_dotenv("tokenlar.env")

# ============================================================
# AYARLAR
# ============================================================

NMAP_PATH = os.getenv(
    "NMAP_PATH",
    r"C:\Program Files (x86)\Nmap\nmap.exe"
)

OUTPUT_FILE = "nmap_results.json"


# ============================================================
# NMAP TARAMASI
# ============================================================

def scan(ip_address, asset_id=None):
    """
    Belirtilen GLPI asset'in IP adresini
    Nmap + Vulners ile tarar.

    asset_id:
        GLPI'deki Computer ID.
        Örn: 43

    Dönen sonuçlar:
        CVE bulguları veya açık port bilgisi.
    """

    print(f"   🌐 [NMAP] {ip_address} taranıyor...")

    cmd = [
        NMAP_PATH,
        "-sV",
        "-F",
        "--script", "vulners",
        ip_address
    ]

    findings = []

    try:

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180
        )

        output = result.stdout

        if not output:
            print(f"   ⚠️ [NMAP] {ip_address} için çıktı alınamadı.")
            return []

        # ====================================================
        # SERVİSLER / AÇIK PORTLAR
        # ====================================================

        open_ports = re.findall(
            r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?",
            output
        )

        services = []

        for port, service, version in open_ports:

            services.append({
                "port": int(port),
                "service": service,
                "version": (version or "").strip()
            })

        # ====================================================
        # VULNERS CVE SONUÇLARI
        # ====================================================

        vuln_matches = re.findall(
            r"(CVE-\d{4}-\d+)\s+([\d\.]+)\s+(http\S+)",
            output
        )

        # Aynı CVE'nin birden fazla kez gelmesini engelle
        seen_cves = set()

        for cve_id, cvss, link in vuln_matches:

            if cve_id in seen_cves:
                continue

            seen_cves.add(cve_id)

            try:
                cvss_score = float(cvss)
            except ValueError:
                cvss_score = 0.0

            findings.append({
                "asset_id": asset_id,
                "ip": ip_address,
                "scanner": "nmap_vulners",
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "title": f"Network Service Vulnerability ({cve_id})",
                "reference": link,
                "services": services
            })

        # ====================================================
        # CVE YOKSA AÇIK PORT BİLGİSİ
        # ====================================================

        if not findings and services:

            port_desc = ", ".join(
                f"{item['port']}/tcp ({item['service']})"
                for item in services
            )

            findings.append({
                "asset_id": asset_id,
                "ip": ip_address,
                "scanner": "nmap_service",
                "cve_id": "INFO-OPEN-PORTS",
                "cvss_score": 0.0,
                "title": f"Açık Portlar: {port_desc}",
                "reference": "",
                "services": services
            })

        print(
            f"   ✅ [NMAP] {ip_address} için "
            f"{len(findings)} bulgu tespit edildi."
        )

        return findings

    # ========================================================
    # HATA YÖNETİMİ
    # ========================================================

    except subprocess.TimeoutExpired:

        print(
            f"   ⚠️ [NMAP] {ip_address} "
            f"zaman aşımına uğradı."
        )

    except FileNotFoundError:

        print(
            f"   ❌ [NMAP] Nmap bulunamadı: "
            f"{NMAP_PATH}"
        )

    except Exception as e:

        print(
            f"   ❌ [NMAP] Tarama hatası "
            f"({ip_address}): {e}"
        )

    return []


# ============================================================
# JSON KAYDETME
# ============================================================

def save_results(results):

    data = {
        "scanner": "nmap_vulners",
        "scan_time": datetime.now().isoformat(),
        "findings": results
    }

    try:

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"\n💾 [NMAP] Sonuçlar "
            f"{OUTPUT_FILE} dosyasına kaydedildi."
        )

    except Exception as e:

        print(
            f"❌ JSON kaydetme hatası: {e}"
        )


# ============================================================
# BAĞIMSIZ TEST
# ============================================================

if __name__ == "__main__":

    print("==============================================")
    print("      NMAP VULNERS SCANNER TEST")
    print("==============================================")

    test_ip = input(
        "Taranacak IP adresini gir "
        "(örn. 192.168.1.9): "
    ).strip()

    if not test_ip:

        print("❌ IP adresi girilmedi.")

    else:

        # Test sırasında GLPI asset ID'sini
        # elle verebiliriz.
        test_asset_id = input(
            "GLPI Asset ID gir "
            "(örn. 43, boş bırakılabilir): "
        ).strip()

        if test_asset_id:
            try:
                test_asset_id = int(test_asset_id)
            except ValueError:
                test_asset_id = None
        else:
            test_asset_id = None

        results = scan(
            test_ip,
            test_asset_id
        )

        print("\n==============================================")
        print("                 SONUÇLAR")
        print("==============================================")

        for result in results:
            print(result)

        save_results(results)