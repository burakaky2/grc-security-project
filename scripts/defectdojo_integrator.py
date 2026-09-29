import os
import re
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv("tokenlar.env")

# ============================================================
# AYARLAR
# ============================================================
DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8081").rstrip("/")
DOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY")

HEADERS = {
    "Authorization": f"Token {DOJO_API_KEY}",
    "Content-Type": "application/json"
}

# DefectDojo'nun beklediği severity -> numerical_severity kodu
NUMERICAL_SEVERITY_MAP = {
    "Critical": "S0",
    "High": "S1",
    "Medium": "S2",
    "Low": "S3"
}

# ============================================================
# KRİTİKLİK KATSAYISI AYRIŞTIRICI
# ============================================================
def extract_criticality_multiplier(criticality_label):
    if not criticality_label:
        return 1.0
    match = re.search(r"\((\d+)\)", str(criticality_label))
    if match:
        return float(match.group(1))
    return 1.0

# ============================================================
# DEFECTDOJO API YARDIMCILARI
# ============================================================
def get_or_create(endpoint, search_payload, create_payload):
    url = f"{DEFECTDOJO_URL}/api/v2/{endpoint}/"
    try:
        res = requests.get(url, headers=HEADERS, params=search_payload)
        if res.status_code == 200:
            data = res.json()
            if data.get("count", 0) > 0:
                return data["results"][0]["id"]
        else:
            print(f"   ⚠️ [{endpoint}] arama başarısız: HTTP {res.status_code}")
            print(f"      {res.text[:200]}")

        res_create = requests.post(url, headers=HEADERS, json=create_payload)
        if res_create.status_code in [200, 201]:
            return res_create.json().get("id")
        else:
            print(f"   ❌ [{endpoint}] oluşturulamadı: HTTP {res_create.status_code}")
            print(f"      {res_create.text[:200]}")

    except requests.RequestException as e:
        print(f"❌ DefectDojo bağlantı hatası ({endpoint}):", e)
    return None

def push_findings_to_dojo(asset_data, findings):
    if not DOJO_API_KEY:
        print("❌ Hata: DEFECTDOJO_API_KEY tokenlar.env dosyasında bulunamadı!")
        return

    asset_id = asset_data.get("id")
    asset_name = asset_data.get("name", f"Asset-{asset_id}")
    criticality_label = asset_data.get("criticality", "Düşük (1)")
    multiplier = extract_criticality_multiplier(criticality_label)

    print(f"   └─ Kritiklik: {criticality_label} | Çarpan: {multiplier}x")

    pt_id = get_or_create(
        "product_types",
        {"name": "GLPI Infrastructure"},
        {"name": "GLPI Infrastructure", "description": "GLPI Envanteri"}
    )
    if pt_id is None:
        print("   ❌ Product Type kurulamadığı için bulgular aktarılamadı.")
        return

    p_id = get_or_create(
        "products",
        {"name": asset_name},
        {"name": asset_name, "description": f"GLPI ID: {asset_id}", "prod_type": pt_id}
    )
    if p_id is None:
        print("   ❌ Product kurulamadığı için bulgular aktarılamadı.")
        return

    today = datetime.now().strftime("%Y-%m-%d")
    eng_name = f"Continuous Assessment - {today}"
    eng_id = get_or_create(
        "engagements",
        {"name": eng_name, "product": p_id},
        {"name": eng_name, "product": p_id, "target_start": today, "target_end": today, "status": "In Progress"}
    )
    if eng_id is None:
        print("   ❌ Engagement kurulamadığı için bulgular aktarılamadı.")
        return

    test_type_id = get_or_create("test_types", {"name": "GRC Unified Assessment"}, {"name": "GRC Unified Assessment"})
    if test_type_id is None:
        print("   ❌ Test Type kurulamadığı için bulgular aktarılamadı.")
        return

    test_id = get_or_create(
        "tests",
        {"engagement": eng_id, "test_type": test_type_id},
        {"engagement": eng_id, "test_type": test_type_id, "target_start": today, "target_end": today}
    )
    if not test_id:
        print("   ❌ Test yapısı kurulamadığı için bulgular aktarılamadı.")
        return

    created_count = 0
    failed_count = 0

    for f in findings:
        raw_cvss = f.get("cvss_score", 0.0)
        calculated_risk = round(raw_cvss * multiplier, 2)

        if calculated_risk >= 25.0:
            severity = "Critical"
        elif calculated_risk >= 15.0:
            severity = "High"
        elif calculated_risk >= 7.0:
            severity = "Medium"
        else:
            severity = "Low"

        description_text = (
            f"**Kaynak Tarayıcı:** {f.get('scanner')}\n"
            f"**GLPI Asset ID:** {asset_id}\n"
            f"**Temel CVSS Skoru:** {raw_cvss}\n"
            f"**Kritiklik Çarpanı:** {multiplier}x ({criticality_label})\n"
            f"**Hesaplanan Nihai Risk Skoru:** {calculated_risk}\n\n"
            f"**Referans:** {f.get('reference', 'Yok')}"
        )

        finding_payload = {
            "test": test_id,
            "title": f.get("title", "Zafiyet Başlığı Yok"),
            "cve": f.get("cve_id") if str(f.get("cve_id", "")).startswith("CVE") else None,
            "severity": severity,
            "description": description_text,
            "active": True,
            "verified": True,
            "date": today,
            "numerical_severity": NUMERICAL_SEVERITY_MAP.get(severity, "S2"),
            "found_by": [test_type_id]
        }
        # Mükerrer (Duplicate) Kayıt Kontrolü
        check_params = {"test": test_id, "title": finding_payload["title"]}
        existing = requests.get(f"{DEFECTDOJO_URL}/api/v2/findings/", headers=HEADERS, params=check_params)
        if existing.status_code == 200 and existing.json().get("count", 0) > 0:
            print(f"   ℹ️ Bulgu zaten ekli, atlandı: {f.get('title', '')[:35]}...")
            continue

        res_finding = requests.post(f"{DEFECTDOJO_URL}/api/v2/findings/", headers=HEADERS, json=finding_payload)
        if res_finding.status_code in [200, 201]:
            created_count += 1
        else:
            failed_count += 1
            print(f"   ❌ Finding reddedildi ({f.get('cve_id')}): HTTP {res_finding.status_code}")
            print(f"      {res_finding.text[:300]}")

    print(f"   ✅ {created_count} bulgu DefectDojo'ya başarıyla işlendi.", end="")
    if failed_count:
        print(f" | ❌ {failed_count} bulgu reddedildi (yukarıdaki hatalara bak).")
    else:
        print()