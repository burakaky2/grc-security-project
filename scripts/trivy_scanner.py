import os
import json
import subprocess
from datetime import datetime

OUTPUT_FILE = "trivy_results.json"

SEVERITY_CVSS_FALLBACK = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5
}

def extract_cvss(vulnerability_dict):
    """Farklı vendor'lardan (nvd, redhat, ghsa vb.) CVSS puanını yakalar, yoksa severity'den türetir."""
    cvss_data = vulnerability_dict.get("CVSS", {})
    
    # 1. Vendor skorlarını tara
    for vendor, scores in cvss_data.items():
        if isinstance(scores, dict):
            score = scores.get("V3Score") or scores.get("V2Score")
            if score:
                try:
                    return float(score)
                except (ValueError, TypeError):
                    pass

    # 2. Vendor skoru yoksa metin tabanlı Severity üzerinden skor ata
    severity = str(vulnerability_dict.get("Severity", "LOW")).upper()
    return SEVERITY_CVSS_FALLBACK.get(severity, 1.0)

def scan(image_name, asset_id=None, ip_address=None):
    """
    Belirtilen Docker imajını Trivy ile tarar ve bulguları normalize eder.
    """
    print(f"   🐳 [TRIVY] {image_name} taranıyor...")
    
    temp_json = f"temp_trivy_{asset_id if asset_id else 'test'}.json"
    cmd = [
        "trivy", 
        "image", 
        "--format", "json", 
        "--output", temp_json, 
        image_name
    ]

    findings = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if res.returncode != 0 and not os.path.exists(temp_json):
            print(f"   ❌ [TRIVY] Komut hatası: {res.stderr.strip()[:200]}")
            return []

        if os.path.exists(temp_json):
            with open(temp_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            if "Results" in data:
                for result in data["Results"]:
                    target_library = result.get("Target", "Bilinmeyen Kütüphane")
                    
                    if "Vulnerabilities" in result:
                        for v in result["Vulnerabilities"]:
                            cve_id = v.get("VulnerabilityID", "Bilinmiyor")
                            title = v.get("Title", v.get("PkgName", "Bilinmeyen Başlık"))
                            cvss_score = extract_cvss(v)

                            findings.append({
                                "asset_id": asset_id,
                                "ip": ip_address,
                                "scanner": "trivy",
                                "cve_id": cve_id,
                                "cvss_score": cvss_score,
                                "title": f"[{image_name}] {title} ({target_library})",
                                "reference": v.get("PrimaryURL", "")
                            })
            
            os.remove(temp_json)

        print(f"   ✅ [TRIVY] {image_name} için {len(findings)} bulgu ayrıştırıldı.")
        return findings

    except FileNotFoundError:
        print("   ❌ [TRIVY] Trivy CLI bulunamadı. Sistem PATH ayarlarını kontrol edin.")
    except Exception as e:
        print(f"   ❌ [TRIVY] Tarama hatası ({image_name}): {e}")
        
    return []

def save_results(results):
    data = {
        "scanner": "trivy",
        "scan_time": datetime.now().isoformat(),
        "findings": results
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
    print(f"\n💾 [TRIVY] Sonuçlar {OUTPUT_FILE} dosyasına kaydedildi.")

if __name__ == "__main__":
    print("==============================================")
    print("      TRIVY CONTAINER SCANNER TEST")
    print("==============================================")
    
    test_image = input("Taranacak Docker İmajını gir (örn. diouxx/glpi:latest): ").strip()
    if test_image:
        test_id = input("GLPI Asset ID gir (varsayılan 1): ").strip()
        test_id = int(test_id) if test_id else 1
        
        results = scan(test_image, asset_id=test_id, ip_address="127.0.0.1")
        if results:
            save_results(results)