# GRC Posture & Automation Platform

GLPI (varlık envanteri), DefectDojo (zafiyet yönetimi), Trivy ve Nmap Vulners'ı birleştiren, varlık kritikliğine göre risk hesaplayan ve sonucu bir Streamlit panelinde gösteren otomasyon projesi.

## Ne yapar?

| Bileşen | Dosya | Görev |
|---|---|---|
| Varlık keşfi | `scripts/asset_collector.py` | Nmap ile ağı tarar, cihaz türü ve kritiklik atar, GLPI'ye REST API ile yazar (varsa günceller) |
| Zafiyet tarama | `scripts/nmap_vulners_scanner.py`, `scripts/trivy_scanner.py` | Ağ servislerini (Nmap + vulners) ve çalışan Docker imajlarını (Trivy) tarar, bulguları ortak formata çevirir |
| Entegrasyon | `scripts/defectdojo_integrator.py` | Bulguları DefectDojo'ya Product / Engagement / Test / Finding olarak aktarır |
| Orkestrasyon | `scripts/orchestrator.py` | GLPI'deki varlıkları çeker, her biri için taramaları çalıştırır, bulguları DefectDojo'ya gönderir |
| Panel | `dashboard.py` | GLPI + DefectDojo verisinden risk endeksi ve varlık duruşunu gösterir |
| Altyapı | `docker/docker-compose.yml` | GLPI + MariaDB ve DefectDojo (PostgreSQL, Valkey, uWSGI, Celery, Nginx) |

Akış: **Nmap → GLPI (envanter) → orchestrator (Nmap Vulners + Trivy) → DefectDojo (bulgular) → Streamlit paneli (risk endeksi)**

## Gereksinimler

- Docker Desktop veya Docker Engine + Docker Compose
- Python 3.10 veya üzeri
- [Nmap](https://nmap.org/download) (`vulners` betiği Nmap ile birlikte gelir)
- [Trivy](https://trivy.dev) (CLI, PATH'te olmalı)

## Kurulum

Tüm komutlar **proje ana klasöründen** çalıştırılmalıdır.

### 1. Repoyu klonla

```bash
git clone https://github.com/burakaky2/grc-security-project.git
cd grc-security-project
```

### 2. GLPI ve DefectDojo'yu başlat

```bash
docker compose -f docker/docker-compose.yml up -d
```

İlk açılışta DefectDojo'nun veritabanını hazırlaması birkaç dakika sürebilir. Hazır olunca:

- GLPI: http://localhost:8080
- DefectDojo: http://localhost:8081 (kullanıcı: `admin`, parola: `adminpassword`)

GLPI kurulum sihirbazında veritabanı bilgileri: sunucu `mariadb`, kullanıcı `glpiuser`, parola `glpipass`, veritabanı `glpidb`.
Kurulumdan sonra varsayılan yönetici parolalarını değiştirin.

> **Uyarı:** `docker-compose.yml` içindeki parolalar yalnızca yerel test ortamı içindir. Gerçek ortamda kullanmayın; parolaları `.env` dosyasına taşıyın.

### 3. API anahtarlarını al

**GLPI:**
1. Kurulum > Genel > API: "REST API'yi etkinleştir" ve "Kullanıcı token'ı ile girişi etkinleştir" seçeneklerini açın.
2. Aynı sayfada bir API istemcisi oluşturun, **App-Token** değerini kopyalayın.
3. Kullanıcı tercihlerinden (Uzaktan erişim anahtarı) **User-Token** değerini oluşturup kopyalayın.

**DefectDojo:** Sağ üstteki kullanıcı menüsü > **API v2 Key**.

### 4. Ortam dosyasını hazırla

```bash
cp .env.example tokenlar.env
```

`tokenlar.env` dosyasını açıp token'ları doldurun. Bu dosya `.gitignore` içindedir, repoya gönderilmez.

| Değişken | Açıklama |
|---|---|
| `GLPI_URL` | Varsayılan `http://localhost:8080` |
| `GLPI_APP_TOKEN`, `GLPI_USER_TOKEN` | GLPI API anahtarları |
| `DEFECTDOJO_URL` | Varsayılan `http://localhost:8081` |
| `DEFECTDOJO_API_KEY` | DefectDojo API v2 anahtarı |
| `NMAP_PATH` | İsteğe bağlı. Nmap PATH'teyse `nmap` yazın (Linux/macOS için gerekli; varsayılan Windows yoludur) |

### 5. Python ortamını kur

```bash
python -m venv venv
# Windows:  venv\Scripts\activate
# Linux/macOS:  source venv/bin/activate
pip install -r requirements.txt
```

## Kullanım

> Nmap'in işletim sistemi tespiti (`-O`) yönetici yetkisi ister: Windows'ta terminali yönetici olarak, Linux/macOS'ta `sudo` ile çalıştırın.
> Yalnızca sahibi olduğunuz veya izniniz olan ağları tarayın.

**1) Ağdaki cihazları GLPI'ye aktar**

```bash
python scripts/asset_collector.py --target 192.168.1.0/24
```

`--target` / `-t` tek IP veya CIDR alır (varsayılan: `127.0.0.1`). Sonunda hostname, IP, varlık türü, işlem durumu (Oluşturuldu / Güncellendi) ve GLPI ID içeren bir özet tablo yazdırılır.

**2) Zafiyet taraması yap ve DefectDojo'ya aktar**

```bash
python scripts/orchestrator.py
```

GLPI'deki her varlık için Nmap Vulners çalışır. Varlık yerel Docker host'u ise çalışan konteyner imajları Trivy ile taranır. Sonuçlar DefectDojo'ya gönderilir ve `mapped_scan_results.json` dosyasına yazılır.

**3) Paneli aç**

```bash
streamlit run dashboard.py
```

Panel http://localhost:8501 adresinde açılır.

<!-- Ekran görüntüleri: docs/ klasörüne koyup aşağıdaki satırları açın
![Dashboard](docs/dashboard.png)
![Mimari](docs/architecture.png)
-->

## Risk hesabı

**Varlık kritikliği** (`asset_collector.py`), açık portlara göre 1–4 arası verilir:

| Derece | Koşul |
|---|---|
| Kritik (4) | 22, 23, 3306, 5432, 3389 veya 445 açık |
| Yüksek (3) | 21, 25, 139, 8080 veya 8081 açık |
| Orta (2) | Yukarıdakiler yok, 2 veya daha fazla açık port |
| Düşük (1) | Diğer |

Kritiklik GLPI'de varlığın "Durum" alanına `Kritik (4)` biçiminde yazılır.

**Bulgu bazında risk** (`defectdojo_integrator.py`): `CVSS × kritiklik çarpanı`. DefectDojo ciddiyeti bu değerden belirlenir: ≥25 Critical, ≥15 High, ≥7 Medium, altı Low.

**Varlık risk endeksi** (`dashboard.py`): `(Critical×4 + High×3 + Medium×2 + Low×1) × kritiklik çarpanı`.

## Bilinen sınırlamalar

- Kritiklik yalnızca açık portlara bakan bir sezgisel yöntemdir; Gizlilik-Bütünlük-Erişilebilirlik (GBE) değerlendirmesi yapmaz.
- DefectDojo'daki ciddiyet, kritiklik çarpanıyla ağırlıklandırılmış değerdir; ham CVSS bandı değildir.
- Mükerrer bulgu kontrolü bulgu başlığına göre yapılır.
- Trivy'de CVSS puanı yoksa ciddiyet etiketinden türetilmiş varsayılan bir puan kullanılır.
- Panel, bir varlığı DefectDojo'daki aynı adlı Product ile eşleştirir.

## Proje yapısı

```
.
├── dashboard.py
├── requirements.txt
├── .env.example
├── docker/
│   └── docker-compose.yml
└── scripts/
    ├── asset_collector.py
    ├── defectdojo_integrator.py
    ├── nmap_vulners_scanner.py
    ├── orchestrator.py
    └── trivy_scanner.py
```
