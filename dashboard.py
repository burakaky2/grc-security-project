import os
import re
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv("tokenlar.env")

# ============================================================
# AYARLAR
# ============================================================
GLPI_URL = os.getenv("GLPI_URL", "http://localhost:8080").rstrip("/")
GLPI_APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
GLPI_USER_TOKEN = os.getenv("GLPI_USER_TOKEN")

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8081").rstrip("/")
DOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY")
DOJO_HEADERS = {"Authorization": f"Token {DOJO_API_KEY}", "Content-Type": "application/json"}

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

st.set_page_config(page_title="GRC Posture Dashboard", page_icon="🛡️", layout="wide")

# ============================================================
# GLPI YARDIMCILARI
# ============================================================
def glpi_init_session():
    if not GLPI_APP_TOKEN or not GLPI_USER_TOKEN:
        return None
    url = f"{GLPI_URL}/apirest.php/initSession"
    headers = {
        "Content-Type": "application/json",
        "App-Token": GLPI_APP_TOKEN,
        "Authorization": f"user_token {GLPI_USER_TOKEN}",
    }
    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            return res.json().get("session_token")
    except requests.RequestException:
        pass
    return None


def glpi_kill_session(token):
    if not token:
        return
    try:
        requests.get(
            f"{GLPI_URL}/apirest.php/killSession",
            headers={"App-Token": GLPI_APP_TOKEN, "Session-Token": token},
            timeout=10,
        )
    except requests.RequestException:
        pass


def extract_criticality_score(label):
    if not label:
        return 1
    match = re.search(r"\((\d+)\)", str(label))
    return int(match.group(1)) if match else 1


@st.cache_data(ttl=60, show_spinner=False)
def fetch_glpi_assets():
    token = glpi_init_session()
    if not token:
        return []
    headers = {"Content-Type": "application/json", "App-Token": GLPI_APP_TOKEN, "Session-Token": token}
    try:
        res = requests.get(f"{GLPI_URL}/apirest.php/Computer?expand_dropdowns=true", headers=headers, timeout=15)
        raw = res.json() if res.status_code == 200 else []
        if not isinstance(raw, list):
            raw = []
    except requests.RequestException:
        raw = []
    glpi_kill_session(token)

    assets = []
    for c in raw:
        label = c.get("states_id", "Düşük (1)")
        assets.append(
            {
                "id": c.get("id"),
                "name": c.get("name", f"Asset-{c.get('id')}"),
                "type": c.get("computertypes_id", "Genel") or "Genel",
                "criticality_label": label,
                "criticality_score": extract_criticality_score(label),
            }
        )
    return assets


# ============================================================
# DEFECTDOJO YARDIMCILARI
# ============================================================
def dojo_get(endpoint, params=None):
    if not DOJO_API_KEY:
        return {"count": 0, "results": []}
    try:
        res = requests.get(
            f"{DEFECTDOJO_URL}/api/v2/{endpoint}/", headers=DOJO_HEADERS, params=params or {}, timeout=15
        )
        if res.status_code == 200:
            return res.json()
    except requests.RequestException:
        pass
    return {"count": 0, "results": []}


def dojo_find_product_id(name):
    data = dojo_get("products", {"name": name, "limit": 1})
    results = data.get("results", [])
    return results[0]["id"] if results else None


def dojo_test_ids_for_product(product_id):
    test_ids = []
    engagements = dojo_get("engagements", {"product": product_id, "limit": 100}).get("results", [])
    for eng in engagements:
        tests = dojo_get("tests", {"engagement": eng["id"], "limit": 100}).get("results", [])
        test_ids.extend(t["id"] for t in tests)
    return test_ids


@st.cache_data(ttl=60, show_spinner=False)
def fetch_severity_counts(asset_name):
    counts = {s: 0 for s in SEVERITIES}
    product_id = dojo_find_product_id(asset_name)
    if not product_id:
        return counts
    for test_id in dojo_test_ids_for_product(product_id):
        for sev in SEVERITIES:
            data = dojo_get("findings", {"test": test_id, "severity": sev, "limit": 1})
            counts[sev] += data.get("count", 0)
    return counts


# ============================================================
# VERİ BİRLEŞTİRME
# ============================================================
def build_posture_dataframe(assets):
    rows = []
    for asset in assets:
        counts = fetch_severity_counts(asset["name"])
        total_findings = sum(counts.values())
        risk_index = sum(counts[s] * SEVERITY_WEIGHT[s] for s in SEVERITIES) * asset["criticality_score"]
        rows.append(
            {
                "Varlık": asset["name"],
                "Tür": asset["type"],
                "Kritiklik": asset["criticality_label"],
                "Kritik": counts["Critical"],
                "Yüksek": counts["High"],
                "Orta": counts["Medium"],
                "Düşük": counts["Low"],
                "Toplam Bulgu": total_findings,
                "Risk Endeksi": risk_index,
            }
        )
    return pd.DataFrame(rows)


# ============================================================
# ARAYÜZ
# ============================================================
st.title("🛡️ GRC Posture Dashboard")
st.caption(f"Son güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M')} — GLPI ve DefectDojo API'den canlı veri")

if not GLPI_APP_TOKEN or not GLPI_USER_TOKEN:
    st.error("tokenlar.env dosyasında GLPI_APP_TOKEN / GLPI_USER_TOKEN eksik.")
    st.stop()
if not DOJO_API_KEY:
    st.error("tokenlar.env dosyasında DEFECTDOJO_API_KEY eksik.")
    st.stop()

with st.spinner("GLPI'dan varlık envanteri çekiliyor..."):
    assets = fetch_glpi_assets()

if not assets:
    st.warning("GLPI'dan varlık verisi alınamadı. Bağlantı ayarlarını / token'ları kontrol edin.")
    st.stop()

with st.spinner("DefectDojo bulguları varlıklarla eşleştiriliyor... (varlık sayısına göre biraz sürebilir)"):
    df = build_posture_dataframe(assets)

clean_ratio = (df["Kritik"] == 0).mean() * 100 if len(df) else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Toplam Varlık", len(df))
col2.metric("Toplam Bulgu", int(df["Toplam Bulgu"].sum()))
col3.metric("Kritik Zafiyeti Olmayan Sistem Oranı", f"%{clean_ratio:.0f}")
col4.metric("En Yüksek Risk Endeksi", int(df["Risk Endeksi"].max()) if len(df) else 0)

st.divider()

left, right = st.columns(2)
with left:
    st.subheader("Kritiklik Dağılımı")
    crit_dist = df["Kritiklik"].value_counts()
    fig1, ax1 = plt.subplots()
    ax1.bar(crit_dist.index.astype(str), crit_dist.values, color="#4C78A8")
    ax1.set_ylabel("Varlık Sayısı")
    ax1.tick_params(axis="x", rotation=20)
    fig1.tight_layout()
    st.pyplot(fig1)
with right:
    st.subheader("En Yüksek Riskli 5 Varlık")
    top5 = df.sort_values("Risk Endeksi", ascending=False).head(5)
    fig2, ax2 = plt.subplots()
    ax2.barh(top5["Varlık"].astype(str)[::-1], top5["Risk Endeksi"][::-1], color="#E45756")
    ax2.set_xlabel("Risk Endeksi")
    fig2.tight_layout()
    st.pyplot(fig2)

st.divider()
st.subheader("Tüm Varlıkların Detaylı Görünümü")
detail_df = df.sort_values("Risk Endeksi", ascending=False)
st.markdown(detail_df.to_html(index=False), unsafe_allow_html=True)

if st.button("🔄 Verileri Yenile"):
    st.cache_data.clear()
    st.rerun()