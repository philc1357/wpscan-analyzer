import os
import json
import requests
from dotenv import load_dotenv
import time
from datetime import datetime

# API-Key aus .env laden
load_dotenv(override=True)
api_key = os.getenv("OPENROUTER_API_KEY")
wpscan_api_token = os.getenv("WPScan_API_Token", "")

# Benutzer wird aufgefordert, den Dateinamen der JSON-Datei einzugeben
print("📂 Bitte geben Sie den Pfad zur WPScan JSON-Datei ein:")
print("   (z.B. wpscan_scan.json oder /pfad/zu/datei.json)")
json_file_path = input("Dateipfad: ").strip()

# Prüfen ob die Datei existiert
if not os.path.exists(json_file_path):
    print(f"❌ Datei nicht gefunden: {json_file_path}")
    print("   Bitte stellen Sie sicher, dass der Pfad korrekt ist.")
    exit(1)

# Prüfen ob es eine JSON-Datei ist
if not json_file_path.lower().endswith('.json'):
    print("⚠️  Warnung: Die Datei hat keine .json-Endung. Es wird trotzdem versucht, sie zu laden.")

print(f"\n📂 Lade JSON-Datei: {json_file_path}")

# JSON-Datei laden
try:
    with open(json_file_path, 'r', encoding='utf-8') as f:
        scan_data = json.load(f)
    print("✅ JSON-Datei erfolgreich geladen")
    
    # Prüfen ob es sich um WPScan-Daten handelt
    if "version" not in scan_data and "plugins" not in scan_data and "main_theme" not in scan_data:
        print("⚠️  Warnung: Die Datei scheint keine typischen WPScan-Daten zu enthalten.")
        print("   Es wird trotzdem versucht, die Daten zu analysieren.")
        
except json.JSONDecodeError as e:
    print(f"❌ Fehler beim Parsen der JSON-Datei: {e}")
    print("   Bitte stellen Sie sicher, dass es sich um eine gültige JSON-Datei handelt.")
    exit(1)
except Exception as e:
    print(f"❌ Fehler beim Laden der Datei: {e}")
    exit(1)

# Extrahiere Domain aus den Daten (falls vorhanden)
domain = "unbekannte-domain"
if "url" in scan_data:
    # Extrahiere Domain aus URL
    url = scan_data["url"]
    if url.startswith("http"):
        domain = url.split("//")[1].split("/")[0]
    else:
        domain = url.split("/")[0]

# Funktion zum Extrahieren von CVEs aus den Scan-Daten (lokale Extraktion)
def extract_cves_from_scan(scan_data):
    cves = {
        'core': [],
        'themes': [],
        'plugins': []
    }
    
    # CVEs aus WordPress Core
    if "version" in scan_data and scan_data["version"]:
        version_data = scan_data["version"]
        if "vulnerabilities" in version_data:
            for vuln in version_data["vulnerabilities"]:
                cve_info = {
                    'cve': vuln.get('cve', 'N/A'),
                    'title': vuln.get('title', ''),
                    'severity': vuln.get('severity', 'N/A'),
                    'description': vuln.get('description', ''),
                    'references': vuln.get('references', []),
                    'cvss_score': vuln.get('cvss', {}).get('score', 'N/A'),
                    'cvss_vector': vuln.get('cvss', {}).get('vector', 'N/A'),
                    'source': 'WPScan Scan'
                }
                if cve_info['cve'] != 'N/A':
                    cves['core'].append(cve_info)
    
    # CVEs aus Themes
    if "main_theme" in scan_data and scan_data["main_theme"]:
        theme = scan_data["main_theme"]
        if "vulnerabilities" in theme:
            for vuln in theme["vulnerabilities"]:
                cve_info = {
                    'cve': vuln.get('cve', 'N/A'),
                    'title': vuln.get('title', ''),
                    'severity': vuln.get('severity', 'N/A'),
                    'description': vuln.get('description', ''),
                    'references': vuln.get('references', []),
                    'cvss_score': vuln.get('cvss', {}).get('score', 'N/A'),
                    'cvss_vector': vuln.get('cvss', {}).get('vector', 'N/A'),
                    'source': 'WPScan Scan'
                }
                if cve_info['cve'] != 'N/A':
                    cves['themes'].append(cve_info)
    
    # CVEs aus Plugins
    if "plugins" in scan_data:
        for plugin_name, plugin_data in scan_data["plugins"].items():
            if isinstance(plugin_data, dict) and "vulnerabilities" in plugin_data:
                for vuln in plugin_data["vulnerabilities"]:
                    cve_info = {
                        'plugin': plugin_name,
                        'cve': vuln.get('cve', 'N/A'),
                        'title': vuln.get('title', ''),
                        'severity': vuln.get('severity', 'N/A'),
                        'description': vuln.get('description', ''),
                        'references': vuln.get('references', []),
                        'cvss_score': vuln.get('cvss', {}).get('score', 'N/A'),
                        'cvss_vector': vuln.get('cvss', {}).get('vector', 'N/A'),
                        'source': 'WPScan Scan'
                    }
                    if cve_info['cve'] != 'N/A':
                        cves['plugins'].append(cve_info)
    
    return cves

# Funktion zum Abrufen zusätzlicher CVE-Informationen über die NVD API
def fetch_additional_cve_details(cve_ids):
    """Ruft zusätzliche CVE-Details von der NVD API ab"""
    additional_cves = []
    
    for cve_id in cve_ids:
        try:
            # NVD API für CVE-Details
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(nvd_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # CVSS Score aus NVD holen (aktueller)
                    cvss_metrics = vuln.get('metrics', {})
                    cvss_v3 = cvss_metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    cvss_v2 = cvss_metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
                    
                    # Beschreibung aus NVD
                    descriptions = vuln.get('descriptions', [])
                    description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
                    
                    # CVSS Score (V3 bevorzugt)
                    cvss_score = cvss_v3.get('baseScore', cvss_v2.get('baseScore', 'N/A'))
                    cvss_vector = cvss_v3.get('vectorString', cvss_v2.get('vectorString', 'N/A'))
                    
                    additional_cves.append({
                        'cve': cve_id,
                        'title': description[:200] + '...' if len(description) > 200 else description,
                        'severity': cvss_v3.get('baseSeverity', cvss_v2.get('severity', 'N/A')),
                        'description': description,
                        'references': [ref['url'] for ref in vuln.get('references', [])[:5]],
                        'cvss_score': cvss_score,
                        'cvss_vector': cvss_vector,
                        'source': 'NVD API',
                        'published_date': vuln.get('published', 'N/A'),
                        'last_modified': vuln.get('lastModified', 'N/A')
                    })
                    print(f"   ✅ Zusätzliche CVE-Details von NVD: {cve_id}")
                else:
                    print(f"   ⚠️ Keine NVD-Daten für {cve_id}")
            else:
                print(f"   ⚠️ NVD API Fehler für {cve_id}: {response.status_code}")
                
        except Exception as e:
            print(f"   ⚠️ Fehler beim Abrufen von {cve_id}: {e}")
        
        # Rate Limiting für NVD API
        time.sleep(1)
    
    return additional_cves

# CVEs aus den Scan-Daten extrahieren (lokale Extraktion)
local_cves = extract_cves_from_scan(scan_data)

# Zusätzliche CVE-Details von NVD abrufen (wenn API-Token vorhanden)
additional_cves = []
all_cve_ids = set()

# Sammle alle CVE-IDs aus lokalen Daten
for category in ['core', 'themes', 'plugins']:
    for cve in local_cves[category]:
        if cve['cve'] != 'N/A':
            all_cve_ids.add(cve['cve'])

# Nur wenn wir API-Token haben, NVD für zusätzliche Details abfragen
if wpscan_api_token and all_cve_ids:
    print(f"\n🔍 Rufe zusätzliche CVE-Details von NVD API ab ({len(all_cve_ids)} CVEs)...")
    additional_cves = fetch_additional_cve_details(list(all_cve_ids))
    print(f"✅ {len(additional_cves)} zusätzliche CVE-Details abgerufen")
elif not wpscan_api_token:
    print("\n⚠️  Kein WPScan API Token - Schwachstellendaten werden nur aus der JSON-Datei angezeigt")
    print("   💡 Registrierung für API-Token: https://wpscan.com/register")

# JSON-Daten für die Analyse vorbereiten
scan_json = json.dumps(scan_data, indent=2, ensure_ascii=False)

# Formatierte CVE-Liste für den Prompt (kombiniert lokale + NVD Daten)
def format_cve_list(local_cves, additional_cves):
    formatted = "\n\n# Gefundene CVEs:\n"
    cve_count = 0
    
    # Erstelle Dictionary für schnellen Zugriff auf zusätzliche Details
    additional_dict = {cve['cve']: cve for cve in additional_cves}
    
    # WordPress Core CVEs
    if local_cves['core']:
        formatted += "\n## WordPress Core CVEs:\n"
        for cve in local_cves['core']:
            cve_id = cve['cve']
            if cve_id in additional_dict:
                extra = additional_dict[cve_id]
                formatted += f"- **{cve_id}**: {extra.get('title', cve['title'])}\n"
                formatted += f"  - Severity: {extra.get('severity', cve['severity'])}\n"
                formatted += f"  - CVSS Score: {extra.get('cvss_score', 'N/A')}\n"
                formatted += f"  - Source: {extra.get('source', cve['source'])}\n"
            else:
                formatted += f"- **{cve_id}**: {cve['title']}\n"
                formatted += f"  - Severity: {cve['severity']}\n"
                formatted += f"  - CVSS Score: {cve.get('cvss_score', 'N/A')}\n"
            
            if cve.get('description'):
                formatted += f"  - {cve['description'][:150]}...\n"
            cve_count += 1
    
    # Theme CVEs
    if local_cves['themes']:
        formatted += "\n## Theme CVEs:\n"
        for cve in local_cves['themes']:
            cve_id = cve['cve']
            if cve_id in additional_dict:
                extra = additional_dict[cve_id]
                formatted += f"- **{cve_id}**: {extra.get('title', cve['title'])}\n"
                formatted += f"  - Severity: {extra.get('severity', cve['severity'])}\n"
                formatted += f"  - CVSS Score: {extra.get('cvss_score', 'N/A')}\n"
            else:
                formatted += f"- **{cve_id}**: {cve['title']}\n"
                formatted += f"  - Severity: {cve['severity']}\n"
                formatted += f"  - CVSS Score: {cve.get('cvss_score', 'N/A')}\n"
            
            if cve.get('description'):
                formatted += f"  - {cve['description'][:150]}...\n"
            cve_count += 1
    
    # Plugin CVEs
    if local_cves['plugins']:
        formatted += "\n## Plugin CVEs:\n"
        for cve in local_cves['plugins']:
            cve_id = cve['cve']
            plugin_name = cve.get('plugin', 'Unknown Plugin')
            if cve_id in additional_dict:
                extra = additional_dict[cve_id]
                formatted += f"- **{cve_id}** (Plugin: {plugin_name}): {extra.get('title', cve['title'])}\n"
                formatted += f"  - Severity: {extra.get('severity', cve['severity'])}\n"
                formatted += f"  - CVSS Score: {extra.get('cvss_score', 'N/A')}\n"
            else:
                formatted += f"- **{cve_id}** (Plugin: {plugin_name}): {cve['title']}\n"
                formatted += f"  - Severity: {cve['severity']}\n"
                formatted += f"  - CVSS Score: {cve.get('cvss_score', 'N/A')}\n"
            
            if cve.get('description'):
                formatted += f"  - {cve['description'][:150]}...\n"
            cve_count += 1
    
    if cve_count == 0:
        formatted += "\n⚠️ Keine bekannten CVEs in den WPScan-Ergebnissen gefunden.\n"
        formatted += "💡 Hinweis: Für detaillierte CVE-Informationen wird ein WPScan API Token benötigt.\n"
    
    return formatted

cve_list_formatted = format_cve_list(local_cves, additional_cves)

# Prompt für die LLM-Analyse
prompt = f"""
# Kontext
Du bist ein Security Researcher und analysierst die Ergebnisse eines WPScan-Audits gegen eine WordPress-Website.

# Wichtiger Hinweis zum Scan-Status
Der WPScan-Scan wurde möglicherweise abgebrochen oder war unvollständig. 
Analysiere die vorhandenen Daten trotzdem und weise auf die Einschränkungen hin.

# CVE-Informationsquelle
Die CVEs wurden aus folgenden Quellen zusammengeführt:
- **WPScan Scan**: Lokale CVE-Daten aus dem Scan (basierend auf WPScan Datenbank)
- **NVD API**: Zusätzliche aktuelle CVE-Details (wenn API-Token vorhanden)

# Zu analysierende Daten
Die folgenden Daten sind verfügbar:
- WordPress Version (falls erkannt)
- Haupt-Theme (falls erkannt)  
- Gefundene Plugins (falls erkannt - beachte mögliche False Positives)
- Benutzer (falls erkannt)
- Interessante Funde (XML-RPC, Debug-Log, etc.)
- Gefundene CVEs mit Details (von WPScan und NVD)

# Aufgabe
Analysiere die folgenden WPScan-Ergebnisse und erstelle eine **Sicherheitsbewertung** in deutscher Sprache:

1. **WordPress Core**: 
   - Ist die Version aktuell?
   - Gibt es bekannte Sicherheitslücken? Liste alle gefundenen CVEs auf.

2. **Themes**:
   - Ist das Theme aktuell?
   - Gibt es bekannte Sicherheitslücken? Liste alle gefundenen CVEs auf.

3. **Plugins**:
   - Welche Plugins sind installiert?
   - Sind sie aktuell?
   - Gibt es bekannte Sicherheitslücken?
   - Liste alle gefundenen CVEs für jedes Plugin auf.

4. **Sicherheitskonfiguration**:
   - XML-RPC aktiviert?
   - Debug-Log sichtbar?
   - WP-Cron extern erreichbar?
   - Robots.txt vorhanden?

5. **Benutzer**:
   - Gefundene Benutzernamen
   - Gibt es Standard-Benutzer (admin, Administrator)?

6. **CVEs (Common Vulnerabilities and Exposures)**:
   - Liste alle gefundenen CVEs mit Details auf
   - Bewerte die Schwere der CVEs (basierend auf CVSS-Score)
   - Priorisiere kritische CVEs (Score >= 7.0)

# Format
Erstelle eine strukturierte Zusammenfassung:

## 1. Executive Summary
Kurze Zusammenfassung (3-4 Sätze) des Sicherheitszustands

## 2. Kritische Funde
Nur kritische/hohe Schwachstellen oder Sicherheitsrisiken (CVSS Score >= 7.0)

## 3. Detaillierte Analyse
Detaillierte Auflistung aller Funde

## 4. Gefundene CVEs (Common Vulnerabilities and Exposures)
Liste aller gefundenen CVEs mit:
- CVE-ID
- Betroffene Komponente (Core/Theme/Plugin)
- Schweregrad (Severity)
- CVSS Score
- Beschreibung
- Quelle (WPScan oder NVD)

# WPScan-Ergebnisse (aus JSON-Datei: {os.path.basename(json_file_path)}):
{scan_json}

{cve_list_formatted}
"""

# API-Anfrage an OpenRouter
print("\n🤖 Analysiere Schwachstellen mit KI...")
try:
    response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "openai/gpt-oss-20b:free",
            "messages": [
                {
                    "role": "system",
                    "content": "Du bist ein Security Researcher, der WordPress-Sicherheitsaudits durchführt. Du bist präzise, professionell und gibst klare Handlungsempfehlungen. Du hast Zugang zu detaillierten CVE-Daten aus WPScan und NVD und kannst diese analysieren und priorisieren."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 1.0,
            "max_tokens": 3000,
            "stream": False
        },
        timeout=60
    )
    
    response.raise_for_status()
    data = response.json()
    security_analysis = data["choices"][0]["message"]["content"]
    print("✅ KI-Analyse abgeschlossen")
    
except requests.exceptions.Timeout:
    print("❌ Zeitüberschreitung bei der KI-Analyse")
    exit(1)
except Exception as e:
    print(f"❌ Fehler bei der KI-Analyse: {e}")
    exit(1)

# Ausgabe speichern - Kombinierte Datei mit KI-Analyse und rohen WPScan-Daten
output_filename = f"wpscan_analysis_{domain.replace('.', '_')}.md"
with open(output_filename, "w", encoding="utf-8") as f:
    # Zuerst die KI-Analyse
    f.write(security_analysis)
    f.write("\n\n---\n\n")
    f.write("# ANHANG: ROHER WPScan-SCAN\n\n")
    f.write("```json\n")
    f.write(scan_json)
    f.write("\n```\n")

# Zusätzlich: Rohdaten separat speichern
raw_output = f"wpscan_raw_{domain.replace('.', '_')}.json"
with open(raw_output, "w", encoding="utf-8") as f:
    json.dump(scan_data, f, indent=2, ensure_ascii=False)

# CVE-Zusammenfassung speichern
cve_summary = f"cve_summary_{domain.replace('.', '_')}.json"
with open(cve_summary, "w", encoding="utf-8") as f:
    json.dump({
        'total_cves': len(all_cve_ids),
        'local_cves': local_cves,
        'additional_cves': additional_cves,
        'scan_date': datetime.now().isoformat(),
        'domain': domain,
        'source_file': json_file_path
    }, f, indent=2, ensure_ascii=False)

print(f"\n✅ Schwachstellenanalyse erfolgreich erstellt:")
print(f"📄 Bericht (mit rohen WPScan-Daten): {os.path.abspath(output_filename)}")
print(f"📊 Rohdaten (separat): {os.path.abspath(raw_output)}")
print(f"📋 CVE-Zusammenfassung: {os.path.abspath(cve_summary)}")

# Detaillierte Konsolenausgabe mit CVEs
print("\n" + "="*60)
print("📋 KURZZUSAMMENFASSUNG")
print("="*60)

try:
    # WordPress Version
    if "version" in scan_data and scan_data["version"]:
        version = scan_data["version"]
        print(f"\n🔹 WordPress Version: {version.get('number', 'Unbekannt')}")
        if version.get("status") == "outdated":
            print(f"   ⚠️  VERALTET! Aktuelle Version: 6.8.6 (Stand 26.07.2026)")
            print(f"   📅 Release: {version.get('release_date', 'Unbekannt')}")
    
    # Theme
    if "main_theme" in scan_data and scan_data["main_theme"]:
        theme = scan_data["main_theme"]
        print(f"\n🔹 Theme: {theme.get('slug', 'Unbekannt')}")
        if "version" in theme and theme["version"]:
            print(f"   Version: {theme['version'].get('number', 'Unbekannt')}")
        if theme.get("outdated"):
            print(f"   ⚠️  VERALTET! Aktuelle Version: {theme.get('latest_version', 'Unbekannt')}")
    
    # Sicherheitsrelevante Funde
    print("\n🔹 Sicherheitsrelevante Konfigurationen:")
    if "interesting_findings" in scan_data:
        findings = scan_data["interesting_findings"]
        security_findings = []
        for f in findings:
            ftype = f.get("type")
            if ftype in ["xmlrpc", "debug_log", "wp_cron"]:
                security_findings.append(f"   ⚠️  {ftype.upper()}: {f.get('to_s', '')}")
            elif ftype == "robots_txt":
                security_findings.append(f"   ℹ️  ROBOTS.TXT: {f.get('to_s', '')}")
            elif ftype == "readme":
                security_findings.append(f"   ⚠️  README: {f.get('to_s', '')}")
        
        if security_findings:
            for sf in security_findings:
                print(sf)
        else:
            print("   ✅ Keine auffälligen Konfigurationen gefunden")
    
    # CVEs anzeigen
    print("\n🔹 Gefundene CVEs (Gesamt: {})".format(len(all_cve_ids)))
    
    # Kritische CVEs hervorheben
    critical_cves = []
    for cve in additional_cves:
        try:
            score = float(cve.get('cvss_score', 0))
            if score >= 7.0:
                critical_cves.append(cve)
        except:
            pass
    
    if critical_cves:
        print("\n   ⚠️ KRITISCHE CVES (CVSS >= 7.0):")
        for cve in critical_cves:
            print(f"   - {cve['cve']} (Score: {cve.get('cvss_score', 'N/A')})")
            print(f"     {cve.get('title', '')[:100]}...")
    
    # Alle CVEs auflisten
    if all_cve_ids:
        print("\n   Alle gefundenen CVEs:")
        for cve_id in sorted(all_cve_ids):
            # Prüfen ob zusätzliche Details vorhanden
            extra = next((c for c in additional_cves if c['cve'] == cve_id), None)
            if extra:
                severity = extra.get('severity', 'N/A')
                score = extra.get('cvss_score', 'N/A')
                print(f"   - {cve_id} (Severity: {severity}, Score: {score})")
            else:
                # Lokale Daten
                found = False
                for category in ['core', 'themes', 'plugins']:
                    for cve in local_cves[category]:
                        if cve['cve'] == cve_id:
                            print(f"   - {cve_id} (Severity: {cve.get('severity', 'N/A')})")
                            found = True
                            break
                    if found:
                        break
    else:
        print("   ✅ Keine bekannten CVEs gefunden")
    
    # CVE-Quellen anzeigen
    print(f"\n   📊 CVE-Quellen:")
    print(f"   - WPScan Scan: {len([c for cat in local_cves.values() for c in cat if c['cve'] != 'N/A'])} CVEs")
    print(f"   - NVD API: {len(additional_cves)} CVEs (zusätzliche Details)")
    
    # WPScan API Status
    if "vuln_api" in scan_data and "error" in scan_data["vuln_api"]:
        print(f"\n⚠️  WPScan API: {scan_data['vuln_api']['error']}")
        print("   → Schwachstellendaten nicht verfügbar")
        print("   → Holen Sie einen kostenlosen Token: https://wpscan.com/register")
    
    # Scan Status
    if scan_data.get("scan_aborted"):
        print(f"\n⚠️  SCAN ABGEBROCHEN:")
        print(f"   {scan_data['scan_aborted']}")
        print("   → Die Analyse basiert auf unvollständigen Daten")
        
        # Empfehlung für manuelle Nachbearbeitung
        print("\n💡 EMPFEHLUNG FÜR MANUELLE NACHBEARBEITUNG:")
        print("   Führen Sie den Scan mit diesen Optionen aus:")
        print(f"   wpscan --url {domain} -e u,vt,vp --exclude-content-based '\"\"' --api-token IHR_TOKEN")
        print("   Oder verwenden Sie --plugins-detection aggressive für genauere Ergebnisse")
    
except Exception as e:
    print(f"Fehler bei der Ausgabe: {e}")

print("\n" + "="*60)
print("📄 Vollständiger Bericht in der Markdown-Datei verfügbar")
print("   (KI-Analyse + rohe WPScan-Daten)")
print("="*60)