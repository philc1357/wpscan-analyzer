# WPScan Analyzer

Ein einzelnes Python-Skript (`analyzer.py`), das die JSON-Ergebnisse eines WPScan-Scans einliest, gefundene
CVEs mit zusätzlichen Details aus der NVD-API anreichert, alles an ein LLM (über OpenRouter) zur
Sicherheitsbewertung schickt und die Ergebnisse als Markdown/JSON-Dateien ausgibt.

## Funktionsweise

1. Interaktive Abfrage des Pfads zu einer WPScan-JSON-Datei.
2. Lokale Extraktion aller CVEs aus WordPress Core, Haupt-Theme und Plugins.
3. Optionale Anreicherung dieser CVEs mit aktuellen CVSS-Scores/Beschreibungen über die NVD-API.
4. Erstellung eines deutschsprachigen Prompts mit den vollständigen Scan-Daten und der CVE-Liste, gesendet an
   OpenRouter (Modell `openai/gpt-oss-20b:free`).
5. Ausgabe der KI-Sicherheitsbewertung sowie eine Kurzzusammenfassung in der Konsole.

## Voraussetzungen

- Python 3 mit den Paketen `requests` und `python-dotenv` (bereits im mitgelieferten `venv/` installiert)
- Ein OpenRouter API-Key
- Optional: ein API-Token, das die NVD-Anreicherung aktiviert (Registrierung unter https://wpscan.com/register)

## Setup

1. `.env`-Datei im Projektverzeichnis anlegen (wird von Git ignoriert):

   ```env
   OPENROUTER_API_KEY=dein_openrouter_api_key
   WPScan_API_Token=dein_token   # optional, aktiviert NVD-Anreicherung
   ```

2. Virtuelle Umgebung aktivieren:

   ```bash
   source venv/bin/activate
   ```

## Nutzung

```bash
python analyzer.py
```

Das Skript fragt interaktiv nach dem Pfad zur WPScan-JSON-Datei (keine CLI-Argumente).

## Ausgabedateien

Pro Durchlauf werden drei Dateien erzeugt, benannt nach der aus `scan_data["url"]` extrahierten Domain:

- `wpscan_analysis_<domain>.md` — KI-Sicherheitsbewertung inklusive der rohen Scan-Daten als Anhang
- `wpscan_raw_<domain>.json` — die rohen WPScan-Scandaten
- `cve_summary_<domain>.json` — strukturierte Zusammenfassung aller lokal und über NVD gefundenen CVEs

Zusätzlich wird eine Kurzzusammenfassung (WordPress-Version, Theme, sicherheitsrelevante Funde, kritische CVEs)
in der Konsole ausgegeben.

## Hinweise

- Es gibt keine Paketstruktur, keine Tests und keinen Build-Schritt — ein einzelnes, linear ablaufendes Skript.
- Die Umgebungsvariable `WPScan_API_Token` authentifiziert entgegen ihres Namens nicht gegen WPScan oder NVD,
  sondern dient nur als Schalter für den NVD-Anreicherungsschritt.
- `.gitignore` schließt `.env` und `*.json` aus — Scandateien und generierte Analysen im Projektverzeichnis sind
  lokale Artefakte und keine Testdaten.
