import requests
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

banner = """
***********************************************************
* Debian Security Advisories Update Script                *
* Author: w4zu                                            *
* Version: 1.1                                            *
* Description: This script fetches and updates the        *
*              README.md with the latest 14 days          *
*              DSA and DLA advisories from Debian.        *
* License: Apache 2.0                                     *
***********************************************************
"""

print(banner)
# URLs pour les listes DLA et DSA
DLA_LIST_URL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list"
DSA_LIST_URL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list"

# Cache global avec expiration
cache = {}

def set_cache(key, value, ttl_seconds):
    """
    Définit une entrée dans le cache qui expire après `ttl_seconds`.
    """
    expiration_time = datetime.now() + timedelta(seconds=ttl_seconds)
    cache[key] = {"value": value, "expiration": expiration_time}

def get_cache(key):
    """
    Récupère une entrée valide du cache ou retourne `None`.
    """
    if key in cache:
        entry = cache[key]
        if datetime.now() < entry["expiration"]:
            return entry["value"]
        else:
            # L'entrée a expiré, on la supprime
            del cache[key]
    return None

def fetch_from_url_with_cache(url, cache_duration_seconds=21600):  # 21600 = 6 heures
    """
    Télécharge le contenu d'une URL et le met en cache pendant `cache_duration_seconds`.
    """
    cached_data = get_cache(url)
    if cached_data:
        return cached_data
    response = requests.get(url)
    if response.status_code == 200:
        set_cache(url, response.text, cache_duration_seconds)
        return response.text
    else:
        return None

def get_cvss4_score_with_cache(cve, cache_duration_seconds=21600):  # 21600 = 6 heures
    """
    Récupère le score CVSS depuis le cache ou interroge l'API si nécessaire avec une durée de cache de 6 heures.
    """
    cached_score = get_cache(cve)
    if cached_score is not None:
        print(f"Utilisation du cache pour {cve}")
        return cached_score
    cve_url = f"https://cveawg.mitre.org/api/cve/{cve}"
    try:
        response = requests.get(cve_url)
        if response.status_code != 200:
            set_cache(cve, None, cache_duration_seconds)
            return None
        json_data = response.json()
        base_score = json_data["containers"]["cna"]["metrics"][0]["cvssV4_0"]["baseScore"]
        set_cache(cve, base_score, cache_duration_seconds)  # Mise en cache du score
        return base_score
    except Exception as e:
        set_cache(cve, None, cache_duration_seconds)
        return None

# Analyse des listes DLA ou DSA
def parse_list(list_url, list_type):
    """
    Télécharge et analyse une liste DLA ou DSA, retourne les alertes des 14 derniers jours.
    """
    list_data = fetch_from_url_with_cache(list_url)
    if list_data is None:
        return []
    lines = list_data.splitlines()
    cutoff_date = datetime.now() - timedelta(days=14)
    alerts = []
    date_line_regex = re.compile(r"\[\d{2} \w{3} \d{4}\]")
    current_entry = []
    for line in lines:
        if date_line_regex.match(line):
            if current_entry:
                process_entry(alerts, current_entry, cutoff_date, list_type)
                current_entry = []
        current_entry.append(line)
    if current_entry:
        process_entry(alerts, current_entry, cutoff_date, list_type)
    return alerts

def process_entry(alerts, entry_lines, cutoff_date, list_type):
    """
    Traite une entrée complète (DLA ou DSA) et ajoute des alertes si la date est valide.
    """
    entry_text = " ".join(entry_lines)
    regex = re.compile(
        r"^\s*\[(\d{2} \w{3} \d{4})\]\s+"
        r"(D(LA|SA)-\d+-\d+)\s+"
        r"(.*?)\s+-\s+"
        r"(.*?)\s+\{\s*(.*?)\s*\}\s+"
        r"\[(.*?)\]\s+-\s+(.*)$"
    )
    match = regex.match(entry_text)
    if not match:
        return
    date_str, entry_id, _, package, description, cve_list, suite, version = match.groups()
    date_obj = datetime.strptime(date_str, "%d %b %Y")
    if date_obj >= cutoff_date:
        alerts.append({
            "date": date_obj.strftime("%Y-%m-%d"),
            "id": entry_id,
            "package": package,
            "description": description,
            "cve_list": cve_list.split(),
            "suite": suite,
            "version": version,
            "type": list_type
        })

# Récupération des scores CVSS en parallèle
def fetch_cvss_scores(alerts):
    """
    Récupère les scores CVSS pour tous les CVEs des alertes en parallèle.
    """
    all_cves = {cve for alert in alerts for cve in alert["cve_list"]}
    with ThreadPoolExecutor(max_workers=10) as executor:
        cve_to_score = list(executor.map(lambda cve: (cve, get_cvss4_score_with_cache(cve)), all_cves))
    cve_scores = {cve: score for cve, score in cve_to_score if score is not None}
    for alert in alerts:
        alert["cve_scores"] = {cve: cve_scores.get(cve) for cve in alert["cve_list"]}

def generate_readme(alerts):
    """
    Generates Markdown content for README.md file.
    """
    readme_content = "# Debian Security Advisories (DSA & DLA) - for the last 14 days\n\n"
    if alerts:
        for alert in alerts:
            readme_content += f"**{alert['date']}** - **[{alert['id']}](https://security-tracker.debian.org/tracker/{alert['id']})** - {alert['package']}\n\n"
            readme_content += "**CVE(s) :**\n"
            for cve, score in alert["cve_scores"].items():
                if score and score >= 7.0:
                    severity = "🔥 **Severity: High**"
                elif score and score < 7.0:
                    severity = "🟠 **Severity: Medium**"
                else:
                    severity = "**Severity: Unknown**"
                readme_content += f"- **[{cve}](https://www.cve.org/CVERecord?id={cve})** : {severity} (Score: {score if score else 'N/A'})\n\n"
            readme_content += f"**Debian Version :** {alert['suite']}\n "
            readme_content += f"**Package Version :** {alert['version']}\n "
            readme_content += f"**Type :** {alert['type']}\n\n"
            readme_content += f"------------------------------\n\n"
    else:
        readme_content += "No alerts found for the last 14 days.\n\n"

    return readme_content

def main():
    dla_alerts = parse_list(DLA_LIST_URL, "DLA")
    dsa_alerts = parse_list(DSA_LIST_URL, "DSA")
    all_alerts = dla_alerts + dsa_alerts
    all_alerts.sort(key=lambda x: x["date"], reverse=True)
    fetch_cvss_scores(all_alerts)

    readme_content = generate_readme(all_alerts)
    with open("README.md", "w") as readme_file:
        readme_file.write(readme_content)

if __name__ == "__main__":
    main()
