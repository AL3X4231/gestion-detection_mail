import feedparser
import requests
import re
import time
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# =====================================================================
# CONFIGURATION
# =====================================================================
RSS_URL = "https://www.cert.ssi.gouv.fr/avis/feed/"
ETAT_FICHIER = "etat_surveillance.json" # Fichier pour mémoriser les alertes déjà traitées
DELAI_VERIFICATION = 70 # Vérification toutes les heures (3600 secondes)
DELAI_REQUETE = 2 # Respect du Rate Limiting (2 secondes entre chaque appel API)

# Limites pour que les tests aillent très vite
MAX_BULLETINS = 2
MAX_CVE_PER_BULLETIN = 3

EMAIL_EXPEDITEUR = "moa6168@gmail.com"
MOT_DE_PASSE = "ucmo ajdf cwpa zykz"

LISTE_ABONNES = [
    {"email": "moa6168@gmail.com", "produit": "Chrome"},
    {"email": "moa6168@gmail.com", "produit": "Windows"},
    {"email": "moa6168@gmail.com", "produit": "Cisco"},
    {"email": "moa6168@gmail.com", "produit": "Ivanti"}
]

# =====================================================================
# FONCTIONS UTILITAIRES (ENRICHISSEMENT)
# =====================================================================
def get_base_severity(score):
    try:
        score = float(str(score).replace(',', '.'))
        if score == 0.0: return "None"
        elif 0.1 <= score <= 3.9: return "Low"
        elif 4.0 <= score <= 6.9: return "Medium"
        elif 7.0 <= score <= 8.9: return "High"
        elif 9.0 <= score <= 10.0: return "Critical"
    except (ValueError, TypeError):
        pass
    return "Non disponible"

def fetch_cve_details(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return None
        data = response.json()
    except Exception:
        return None

    cna_container = data.get("containers", {}).get("cna", {})
    if not cna_container: return None

    # Description
    descriptions = cna_container.get("descriptions", [])
    description = descriptions[0].get("value", "Non disponible") if descriptions else "Non disponible"
    description = description.replace('\n', ' ').replace('\r', '')

    # CVSS (CNA + ADP + v4.0)
    cvss_score = "Non disponible"
    containers_to_check = []
    if "cna" in data.get("containers", {}):
        containers_to_check.append(data["containers"]["cna"])
    if "adp" in data.get("containers", {}):
        containers_to_check.extend(data["containers"]["adp"])

    for container in containers_to_check:
        metrics_list = container.get("metrics", [])
        for metric in metrics_list:
            for version_key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if version_key in metric:
                    cvss_score = metric[version_key].get("baseScore", cvss_score)
                    break
            if cvss_score != "Non disponible": break
        if cvss_score != "Non disponible": break

    base_severity = get_base_severity(cvss_score)

    # CWE
    cwe = "Non disponible"
    problem_types = cna_container.get("problemTypes", [])
    if problem_types and "descriptions" in problem_types[0]:
        cwe_descriptions = problem_types[0]["descriptions"]
        if cwe_descriptions:
            cwe = cwe_descriptions[0].get("cweId", "Non disponible")

    # Produit / Editeur
    vendor, product_name, versions_str = "Inconnu", "Inconnu", "Inconnues"
    products_list = cna_container.get("affected", [])
    if products_list:
        first_prod = products_list[0]
        vendor = first_prod.get("vendor", "Inconnu")
        product_name = first_prod.get("product", "Inconnu")
        versions = [v.get("version", "Inconnue") for v in first_prod.get("versions", []) if v.get("status") == "affected"]
        versions_str = ", ".join(versions) if versions else "Non spécifiées"

    return {
        "Description": description,
        "CVSS": cvss_score,
        "Base Severity": base_severity,
        "CWE": cwe,
        "Éditeur": vendor,
        "Produit": product_name,
        "Versions affectées": versions_str
    }

def fetch_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                return data["data"][0]["epss"]
    except Exception:
        pass
    return "Non disponible"

# =====================================================================
# GESTION DES EMAILS ET DE L'ETAT
# =====================================================================
def charger_etat():
    if os.path.exists(ETAT_FICHIER):
        with open(ETAT_FICHIER, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def sauvegarder_etat(etat):
    with open(ETAT_FICHIER, 'w', encoding='utf-8') as f:
        json.dump(etat, f, indent=4)

def envoyer_alerte(destinataire, row):
    # Logique pour adapter le design
    gravite_str = str(row.get('Base Severity', 'UNKNOWN')).upper()
    couleur_alerte = "#8b0000" if "CRITI" in gravite_str else "#d9534f" # Dark Red pour Critique, sinon Rouge standard
    
    # Formatage de l'EPSS en pourcentage
    epss_raw = row.get('EPSS', 'Non disponible')
    try:
        epss_pourcentage = f"{float(epss_raw) * 100:.1f}%"
    except (ValueError, TypeError):
        epss_pourcentage = "N/A"

    sujet = f"🚨 [ALERTE SÉCURITÉ {gravite_str}] {row.get('Produit', 'Produit Inconnu')} impacté par {row.get('CVE', '')}"
    
    corps_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    </head>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px;">
        <div style="max-width: 650px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
            
            <!-- Header Dynamique -->
            <div style="background-color: {couleur_alerte}; padding: 25px; text-align: center; color: white;">
                <h1 style="margin: 0; font-size: 26px; letter-spacing: 1px;">ALERTE DE SÉCURITÉ {gravite_str}</h1>
                <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Action immédiate requise pour les administrateurs de <strong>{row.get('Produit', 'Systèmes')}</strong></p>
            </div>
            
            <!-- Content -->
            <div style="padding: 30px;">
                <p style="font-size: 16px; color: #333333; line-height: 1.6;">Bonjour,</p>
                <p style="font-size: 16px; color: #333333; line-height: 1.6;">Le système automatisé de veille <i>Cyber Threat Intelligence</i> a détecté une vulnérabilité critique affectant l'un des systèmes de votre périmètre. Une analyse de l'impact métier et une action corrective sont fortement recommandées.</p>
                
                <!-- Key Metrics Table -->
                <table style="width: 100%; margin: 25px 0; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 15px; background-color: #f8f9fa; border: 1px solid #dee2e6; text-align: center; width: 33%; border-radius: 4px 0 0 4px;">
                            <span style="display: block; font-size: 11px; color: #6c757d; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Score CVSS</span>
                            <strong style="font-size: 26px; color: {couleur_alerte};">{row.get('CVSS', 'N/A')}</strong>
                        </td>
                        <td style="padding: 15px; background-color: #f8f9fa; border: 1px solid #dee2e6; text-align: center; width: 33%;">
                            <span style="display: block; font-size: 11px; color: #6c757d; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Probabilité d'exploitation</span>
                            <strong style="font-size: 26px; color: #d9534f;">{epss_pourcentage}</strong>
                        </td>
                        <td style="padding: 15px; background-color: #f8f9fa; border: 1px solid #dee2e6; text-align: center; width: 33%; border-radius: 0 4px 4px 0;">
                            <span style="display: block; font-size: 11px; color: #6c757d; text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Sévérité Base</span>
                            <strong style="font-size: 20px; color: #333333;">{gravite_str}</strong>
                        </td>
                    </tr>
                </table>

                <!-- Details -->
                <h3 style="color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 30px;">Détails Techniques (IoC & Vecteurs)</h3>
                <table style="width: 100%; font-size: 15px; color: #444; line-height: 1.8; border-collapse: collapse;">
                    <tr><td style="padding: 4px 0; width: 35%;"><strong>📌 Identifiant CVE :</strong></td><td>{row.get('CVE', 'N/A')}</td></tr>
                    <tr><td style="padding: 4px 0;"><strong>📜 Bulletin ANSSI :</strong></td><td>{row.get('ID ANSSI', 'N/A')}</td></tr>
                    <tr><td style="padding: 4px 0;"><strong>🏢 Éditeur :</strong></td><td>{row.get('Éditeur', 'N/A')}</td></tr>
                    <tr><td style="padding: 4px 0;"><strong>💻 Produit affecté :</strong></td><td>{row.get('Produit', 'N/A')}</td></tr>
                    <tr><td style="padding: 4px 0;"><strong>⚙️ Versions ciblées :</strong></td><td>{row.get('Versions affectées', 'N/A')}</td></tr>
                    <tr><td style="padding: 4px 0;"><strong>🛡️ Type de faille (CWE) :</strong></td><td>{row.get('CWE', 'N/A')}</td></tr>
                </table>

                <div style="background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 0 4px 4px 0;">
                    <p style="margin: 0; font-size: 14.px; color: #856404; line-height: 1.6;"><strong>Description détaillée :</strong> <br><i>{row.get('Description', 'Description non fournie')}</i></p>
                </div>

                <!-- Call to action -->
                <div style="text-align: center; margin-top: 35px; margin-bottom: 15px;">
                    <a href="{row.get('Lien', '#')}" style="display: inline-block; padding: 14px 28px; background-color: #0056b3; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin-right: 15px; font-size: 14px;">Consulter le bulletin ANSSI</a>
                    <a href="https://nvd.nist.gov/vuln/detail/{row.get('CVE', '')}" style="display: inline-block; padding: 14px 28px; background-color: #6c757d; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 14px;">Voir la base NVD (NIST)</a>
                </div>
            </div>

            <!-- Footer -->
            <div style="background-color: #f1f1f1; padding: 20px; text-align: center; font-size: 12px; color: #777777;">
                <p style="margin: 0;">Ce message a été généré automatiquement par la plateforme CTI. Ne pas y répondre directement.</p>
                <p style="margin: 8px 0 0 0;">© 2026 - Mastercamp EFREI. Projet Détection. <a href="#" style="color: #0056b3; text-decoration: none;">Gérer mes abonnements</a></p>
            </div>
        </div>
    </body>
    </html>
    """
    
    msg = MIMEMultipart()
    msg['From'] = EMAIL_EXPEDITEUR
    msg['To'] = destinataire
    msg['Subject'] = sujet
    msg.attach(MIMEText(corps_html, 'html'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_EXPEDITEUR, MOT_DE_PASSE)
        server.sendmail(EMAIL_EXPEDITEUR, destinataire, msg.as_string())
        server.quit()
        print(f"  [SUCCES] Email envoyé à {destinataire}")
    except Exception as e:
        print(f"  [ERREUR] Impossible d'envoyer l'email à {destinataire} : {e}")

# =====================================================================
# BOUCLE PRINCIPALE DU SERVEUR
# =====================================================================
def run_serveur():
    print("🚀 Démarrage du serveur de surveillance ANSSI/CVE...")
    
    while True:
        print("\n--- Début d'un cycle de vérification ---")
        deja_traites = charger_etat()
        
        rss_feed = feedparser.parse(RSS_URL)
        
        # On ne prend que les derniers bulletins pour être très rapide lors des tests
        for entry in rss_feed.entries[:MAX_BULLETINS]:
            lien_anssi = entry.link
            
            id_anssi_match = re.search(r'(CERTFR-\d{4}-(AVI|ALE)-\d+)', lien_anssi)
            id_anssi = id_anssi_match.group(1) if id_anssi_match else "Inconnu"
            
            json_url = lien_anssi.rstrip('/') + "/json/"
            
            try:
                time.sleep(DELAI_REQUETE) # Rate limiting pour l'ANSSI
                resp = requests.get(json_url, timeout=10)
                if resp.status_code != 200:
                    continue
                cves_trouves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(resp.json()))))
            except Exception:
                continue
                
            for cve in cves_trouves[:MAX_CVE_PER_BULLETIN]:
                identifiant_unique = f"{id_anssi}_{cve}"
                
                # Si on l'a déjà traité, on passe au suivant
                if identifiant_unique in deja_traites:
                    continue
                    
                print(f"Nouvelle vulnérabilité détectée : {identifiant_unique}")
                
                # Enrichissement
                time.sleep(DELAI_REQUETE) # Rate limiting pour MITRE
                mitre_data = fetch_cve_details(cve)
                
                if not mitre_data:
                    deja_traites.append(identifiant_unique) # On marque quand même comme traité si inexistant chez MITRE
                    continue
                
                # Fetch EPSS
                epss_score = fetch_epss_score(cve)
                mitre_data["EPSS"] = epss_score

                # Vérification par rapport aux abonnés
                produit_nom = mitre_data.get("Produit", "").lower()
                gravite = str(mitre_data.get("Base Severity", "")).upper()
                cvss_str = str(mitre_data.get("CVSS", ""))
                
                # Critère de criticité
                est_critique = False
                if any(mot in gravite for mot in ["CRITICAL", "HIGH", "ÉLEVÉ", "CRITIQUE"]):
                    est_critique = True
                else:
                    try:
                        cvss_val = float(cvss_str.replace(',', '.'))
                        if cvss_val >= 7.0:
                            est_critique = True
                    except ValueError:
                        pass
                
                # S'il est critique, on vérifie si ça intéresse quelqu'un
                if est_critique:
                    row_data = {
                        "ID ANSSI": id_anssi,
                        "Lien": lien_anssi,
                        "CVE": cve,
                        **mitre_data
                    }
                    
                    for abo in LISTE_ABONNES:
                        produit_cible = abo.get("produit", "").lower()
                        if produit_cible in produit_nom:
                            print(f"🚨 Alerte Match ! Produit: {abo['produit']} -> Envoi à {abo['email']}")
                            envoyer_alerte(abo['email'], row_data)
                
                # On marque comme traité
                deja_traites.append(identifiant_unique)
                sauvegarder_etat(deja_traites)

        print(f"--- Fin du cycle. En attente {DELAI_VERIFICATION} secondes... ---")
        time.sleep(DELAI_VERIFICATION)

if __name__ == "__main__":
    run_serveur()
