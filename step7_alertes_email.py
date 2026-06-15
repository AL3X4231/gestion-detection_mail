import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(to_email, subject, body, from_email, password):
    """
    Fonction pour envoyer un email via SMTP (Gmail par défaut).
    """
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    
    # Attacher le corps du message en format HTML pour un rendu plus pro
    msg.attach(MIMEText(body, 'html'))
    
    try:
        # Configuration pour Gmail
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"[SUCCES] Email envoyé avec succès à {to_email} !")
    except Exception as e:
        print(f"[ERREUR] Erreur lors de l'envoi de l'email à {to_email} : {e}")

def generer_contenu_mail(row):
    """
    Génère le sujet et le corps du mail (en HTML) à partir d'une ligne de vulnérabilité.
    """
    sujet = f"[ALERTE SÉCURITÉ] Vulnérabilité détectée sur {row['Produit']} ({row['CVE']})"
    
    corps_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #333;">
        <h2 style="color: #d9534f;">Alerte de Sécurité - Action Requise</h2>
        <p>Une nouvelle vulnérabilité critique correspondant à vos critères de surveillance a été publiée.</p>
        
        <div style="background-color: #f9f9f9; padding: 15px; border-left: 5px solid #d9534f;">
            <h3>Détails de la vulnérabilité :</h3>
            <ul>
                <li><strong>ID ANSSI :</strong> <a href="{row['Lien']}">{row['ID ANSSI']}</a></li>
                <li><strong>CVE :</strong> {row['CVE']}</li>
                <li><strong>Éditeur :</strong> {row['Éditeur']}</li>
                <li><strong>Produit :</strong> {row['Produit']}</li>
                <li><strong>Versions affectées :</strong> {row['Versions affectées']}</li>
                <li><strong>Score CVSS :</strong> <span style="color: red; font-weight: bold;">{row['CVSS']}</span> (Gravité : {row['Base Severity']})</li>
                <li><strong>Type CWE :</strong> {row['CWE']}</li>
                <li><strong>Probabilité d'exploitation (EPSS) :</strong> {row['EPSS']}</li>
            </ul>
        </div>
        
        <h3>Description :</h3>
        <p style="background-color: #f1f1f1; padding: 10px; border-radius: 5px;"><i>{row.get('Description', 'Description non fournie')}</i></p>
        
        <br>
        <p>Veuillez consulter le bulletin ANSSI complet pour les recommandations détaillées et mettre à jour vos systèmes dans les plus brefs délais.</p>
        <p>Cordialement,<br><strong>Votre Système d'Alerte Automatisé</strong></p>
    </body>
    </html>
    """
    return sujet, corps_html

def executer_systeme_alertes(chemin_csv, abonnements, from_email, password):
    """
    Lit les données, filtre selon les abonnements (produit & criticité) et déclenche l'envoi des alertes.
    """
    # 1. Charger les données consolidées
    try:
        print(f"Chargement du fichier {chemin_csv}...")
        df = pd.read_csv(chemin_csv, sep=';', dtype=str)
    except Exception as e:
        print(f"Erreur lors du chargement du fichier CSV : {e}")
        return

    # Nettoyage pour éviter les erreurs lors des filtrages
    df.fillna("Non renseigné", inplace=True)

    # 2. Parcourir les abonnements (utilisateurs)
    for abo in abonnements:
        produit_cible = abo.get('produit', '')
        destinataire = abo.get('email', '')
        
        print(f"\nRecherche d'alertes pour l'abonné {destinataire} (Surveillance : {produit_cible})...")
        
        # Création d'un masque pour trouver le produit cible (insensible à la casse)
        masque_produit = df['Produit'].str.contains(produit_cible, case=False, na=False)
        
        # Fonction interne pour évaluer la criticité d'une vulnérabilité
        def est_critique(row):
            # Critère 1 : Mots clés dans "Base Severity"
            gravite = str(row['Base Severity']).upper()
            if any(mot in gravite for mot in ["CRITICAL", "HIGH", "ÉLEVÉ", "CRITIQUE"]):
                return True
            
            # Critère 2 : Score CVSS >= 7.0
            try:
                cvss_val = float(str(row['CVSS']).replace(',', '.'))
                if cvss_val >= 7.0:
                    return True
            except ValueError:
                pass # Si le score n'est pas un nombre (ex: "Non disponible")
                
            return False

        # On applique le filtre sur les produits, puis sur la criticité
        df_produit = df[masque_produit]
        
        if df_produit.empty:
            print(f"Aucune mention du produit '{produit_cible}' dans les données.")
            continue
            
        masque_critique = df_produit.apply(est_critique, axis=1)
        alertes = df_produit[masque_critique]
        
        if alertes.empty:
            print(f"Aucune vulnérabilité *critique* trouvée pour {produit_cible}.")
            continue
            
        print(f"  -> {len(alertes)} alerte(s) générée(s) ! Préparation de l'envoi...")
        
        # 3. Générer et envoyer les emails 
        # (On limite arbitrairement à 3 envois par utilisateur pour éviter de spammer durant les tests)
        max_emails = 3
        count = 0
        for index, row in alertes.iterrows():
            if count >= max_emails:
                print(f"  -> [Info] Limite de {max_emails} emails de test atteinte pour cet abonné.")
                break
                
            sujet, corps = generer_contenu_mail(row)
            
            # Affichage console pour vérification (très utile si on n'envoie pas le vrai mail)
            print("-" * 60)
            print(f"MAIL PRÉPARÉ POUR : {destinataire}")
            print(f"SUJET : {sujet}")
            print("-" * 60)
            
            # Si les identifiants SMTP ont été configurés, on envoie le mail
            if from_email and password and from_email != "votre_email@gmail.com":
                send_email(destinataire, sujet, corps, from_email, password)
            else:
                print("Mode simulation : Le vrai email n'a pas été envoyé car les identifiants SMTP (expéditeur/mot de passe) ne sont pas configurés dans le script.")
                
            count += 1

if __name__ == "__main__":
    # =====================================================================
    # CONFIGURATION DU SYSTÈME D'ALERTE
    # =====================================================================
    
    # 1. Base de données factice de nos utilisateurs abonnés
    liste_abonnes = [
        {"email": "admin.reseau@entreprise.com", "produit": "Chrome"},
        {"email": "admin.sys@entreprise.com", "produit": "Windows"},
        {"email": "ciso@entreprise.com", "produit": "Cisco"}
    ]
    
    # 2. Configuration SMTP (Optionnel - requis seulement pour l'envoi réel)
    # Remplacer par une vraie adresse Gmail et un "Mot de passe d'application"
    EMAIL_EXPEDITEUR = "moa6168@gmail.com" 
    MOT_DE_PASSE = "ucmo ajdf cwpa zykz"
    
    # 3. Fichier de données cible
    FICHIER_DONNEES = "donnees_consolidees_anssi.csv"
    
    # Lancement du traitement
    executer_systeme_alertes(FICHIER_DONNEES, liste_abonnes, EMAIL_EXPEDITEUR, MOT_DE_PASSE)
