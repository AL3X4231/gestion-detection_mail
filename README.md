# Système de Veille et d'Alerte CVE — ANSSI

Pipeline automatisé de collecte, d'enrichissement, d'analyse et d'alerte sur les vulnérabilités publiées par l'ANSSI (CERT-FR). Le projet couvre l'intégralité de la chaîne : scraping des bulletins, enrichissement multi-API, visualisation des données, modèles de machine learning, et envoi d'alertes email personnalisées.

---

## Fonctionnalités

- **Collecte** : Scraping du flux RSS de l'ANSSI (`cert.ssi.gouv.fr`) et lecture de bulletins JSON locaux
- **Enrichissement** : Appel aux API [MITRE CVE](https://cveawg.mitre.org) (score CVSS, CWE, éditeur, produit, versions affectées) et [FIRST EPSS](https://api.first.org) (probabilité d'exploitation réelle)
- **Analyse & Visualisation** : 10 graphiques sur la distribution des scores, les éditeurs les plus touchés, la corrélation CVSS/EPSS, etc.
- **Machine Learning** :
  - **K-Means** (non supervisé) : segmentation en 4 profils de risque
  - **Random Forest** (supervisé) : classification binaire critique / non critique (AUC-ROC ≈ 0.94)
- **Alertes email** : notification automatique aux abonnés lorsqu'un CVE affecte un produit qu'ils surveillent

---

## Architecture du projet

```
.
├── main.ipynb                    # Notebook principal (étapes 1 à 6)
├── serveur_surveillance.py       # Démon d'alerte email (étape 7)
├── donnees_consolidees_anssi.csv # Dataset complet (~125 000 CVE)
├── cve_2026.csv                  # Sous-ensemble 2026 (~32 000 CVE, utilisé pour le ML)
├── data/
│   ├── Avis/                     # Bulletins ANSSI de type "Avis" (JSON locaux)
│   ├── alertes/                  # Bulletins ANSSI de type "Alerte" (JSON locaux)
│   ├── mitre/                    # Données CVE MITRE en cache local
│   └── first/                    # Scores EPSS en cache local
└── viz_*.png                     # Graphiques générés
```

> **Note :** Le dossier `data/` n'est pas inclus dans le dépôt (trop volumineux). Il est disponible sur la plateforme Moodle du cours.

---

## Pipeline détaillé

### Étape 1–3 : Exploration des sources

Cellules d'exploration permettant de valider la connexion aux trois sources de données :
- Flux RSS ANSSI (via `feedparser`)
- API MITRE CVE (JSON par identifiant CVE)
- API FIRST EPSS

### Étape 4 : Consolidation des données

Deux variantes du pipeline de construction du dataset :

| Mode | Description | Usage |
|------|-------------|-------|
| **Online** (`consolidation_pipeline`) | Scrape le RSS ANSSI en direct + appels API MITRE/EPSS | Tests, données fraîches |
| **Local** (`consolidation_pipeline_local`) | Lit les fichiers JSON du dossier `data/` | Production, grande volumétrie |

**Colonnes produites :** `ID ANSSI`, `Titre ANSSI`, `Type`, `Date`, `CVE`, `CVSS`, `Base Severity`, `CWE`, `EPSS`, `Lien`, `Description`, `Éditeur`, `Produit`, `Versions affectées`

Le dataset est ensuite filtré sur l'année 2026 pour produire `cve_2026.csv`, utilisé pour l'entraînement des modèles.

### Étape 5 : Visualisation

| Fichier | Description |
|---------|-------------|
| `viz_01_hist_cvss.png` | Distribution des scores CVSS |
| `viz_02_pie_severity.png` | Répartition par niveau de sévérité |
| `viz_03_bar_cwe.png` | Top 10 des types CWE |
| `viz_04_bar_products.png` | Top 15 des produits les plus affectés |
| `viz_05_bar_vendors.png` | Top 10 des éditeurs les plus touchés |
| `viz_06_scatter_cvss_epss.png` | Nuage de points CVSS vs EPSS |
| `viz_07_heatmap_corr.png` | Corrélation CVSS / EPSS (r = 0.15) |
| `viz_08_cumul_time.png` | Courbe cumulative des CVE dans le temps |
| `viz_10_boxplot_cvss_vendor.png` | Distribution CVSS par éditeur (top 8) |
| `viz_16_proportion_severity_year.png` | Évolution des sévérités par année |

### Étape 6 : Machine Learning

**Features communes :** `CVSS`, `EPSS`, `Éditeur` (encodé), `CWE` (encodé), `Type` bulletin

#### Modèle 1 — K-Means (non supervisé)

Segmente les CVE en 4 profils de risque opérationnel :

| Cluster | Taille | CVSS moy. | EPSS moy. | Interprétation |
|---------|--------|-----------|-----------|----------------|
| 0 | 25 890 | 7.30 | 0.001 | Graves théoriquement, jamais exploitées |
| 1 | 3 470 | 4.77 | 0.002 | Bruit de fond (faible gravité, non exploitées) |
| **2** | **147** | **7.98** | **0.678** | **DANGER IMMÉDIAT — patch d'urgence** |
| 3 | 4 618 | 7.89 | 0.005 | Graves, risque d'exploitation faible |

Score de silhouette : **0.672**

#### Modèle 2 — Random Forest (supervisé)

Prédit si un CVE est **critique** (CVSS ≥ 7) sans utiliser le score CVSS comme feature (évite le data leakage). Entraîné sur 34 125 CVE de 2026.

| Métrique | Valeur |
|----------|--------|
| AUC-ROC | **0.943** |
| F1-macro (5-fold CV) | ~0.85 |
| Variable la plus importante | `Éditeur_enc` (0.699) |

### Étape 7 : Serveur de surveillance et alertes email

`serveur_surveillance.py` tourne en continu (boucle toutes les ~70 s en mode test) sur un serveur dédié. Pour chaque nouveau bulletin ANSSI, il :
1. Extrait les CVE référencés
2. Les enrichit via les API MITRE et EPSS
3. Envoie un email personnalisé à chaque abonné dont un produit surveillé est affecté

La liste des bulletins déjà traités est persistée dans `etat_surveillance.json` pour éviter les doublons.

---

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/AL3X4231/gestion-detection_mail.git
cd gestion-detection_mail

# Installer les dépendances
pip install feedparser requests pandas matplotlib seaborn scikit-learn
```

> Récupérer le dossier `data/` depuis Moodle et le placer à la racine du projet avant de lancer le notebook.

---

## Utilisation

### Notebook (analyse complète)

Ouvrir `main.ipynb` dans Jupyter et exécuter les cellules dans l'ordre. Les étapes sont indépendantes à partir de l'étape 5 si les CSV sont déjà générés.

### Serveur d'alertes

```bash
python serveur_surveillance.py
```

Configurer les variables en tête de fichier (`EMAIL_EXPEDITEUR`, `MOT_DE_PASSE`, `LISTE_ABONNES`) avant le lancement.

---

## Sources de données

| Source | URL | Usage |
|--------|-----|-------|
| ANSSI CERT-FR | `https://www.cert.ssi.gouv.fr/avis/feed/` | Flux RSS des bulletins |
| MITRE CVE API | `https://cveawg.mitre.org/api/cve/{id}` | Détails CVE (CVSS, CWE, produits) |
| FIRST EPSS API | `https://api.first.org/data/v1/epss` | Score de probabilité d'exploitation |

---

## Limitations connues

- **Scores CVSS manquants** : ~61 % des CVE n'ont pas de score CVSS disponible, principalement dû aux retards du NIST/NVD depuis 2023 et à des demandes de non-divulgation de certains éditeurs. L'EPSS est utilisé comme signal de substitution.
- **Données locales requises** : le pipeline complet (125 000 CVE) nécessite le dossier `data/` non versionné.
- **Rate limiting** : un délai de 0.2–1 s est appliqué entre les appels API pour respecter les limitations des serveurs tiers.