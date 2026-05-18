# Gestion Examens Blancs

Application web de gestion des examens blancs pour le **Collège Jean XXIII**. Elle couvre le cycle complet : inscription des élèves, saisie des notes sur deux tours, calcul automatique des résultats, génération de documents officiels et suivi statistique pour les classes de Terminale et de 3ème.

L'application est entièrement côté client (HTML / CSS / JavaScript) et ne nécessite aucun serveur ni installation.

---

## Fonctionnalités

### Gestion des élèves
- Ajout, modification, suppression d'élèves
- Import et export Excel
- Organisation par classe (Terminale, 3ème, etc.)

### Notes et délibération
- Saisie des notes sur **deux tours** d'examens
- Calcul automatique des moyennes pondérées
- Détermination du statut (admis, repêchage, refusé)
- Comparatif 1er tour / 2ème tour

### Statistiques
- Graphiques interactifs (Chart.js)
- Taux de réussite par classe et par matière
- Moyennes globales et par discipline

### Documents
- Bulletins individuels en PDF
- Listes de délibération (PDF et Excel)
- Procès-verbaux

### Autres
- **Assistant IA** intégré pour l'aide à la décision et les requêtes
- **Journal d'activité** : historique complet des actions et connexions
- **Paramètres** : configuration de l'application

---

## Démarrage rapide

Aucune installation n'est requise.

1. Cloner le dépôt :
   ```bash
   git clone https://github.com/cjr23/Gestion-Examens-Blancs.git
   ```
2. Ouvrir `app/index.html` dans un navigateur moderne (Chrome ou Edge recommandés)
3. Se connecter avec un compte valide

> **Important** : les identifiants par défaut sont définis dans `app/app.js` (constante `LOGIN_ACCOUNTS`). Pensez à les modifier avant tout déploiement réel.

---

## Rôles utilisateurs

| Rôle | Accès |
|------|-------|
| **Administrateur** | Surveillance complète en mode lecture seule, avec bannière de monitoring |
| **Administration** | Accès opérationnel : saisie des notes, gestion des élèves, documents (sans paramètres ni journal) |

---

## Stack technique

- **Langages** : HTML5, CSS3, JavaScript ES6+ (sans framework)
- **Stockage** : `sessionStorage` et `localStorage` du navigateur
- **Bibliothèques externes** (chargées via CDN) :
  - [SheetJS / xlsx.js](https://github.com/SheetJS/sheetjs) — import / export Excel
  - [html2pdf.js](https://github.com/eKoopmans/html2pdf.js) — génération de PDF
  - [Chart.js](https://www.chartjs.org/) — graphiques
- **Polices** : Inter et Plus Jakarta Sans (Google Fonts)

---

## Structure du projet

```
Gestion-Examens-Blancs/
├── app/
│   ├── index.html       # Page principale et toutes les vues
│   ├── app.js           # Logique applicative (~3400 lignes)
│   ├── style.css        # Styles (~4300 lignes)
│   └── logo.jpg         # Logo du collège
├── .gitignore
├── .gitattributes
└── README.md
```

L'application est organisée en **11 pages** accessibles via la navigation latérale :
Tableau de Bord, Élèves, 1er Tour — Notes, Résultats 1er Tour, 2ème Tour — Notes, Résultats 2ème Tour, Statistiques, Documents, Journal, Assistant IA, Paramètres.

---

## Sécurité

Toutes les données sont stockées **localement dans le navigateur** — rien n'est envoyé à un serveur. Les identifiants de connexion étant présents dans le code source côté client, ils sont visibles par toute personne ouvrant les outils de développement. **Modifiez les mots de passe par défaut** dans `app/app.js` avant tout usage réel, et envisagez une solution serveur si une véritable sécurité d'authentification est requise.

---

## Compatibilité

Testé sur les navigateurs récents basés sur Chromium (Chrome, Edge). Fonctionne également sur Firefox avec quelques différences mineures d'affichage (zoom).
