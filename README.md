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
2. **Créer le fichier de configuration locale** :
   - Copier `app/config.local.example.js` vers `app/config.local.js`
   - Générer un hash SHA-256 pour chaque mot de passe (méthodes documentées dans le template)
   - Remplacer les `REMPLACER_PAR_HASH_SHA256` par les hashes générés
3. Ouvrir `app/index.html` dans un navigateur moderne (Chrome ou Edge recommandés)
4. Se connecter avec un compte valide

> **Note** : `app/config.local.js` est exclu de git via `.gitignore` — il reste local à votre machine. Sans ce fichier, l'app affiche un message d'erreur au login.

### Changer son mot de passe

Une fois connecté, cliquez sur **"Changer mon MdP"** dans la barre latérale. Le nouveau hash est stocké dans `localStorage` du navigateur et prend le pas sur celui de `config.local.js`. Vider le cache du navigateur restaure le mot de passe d'origine.

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

- Toutes les données sont stockées **localement dans le navigateur** (sessionStorage et localStorage) — rien n'est envoyé à un serveur.
- Les mots de passe sont stockés sous forme de **hashes SHA-256** dans `app/config.local.js` (non versionné). Les mots de passe en clair n'apparaissent jamais dans le code ni dans l'historique git.
- L'authentification reste **côté client** : un utilisateur déterminé peut contourner le contrôle via les outils de développement du navigateur. Pour une vraie sécurité (administration multi-utilisateurs, données sensibles), une solution serveur est nécessaire.
- SHA-256 sans salt est vulnérable aux attaques par dictionnaire si les hashes fuitent. Utilisez des mots de passe longs et aléatoires.

### Module `Security` (protection des entrées)

Un module défensif (`Security`, en haut de `app/app.js`) protège contre les **injections XSS et SQL** ainsi que les **doubles-clics** :

- **Validation à la saisie** : ajout/modification d'élèves, import CSV, et informations de l'établissement passent par `Security.validateName` / `validateText` / `validateNumber`. Les balises HTML, handlers JavaScript (`onerror=`, `onclick=`…), URLs `javascript:` et patterns SQL (`UNION SELECT`, `OR 1=1`, `--`…) sont rejetés.
- **Échappement à l'affichage** : les noms d'élèves sont passés par `Security.escapeHTML()` dans les tableaux rendus en `innerHTML` (défense en profondeur pour d'éventuelles données pré-existantes).
- **Bouclier global** : tous les `<input>` et `<textarea>` (hors mots de passe) sont surveillés en temps réel ; un champ contenant un pattern suspect est marqué visuellement en orange.
- **Anti double-clic** : les boutons `.btn-primary`, `.btn-success` et `.btn-danger` sont verrouillés ~700 ms après chaque clic pour éviter les soumissions multiples involontaires.

---

## Compatibilité

Testé sur les navigateurs récents basés sur Chromium (Chrome, Edge). Fonctionne également sur Firefox avec quelques différences mineures d'affichage (zoom).
