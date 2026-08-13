# SchoolPro — Gestion Scolaire

> Simple · Efficace · Connectée

Application web de gestion scolaire pour les établissements sénégalais. Partie de la gestion des examens blancs, elle couvre aujourd'hui l'ensemble du cycle scolaire — de l'inscription d'un élève au CI jusqu'à sa sortie en Terminale : dossiers administratifs, classes, notes, bulletins, assiduité, cahier de texte, emplois du temps, personnel et comptabilité.

Elle couvre les **trois cycles du système éducatif sénégalais** : Élémentaire (CI – CM2), Moyen (6ème – 3ème) et Secondaire (Seconde – Terminale).

L'application est entièrement côté client (HTML / CSS / JavaScript), sans serveur ni installation. Elle **fonctionne hors connexion**.

---

## Fonctionnalités

### Module Examens Blancs

- Quatre niveaux d'examen : **CFEE** (CM2), **BFEM** (3ème), **BAC S** et **BAC L2**
- Saisie des notes sur **deux tours**, avec gestion des absents et des inaptes E.P.S.
- Calcul automatique des moyennes pondérées, décisions (admis, 2ème tour, ajourné), mentions et rangs
- Numéros d'anonymat, import / export Excel et CSV
- Statistiques, graphiques et comparatif 1er / 2ème tour
- Documents : relevés de notes, listes de délibération, procès-verbaux, bulletins

### Module École

| Page | Rôle |
|------|------|
| **Mon École** | Informations de l'établissement, direction par cycle, effectifs |
| **Classes** | Classes rangées automatiquement par cycle, inscription et transfert d'élèves, **passage de classe** en fin d'année |
| **Espace Élève** | Dossier scolaire consolidé : identité, IEN, notes et moyennes des trois trimestres, rang, assiduité, moyenne annuelle, export PDF |
| **Dossiers élèves** | Pièces justificatives fournies à l'inscription, dossiers incomplets, liste des pièces configurable |
| **Alertes & Suivi** | Élèves en difficulté repérés avant le conseil de classe |
| **Anciens élèves** | Registre des sortants et des diplômés |
| **Matières & Coefficients** | Une grille par cycle |
| **Présences** | Appel quotidien : absences et retards |
| **Cahier de texte** | Séances, contenus traités, devoirs et dates de remise |
| **Notes & Bulletins** | Saisie trimestrielle et génération des bulletins |
| **Professeurs** | Permanents et vacataires, disponibilités |
| **Emplois du temps** | Grille hebdomadaire par classe, détection des conflits |

### Module Administration

- Gestion du personnel non enseignant

### Module Comptabilité

- Inscriptions en attente de validation, paiements, journal de caisse, dépenses
- Un élève n'intègre sa classe qu'une fois son inscription encaissée

### Transverse

- **Assistant IA** pour l'aide à la décision
- **Journal d'activité** : historique complet des actions et connexions
- **Sauvegarde / restauration** JSON, avec rappel automatique au-delà de sept jours
- Mode sombre, mode présentation, recherche globale

---

## Points saillants

### Passage de classe

En fin d'année, une promotion monte d'un niveau en une seule opération. Décision par élève — **passe**, **redouble**, **sortie** — création automatique de la classe de destination si elle n'existe pas, report des paiements. Les redoublants restent en place ; les sortants et les diplômés sont archivés, jamais supprimés.

### Alertes & Suivi

Trois signaux indépendants, calculés en continu :

- moyenne du dernier trimestre sous **10/20**
- **5 absences** ou plus sur l'année
- chute d'au moins **2 points** entre deux trimestres

Le troisième critère est le plus utile : il repère l'élève qui décroche alors que sa moyenne reste correcte — le cas qu'on rate à l'œil nu.

### Dossiers élèves

Sept pièces par défaut (extrait de naissance, photos, fiche d'inscription signée, bulletin précédent, certificat de transfert, certificat médical, pièce du tuteur), la liste étant modifiable par établissement.

Les fichiers sont stockés dans **IndexedDB**, pas dans `localStorage` : ce dernier plafonne vers 5 Mo et héberge déjà toutes les données scolaires. Plafond de **5 Mo par pièce**.

> ⚠️ **La sauvegarde JSON n'emporte pas ces fichiers**, seulement la liste des pièces déposées. Conservez les originaux tant que l'application n'a pas de serveur.

### Cahier de texte

Séance par séance : date, matière, professeur, contenu traité, devoirs et date de remise. Un bandeau liste les devoirs encore à rendre. Impression et export PDF du cahier complet.

---

## Démarrage rapide

Aucune installation n'est requise.

1. Cloner le dépôt :
   ```bash
   git clone https://github.com/cjr23/Gestion-Examens-Blancs.git
   ```
2. **Créer le fichier de configuration locale** :
   - Copier `app/config.local.example.js` vers `app/config.local.js`
   - Générer un hash SHA-256 pour chaque mot de passe :
     ```bash
     node -e "console.log(require('crypto').createHash('sha256').update(process.argv[1]).digest('hex'))" VOTRE_MOT_DE_PASSE
     ```
   - Remplacer les `REMPLACER_PAR_HASH_SHA256` par les hashes obtenus
3. Ouvrir `app/index.html` dans un navigateur moderne (Chrome ou Edge recommandés)
4. Se connecter avec un compte valide

> `app/config.local.js` est exclu de git via `.gitignore` — il reste local à votre machine.

### Changer son mot de passe

Une fois connecté, cliquez sur **« Changer mon MdP »** dans la barre latérale. Le nouveau hash est stocké dans `localStorage` et prend le pas sur celui de `config.local.js`.

---

## Mode chantier

Deux drapeaux en haut de `app/app.js` neutralisent temporairement des parties de l'application pendant les développements :

| Drapeau | Effet | Remettre en service |
|---------|-------|---------------------|
| `DEV_SKIP_LOGIN` | L'écran de connexion est court-circuité : l'application s'ouvre directement sur le tableau de bord, **sans mot de passe** | `false` |
| `HIDDEN_MODULES` | Modules retirés de la barre latérale (le code et les pages restent intacts) | `[]` |

> ⚠️ **`DEV_SKIP_LOGIN` doit être remis à `false` avant toute mise en service.** Tant qu'il vaut `true`, une pastille rouge « LOGIN DÉSACTIVÉ » s'affiche en bas de l'écran.

---

## Rôles utilisateurs

| Rôle | Accès |
|------|-------|
| **Administrateur** | Accès complet : tableau de bord, paramètres et journal en plus de l'opérationnel, avec bannière de monitoring |
| **Administration** | Accès opérationnel : notes, élèves, documents (sans paramètres ni journal) |

---

## Stack technique

- **Langages** : HTML5, CSS3, JavaScript ES6+ (sans framework)
- **Stockage** : `localStorage` et `sessionStorage` pour les données, **IndexedDB** pour les pièces justificatives
- **Bibliothèques externes** (CDN) :
  - [SheetJS / xlsx.js](https://github.com/SheetJS/sheetjs) — import / export Excel
  - [html2pdf.js](https://github.com/eKoopmans/html2pdf.js) — génération de PDF
  - [Chart.js](https://www.chartjs.org/) — graphiques
- **Polices** : Inter (texte) et Plus Jakarta Sans (titres), via Google Fonts

### Charte graphique

Les couleurs sont dérivées du logo, relevées par analyse des dominantes de `app/logo.png` :

| Rôle | Valeur | Usage |
|------|--------|-------|
| Navy | `#022557` | Couleur primaire, titres, barre latérale |
| Bleu vif | `#0179f6` | Accent, éléments actifs, liens |
| Or | `#fbb903` | Alertes et mises en garde |

Les rouges d'erreur et les verts de réussite restent inchangés : ils portent un sens, pas l'identité.

---

## Structure du projet

```
Gestion-Examens-Blancs/
├── app/
│   ├── index.html               # Page principale et toutes les vues
│   ├── app.js                   # Logique applicative
│   ├── style.css                # Styles
│   ├── config.local.example.js  # Modèle de configuration
│   └── logo.png                 # Logo SchoolPro (source de la charte)
├── .gitignore
├── .gitattributes
└── README.md
```

---

## Adaptation au système sénégalais

Les cycles, niveaux et examens suivent l'organisation du système éducatif sénégalais. Les grilles de matières, les coefficients et les seuils d'admission sont fournis comme **points de départ modifiables**, non comme une norme officielle.

> ⚠️ Les coefficients et seuils du **CFEE** en particulier doivent être confirmés avec les textes de l'IEF avant tout usage en délibération réelle.

L'**IEN** (Identifiant National de l'Élève) est stocké sur la fiche élève. L'application ne peut pas en attribuer — l'identifiant est délivré par l'Inspection — elle se contente de le conserver pour que les dossiers s'alignent sur le système national.

---

## Sécurité

- Toutes les données restent **dans le navigateur** — rien n'est envoyé à un serveur.
- Les mots de passe sont stockés en **hashes SHA-256** dans `app/config.local.js` (non versionné).
- L'authentification est **côté client** : un utilisateur déterminé peut la contourner via les outils de développement. Pour une administration multi-utilisateurs ou des données sensibles, une solution serveur est nécessaire.
- SHA-256 sans salt cède au dictionnaire si les hashes fuitent. Utilisez des mots de passe longs et aléatoires.

### Module `Security` (protection des entrées)

Un module défensif en haut de `app/app.js` protège contre les **injections XSS et SQL** et les **doubles-clics** :

- **Validation à la saisie** : ajout et modification d'élèves, imports CSV et Excel, informations de l'établissement. Balises HTML, handlers JavaScript, URLs `javascript:` et motifs SQL sont rejetés.
- **Échappement à l'affichage** : les noms d'élèves passent par `Security.escapeHTML()` dans toutes les vues rendues en `innerHTML`.
- **Bouclier global** : tous les `<input>` et `<textarea>` hors mots de passe sont surveillés en temps réel.
- **Anti double-clic** : les boutons d'action sont verrouillés ~700 ms après chaque clic.

---

## Limites connues

L'application tourne sur **un seul poste**, dans **un seul navigateur**. Il en découle :

- pas d'accès parent à distance, contrairement à [Planète Élève](https://eleve.education.sn/)
- pas de notification SMS ou WhatsApp aux familles
- pas de partage entre plusieurs ordinateurs de l'établissement
- un vidage du cache navigateur efface l'année — **sauvegardez régulièrement**
- les pièces justificatives ne sont pas incluses dans la sauvegarde JSON

Lever ces limites suppose un serveur et une base de données.

---

## Compatibilité

Testée sur les navigateurs récents basés sur Chromium (Chrome, Edge). Fonctionne sur Firefox avec des différences mineures d'affichage.
