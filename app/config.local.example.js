// ============================================================
// MODÈLE DE CONFIGURATION LOCALE
//
// 1) Copier ce fichier en `config.local.js` dans le même dossier
// 2) Remplacer les valeurs `passwordHash` par les hashes SHA-256
//    de vos vrais mots de passe.
//
// Pour générer un hash SHA-256 d'un mot de passe :
//
//   - Dans la console d'un navigateur :
//       crypto.subtle.digest('SHA-256', new TextEncoder().encode('VOTRE_MDP'))
//         .then(b => console.log(
//           Array.from(new Uint8Array(b))
//             .map(x => x.toString(16).padStart(2,'0')).join('')
//         ));
//
//   - En Python :
//       python -c "import hashlib; print(hashlib.sha256(b'VOTRE_MDP').hexdigest())"
//
// `config.local.js` est exclu de git via .gitignore.
// ============================================================

window.LOGIN_ACCOUNTS = {
    admin: {
        passwordHash: 'REMPLACER_PAR_HASH_SHA256',
        role: 'Administrateur',
        access: 'readonly'
    },
    administration: {
        passwordHash: 'REMPLACER_PAR_HASH_SHA256',
        role: 'Administration',
        access: 'full'
    }
};
