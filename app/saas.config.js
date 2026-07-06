// ============================================================
// CONFIGURATION DU MODE SaaS (multi-écoles)
//
// Ce fichier EST committé : la clé "publishable" est prévue pour
// être exposée côté client. La sécurité des données est assurée
// par les politiques RLS (Row Level Security) de la base Supabase :
// chaque utilisateur ne peut lire et écrire que les données de
// SON école.
//
// Pour désactiver le mode SaaS (retour au mode local avec
// config.local.js), supprimez ou commentez ce bloc.
// ============================================================

window.SAAS_CONFIG = {
    url: 'https://pysngepfvmokirpjsrzm.supabase.co',
    anonKey: 'sb_publishable_gETaM6fCH9Zpg40weT9QLg_hh2h7tii'
};
