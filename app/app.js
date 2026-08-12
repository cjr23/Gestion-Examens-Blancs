// ========== SECURITY MODULE ==========
// Couche défensive contre XSS, injection SQL (pour les données exportées),
// caractères de contrôle, et double-clic sur les boutons.
// Toutes les saisies utilisateur passent par ce module avant stockage.
const Security = (function() {
    const HTML_ENTITIES = { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;', '`':'&#96;' };

    const XSS_PATTERNS = [
        /<\s*script\b/i, /<\s*iframe\b/i, /<\s*object\b/i, /<\s*embed\b/i,
        /<\s*link\b/i, /<\s*meta\b/i, /<\s*style\b/i, /<\s*svg\b[^>]*\bon\w+/i,
        /\bjavascript\s*:/i, /\bvbscript\s*:/i, /\bdata\s*:\s*text\/html/i,
        /\bon(click|error|load|mouseover|focus|blur|submit|change|keydown|keyup|keypress)\s*=/i,
        /\bformaction\s*=/i, /\bsrcdoc\s*=/i, /expression\s*\(/i
    ];

    const SQL_PATTERNS = [
        /\b(union\s+select|select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|truncate\s+table|alter\s+table|create\s+table|exec(ute)?\s*\()/i,
        /(--\s|\/\*|\*\/)/, /'\s*or\s*'1'\s*=\s*'1/i, /\bor\s+1\s*=\s*1\b/i,
        /'\s*;\s*(drop|delete|update|insert)/i, /\bxp_cmdshell\b/i,
        /\bsleep\s*\(\s*\d+\s*\)/i, /\bbenchmark\s*\(/i, /\bload_file\s*\(/i
    ];

    function escapeHTML(str) {
        if (str == null) return '';
        return String(str).replace(/[&<>"'`]/g, ch => HTML_ENTITIES[ch]);
    }

    function detectXSS(str) {
        if (!str) return false;
        const s = String(str);
        return XSS_PATTERNS.some(rx => rx.test(s));
    }

    function detectSQLi(str) {
        if (!str) return false;
        const s = String(str);
        return SQL_PATTERNS.some(rx => rx.test(s));
    }

    function isMalicious(str) {
        return detectXSS(str) || detectSQLi(str);
    }

    function sanitizeInput(str, opts) {
        if (str == null) return '';
        opts = opts || {};
        let s = String(str);
        s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
        s = s.replace(/<[^>]*>/g, '');
        s = s.replace(/^\s*(javascript|vbscript|data)\s*:/gi, '');
        s = s.replace(/\bon\w+\s*=\s*["'][^"']*["']/gi, '');
        if (opts.trim !== false) s = s.trim();
        const max = opts.maxLength || 200;
        if (s.length > max) s = s.substring(0, max);
        return s;
    }

    function validateName(str, opts) {
        opts = opts || {};
        const field = opts.field || 'Le nom';
        if (!str) return { ok: false, error: `${field} est requis.` };
        const s = sanitizeInput(str, { maxLength: 80 });
        if (s.length < 1) return { ok: false, error: `${field} est vide après nettoyage.` };
        if (s.length > 80) return { ok: false, error: `${field} est trop long (max 80 caractères).` };
        if (isMalicious(s)) return { ok: false, error: `${field} contient des caractères interdits (XSS/SQLi).` };
        if (!/^[A-Za-zÀ-ÖØ-öø-ÿ\s'\-.]+$/.test(s)) {
            return { ok: false, error: `${field} ne doit contenir que des lettres, espaces, apostrophes, tirets ou points.` };
        }
        return { ok: true, value: s };
    }

    function validateNumber(val, opts) {
        opts = opts || {};
        const field = opts.field || 'Le nombre';
        const n = parseInt(val, 10);
        if (isNaN(n)) return { ok: false, error: `${field} doit être un nombre.` };
        if (opts.min !== undefined && n < opts.min) return { ok: false, error: `${field} doit être ≥ ${opts.min}.` };
        if (opts.max !== undefined && n > opts.max) return { ok: false, error: `${field} doit être ≤ ${opts.max}.` };
        return { ok: true, value: n };
    }

    function validateText(str, opts) {
        opts = opts || {};
        const field = opts.field || 'Le texte';
        if (!str) return { ok: true, value: '' };
        if (isMalicious(str)) return { ok: false, error: `${field} contient des éléments interdits (XSS/SQLi).` };
        const s = sanitizeInput(str, { maxLength: opts.maxLength || 200 });
        if (isMalicious(s)) return { ok: false, error: `${field} contient des éléments interdits.` };
        return { ok: true, value: s };
    }

    function protectButton(btn, ms) {
        if (!btn || btn._secProtected) return;
        btn._secProtected = true;
        const lockMs = ms || 700;
        btn.addEventListener('click', function(e) {
            if (btn._secLocked) { e.preventDefault(); e.stopImmediatePropagation(); return false; }
            btn._secLocked = true;
            btn.classList.add('btn-locked');
            setTimeout(() => { btn._secLocked = false; btn.classList.remove('btn-locked'); }, lockMs);
        }, true);
    }

    function installInputShield() {
        document.addEventListener('input', function(e) {
            const t = e.target;
            if (!t || (t.tagName !== 'INPUT' && t.tagName !== 'TEXTAREA')) return;
            if (t.type === 'password' || t.type === 'hidden' || t.type === 'file') return;
            const v = t.value;
            if (!v) { t.classList.remove('input-warn'); t.title = ''; return; }
            if (isMalicious(v)) {
                t.classList.add('input-warn');
                t.title = 'Caractères suspects détectés (XSS/SQL). Ils seront filtrés à la sauvegarde.';
            } else {
                t.classList.remove('input-warn');
                if (t.title && t.title.startsWith('Caractères suspects')) t.title = '';
            }
        }, true);

        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('button.btn-primary, button.btn-success, button.btn-danger').forEach(btn => protectButton(btn));
        });
    }

    return {
        escapeHTML, sanitizeInput, detectXSS, detectSQLi, isMalicious,
        validateName, validateNumber, validateText, protectButton, installInputShield
    };
})();

Security.installInputShield();

// ========== DEV : CONTOURNEMENT TEMPORAIRE DU LOGIN ==========
// Chantier en cours : la page de connexion va être refaite. Tant que
// DEV_SKIP_LOGIN vaut true, l'app s'ouvre directement sur le tableau de bord
// et n'importe qui y accède sans mot de passe.
//
//   >>> REMETTRE À false AVANT TOUTE MISE EN LIGNE <<<
//
// (ce bloc est à supprimer une fois la nouvelle page terminée)
const DEV_SKIP_LOGIN = true;
const DEV_SKIP_LOGIN_ROLE = 'admin'; // 'admin' ou 'administration'

// ========== LOGIN SYSTEM ==========
// LOGIN_ACCOUNTS (depuis config.local.js) fournit les hashes par défaut.
// Les hashes personnalisés par l'utilisateur sont stockés dans localStorage.
const LOGIN_ACCOUNTS = window.LOGIN_ACCOUNTS || {};
const PASSWORD_STORAGE_KEY = 'examBlanc_passwordHashes';
let currentUserRole = null;
let currentUserRoleId = null;

async function sha256Hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getStoredPasswordHashes() {
    try {
        return JSON.parse(localStorage.getItem(PASSWORD_STORAGE_KEY)) || {};
    } catch (e) { return {}; }
}

function getAccountHash(roleId) {
    const stored = getStoredPasswordHashes();
    if (stored[roleId]) return stored[roleId];
    return (LOGIN_ACCOUNTS[roleId] || {}).passwordHash;
}

function setAccountHash(roleId, hash) {
    const stored = getStoredPasswordHashes();
    stored[roleId] = hash;
    localStorage.setItem(PASSWORD_STORAGE_KEY, JSON.stringify(stored));
}

function resetAccountPasswords() {
    localStorage.removeItem(PASSWORD_STORAGE_KEY);
}

function selectLoginRole(btn) {
    document.querySelectorAll('.login-role').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
}

function toggleLoginPassword() {
    const input = document.getElementById('loginPass');
    const eye = document.getElementById('loginEye');
    if (input.type === 'password') {
        input.type = 'text';
        eye.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    } else {
        input.type = 'password';
        eye.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    }
}

async function doLogin() {
    const user = document.getElementById('loginUser').value.trim().toLowerCase();
    const pass = document.getElementById('loginPass').value;
    const roleBtn = document.querySelector('.login-role.active');
    const role = roleBtn ? roleBtn.dataset.role : 'admin';

    // Remove previous error
    const oldErr = document.querySelector('.login-error');
    if (oldErr) oldErr.remove();

    if (!LOGIN_ACCOUNTS || Object.keys(LOGIN_ACCOUNTS).length === 0) {
        showLoginError('Configuration manquante : créez app/config.local.js à partir de config.local.example.js.');
        return;
    }

    const account = LOGIN_ACCOUNTS[role];
    if (!account) { showLoginError('Rôle invalide.'); return; }
    if (!user) { showLoginError('Veuillez entrer votre identifiant.'); return; }
    if (!pass) { showLoginError('Veuillez entrer votre mot de passe.'); return; }
    const passHash = await sha256Hex(pass);
    if (user !== role || passHash !== getAccountHash(role)) {
        showLoginError('Identifiant ou mot de passe incorrect.');
        document.querySelector('.login-card').classList.add('login-shake');
        setTimeout(() => document.querySelector('.login-card').classList.remove('login-shake'), 600);
        return;
    }

    currentUserRole = account;
    currentUserRoleId = role;
    sessionStorage.setItem('examBlanc_session', JSON.stringify({ role: role, loggedIn: true }));
    logActivity(`Connexion: ${account.role}`, 'auth');

    // Animate out
    const loginPage = document.getElementById('loginPage');
    loginPage.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    loginPage.style.opacity = '0';
    loginPage.style.transform = 'scale(1.05)';
    setTimeout(() => {
        loginPage.style.display = 'none';
        document.getElementById('appWrapper').style.display = 'block';
        resetZoom();
        applyRoleAccess(role);
    }, 500);
}

// Force 100% zoom on app entry (Chromium-based browsers)
function resetZoom() {
    try {
        document.body.style.zoom = '1';
        document.documentElement.style.zoom = '1';
        // Firefox fallback (doesn't support zoom): reset via transform if previously scaled
        if (document.body.style.transform && document.body.style.transform.includes('scale')) {
            document.body.style.transform = '';
        }
    } catch(e) {}
}

function showLoginError(msg) {
    const oldErr = document.querySelector('.login-error');
    if (oldErr) oldErr.remove();
    const err = document.createElement('p');
    err.className = 'login-error';
    err.textContent = msg;
    document.querySelector('.login-btn').insertAdjacentElement('beforebegin', err);
}

function applyRoleAccess(role) {
    if (role === 'admin') {
        // Évite les doublons : retire une éventuelle bannière déjà présente.
        document.querySelectorAll('.admin-banner').forEach(el => el.remove());
        // Administrateur: full access + monitoring banner
        const banner = document.createElement('div');
        banner.className = 'admin-banner';
        banner.innerHTML = '&#128274; Mode Administrateur — Surveillance & Gestion (tous les droits)';
        document.querySelector('.content-area .header').insertAdjacentElement('afterend', banner);
    } else if (role === 'administration') {
        // Administration: working access, hide config, journal and dashboard
        const navBtns = document.querySelectorAll('#mainNav button');
        navBtns.forEach(btn => {
            const t = btn.textContent.trim();
            // dataset.roleHidden : syncModuleUI ne doit pas réafficher ces boutons
            if (t === 'Paramètres' || t === 'Journal' || t === 'Tableau de Bord') {
                btn.dataset.roleHidden = '1';
                btn.style.display = 'none';
            }
        });
        const backupBtn = document.querySelector('.btn-outline[onclick*="showBackupModal"]');
        if (backupBtn) backupBtn.style.display = 'none';
        // Redirect to students page instead of dashboard
        showPage('students');
    }
}

function checkSession() {
    // Chantier : login court-circuité, voir DEV_SKIP_LOGIN en haut du fichier.
    if (DEV_SKIP_LOGIN) {
        const role = DEV_SKIP_LOGIN_ROLE;
        // Repli si config.local.js est absent : LOGIN_ACCOUNTS est alors vide.
        currentUserRole = LOGIN_ACCOUNTS[role] || {
            role: role === 'admin' ? 'Administrateur' : 'Administration',
            access: role === 'admin' ? 'readonly' : 'full'
        };
        currentUserRoleId = role;
        document.getElementById('loginPage').style.display = 'none';
        document.getElementById('appWrapper').style.display = 'block';
        resetZoom();
        applyRoleAccess(role);
        showDevSkipLoginBadge();
        return true;
    }

    try {
        const session = JSON.parse(sessionStorage.getItem('examBlanc_session'));
        if (session && session.loggedIn) {
            currentUserRole = LOGIN_ACCOUNTS[session.role];
            currentUserRoleId = session.role;
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('appWrapper').style.display = 'block';
            resetZoom();
            applyRoleAccess(session.role);
            return true;
        }
    } catch(e) {}
    return false;
}

// Pastille de rappel : impossible d'oublier que le login est désactivé.
// Styles en inline volontairement, pour que tout parte avec le bloc DEV.
function showDevSkipLoginBadge() {
    if (document.getElementById('devSkipLoginBadge')) return;
    const badge = document.createElement('div');
    badge.id = 'devSkipLoginBadge';
    badge.textContent = 'LOGIN DÉSACTIVÉ (mode chantier)';
    badge.title = 'DEV_SKIP_LOGIN = true dans app.js — remettre à false avant mise en ligne';
    badge.style.cssText = [
        'position:fixed', 'bottom:12px', 'right:12px', 'z-index:99999',
        'background:#b91c1c', 'color:#fff', 'padding:6px 12px',
        'border-radius:999px', 'font-size:11px', 'font-weight:700',
        'letter-spacing:0.04em', 'box-shadow:0 2px 8px rgba(0,0,0,0.35)',
        'pointer-events:none', 'user-select:none'
    ].join(';');
    document.body.appendChild(badge);
}

// ========== CHANGE PASSWORD ==========
function openChangePasswordModal() {
    const modal = document.getElementById('changePasswordModal');
    if (!modal) return;
    document.getElementById('cpOldPass').value = '';
    document.getElementById('cpNewPass').value = '';
    document.getElementById('cpConfirmPass').value = '';
    const errEl = document.getElementById('cpError');
    if (errEl) { errEl.textContent = ''; errEl.style.display = 'none'; }
    const okEl = document.getElementById('cpSuccess');
    if (okEl) { okEl.textContent = ''; okEl.style.display = 'none'; }
    const lbl = document.getElementById('cpRoleLabel');
    if (lbl) lbl.textContent = (currentUserRole && currentUserRole.role) ? currentUserRole.role : '';
    modal.classList.add('show');
}

function closeChangePasswordModal() {
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.classList.remove('show');
}

function cpShowError(msg) {
    const el = document.getElementById('cpError');
    const ok = document.getElementById('cpSuccess');
    if (ok) { ok.textContent = ''; ok.style.display = 'none'; }
    if (el) { el.textContent = msg; el.style.display = 'block'; }
}

function cpShowSuccess(msg) {
    const el = document.getElementById('cpSuccess');
    const err = document.getElementById('cpError');
    if (err) { err.textContent = ''; err.style.display = 'none'; }
    if (el) { el.textContent = msg; el.style.display = 'block'; }
}

async function submitChangePassword() {
    if (!currentUserRoleId) { cpShowError('Session invalide.'); return; }
    const oldPass = document.getElementById('cpOldPass').value;
    const newPass = document.getElementById('cpNewPass').value;
    const confirm = document.getElementById('cpConfirmPass').value;

    if (!oldPass || !newPass || !confirm) { cpShowError('Tous les champs sont obligatoires.'); return; }
    if (newPass.length < 8) { cpShowError('Le nouveau mot de passe doit contenir au moins 8 caractères.'); return; }
    if (newPass !== confirm) { cpShowError('La confirmation ne correspond pas.'); return; }
    if (newPass === oldPass) { cpShowError('Le nouveau mot de passe doit être différent de l\'ancien.'); return; }

    const oldHash = await sha256Hex(oldPass);
    if (oldHash !== getAccountHash(currentUserRoleId)) {
        cpShowError('Ancien mot de passe incorrect.');
        return;
    }

    const newHash = await sha256Hex(newPass);
    setAccountHash(currentUserRoleId, newHash);
    logActivity(`Changement de mot de passe : ${currentUserRole.role}`, 'auth');
    cpShowSuccess('Mot de passe modifié avec succès.');
    setTimeout(() => closeChangePasswordModal(), 1500);
}

function logout() {
    sessionStorage.removeItem('examBlanc_session');
    currentUserRole = null;
    location.reload();
}

// Enter key to submit login
document.addEventListener('DOMContentLoaded', () => {
    const loginPass = document.getElementById('loginPass');
    if (loginPass) loginPass.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    const loginUser = document.getElementById('loginUser');
    if (loginUser) loginUser.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    updateHeaderClock();
    setInterval(updateHeaderClock, 1000);
    initTcDotMap();
});

function initTcDotMap() {
    const canvas = document.getElementById('tcDotMap');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let dots = [], W = 0, H = 0, startTime = Date.now();
    function gen(w, h) {
        const out = [], gap = 12;
        for (let x = 0; x < w; x += gap) for (let y = 0; y < h; y += gap) {
            const ok =
                (x < w*0.25 && x > w*0.05 && y < h*0.4  && y > h*0.1) ||
                (x < w*0.25 && x > w*0.15 && y < h*0.8  && y > h*0.4) ||
                (x < w*0.45 && x > w*0.30 && y < h*0.35 && y > h*0.15) ||
                (x < w*0.50 && x > w*0.35 && y < h*0.65 && y > h*0.35) ||
                (x < w*0.70 && x > w*0.45 && y < h*0.50 && y > h*0.10) ||
                (x < w*0.80 && x > w*0.65 && y < h*0.80 && y > h*0.60);
            if (ok && Math.random() > 0.3) out.push({x,y,o:Math.random()*0.5+0.1});
        }
        return out;
    }
    function resize() {
        const r = canvas.parentElement.getBoundingClientRect();
        W = Math.max(1, r.width); H = Math.max(1, r.height);
        canvas.width = W; canvas.height = H;
        dots = gen(W, H);
    }
    const routes = [
        { s:[0.31,0.25], e:[0.63,0.13], d:0 },
        { s:[0.63,0.13], e:[0.81,0.20], d:2 },
        { s:[0.16,0.08], e:[0.47,0.30], d:1 },
        { s:[0.88,0.10], e:[0.56,0.30], d:0.5 },
    ];
    function draw() {
        ctx.clearRect(0,0,W,H);
        for (const d of dots) {
            ctx.beginPath(); ctx.arc(d.x,d.y,1,0,Math.PI*2);
            ctx.fillStyle = `rgba(255,255,255,${d.o})`; ctx.fill();
        }
        const t = (Date.now()-startTime)/1000;
        for (const r of routes) {
            const e = t - r.d; if (e <= 0) continue;
            const p = Math.min(e/3, 1);
            const sx = r.s[0]*W, sy = r.s[1]*H, ex = r.e[0]*W, ey = r.e[1]*H;
            const x = sx+(ex-sx)*p, y = sy+(ey-sy)*p;
            ctx.beginPath(); ctx.moveTo(sx,sy); ctx.lineTo(x,y);
            ctx.strokeStyle = '#B8A67A'; ctx.lineWidth = 1.5; ctx.stroke();
            ctx.beginPath(); ctx.arc(sx,sy,3,0,Math.PI*2); ctx.fillStyle='#B8A67A'; ctx.fill();
            ctx.beginPath(); ctx.arc(x,y,3,0,Math.PI*2); ctx.fillStyle='#d4c4a8'; ctx.fill();
            ctx.beginPath(); ctx.arc(x,y,6,0,Math.PI*2); ctx.fillStyle='rgba(212,196,168,0.3)'; ctx.fill();
            if (p === 1) { ctx.beginPath(); ctx.arc(ex,ey,3,0,Math.PI*2); ctx.fillStyle='#B8A67A'; ctx.fill(); }
        }
        if (t > 15) startTime = Date.now();
        requestAnimationFrame(draw);
    }
    resize(); window.addEventListener('resize', resize); draw();
}

let _clockDateKey = '';
function updateHeaderClock() {
    const timeEl = document.getElementById('clockTime');
    const dateEl = document.getElementById('clockDate');
    if (!timeEl || !dateEl) return;
    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    timeEl.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    // La date ne change qu'une fois par jour : on évite de recalculer
    // toLocaleDateString à chaque seconde (texte identique, juste mémoïsé).
    const dateKey = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}`;
    if (dateKey !== _clockDateKey) {
        _clockDateKey = dateKey;
        try {
            dateEl.textContent = now.toLocaleDateString('fr-FR', { weekday: 'short', day: '2-digit', month: 'short', year: 'numeric' });
        } catch (e) {
            dateEl.textContent = `${pad(now.getDate())}/${pad(now.getMonth() + 1)}/${now.getFullYear()}`;
        }
    }
}

// ========== TOAST SYSTEM ==========
function toast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toastContainer');
    const icons = { success: '\u2713', error: '\u2717', info: '\u2139', warning: '\u26A0' };
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span class="toast-icon">${icons[type] || ''}</span><span>${message}</span><button class="toast-close" onclick="this.parentElement.remove()">\u2715</button>`;
    container.appendChild(el);
    setTimeout(() => { el.classList.add('hiding'); setTimeout(() => el.remove(), 300); }, duration);
}

// ========== CONFIRM DIALOG ==========
function showConfirm(title, message, onConfirm) {
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMsg').textContent = message;
    const btn = document.getElementById('confirmBtn');
    btn.onclick = () => { closeModal('confirmModal'); onConfirm(); };
    document.getElementById('confirmModal').classList.add('show');
}

// ========== SIDEBAR ==========
function toggleSidebar() {
    const sb = document.getElementById('sidebar');
    const bd = document.getElementById('sidebarBackdrop');
    const shell = document.getElementById('appShell');
    if (!sb) return;
    if (window.innerWidth <= 900) {
        sb.classList.toggle('open');
        bd.classList.toggle('show');
    } else {
        shell.classList.toggle('collapsed');
        localStorage.setItem('examBlanc_sidebar', shell.classList.contains('collapsed') ? 'collapsed' : 'expanded');
    }
}
function loadSidebarState() {
    if (localStorage.getItem('examBlanc_sidebar') === 'collapsed' && window.innerWidth > 900) {
        document.getElementById('appShell')?.classList.add('collapsed');
    }
}

// ========== DARK MODE ==========
function toggleDarkMode() {
    const html = document.documentElement;
    const isDark = html.getAttribute('data-theme') === 'dark';
    html.setAttribute('data-theme', isDark ? 'light' : 'dark');
    document.getElementById('darkToggle').innerHTML = isDark ? '&#9790;' : '&#9788;';
    localStorage.setItem('examBlanc_theme', isDark ? 'light' : 'dark');
}
function loadTheme() {
    const theme = localStorage.getItem('examBlanc_theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    document.getElementById('darkToggle').innerHTML = theme === 'dark' ? '&#9788;' : '&#9790;';
}

// ========== DATA ==========
const STORAGE_KEY = 'examBlanc_v2';
const LEVELS = {
    // CFEE blanc — fin du cycle élémentaire (CM2).
    // Grille et seuils par défaut, modifiables dans Paramètres : à confirmer
    // avec les textes officiels de l'IEF avant usage en délibération réelle.
    // Le CFEE n'a pas de second tour officiel ; les pages « 2ème Tour »
    // peuvent servir de rattrapage interne à l'établissement.
    cfeeCM2: {
        label: 'CFEE Blanc - CM2', shortLabel: 'CM2', examLabel: 'CFEE BLANC', className: 'CM2',
        subjects: [
            { name: 'Rédaction', code: 'RED', coef: 2 },
            { name: 'Dictée', code: 'DIC', coef: 1 },
            { name: 'Questions', code: 'QUE', coef: 1 },
            { name: 'Calcul', code: 'CAL', coef: 1 },
            { name: 'Problème', code: 'PB', coef: 2 },
            { name: 'Étude du milieu', code: 'EDM', coef: 2 }
        ],
        subjects2: [
            { name: 'Rédaction', code: 'RED', coef: 2 },
            { name: 'Dictée', code: 'DIC', coef: 1 },
            { name: 'Questions', code: 'QUE', coef: 1 },
            { name: 'Calcul', code: 'CAL', coef: 1 },
            { name: 'Problème', code: 'PB', coef: 2 },
            { name: 'Étude du milieu', code: 'EDM', coef: 2 }
        ],
        seuilAdmis: 90, seuil2eTour: 72, seuilAdmis2: 90, coefTotal: 9, coefTotal2: 9, anoPrefix: 'E'
    },
    bfem3: {
        label: 'BFEM Blanc - 3ème', shortLabel: '3ème', examLabel: 'EXAMEN BLANC', className: '3ème',
        subjects: [
            { name: 'Comp. Française', code: 'CF', coef: 2 },
            { name: 'Dictée', code: 'DIC', coef: 1 },
            { name: 'T.S.Q.', code: 'TSQ', coef: 1 },
            { name: 'E.C.', code: 'EC', coef: 1 },
            { name: 'H.G.', code: 'HG', coef: 2 },
            { name: 'Anglais', code: 'ANG', coef: 2 },
            { name: 'Maths', code: 'MATH', coef: 3 },
            { name: 'P.C.', code: 'PC', coef: 2 },
            { name: 'S.V.T.', code: 'SVT', coef: 2 },
            { name: 'Espagnol', code: 'ESP', coef: 2 },
            { name: 'Oral Anglais', code: 'OA', coef: 1 },
            { name: 'E.P.S.', code: 'EPS', coef: 2 }
        ],
        subjects2: [
            { name: 'T.S.Q.', code: 'TSQ', coef: 3 },
            { name: 'Maths', code: 'MATH', coef: 3 },
            { name: 'P.C.', code: 'PC', coef: 2 },
            { name: 'Espagnol', code: 'ESP', coef: 2 }
        ],
        seuilAdmis: 210, seuil2eTour: 168, seuilAdmis2: 100, coefTotal: 21, coefTotal2: 10, anoPrefix: 'P'
    },
    bacTS: {
        label: 'BAC Blanc - Terminale S', shortLabel: 'Tle S', examLabel: 'BAC BLANC', className: 'Terminale S',
        subjects: [
            { name: 'LM', code: 'LM', coef: 3 },
            { name: 'H.G.', code: 'HG', coef: 2 },
            { name: 'Maths', code: 'MATH', coef: 5 },
            { name: 'S.P.', code: 'SP', coef: 6 },
            { name: 'S.V.T.', code: 'SVT', coef: 6 },
            { name: 'Philo', code: 'PHILO', coef: 2 },
            { name: 'Anglais', code: 'ANG', coef: 2 },
            { name: 'E.P.S.', code: 'EPS', coef: 1 }
        ],
        subjects2: [
            { name: 'LM', code: 'LM', coef: 3 }, { name: 'H.G.', code: 'HG', coef: 2 },
            { name: 'Maths', code: 'MATH', coef: 5 }, { name: 'S.P.', code: 'SP', coef: 6 },
            { name: 'S.V.T.', code: 'SVT', coef: 6 }, { name: 'Philo', code: 'PHILO', coef: 2 },
            { name: 'Anglais', code: 'ANG', coef: 2 }, { name: 'E.P.S.', code: 'EPS', coef: 1 }
        ],
        seuilAdmis: 270, seuil2eTour: 216, seuilAdmis2: 270, coefTotal: 27, coefTotal2: 27, anoPrefix: 'Q'
    },
    bacTL2: {
        label: 'BAC Blanc - Terminale L2', shortLabel: 'Tle L2', examLabel: 'BAC BLANC', className: 'Terminale L2',
        subjects: [
            { name: 'LM', code: 'LM', coef: 5 },
            { name: 'H.G.', code: 'HG', coef: 6 },
            { name: 'Maths', code: 'MATH', coef: 2 },
            { name: 'SVT/PC', code: 'SPC', coef: 2 },
            { name: 'LV1', code: 'LV1', coef: 4 },
            { name: 'LV2/EG', code: 'LV2', coef: 2 },
            { name: 'Philo', code: 'PHILO', coef: 6 },
            { name: 'E.P.S.', code: 'EPS', coef: 1 }
        ],
        subjects2: [
            { name: 'LM', code: 'LM', coef: 5 }, { name: 'H.G.', code: 'HG', coef: 6 },
            { name: 'Maths', code: 'MATH', coef: 2 }, { name: 'SVT/PC', code: 'SPC', coef: 2 },
            { name: 'LV1', code: 'LV1', coef: 4 }, { name: 'LV2/EG', code: 'LV2', coef: 2 },
            { name: 'Philo', code: 'PHILO', coef: 6 }, { name: 'E.P.S.', code: 'EPS', coef: 1 }
        ],
        seuilAdmis: 280, seuil2eTour: 224, seuilAdmis2: 280, coefTotal: 28, coefTotal2: 28, anoPrefix: 'N'
    }
};

let currentLevel = 'bfem3';
let currentPage = 'dashboard';
// ========== MODULES (structure CRM multi-espaces) ==========
// Chaque module a sa propre navigation ; les pages "Système" sont communes.
const MODULES = {
    examens: { label: 'Examens Blancs', home: 'dashboard', pages: ['dashboard', 'students', 'grades1', 'results1', 'grades2', 'results2', 'stats', 'documents'] },
    ecole:   { label: 'École',          home: 'ecole',     pages: ['ecole', 'classes', 'espaceEleve', 'alertes', 'sortants', 'matieres', 'presences', 'cahierTexte', 'notesBulletins', 'professeurs', 'emploiTemps'] },
    admin:   { label: 'Administration', home: 'personnel', pages: ['personnel'] },
    compta:  { label: 'Comptabilité',   home: 'compta',    pages: ['compta', 'inscriptions', 'paiements', 'journalCaisse', 'depenses'] }
};
const SYSTEM_PAGES = ['journal', 'aichat', 'config'];

// Modules retirés de la barre latérale le temps du chantier. Le code et les
// pages restent intacts : vider le tableau suffit à tout réafficher.
const HIDDEN_MODULES = ['compta'];

function isModuleHidden(m) {
    return HIDDEN_MODULES.includes(m);
}

function applyHiddenModules() {
    HIDDEN_MODULES.forEach(m => {
        document.querySelectorAll(`#mainNav .nav-group[data-module="${m}"]`).forEach(g => {
            g.style.display = 'none';
        });
    });
}

let currentModule = 'examens';
// Niveaux du système éducatif sénégalais, de l'élémentaire au lycée.
const CLASSE_NIVEAUX = [
    'CI', 'CP', 'CE1', 'CE2', 'CM1', 'CM2',
    '6ème', '5ème', '4ème', '3ème',
    'Seconde', 'Première', 'Terminale'
];

// Trois cycles pédagogiques, chacun avec son responsable ;
// le directeur gère l'ensemble de l'établissement.
// `chef` désigne la clé correspondante dans ec.direction.
const CYCLES = {
    elementaire: {
        label: 'Cycle Élémentaire', sub: 'CI – CM2', chef: 'directeurElementaire', chefLabel: 'Directeur d\'école',
        niveaux: ['CI', 'CP', 'CE1', 'CE2', 'CM1', 'CM2']
    },
    moyen: {
        label: 'Cycle Moyen', sub: '6ème – 3ème', chef: 'prefetMoyen', chefLabel: 'Préfet',
        niveaux: ['6ème', '5ème', '4ème', '3ème']
    },
    secondaire: {
        label: 'Cycle Secondaire', sub: 'Seconde – Terminale', chef: 'prefetSecondaire', chefLabel: 'Préfet',
        niveaux: ['Seconde', 'Première', 'Terminale']
    }
};

function cycleOfNiveau(niveau) {
    const found = Object.keys(CYCLES).find(cy => CYCLES[cy].niveaux.includes(niveau));
    return found || 'moyen';
}

// Responsable d'un cycle (directeur d'école au primaire, préfet ensuite).
function chefOfCycle(ec, cy) {
    const cycle = CYCLES[cy];
    if (!cycle || !ec || !ec.direction) return '';
    return ec.direction[cycle.chef] || '';
}

// Matières des bulletins, par cycle (modifiables dans Matières & Coefficients).
// Un bulletin de CE1 n'a rien à voir avec un bulletin de Terminale : chaque
// cycle a donc sa propre grille. Ce sont des valeurs de départ, pas une norme.
const ECOLE_MATIERES_PAR_CYCLE = {
    elementaire: [
        { nom: 'Lecture', code: 'LEC', coef: 1 },
        { nom: 'Expression écrite', code: 'EXE', coef: 2 },
        { nom: 'Grammaire / Orthographe', code: 'GRA', coef: 1 },
        { nom: 'Mathématiques', code: 'MATH', coef: 2 },
        { nom: 'Étude du milieu', code: 'EDM', coef: 1 },
        { nom: 'Éducation civique et morale', code: 'ECM', coef: 1 },
        { nom: 'Anglais', code: 'ANG', coef: 1 },
        { nom: 'E.P.S.', code: 'EPS', coef: 1 },
        { nom: 'Éducation artistique', code: 'ART', coef: 1 }
    ],
    moyen: [
        { nom: 'Français', code: 'FR', coef: 1 },
        { nom: 'Maths', code: 'MATH', coef: 1 },
        { nom: 'Anglais', code: 'ANG', coef: 1 },
        { nom: 'Histoire et Géo', code: 'HG', coef: 1 },
        { nom: 'S.V.T.', code: 'SVT', coef: 1 },
        { nom: 'P.C.', code: 'PC', coef: 1 },
        { nom: 'Éducation civique', code: 'EC', coef: 1 },
        { nom: 'Informatique', code: 'INFO', coef: 1 },
        { nom: 'Morale et Catéchèse', code: 'MOR', coef: 1 },
        { nom: 'E.P.S.', code: 'EPS', coef: 1 }
    ],
    secondaire: [
        { nom: 'Lettres / Français', code: 'LM', coef: 1 },
        { nom: 'Maths', code: 'MATH', coef: 1 },
        { nom: 'Sciences Physiques', code: 'SP', coef: 1 },
        { nom: 'S.V.T.', code: 'SVT', coef: 1 },
        { nom: 'Histoire et Géo', code: 'HG', coef: 1 },
        { nom: 'Philosophie', code: 'PHILO', coef: 1 },
        { nom: 'Anglais', code: 'ANG', coef: 1 },
        { nom: 'LV2', code: 'LV2', coef: 1 },
        { nom: 'Économie', code: 'ECO', coef: 1 },
        { nom: 'Informatique', code: 'INFO', coef: 1 },
        { nom: 'Morale et Catéchèse', code: 'MOR', coef: 1 },
        { nom: 'E.P.S.', code: 'EPS', coef: 1 }
    ]
};

// Grille des matières d'un cycle, puis d'une classe donnée.
function matieresOfCycle(ec, cy) {
    const grilles = (ec && ec.matieres) || {};
    return Array.isArray(grilles[cy]) ? grilles[cy] : [];
}

function matieresOfClasse(ec, classe) {
    return matieresOfCycle(ec, cycleOfNiveau(classe && classe.niveau));
}
const TRIMESTRES = { t1: '1er Trimestre', t2: '2ème Trimestre', t3: '3ème Trimestre' };

// Grille hebdomadaire des emplois du temps
const EDT_JOURS = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
const EDT_CRENEAUX = ['08h-09h', '09h-10h', '10h-11h', '11h-12h', '12h-13h', '15h-16h', '16h-17h', '17h-18h'];
function edtKey(jour, creneau) { return jour + '|' + creneau; }

function moduleOfPage(pageId) {
    return Object.keys(MODULES).find(m => MODULES[m].pages.includes(pageId)) || null;
}

// Ouvre le groupe accordéon du module actif (les autres se replient),
// sans naviguer. Les en-têtes de groupe restent tous visibles.
function syncModuleUI(m) {
    // Un module masqué ne doit pas non plus revenir via localStorage.
    if (!MODULES[m] || isModuleHidden(m)) m = 'examens';
    currentModule = m;
    try { localStorage.setItem('examBlanc_module', m); } catch(e) {}
    document.querySelectorAll('#mainNav .nav-group').forEach(g => {
        g.classList.toggle('open', g.dataset.module === m);
    });
}

function showModule(m) {
    syncModuleUI(m);
    showPage(MODULES[currentModule].home);
}

let appData = {
    year: '2025-2026',
    school: { name: 'Collège Jean XXIII', ia: 'Tambacounda', ief: 'Tambacounda', dates: '', principal: '' },
    levels: {}
};

function getLevelData() {
    if (!appData.levels[currentLevel]) {
        const cfg = LEVELS[currentLevel];
        appData.levels[currentLevel] = {
            subjects: JSON.parse(JSON.stringify(cfg.subjects)),
            subjects2: JSON.parse(JSON.stringify(cfg.subjects2)),
            seuilAdmis: cfg.seuilAdmis,
            seuil2eTour: cfg.seuil2eTour,
            seuilAdmis2: cfg.seuilAdmis2,
            coefTotal: cfg.coefTotal,
            coefTotal2: cfg.coefTotal2,
            students: [],
            grades1: {},
            grades2: {},
            results1: [],
            results2: [],
            tour2Students: []
        };
    }
    return appData.levels[currentLevel];
}

// ========== DEBOUNCED AUTOSAVE ==========
let saveTimeout = null;
function debouncedSave() {
    clearTimeout(saveTimeout);
    const indicator = document.getElementById('autosaveIndicator');
    indicator.classList.add('show');
    saveTimeout = setTimeout(() => {
        saveData();
        setTimeout(() => indicator.classList.remove('show'), 800);
    }, 600);
}

// ========== LEVEL SELECTION ==========
function selectLevel(level) {
    if (currentLevel !== level) {
        // Changement de niveau : chaque niveau a ses propres élèves, on repart
        // donc d'une vue propre (ordre alphabétique canonique) et d'une
        // recherche vide pour ne pas mélanger les contextes.
        studentViewOrder = null;
        const searchEl = document.getElementById('studentSearch');
        if (searchEl) searchEl.value = '';
    }
    currentLevel = level;
    document.querySelectorAll('.level-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('lvl-' + level).classList.add('active');
    updateLevelTags();
    refreshCurrentPage();
}

function updateLevelTags() {
    const cfg = LEVELS[currentLevel];
    document.querySelectorAll('[id^="levelTag"]').forEach(el => { if (el) el.textContent = cfg.shortLabel; });
    document.getElementById('configLevelName').textContent = cfg.label;
    Object.keys(LEVELS).forEach(lv => {
        const d = appData.levels[lv];
        document.getElementById('count-' + lv).textContent = d ? d.students.length : 0;
    });
}

// ========== NAVIGATION ==========
function showPage(pageId) {
    // Dashboard réservé à l'administrateur
    if (pageId === 'dashboard' && currentUserRole && currentUserRole.access !== 'readonly') {
        pageId = 'students';
    }
    currentPage = pageId;
    // Si la page appartient à un autre module, on bascule le commutateur en conséquence
    const mod = moduleOfPage(pageId);
    if (mod && mod !== currentModule) syncModuleUI(mod);
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    // Boutons de page uniquement (pas les en-têtes de groupe de modules)
    document.querySelectorAll('#mainNav button[data-page]').forEach(b => b.classList.remove('active'));
    document.getElementById('page-' + pageId).classList.add('active');
    const navBtn = document.querySelector(`#mainNav button[data-page="${pageId}"]`);
    if (navBtn) navBtn.classList.add('active');
    // La barre NIVEAU (3ème / Tle S / Tle L2) ne concerne que le module Examens
    // (et les pages Système qui l'utilisaient déjà).
    const levelBar = document.querySelector('.level-bar');
    if (levelBar) levelBar.style.display = (mod === null || mod === 'examens') ? '' : 'none';
    if (window.innerWidth <= 900) { document.getElementById('sidebar')?.classList.remove('open'); document.getElementById('sidebarBackdrop')?.classList.remove('show'); }
    refreshCurrentPage();
}

function refreshCurrentPage() {
    updateLevelTags();
    if (currentPage === 'dashboard') renderDashboard();
    if (currentPage === 'students') renderStudentsTable();
    if (currentPage === 'grades1') renderGrades1Table();
    if (currentPage === 'grades2') renderGrades2Table();
    if (currentPage === 'results1') showResults1Tab('all');
    if (currentPage === 'results2') showResults2Tab('all');
    if (currentPage === 'stats') renderStats('current');
    if (currentPage === 'documents') {}
    if (currentPage === 'journal') renderJournal();
    if (currentPage === 'config') renderConfigPage();
    if (currentPage === 'ecole') renderEcolePage();
    if (currentPage === 'classes') renderClassesPage();
    if (currentPage === 'espaceEleve') renderEspaceElevePage();
    if (currentPage === 'alertes') renderAlertesPage();
    if (currentPage === 'sortants') renderSortantsPage();
    if (currentPage === 'cahierTexte') renderCahierTextePage();
    if (currentPage === 'professeurs') renderProfsTable();
    if (currentPage === 'matieres') renderEcoleMatieres();
    if (currentPage === 'presences') renderPresencesPage();
    if (currentPage === 'notesBulletins') renderNotesBulletinsPage();
    if (currentPage === 'emploiTemps') renderEmploiTempsPage();
    if (currentPage === 'personnel') renderPersonnelTable();
    if (currentPage === 'compta') renderComptaDashboard();
    if (currentPage === 'inscriptions') renderInscriptionsPage();
    if (currentPage === 'paiements') renderPaiementsPage();
    if (currentPage === 'journalCaisse') renderJournalCaissePage();
    if (currentPage === 'depenses') renderDepensesPage();
    updateInscriptionsBadge();
}

// ========== STUDENTS ==========
// View-only display order: null = canonical (alphabetical, stored) order ;
// array of real indices = temporary view (e.g. sorted by table number) without mutating ld.students.
let studentViewOrder = null;

function renderStudentsTable() {
    const ld = getLevelData();
    const searchEl = document.getElementById('studentSearch');
    const search = searchEl ? searchEl.value.toLowerCase().trim() : '';
    const tbody = document.querySelector('#studentsTable tbody');
    tbody.innerHTML = '';
    let displayed = 0;
    // Build the iteration list: either the canonical order, or the temporary view order (mapping to real indices).
    const indices = (studentViewOrder && studentViewOrder.length === ld.students.length)
        ? studentViewOrder
        : ld.students.map((_, i) => i);
    indices.forEach(i => {
        const s = ld.students[i];
        if (!s) return;
        if (search && !(`${s.prenom} ${s.nom} ${s.numTable} ${s.anonymat || ''}`).toLowerCase().includes(search)) return;
        displayed++;
        const tr = document.createElement('tr');
        const isInapte = s.inapteEPS || false;
        const sexeTag = s.sexe === 'F' ? '<span class="sexe-tag sexe-f">F</span>' : '<span class="sexe-tag sexe-m">M</span>';
        tr.innerHTML = `<td>${Security.escapeHTML(s.numTable)}</td><td><span class="ano-tag">${Security.escapeHTML(s.anonymat || '-')}</span></td>
            <td style="text-align:left;">${Security.escapeHTML(s.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(s.nom)}</td>
            <td>${sexeTag}</td>
            <td class="no-print"><label class="inapte-toggle"><input type="checkbox" ${isInapte ? 'checked' : ''} onchange="toggleInapteEPS(${i}, this.checked)"><span class="inapte-label">${isInapte ? 'Oui' : 'Non'}</span></label></td>
            <td class="no-print"><button class="btn btn-primary btn-sm" onclick="editStudent(${i})">Modifier</button>
            <button class="btn btn-danger btn-sm" onclick="confirmDeleteStudent(${i})">Supprimer</button></td>`;
        tbody.appendChild(tr);
    });
    document.getElementById('studentCount').textContent = ld.students.length + (search ? ` (${displayed} affiché(s))` : '');
}

function toggleInapteEPS(idx, checked) {
    const ld = getLevelData();
    const st = ld.students[idx];
    st.inapteEPS = checked;
    const k = stKey(st);
    // Sync grades: set/remove INAPTE for EPS in both tours
    if (checked) {
        if (!ld.grades1[k]) ld.grades1[k] = {};
        ld.grades1[k]['EPS'] = 'INAPTE';
        if (!ld.grades2[k]) ld.grades2[k] = {};
        ld.grades2[k]['EPS'] = 'INAPTE';
    } else {
        if (ld.grades1[k] && ld.grades1[k]['EPS'] === 'INAPTE') ld.grades1[k]['EPS'] = '';
        if (ld.grades2[k] && ld.grades2[k]['EPS'] === 'INAPTE') ld.grades2[k]['EPS'] = '';
    }
    renderStudentsTable();
    saveData();
}

function toggleInapteFromGrade(studentIdx, checked, tour) {
    const ld = getLevelData();
    const students = tour === 1 ? ld.students : (ld.tour2Students || []);
    const st = students[studentIdx];
    if (!st) return;
    // Find the student in main list to set inapteEPS property
    const mainIdx = ld.students.findIndex(s => stKey(s) === stKey(st));
    if (mainIdx !== -1) ld.students[mainIdx].inapteEPS = checked;
    const k = stKey(st);
    if (checked) {
        if (!ld.grades1[k]) ld.grades1[k] = {};
        ld.grades1[k]['EPS'] = 'INAPTE';
        if (!ld.grades2[k]) ld.grades2[k] = {};
        ld.grades2[k]['EPS'] = 'INAPTE';
    } else {
        if (ld.grades1[k] && ld.grades1[k]['EPS'] === 'INAPTE') ld.grades1[k]['EPS'] = '';
        if (ld.grades2[k] && ld.grades2[k]['EPS'] === 'INAPTE') ld.grades2[k]['EPS'] = '';
    }
    if (tour === 1) renderGrades1Table(); else renderGrades2Table();
    saveData();
}

let selectedSexe = 'M';
function selectSexe(s) {
    selectedSexe = s;
    document.querySelectorAll('.btn-sexe').forEach(b => b.classList.toggle('active', b.dataset.sexe === s));
}

function showAddStudentModal() {
    const ld = getLevelData();
    document.getElementById('editStudentIdx').value = -1;
    document.getElementById('studentModalTitle').textContent = 'Ajouter un élève (' + LEVELS[currentLevel].shortLabel + ')';
    document.getElementById('studentNumTable').value = ld.students.length + 1;
    document.getElementById('studentPrenom').value = '';
    document.getElementById('studentNom').value = '';
    selectSexe('M');
    document.getElementById('studentModal').classList.add('show');
    setTimeout(() => document.getElementById('studentPrenom').focus(), 200);
}

function editStudent(idx) {
    const s = getLevelData().students[idx];
    document.getElementById('editStudentIdx').value = idx;
    document.getElementById('studentModalTitle').textContent = 'Modifier l\'élève';
    document.getElementById('studentNumTable').value = s.numTable;
    document.getElementById('studentPrenom').value = s.prenom;
    document.getElementById('studentNom').value = s.nom;
    selectSexe(s.sexe || 'M');
    document.getElementById('studentModal').classList.add('show');
}

function saveStudent() {
    const ld = getLevelData();
    const idx = parseInt(document.getElementById('editStudentIdx').value);
    const numCheck = Security.validateNumber(document.getElementById('studentNumTable').value, { min: 1, max: 9999, field: 'Le numéro de table' });
    if (!numCheck.ok) { toast(numCheck.error, 'error'); return; }
    const numTable = numCheck.value;
    const prenomCheck = Security.validateName(document.getElementById('studentPrenom').value, { field: 'Le prénom' });
    if (!prenomCheck.ok) { toast(prenomCheck.error, 'error', 5000); return; }
    const nomCheck = Security.validateName(document.getElementById('studentNom').value, { field: 'Le nom' });
    if (!nomCheck.ok) { toast(nomCheck.error, 'error', 5000); return; }
    const prenom = prenomCheck.value;
    const nom = nomCheck.value.toUpperCase();
    const duplicate = ld.students.findIndex((s, i) => s && s.numTable === numTable && i !== idx);
    if (duplicate !== -1) { toast(`Le numéro de table ${numTable} est déjà attribué à ${ld.students[duplicate].prenom} ${ld.students[duplicate].nom}.`, 'warning', 5000); return; }
    if (idx === -1) {
        ld.students.push({ numTable, prenom, nom, anonymat: '', sexe: selectedSexe });
        toast(`${prenom} ${nom} ajouté(e) !`, 'success');
        logActivity(`Élève ajouté : ${prenom} ${nom} (${LEVELS[currentLevel].shortLabel})`, 'eleve');
    } else {
        // Les notes sont indexées par stKey (numTable + nom). Si l'un des deux change,
        // on migre les notes des deux tours et les clés des résultats déjà calculés,
        // sinon elles deviendraient orphelines (perte silencieuse).
        const oldKey = stKey(ld.students[idx]);
        ld.students[idx].numTable = numTable; ld.students[idx].prenom = prenom; ld.students[idx].nom = nom; ld.students[idx].sexe = selectedSexe;
        const newKey = stKey(ld.students[idx]);
        if (newKey !== oldKey) {
            if (ld.grades1[oldKey]) { ld.grades1[newKey] = ld.grades1[oldKey]; delete ld.grades1[oldKey]; }
            if (ld.grades2[oldKey]) { ld.grades2[newKey] = ld.grades2[oldKey]; delete ld.grades2[oldKey]; }
            (ld.results1 || []).forEach(r => { if (r.key === oldKey) r.key = newKey; });
            (ld.results2 || []).forEach(r => { if (r.key === oldKey) r.key = newKey; });
        }
        toast('Élève modifié(e).', 'success');
    }
    sortStudentsAlpha(ld);
    studentViewOrder = null;
    closeModal('studentModal');
    renderStudentsTable();
    updateLevelTags();
    saveData();
}

function confirmDeleteStudent(idx) {
    const s = getLevelData().students[idx];
    showConfirm('Supprimer cet élève ?', `Voulez-vous vraiment supprimer ${s.prenom} ${s.nom} ?`, () => deleteStudent(idx));
}

function deleteStudent(idx) {
    const s = getLevelData().students[idx];
    getLevelData().students.splice(idx, 1);
    studentViewOrder = null;
    renderStudentsTable();
    updateLevelTags();
    saveData();
    toast(`${s.prenom} ${s.nom} supprimé(e).`, 'info');
}

// Canonical alphabetical sort — MUTATES ld.students. The stored/reference order
// is ALWAYS alphabetical (this is the "liste de classe" used as reference).
function sortStudentsAlpha(ld) {
    ld = ld || getLevelData();
    // Robustesse : une entrée null/corrompue ou un nom non-textuel (sauvegarde JSON
    // restaurée à la main, localStorage abîmé) faisait planter le comparateur. Le tri
    // était alors ABANDONNÉ : la liste restait dans l'ordre d'insertion et chaque nouvel
    // élève s'empilait en bas au lieu de se placer alphabétiquement. On purge donc les
    // entrées invalides et on force les clés de tri en chaîne pour ne jamais lever d'exception.
    ld.students = (ld.students || []).filter(s => s && typeof s === 'object');
    ld.students.sort((a, b) => {
        const nomCmp = String(a.nom || '').localeCompare(String(b.nom || ''), 'fr', { sensitivity: 'base' });
        if (nomCmp !== 0) return nomCmp;
        return String(a.prenom || '').localeCompare(String(b.prenom || ''), 'fr', { sensitivity: 'base' });
    });
}

// "Trier par n° de table" = VUE TEMPORAIRE uniquement. Ne modifie pas la liste
// stockée (qui reste alphabétique). Revient à l'ordre alphabétique dès qu'on
// ajoute/modifie/supprime/importe/rafraîchit.
function sortStudentsByNumTable() {
    const ld = getLevelData();
    if (!ld.students.length) return;
    studentViewOrder = ld.students
        .map((s, i) => i)
        .sort((a, b) => {
            const an = String(ld.students[a].numTable || '');
            const bn = String(ld.students[b].numTable || '');
            return an.localeCompare(bn, 'fr', { numeric: true, sensitivity: 'base' });
        });
    renderStudentsTable();
    toast('Vue triée par n° de table (la liste de classe reste alphabétique).', 'info');
}

// "Trier A → Z" = retour à la vue canonique alphabétique (aucune mutation nécessaire
// car ld.students est déjà trié alphabétiquement en permanence).
function sortStudentsByAlpha() {
    const ld = getLevelData();
    sortStudentsAlpha(ld); // no-op si déjà trié, garantit l'ordre
    studentViewOrder = null;
    renderStudentsTable();
    toast('Ordre alphabétique (liste de classe).', 'success');
}

function generateAnonymats() {
    const ld = getLevelData();
    if (ld.students.length === 0) { toast('Veuillez d\'abord ajouter des élèves.', 'warning'); return; }
    const prefix = LEVELS[currentLevel].anoPrefix;
    const nums = [...Array(ld.students.length).keys()];
    for (let i = nums.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [nums[i], nums[j]] = [nums[j], nums[i]]; }
    ld.students.forEach((s, i) => s.anonymat = prefix + (nums[i] + 1));
    renderStudentsTable();
    saveData();
    toast(`${ld.students.length} anonymat(s) généré(s) !`, 'success');
}

function importStudentsCSV() { document.getElementById('csvData').value = ''; document.getElementById('csvModal').classList.add('show'); }

function processCsvImport() {
    const ld = getLevelData();
    const data = document.getElementById('csvData').value.trim();
    let sep = document.getElementById('csvSep').value;
    if (sep === '\\t') sep = '\t';
    if (!data) { toast('Aucune donnée.', 'error'); return; }
    let count = 0, rejected = 0;
    data.split('\n').forEach(line => {
        const p = line.trim().split(sep);
        let numTable, rawPrenom, rawNom;
        if (p.length >= 3) {
            numTable = parseInt(p[0]) || (ld.students.length + 1);
            rawPrenom = p[1]; rawNom = p[2];
        } else if (p.length === 2) {
            numTable = ld.students.length + 1;
            rawPrenom = p[0]; rawNom = p[1];
        } else {
            return;
        }
        const prenomCheck = Security.validateName(rawPrenom, { field: 'Prénom' });
        const nomCheck = Security.validateName(rawNom, { field: 'Nom' });
        if (!prenomCheck.ok || !nomCheck.ok) { rejected++; return; }
        ld.students.push({
            numTable: numTable,
            prenom: prenomCheck.value,
            nom: nomCheck.value.toUpperCase(),
            anonymat: ''
        });
        count++;
    });
    sortStudentsAlpha(ld);
    studentViewOrder = null;
    closeModal('csvModal');
    renderStudentsTable();
    updateLevelTags();
    saveData();
    const msg = rejected > 0
        ? `${count} élève(s) importé(s) — ${rejected} ligne(s) rejetée(s) (caractères invalides).`
        : `${count} élève(s) importé(s) dans ${LEVELS[currentLevel].shortLabel} !`;
    toast(msg, rejected > 0 ? 'warning' : 'success', 5000);
    logActivity(`${count} élèves importés par CSV (${LEVELS[currentLevel].shortLabel})${rejected ? ', ' + rejected + ' rejetés' : ''}`, 'import');
}

// ========== EXCEL IMPORT ==========
let xlsxWorkbook = null;

function handleExcelFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (typeof XLSX === 'undefined') { toast('Bibliothèque Excel non chargée. Vérifiez votre connexion Internet.', 'error', 5000); return; }
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = new Uint8Array(e.target.result);
            xlsxWorkbook = XLSX.read(data, { type: 'array' });
            const sheetSelect = document.getElementById('xlsxSheet');
            sheetSelect.innerHTML = '';
            xlsxWorkbook.SheetNames.forEach(n => {
                const opt = document.createElement('option');
                opt.value = n; opt.textContent = n;
                sheetSelect.appendChild(opt);
            });
            document.getElementById('xlsxFileInfo').textContent = `Fichier : ${file.name} — ${xlsxWorkbook.SheetNames.length} feuille(s)`;
            document.getElementById('xlsxHeaderRow').value = 1;
            previewXlsxSheet();
            document.getElementById('xlsxModal').classList.add('show');
        } catch (err) {
            toast('Erreur de lecture du fichier Excel : ' + err.message, 'error', 5000);
        } finally {
            event.target.value = '';
        }
    };
    reader.onerror = () => toast('Erreur de lecture du fichier.', 'error');
    reader.readAsArrayBuffer(file);
}

function getXlsxRows() {
    if (!xlsxWorkbook) return [];
    const sheetName = document.getElementById('xlsxSheet').value;
    const sheet = xlsxWorkbook.Sheets[sheetName];
    return XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '', blankrows: false });
}

function previewXlsxSheet() {
    const rows = getXlsxRows();
    const headerIdx = Math.max(0, (parseInt(document.getElementById('xlsxHeaderRow').value) || 1) - 1);
    const header = rows[headerIdx] || [];
    const dataRows = rows.slice(headerIdx + 1);

    // Populate column selects
    const selects = ['xlsxColNum', 'xlsxColPrenom', 'xlsxColNom', 'xlsxColSexe'];
    const defaults = {
        xlsxColNum:    [/n°?\s*tab/i, /num(é|e)?ro/i, /^n°?$/i, /table/i],
        xlsxColPrenom: [/pr[ée]nom/i, /first\s*name/i],
        xlsxColNom:    [/^nom$/i, /^nom\s*de/i, /last\s*name/i, /family\s*name/i, /^surname$/i],
        xlsxColSexe:   [/sexe/i, /genre/i, /^sex$/i]
    };
    const used = new Set();
    selects.forEach(id => {
        const sel = document.getElementById(id);
        sel.innerHTML = '<option value="-1">— (aucune) —</option>';
        header.forEach((h, i) => {
            const opt = document.createElement('option');
            opt.value = i; opt.textContent = `[${XLSX.utils.encode_col(i)}] ${h || '(vide)'}`;
            sel.appendChild(opt);
        });
        const regs = defaults[id];
        const match = header.findIndex((h, i) => !used.has(i) && regs.some(re => re.test(String(h || ''))));
        if (match !== -1) { sel.value = match; used.add(match); }
    });

    // Preview first 5 data rows
    const preview = document.getElementById('xlsxPreview');
    if (dataRows.length === 0) { preview.innerHTML = '<em>Aucune donnée.</em>'; return; }
    const colCount = Math.max(header.length, ...dataRows.slice(0, 5).map(r => r.length));
    let html = '<table style="font-size:0.82em; border-collapse:collapse;"><thead><tr>';
    for (let i = 0; i < colCount; i++) html += `<th style="border:1px solid var(--border-color); padding:4px 8px; background:var(--primary-light);">[${XLSX.utils.encode_col(i)}] ${header[i] || ''}</th>`;
    html += '</tr></thead><tbody>';
    dataRows.slice(0, 5).forEach(row => {
        html += '<tr>';
        for (let i = 0; i < colCount; i++) html += `<td style="border:1px solid var(--border-color); padding:4px 8px;">${row[i] !== undefined ? String(row[i]) : ''}</td>`;
        html += '</tr>';
    });
    html += `</tbody></table><p style="margin-top:6px; font-size:0.82em; color:var(--text-secondary);">${dataRows.length} ligne(s) de données détectée(s).</p>`;
    preview.innerHTML = html;
}

function processXlsxImport() {
    const rows = getXlsxRows();
    const headerIdx = Math.max(0, (parseInt(document.getElementById('xlsxHeaderRow').value) || 1) - 1);
    const dataRows = rows.slice(headerIdx + 1);
    const cNum = parseInt(document.getElementById('xlsxColNum').value);
    const cPrenom = parseInt(document.getElementById('xlsxColPrenom').value);
    const cNom = parseInt(document.getElementById('xlsxColNom').value);
    const cSexe = parseInt(document.getElementById('xlsxColSexe').value);
    if (cPrenom < 0 || cNom < 0) { toast('Veuillez sélectionner au moins les colonnes Prénom et Nom.', 'warning'); return; }
    const ld = getLevelData();
    let count = 0, skipped = 0;
    dataRows.forEach(row => {
        const rawPrenom = String(row[cPrenom] || '').trim();
        const rawNom = String(row[cNom] || '').trim();
        if (!rawPrenom || !rawNom) { skipped++; return; }
        // Même validation que l'ajout manuel et l'import CSV : rejette le HTML/script
        // et les caractères interdits (défense XSS/SQLi à l'entrée).
        const prenomCheck = Security.validateName(rawPrenom, { field: 'Prénom' });
        const nomCheck = Security.validateName(rawNom, { field: 'Nom' });
        if (!prenomCheck.ok || !nomCheck.ok) { skipped++; return; }
        const prenom = prenomCheck.value;
        const nom = nomCheck.value.toUpperCase();
        let numTable;
        if (cNum >= 0 && row[cNum] !== '' && row[cNum] !== undefined) {
            numTable = parseInt(row[cNum]) || (ld.students.length + 1);
        } else {
            numTable = ld.students.length + 1;
        }
        let sexe = '';
        if (cSexe >= 0 && row[cSexe]) {
            const s = String(row[cSexe]).trim().toUpperCase();
            sexe = (s === 'F' || s.startsWith('FEM') || s.startsWith('FILL')) ? 'F' : 'M';
        } else {
            sexe = 'M';
        }
        ld.students.push({ numTable, prenom, nom, anonymat: '', sexe });
        count++;
    });
    sortStudentsAlpha(ld);
    studentViewOrder = null;
    closeModal('xlsxModal');
    renderStudentsTable();
    updateLevelTags();
    saveData();
    const msg = `${count} élève(s) importé(s) dans ${LEVELS[currentLevel].shortLabel}` + (skipped > 0 ? ` (${skipped} ignoré(s))` : '') + ' !';
    toast(msg, 'success', 4000);
    logActivity(`${count} élèves importés par Excel (${LEVELS[currentLevel].shortLabel})`, 'import');
}

// ========== GRADES 1st TOUR ==========
function stKey(st) { return st.numTable + '_' + st.nom; }

function renderGrades1Table() {
    const ld = getLevelData();
    const info = document.getElementById('grades1Info');
    if (ld.students.length === 0) { info.style.display = 'block'; return; }
    info.style.display = 'none';

    const header = document.getElementById('grades1Header');
    header.innerHTML = '<th>N</th><th>N Tab</th><th>Prénom</th><th>Nom</th>';
    ld.subjects.forEach(s => header.innerHTML += `<th>${s.name}<br><small>(${s.coef})</small></th>`);
    header.innerHTML += '<th>Total</th><th>Moy.</th><th>Rang</th><th>Décision</th>';

    const tbody = document.getElementById('grades1Body');
    tbody.innerHTML = '';
    ld.students.forEach((st, si) => {
        const k = stKey(st);
        if (!ld.grades1[k]) ld.grades1[k] = {};
        let html = `<td>${si + 1}</td><td>${st.numTable}</td><td style="text-align:left; white-space:nowrap;">${Security.escapeHTML(st.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(st.nom)}</td>`;
        ld.subjects.forEach((sub, subi) => {
            const val = ld.grades1[k][sub.code];
            const isAbsent = val === 'ABS';
            const isInapte = val === 'INAPTE';
            const displayVal = (isAbsent || isInapte) ? '' : (val !== undefined ? val : '');
            const extraClass = isAbsent ? ' grade-absent' : (isInapte ? ' grade-inapte' : '');
            const placeholder = isAbsent ? 'ABS' : (isInapte ? 'INAPT' : '');
            if (sub.code === 'EPS') {
                html += `<td class="eps-cell"><input type="number" min="0" max="20" step="0.5" value="${displayVal}" class="grade-input${extraClass}" data-key="${k}" data-code="${sub.code}" data-row="${si}" data-col="${subi}" placeholder="${placeholder}" onchange="setGrade1('${k}','${sub.code}',this.value)" oncontextmenu="toggleAbsent(event, this, 1)" ${isInapte ? 'disabled' : ''}><label class="inapte-cb" title="Inapte EPS"><input type="checkbox" ${isInapte ? 'checked' : ''} onchange="toggleInapteFromGrade(${si}, this.checked, 1)">IN</label></td>`;
            } else {
                html += `<td><input type="number" min="0" max="20" step="0.5" value="${displayVal}" class="grade-input${extraClass}" data-key="${k}" data-code="${sub.code}" data-row="${si}" data-col="${subi}" placeholder="${placeholder}" onchange="setGrade1('${k}','${sub.code}',this.value)" oncontextmenu="toggleAbsent(event, this, 1)"></td>`;
            }
        });
        const res = ld.results1.find(r => r.key === k);
        if (res) {
            const cls = res.decision === 'Admis' ? 'admis' : res.decision === '2ème Tour' ? 'deuxieme-tour' : 'ajourne';
            html += `<td><b>${res.total}</b></td><td><b>${res.moyenne.toFixed(2)}</b></td><td>${res.rang}</td><td class="${cls}">${res.decision}</td>`;
        } else html += '<td>-</td><td>-</td><td>-</td><td>-</td>';
        const tr = document.createElement('tr');
        tr.innerHTML = html;
        tbody.appendChild(tr);
    });
    setupGradeNavigation('grades1Body');
}

function toggleAbsent(e, input, tour) {
    e.preventDefault();
    const k = input.dataset.key, code = input.dataset.code;
    const ld = getLevelData();
    const grades = tour === 1 ? ld.grades1 : ld.grades2;
    if (!grades[k]) grades[k] = {};
    const current = grades[k][code];
    if (code === 'EPS') {
        // EPS: cycle vide -> ABS -> INAPTE -> vide
        if (current === 'ABS') {
            grades[k][code] = 'INAPTE';
            input.value = '';
            input.placeholder = 'INAPT';
            input.classList.remove('grade-absent');
            input.classList.add('grade-inapte');
        } else if (current === 'INAPTE') {
            grades[k][code] = '';
            input.value = '';
            input.placeholder = '';
            input.classList.remove('grade-absent', 'grade-inapte');
        } else {
            grades[k][code] = 'ABS';
            input.value = '';
            input.placeholder = 'ABS';
            input.classList.add('grade-absent');
            input.classList.remove('grade-inapte');
        }
    } else {
        if (current === 'ABS') {
            grades[k][code] = '';
            input.value = '';
            input.placeholder = '';
            input.classList.remove('grade-absent');
        } else {
            grades[k][code] = 'ABS';
            input.value = '';
            input.placeholder = 'ABS';
            input.classList.add('grade-absent');
        }
    }
    debouncedSave();
}

function setupGradeNavigation(tbodyId) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    tbody.addEventListener('keydown', function(e) {
        const input = e.target;
        if (input.tagName !== 'INPUT') return;
        const row = parseInt(input.dataset.row);
        const col = parseInt(input.dataset.col);
        if (isNaN(row) || isNaN(col)) return;
        let targetRow = row, targetCol = col;
        if (e.key === 'Enter') { e.preventDefault(); targetRow = row + 1; }
        else if (e.key === 'ArrowDown') { e.preventDefault(); targetRow = row + 1; }
        else if (e.key === 'ArrowUp') { e.preventDefault(); targetRow = row - 1; }
        else if (e.key === 'ArrowRight' && input.selectionStart === input.value.length) { e.preventDefault(); targetCol = col + 1; }
        else if (e.key === 'ArrowLeft' && input.selectionStart === 0) { e.preventDefault(); targetCol = col - 1; }
        else return;
        const target = tbody.querySelector(`input[data-row="${targetRow}"][data-col="${targetCol}"]`);
        if (target) { target.focus(); target.select(); }
    });
}

function setGrade1(k, code, val) {
    const ld = getLevelData();
    if (!ld.grades1[k]) ld.grades1[k] = {};
    if (ld.grades1[k][code] === 'ABS' || ld.grades1[k][code] === 'INAPTE') return;
    ld.grades1[k][code] = val === '' ? '' : parseFloat(val);
    debouncedSave();
}

function calculateResults1() {
    const ld = getLevelData();
    if (ld.students.length === 0) { toast('Veuillez d\'abord ajouter des élèves.', 'warning'); return; }
    ld.results1 = [];
    ld.students.forEach(st => {
        const k = stKey(st), grades = ld.grades1[k] || {};
        let total = 0, coefUsed = 0, has = false;
        ld.subjects.forEach(sub => {
            const g = grades[sub.code];
            if (g === 'INAPTE') return;                                   // Inapte EPS : exclu du calcul
            if (g === 'ABS') { coefUsed += sub.coef; has = true; return; } // Absent : compte comme 0 (coef au dénominateur)
            if (g !== undefined && g !== '') { total += parseFloat(g) * sub.coef; coefUsed += sub.coef; has = true; }
            // sinon : matière non saisie -> exclue du calcul
        });
        if (!has) return;
        const cTotal = coefUsed || ld.coefTotal;
        const moyenne = total / cTotal;
        const sAdmis = coefUsed < ld.coefTotal ? cTotal * 10 : ld.seuilAdmis;
        const s2e = coefUsed < ld.coefTotal ? cTotal * 8 : ld.seuil2eTour;
        let decision = total >= sAdmis ? 'Admis' : total >= s2e ? '2ème Tour' : 'Ajourné';
        const mention = decision === 'Admis' ? getMention(moyenne, currentLevel) : '';
        ld.results1.push({ key: k, student: st, total: Math.round(total * 100) / 100, moyenne, coefUsed: cTotal, decision, mention, rang: 0 });
    });
    ld.results1.sort((a, b) => b.moyenne - a.moyenne);
    ld.results1.forEach((r, i) => r.rang = i + 1);
    ld.tour2Students = ld.results1.filter(r => r.decision === '2ème Tour').map(r => r.student);
    renderGrades1Table();
    saveData();
    const admis = ld.results1.filter(r => r.decision === 'Admis').length;
    const tour2 = ld.results1.filter(r => r.decision === '2ème Tour').length;
    const ajournés = ld.results1.filter(r => r.decision === 'Ajourné').length;
    toast(`${LEVELS[currentLevel].shortLabel}: ${ld.results1.length} candidat(s) - ${admis} Admis, ${tour2} au 2e Tour, ${ajournés} Ajourné(s)`, 'success', 5000);
    logActivity(`Résultats 1er tour calculés (${LEVELS[currentLevel].shortLabel}): ${admis} admis, ${tour2} 2e tour, ${ajournés} ajournés`, 'calcul');
}

// ========== RESULTS 1st TOUR ==========
function showResults1Tab(tab, btnEl) {
    document.querySelectorAll('#results1Tabs button').forEach(b => b.classList.remove('active'));
    if (btnEl) btnEl.classList.add('active');
    else document.querySelector('#results1Tabs button').classList.add('active');
    const ld = getLevelData(), container = document.getElementById('results1Content');
    let filtered;
    if (tab === 'admis') filtered = ld.results1.filter(r => r.decision === 'Admis');
    else if (tab === 'tour2') filtered = ld.results1.filter(r => r.decision === '2ème Tour');
    else if (tab === 'ajourne') filtered = ld.results1.filter(r => r.decision === 'Ajourné');
    else filtered = [...ld.results1];
    if (filtered.length === 0) { container.innerHTML = '<div class="empty-state"><p>Aucun résultat.</p></div>'; return; }
    if (tab !== 'all') { filtered.sort((a, b) => b.moyenne - a.moyenne); filtered.forEach((r, i) => r.rf = i + 1); }
    const titles = { all: 'RÉSULTATS COMPLETS - 1er TOUR', admis: "ADMIS D'OFFICE", tour2: 'ADMIS AU 2ÈME GROUPE', ajourne: 'AJOURNÉS' };
    let html = docHeader(titles[tab], LEVELS[currentLevel].examLabel + ' ' + appData.year + ' - ' + LEVELS[currentLevel].className);
    const showMention = currentLevel !== 'bfem3';
    html += `<table><thead><tr><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Total</th><th>Moyenne</th><th>Rang</th><th>Décision</th>${showMention ? '<th>Mention</th>' : ''}</tr></thead><tbody>`;
    filtered.forEach(r => {
        const cls = r.decision === 'Admis' ? 'admis' : r.decision === '2ème Tour' ? 'deuxieme-tour' : 'ajourne';
        const mentionHtml = showMention ? `<td><span class="mention-tag ${getMentionClass(r.mention || '')}">${r.mention || '-'}</span></td>` : '';
        html += `<tr><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td>
            <td>${r.total}</td><td>${r.moyenne.toFixed(2)}</td><td>${tab === 'all' ? r.rang : r.rf}</td><td class="${cls}">${r.decision}</td>${mentionHtml}</tr>`;
    });
    html += `</tbody></table><p style="margin-top:10px;"><b>Total: ${filtered.length}</b></p>`;
    container.innerHTML = html;
}

// ========== GRADES 2nd TOUR ==========
function renderGrades2Table() {
    const ld = getLevelData();
    if (!ld.tour2Students || ld.tour2Students.length === 0) { document.getElementById('grades2Info').style.display = 'block'; return; }
    document.getElementById('grades2Info').style.display = 'none';
    const header = document.getElementById('grades2Header');
    header.innerHTML = '<th>N</th><th>N Tab</th><th>Prénom</th><th>Nom</th>';
    ld.subjects2.forEach(s => header.innerHTML += `<th>${s.name}<br><small>(${s.coef})</small></th>`);
    header.innerHTML += '<th>Total</th><th>Moy.</th><th>Rang</th><th>Décision</th>';
    const tbody = document.getElementById('grades2Body');
    tbody.innerHTML = '';
    ld.tour2Students.forEach((st, si) => {
        const k = stKey(st);
        if (!ld.grades2[k]) ld.grades2[k] = {};
        let html = `<td>${si + 1}</td><td>${st.numTable}</td><td style="text-align:left;">${Security.escapeHTML(st.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(st.nom)}</td>`;
        ld.subjects2.forEach((sub, subi) => {
            const val = ld.grades2[k][sub.code];
            const isAbsent = val === 'ABS';
            const isInapte = val === 'INAPTE';
            const displayVal = (isAbsent || isInapte) ? '' : (val !== undefined ? val : '');
            const extraClass = isAbsent ? ' grade-absent' : (isInapte ? ' grade-inapte' : '');
            const placeholder = isAbsent ? 'ABS' : (isInapte ? 'INAPT' : '');
            if (sub.code === 'EPS') {
                html += `<td class="eps-cell"><input type="number" min="0" max="20" step="0.5" value="${displayVal}" class="grade-input${extraClass}" data-key="${k}" data-code="${sub.code}" data-row="${si}" data-col="${subi}" placeholder="${placeholder}" onchange="setGrade2('${k}','${sub.code}',this.value)" oncontextmenu="toggleAbsent(event, this, 2)" ${isInapte ? 'disabled' : ''}><label class="inapte-cb" title="Inapte EPS"><input type="checkbox" ${isInapte ? 'checked' : ''} onchange="toggleInapteFromGrade(${si}, this.checked, 2)">IN</label></td>`;
            } else {
                html += `<td><input type="number" min="0" max="20" step="0.5" value="${displayVal}" class="grade-input${extraClass}" data-key="${k}" data-code="${sub.code}" data-row="${si}" data-col="${subi}" placeholder="${placeholder}" onchange="setGrade2('${k}','${sub.code}',this.value)" oncontextmenu="toggleAbsent(event, this, 2)"></td>`;
            }
        });
        const res = ld.results2.find(r => r.key === k);
        if (res) {
            const cls = res.decision === 'Admis' ? 'admis' : 'ajourne';
            html += `<td><b>${res.total}</b></td><td><b>${res.moyenne.toFixed(2)}</b></td><td>${res.rang}</td><td class="${cls}">${res.decision}</td>`;
        } else html += '<td>-</td><td>-</td><td>-</td><td>-</td>';
        const tr = document.createElement('tr'); tr.innerHTML = html; tbody.appendChild(tr);
    });
    setupGradeNavigation('grades2Body');
}

function setGrade2(k, code, val) {
    const ld = getLevelData();
    if (!ld.grades2[k]) ld.grades2[k] = {};
    if (ld.grades2[k][code] === 'ABS' || ld.grades2[k][code] === 'INAPTE') return;
    ld.grades2[k][code] = val === '' ? '' : parseFloat(val);
    debouncedSave();
}

function calculateResults2() {
    const ld = getLevelData();
    if (!ld.tour2Students || ld.tour2Students.length === 0) { toast('Aucun candidat pour le 2ème tour.', 'warning'); return; }
    ld.results2 = [];
    ld.tour2Students.forEach(st => {
        const k = stKey(st), grades = ld.grades2[k] || {};
        let total = 0, has = false;
        let coefUsed2 = 0;
        ld.subjects2.forEach(sub => {
            const g = grades[sub.code];
            if (g === 'INAPTE') return;                                    // Inapte : exclu
            if (g === 'ABS') { coefUsed2 += sub.coef; has = true; return; } // Absent : compte comme 0
            if (g !== undefined && g !== '') { total += parseFloat(g) * sub.coef; coefUsed2 += sub.coef; has = true; }
            // sinon : matière non saisie -> exclue
        });
        if (!has) return;
        const effectiveCoef2 = coefUsed2 || ld.coefTotal2;
        const moyenne = total / effectiveCoef2;
        const sAdmis2 = effectiveCoef2 < ld.coefTotal2 ? effectiveCoef2 * 10 : ld.seuilAdmis2;
        const decision2 = total >= sAdmis2 ? 'Admis' : 'Ajourné';
        const mention2 = decision2 === 'Admis' ? getMention(moyenne, currentLevel) : '';
        ld.results2.push({ key: k, student: st, total: Math.round(total * 100) / 100, moyenne, decision: decision2, mention: mention2, rang: 0 });
    });
    ld.results2.sort((a, b) => b.moyenne - a.moyenne);
    ld.results2.forEach((r, i) => r.rang = i + 1);
    renderGrades2Table();
    saveData();
    const admis = ld.results2.filter(r => r.decision === 'Admis').length;
    toast(`2ème tour: ${admis} admis sur ${ld.results2.length} candidat(s)`, 'success');
    logActivity(`Résultats 2ème tour calculés (${LEVELS[currentLevel].shortLabel}): ${admis} admis sur ${ld.results2.length}`, 'calcul');
}

// ========== RESULTS 2nd TOUR ==========
function showResults2Tab(tab, btnEl) {
    document.querySelectorAll('#results2Tabs button').forEach(b => b.classList.remove('active'));
    if (btnEl) btnEl.classList.add('active');
    else document.querySelector('#results2Tabs button').classList.add('active');
    const ld = getLevelData(), container = document.getElementById('results2Content');
    let filtered;
    if (tab === 'admis') filtered = ld.results2.filter(r => r.decision === 'Admis');
    else if (tab === 'ajourne') filtered = ld.results2.filter(r => r.decision === 'Ajourné');
    else filtered = [...ld.results2];
    if (filtered.length === 0) { container.innerHTML = '<div class="empty-state"><p>Aucun résultat.</p></div>'; return; }
    const showMention2 = currentLevel !== 'bfem3';
    let html = `<table><thead><tr><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Total</th><th>Moyenne</th><th>Rang</th><th>Décision</th>${showMention2 ? '<th>Mention</th>' : ''}</tr></thead><tbody>`;
    filtered.forEach(r => {
        const cls = r.decision === 'Admis' ? 'admis' : 'ajourne';
        const mentionHtml2 = showMention2 ? `<td><span class="mention-tag ${getMentionClass(r.mention || '')}">${r.mention || '-'}</span></td>` : '';
        html += `<tr><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td>
            <td>${r.total}</td><td>${r.moyenne.toFixed(2)}</td><td>${r.rang}</td><td class="${cls}">${r.decision}</td>${mentionHtml2}</tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

// ========== STATISTICS ==========
function renderStats(mode, btnEl) {
    document.querySelectorAll('#statsTabs button').forEach(b => b.classList.remove('active'));
    if (btnEl) btnEl.classList.add('active');
    else document.querySelector('#statsTabs button').classList.add('active');
    const container = document.getElementById('statsContent');

    // ===== Nouvelles visualisations (v2.0) =====
    if (mode === 'heatmap') { renderHeatmapView(container); return; }
    if (mode === 'radar') { renderRadarView(container); return; }
    if (mode === 'sankey') { renderSankeyView(container); return; }
    if (mode === 'boxplot') { renderBoxPlotView(container); return; }
    if (mode === 'calendar') { renderCalendarHeatmapView(container); return; }

    if (mode === 'compare') {
        let html = '<div style="text-align:center; margin-bottom:20px;"><h3>COMPARAISON ANNUELLE</h3></div>';
        const snapshots = getYearSnapshots();
        const years = Object.keys(snapshots).sort();
        if (years.length === 0) {
            html += `<div class="alert alert-warning">Aucune donnée de comparaison disponible. Les snapshots sont sauvegardés automatiquement lors du calcul des résultats. Utilisez le bouton ci-dessous pour sauvegarder l'année en cours.</div>`;
        } else {
            html += `<table><thead><tr><th>Année</th><th>Niveau</th><th>Inscrits</th><th>Présents</th><th>Admis 1er T</th><th>Admis 2e T</th><th>Total Admis</th><th>Taux</th><th>Moy. Gen.</th></tr></thead><tbody>`;
            years.forEach(yr => {
                const snap = snapshots[yr];
                Object.keys(snap).forEach(lv => {
                    const s = snap[lv];
                    const taux = s.presents > 0 ? ((s.totalAdmis / s.presents) * 100).toFixed(1) : '0.0';
                    html += `<tr><td>${yr}</td><td>${LEVELS[lv] ? LEVELS[lv].shortLabel : lv}</td><td>${s.inscrits}</td><td>${s.presents}</td><td>${s.admis1}</td><td>${s.admis2}</td><td style="font-weight:700;">${s.totalAdmis}</td><td style="font-weight:700;">${taux}%</td><td>${s.moyGen ? s.moyGen.toFixed(2) : '-'}</td></tr>`;
                });
            });
            html += '</tbody></table>';
        }
        html += `<div class="btn-group" style="margin-top:15px;">
            <button class="btn btn-primary" onclick="saveYearSnapshot()">Sauvegarder le snapshot de l'année ${appData.year}</button>
        </div>`;
        container.innerHTML = html;
        return;
    }

    if (mode === 'all') {
        let html = '<div style="text-align:center; margin-bottom:20px;"><h3>STATISTIQUES GLOBALES - TOUS LES NIVEAUX</h3></div>';
        let hasData = false;
        Object.keys(LEVELS).forEach(lv => {
            const d = appData.levels[lv];
            if (!d || d.results1.length === 0) return;
            hasData = true;
            html += renderStatsForLevel(lv, d);
        });
        if (!hasData) html += '<div class="empty-state"><p>Aucun résultat calcule.</p></div>';
        container.innerHTML = html;
    } else {
        const ld = getLevelData();
        if (ld.results1.length === 0) { container.innerHTML = '<div class="empty-state"><p>Veuillez d\'abord calculer les résultats.</p></div>'; return; }
        container.innerHTML = renderStatsForLevel(currentLevel, ld);
    }
}

function renderStatsForLevel(lv, ld) {
    const cfg = LEVELS[lv];
    const inscrits = ld.students.length, présents = ld.results1.length;
    const admis1 = ld.results1.filter(r => r.decision === 'Admis').length;
    const tour2 = ld.results1.filter(r => r.decision === '2ème Tour').length;
    const ajournés1 = ld.results1.filter(r => r.decision === 'Ajourné').length;
    const admis2 = ld.results2 ? ld.results2.filter(r => r.decision === 'Admis').length : 0;
    const totalAdmis = admis1 + admis2;
    const pct = n => présents > 0 ? ((n / présents) * 100).toFixed(1) : '0.0';
    const pctNum = n => présents > 0 ? ((n / présents) * 100) : 0;

    // Moyennes globales
    let sumMoy = 0, bestMoy = 0, worstMoy = 20;
    ld.results1.forEach(r => {
        sumMoy += r.moyenne;
        if (r.moyenne > bestMoy) bestMoy = r.moyenne;
        if (r.moyenne < worstMoy) worstMoy = r.moyenne;
    });
    const avgGlobal = présents > 0 ? (sumMoy / présents) : 0;

    // Donut chart percentages
    const pA = pctNum(admis1), pT = pctNum(tour2), pAj = pctNum(ajournés1);
    const donutGradient = `conic-gradient(#10b981 0% ${pA}%, #f59e0b ${pA}% ${pA+pT}%, #ef4444 ${pA+pT}% 100%)`;

    // Comptage filles / garçons
    const garçons = ld.students.filter(s => s.sexe !== 'F').length;
    const filles = ld.students.filter(s => s.sexe === 'F').length;
    const garçonsPrésents = ld.results1.filter(r => r.student.sexe !== 'F').length;
    const fillesPresentes = ld.results1.filter(r => r.student.sexe === 'F').length;
    const garçonsAdmis = ld.results1.filter(r => r.student.sexe !== 'F' && r.decision === 'Admis').length + (ld.results2 ? ld.results2.filter(r => r.student.sexe !== 'F' && r.decision === 'Admis').length : 0);
    const fillesAdmises = ld.results1.filter(r => r.student.sexe === 'F' && r.decision === 'Admis').length + (ld.results2 ? ld.results2.filter(r => r.student.sexe === 'F' && r.decision === 'Admis').length : 0);
    const pctGarçons = garçons > 0 ? ((garçonsAdmis / garçons) * 100).toFixed(1) : '0.0';
    const pctFilles = filles > 0 ? ((fillesAdmises / filles) * 100).toFixed(1) : '0.0';

    let html = `<div class="card">
        <h3 class="stats-section-title">${cfg.label}</h3>

        <!-- CHIFFRES CLES -->
        <div class="stats-grid">
            <div class="stat-card blue"><div class="number">${inscrits}</div><div class="label">Inscrits</div></div>
            <div class="stat-card blue"><div class="number">${présents}</div><div class="label">Présents</div></div>
            <div class="stat-card green"><div class="number">${totalAdmis}</div><div class="label">Total Admis</div><div class="pct">${pct(totalAdmis)}%</div></div>
            <div class="stat-card orange"><div class="number">${avgGlobal.toFixed(2)}</div><div class="label">Moyenne Générale</div></div>
        </div>

        <!-- REPARTITION FILLES / GARCONS -->
        <h3>Répartition Filles / Garçons</h3>
        <div class="gender-stats">
            <div class="gender-card gender-m">
                <div class="gender-icon">&#9794;</div>
                <div class="gender-info">
                    <div class="gender-title">Garçons</div>
                    <div class="gender-numbers">
                        <span>Inscrits: <b>${garçons}</b></span>
                        <span>Présents: <b>${garçonsPrésents}</b></span>
                        <span>Admis: <b>${garçonsAdmis}</b></span>
                        <span class="gender-pct">${pctGarçons}%</span>
                    </div>
                </div>
            </div>
            <div class="gender-card gender-f">
                <div class="gender-icon">&#9792;</div>
                <div class="gender-info">
                    <div class="gender-title">Filles</div>
                    <div class="gender-numbers">
                        <span>Inscrits: <b>${filles}</b></span>
                        <span>Présents: <b>${fillesPresentes}</b></span>
                        <span>Admis: <b>${fillesAdmises}</b></span>
                        <span class="gender-pct">${pctFilles}%</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- REPARTITION : DONUT + LEGENDE + BARRES -->
        <div class="stats-split">
            <div class="stats-split-left">
                <h3>Répartition 1er Tour</h3>
                <div class="donut-container">
                    <div class="donut" style="background: ${donutGradient};">
                        <div class="donut-center">
                            <div class="donut-center-number">${présents}</div>
                            <div class="donut-center-label">Présents</div>
                        </div>
                    </div>
                    <div class="donut-legend">
                        <div class="donut-legend-item"><span class="donut-dot" style="background:#10b981;"></span> Admis d'Office <b>${admis1}</b> (${pct(admis1)}%)</div>
                        <div class="donut-legend-item"><span class="donut-dot" style="background:#f59e0b;"></span> 2ème Groupe <b>${tour2}</b> (${pct(tour2)}%)</div>
                        <div class="donut-legend-item"><span class="donut-dot" style="background:#ef4444;"></span> Ajournés <b>${ajournés1}</b> (${pct(ajournés1)}%)</div>
                        ${admis2 > 0 ? `<div class="donut-legend-item" style="margin-top:6px; padding-top:6px; border-top:1px solid var(--border-color);"><span class="donut-dot" style="background:#059669;"></span> Admis 2e Tour <b>${admis2}</b> (${pct(admis2)}%)</div>` : ''}
                    </div>
                </div>
            </div>
            <div class="stats-split-right">
                <h3>Barres de progression</h3>
                <div class="bar-chart">
                    <div class="bar-row"><div class="bar-label">Admis</div><div class="bar-track"><div class="bar-fill" style="width:${Math.max(pctNum(admis1), 2)}%; background:#10b981;"><span class="bar-value">${admis1}</span></div></div><div class="bar-value-outside">${pct(admis1)}%</div></div>
                    <div class="bar-row"><div class="bar-label">2ème Groupe</div><div class="bar-track"><div class="bar-fill" style="width:${Math.max(pctNum(tour2), 2)}%; background:#f59e0b;"><span class="bar-value">${tour2}</span></div></div><div class="bar-value-outside">${pct(tour2)}%</div></div>
                    <div class="bar-row"><div class="bar-label">Ajournés</div><div class="bar-track"><div class="bar-fill" style="width:${Math.max(pctNum(ajournés1), 2)}%; background:#ef4444;"><span class="bar-value">${ajournés1}</span></div></div><div class="bar-value-outside">${pct(ajournés1)}%</div></div>
                    <div class="bar-row bar-row-total"><div class="bar-label"><b>Total Admis</b></div><div class="bar-track"><div class="bar-fill" style="width:${Math.max(pctNum(totalAdmis), 2)}%; background:linear-gradient(90deg, #10b981, var(--accent));"><span class="bar-value">${totalAdmis}</span></div></div><div class="bar-value-outside"><b>${pct(totalAdmis)}%</b></div></div>
                </div>
            </div>
        </div>

        <!-- MOYENNES PAR MATIERE -->
        <h3>Moyennes par matière</h3>
        <div class="table-wrapper">
            <table class="stats-table">
                <thead><tr><th>Matière</th><th>Coef</th><th>Moyenne</th><th>Min</th><th>Max</th><th>Barre</th></tr></thead>
                <tbody>`;

    ld.subjects.forEach(sub => {
        let sum = 0, count = 0, min = 20, max = 0;
        ld.results1.forEach(r => {
            const g = ld.grades1[r.key] && ld.grades1[r.key][sub.code];
            if (g !== undefined && g !== '' && g !== 'ABS' && g !== 'INAPTE') {
                const v = parseFloat(g);
                sum += v; count++;
                if (v < min) min = v;
                if (v > max) max = v;
            }
        });
        if (count > 0) {
            const avg = sum / count;
            const pctBar = (avg / 20) * 100;
            const color = avg >= 10 ? '#10b981' : avg >= 8 ? '#f59e0b' : '#ef4444';
            html += `<tr>
                <td style="text-align:left; font-weight:600;">${sub.name}</td>
                <td>${sub.coef}</td>
                <td style="font-weight:700; color:${color};">${avg.toFixed(2)}</td>
                <td>${min.toFixed(1)}</td>
                <td>${max.toFixed(1)}</td>
                <td style="width:200px;"><div class="bar-track" style="height:16px;"><div class="bar-fill" style="width:${Math.max(pctBar, 3)}%; background:${color}; height:100%;"></div></div></td>
            </tr>`;
        }
    });

    html += `</tbody></table></div>

        <!-- MEILLEURES / PLUS FAIBLES MOYENNES -->
        <div class="stats-split" style="margin-top:14px;">
            <div class="stats-split-left">
                <h3>Top 5 - Meilleures Moyennes</h3>
                <div class="stats-ranking">`;

    const top5 = [...ld.results1].sort((a, b) => b.moyenne - a.moyenne).slice(0, 5);
    top5.forEach((r, i) => {
        const medal = i === 0 ? '&#129351;' : i === 1 ? '&#129352;' : i === 2 ? '&#129353;' : '';
        html += `<div class="ranking-row">
            <span class="ranking-pos">${i + 1}</span>
            ${medal ? `<span class="ranking-medal">${medal}</span>` : ''}
            <span class="ranking-name">${r.student.prenom} ${r.student.nom}</span>
            <span class="ranking-score">${r.moyenne.toFixed(2)}/20</span>
        </div>`;
    });

    html += `</div></div>
            <div class="stats-split-right">
                <h3>Tableau Récapitulatif</h3>
                <table class="recap-table">
                    <tr><td>Inscrits</td><td class="recap-val">${inscrits}</td><td class="recap-pct">-</td></tr>
                    <tr><td>Présents</td><td class="recap-val">${présents}</td><td class="recap-pct">-</td></tr>
                    <tr class="recap-admis"><td>Admis d'Office</td><td class="recap-val">${admis1}</td><td class="recap-pct">${pct(admis1)}%</td></tr>
                    <tr class="recap-tour2"><td>2ème Groupe</td><td class="recap-val">${tour2}</td><td class="recap-pct">${pct(tour2)}%</td></tr>
                    <tr class="recap-ajourne"><td>Ajournés</td><td class="recap-val">${ajournés1}</td><td class="recap-pct">${pct(ajournés1)}%</td></tr>
                    ${admis2 > 0 ? `<tr><td>Admis 2e Tour</td><td class="recap-val">${admis2}</td><td class="recap-pct">${pct(admis2)}%</td></tr>` : ''}
                    <tr class="recap-total"><td><b>TOTAL ADMIS</b></td><td class="recap-val"><b>${totalAdmis}</b></td><td class="recap-pct"><b>${pct(totalAdmis)}%</b></td></tr>
                </table>
                <div class="stats-minmax">
                    <div><span>Meilleure moyenne</span><b>${bestMoy.toFixed(2)}/20</b></div>
                    <div><span>Plus faible moyenne</span><b>${worstMoy.toFixed(2)}/20</b></div>
                    <div><span>Moyenne générale</span><b>${avgGlobal.toFixed(2)}/20</b></div>
                </div>
            </div>
        </div>
    </div>`;

    // ===== DISTRIBUTION DES MOYENNES (histogramme) =====
    const bins = [
        { label: '[0-4[',  min: 0,  max: 4,  color: '#7f1d1d' },
        { label: '[4-8[',  min: 4,  max: 8,  color: '#ef4444' },
        { label: '[8-10[', min: 8,  max: 10, color: '#f59e0b' },
        { label: '[10-12[', min: 10, max: 12, color: '#84cc16' },
        { label: '[12-14[', min: 12, max: 14, color: '#10b981' },
        { label: '[14-16[', min: 14, max: 16, color: '#059669' },
        { label: '[16-20]', min: 16, max: 20.01, color: '#047857' }
    ];
    const counts = bins.map(b => ld.results1.filter(r => r.moyenne >= b.min && r.moyenne < b.max).length);
    const maxCount = Math.max(1, ...counts);
    html += `<div class="card">
        <h3>Distribution des moyennes</h3>
        <div style="display:flex; align-items:flex-end; gap:10px; height:220px; padding:10px 4px; border-bottom:2px solid var(--border-color);">`;
    bins.forEach((b, i) => {
        const h = (counts[i] / maxCount) * 180;
        const pctB = présents > 0 ? ((counts[i] / présents) * 100).toFixed(1) : '0.0';
        html += `<div style="flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; height:100%;">
            <div style="font-size:0.8em; font-weight:700; color:${b.color}; margin-bottom:4px;">${counts[i]}${counts[i] > 0 ? ` <small style="color:var(--text-secondary); font-weight:500;">(${pctB}%)</small>` : ''}</div>
            <div title="${b.label} : ${counts[i]} élève(s)" style="width:80%; height:${h}px; min-height:${counts[i] > 0 ? 4 : 0}px; background:linear-gradient(180deg, ${b.color}, ${b.color}cc); border-radius:6px 6px 0 0; transition:height 0.6s ease; box-shadow:0 -2px 8px ${b.color}44;"></div>
        </div>`;
    });
    html += `</div><div style="display:flex; gap:10px; padding:8px 4px 0; font-size:0.78em; color:var(--text-secondary);">`;
    bins.forEach(b => html += `<div style="flex:1; text-align:center; font-weight:600;">${b.label}</div>`);
    html += `</div></div>`;

    // ===== TAUX DE REUSSITE PAR MATIERE =====
    html += `<div class="card">
        <h3>Taux de réussite par matière (note ≥ 10)</h3>
        <div class="bar-chart" style="margin-top:8px;">`;
    ld.subjects.forEach(sub => {
        let total = 0, pass = 0;
        ld.results1.forEach(r => {
            const g = ld.grades1[r.key] && ld.grades1[r.key][sub.code];
            if (g !== undefined && g !== '' && g !== 'ABS' && g !== 'INAPTE') {
                total++;
                if (parseFloat(g) >= 10) pass++;
            }
        });
        const rate = total > 0 ? (pass / total) * 100 : 0;
        const color = rate >= 60 ? '#10b981' : rate >= 40 ? '#f59e0b' : '#ef4444';
        html += `<div class="bar-row">
            <div class="bar-label">${sub.name}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${Math.max(rate, 2)}%; background:${color};"><span class="bar-value">${pass}/${total}</span></div></div>
            <div class="bar-value-outside" style="color:${color}; font-weight:700;">${rate.toFixed(1)}%</div>
        </div>`;
    });
    html += `</div></div>`;

    // ===== REPARTITION DES MENTIONS (sauf BFEM) =====
    if (lv !== 'bfem3') {
        const allAdmis = [
            ...ld.results1.filter(r => r.decision === 'Admis'),
            ...(ld.results2 ? ld.results2.filter(r => r.decision === 'Admis') : [])
        ];
        const mentions = [
            { name: 'Très Bien',   key: 'Très Bien',   color: '#f59e0b', cls: 'mention-tb' },
            { name: 'Bien',        key: 'Bien',        color: '#10b981', cls: 'mention-b' },
            { name: 'Assez Bien',  key: 'Assez Bien',  color: '#B8A67A', cls: 'mention-ab' },
            { name: 'Passable',    key: 'Passable',    color: '#6b7280', cls: 'mention-p' }
        ];
        const totalAdm = Math.max(1, allAdmis.length);
        html += `<div class="card">
            <h3>Répartition des mentions (admis)</h3>
            <div class="stats-grid" style="margin-top:8px;">`;
        mentions.forEach(m => {
            const c = allAdmis.filter(r => r.mention === m.key).length;
            const p = ((c / totalAdm) * 100).toFixed(1);
            html += `<div class="stat-card" style="border-top:4px solid ${m.color};">
                <div class="number" style="color:${m.color};">${c}</div>
                <div class="label">${m.name}</div>
                <div class="pct">${p}%</div>
            </div>`;
        });
        html += `</div>
            <div class="bar-chart" style="margin-top:14px;">`;
        mentions.forEach(m => {
            const c = allAdmis.filter(r => r.mention === m.key).length;
            const p = (c / totalAdm) * 100;
            html += `<div class="bar-row">
                <div class="bar-label">${m.name}</div>
                <div class="bar-track"><div class="bar-fill" style="width:${Math.max(p, 2)}%; background:${m.color};"><span class="bar-value">${c}</span></div></div>
                <div class="bar-value-outside">${p.toFixed(1)}%</div>
            </div>`;
        });
        html += `</div></div>`;
    }

    return html;
}

// ========== CONFIG ==========
function renderConfigPage() {
    const ld = getLevelData();
    document.getElementById('schoolName').value = appData.school.name;
    document.getElementById('iaName').value = appData.school.ia;
    document.getElementById('iefName').value = appData.school.ief;
    document.getElementById('examDates').value = appData.school.dates;
    document.getElementById('principalName').value = appData.school.principal;
    document.getElementById('prefetName').value = appData.school.prefet || '';
    document.getElementById('seuilAdmis').value = ld.seuilAdmis;
    document.getElementById('seuil2eTour').value = ld.seuil2eTour;
    document.getElementById('seuilAdmis2').value = ld.seuilAdmis2;

    renderSallesConfig();
    const tbody = document.querySelector('#subjectsTable tbody');
    tbody.innerHTML = '';
    ld.subjects.forEach((s, i) => {
        const in2 = ld.subjects2.find(s2 => s2.code === s.code);
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><input type="text" value="${s.name}" style="width:140px;" data-si="${i}" class="sname"></td>
            <td><input type="text" value="${s.code}" style="width:70px;" data-si="${i}" class="scode"></td>
            <td><input type="number" value="${s.coef}" min="1" max="10" style="width:60px;" data-si="${i}" class="scoef"></td>
            <td><input type="checkbox" ${in2 ? 'checked' : ''} data-si="${i}" class="sinc2"></td>
            <td><input type="number" value="${in2 ? in2.coef : s.coef}" min="1" max="10" style="width:60px;" data-si="${i}" class="scoef2"></td>
            <td><button class="btn btn-danger btn-sm" onclick="removeSubject(${i})">Supprimer</button></td>`;
        tbody.appendChild(tr);
    });
}

function saveSchoolInfo() {
    const fields = [
        { id: 'schoolName',    key: 'name',      label: "Nom de l'établissement", max: 120 },
        { id: 'iaName',        key: 'ia',        label: "IA",        max: 80 },
        { id: 'iefName',       key: 'ief',       label: "IEF",       max: 80 },
        { id: 'examDates',     key: 'dates',     label: "Dates",     max: 80 },
        { id: 'principalName', key: 'principal', label: "Directeur", max: 80 },
        { id: 'prefetName',    key: 'prefet',    label: "Préfet",    max: 80 }
    ];
    const cleaned = {};
    for (const f of fields) {
        const raw = document.getElementById(f.id).value;
        const r = Security.validateText(raw, { maxLength: f.max, field: f.label });
        if (!r.ok) { toast(r.error, 'error', 5000); return; }
        cleaned[f.key] = r.value;
    }
    Object.assign(appData.school, cleaned);
    saveData();
    toast('Informations de l\'établissement sauvegardées.', 'success');
}

function addSubject() {
    const ld = getLevelData();
    const code = 'MAT' + (ld.subjects.length + 1);
    ld.subjects.push({ name: 'Nouvelle Matière', code: code, coef: 1 });
    renderConfigPage();
    toast('Matière ajoutée. Modifiez le nom et le code puis sauvegardez.', 'info');
}

function removeSubject(idx) {
    const ld = getLevelData();
    const name = ld.subjects[idx].name;
    showConfirm('Supprimer cette matière ?', `Voulez-vous vraiment supprimer "${name}" ?`, () => {
        ld.subjects.splice(idx, 1);
        renderConfigPage();
        toast(`Matière "${name}" supprimée. Pensez à sauvegarder.`, 'info');
    });
}

function saveSubjectsConfig() {
    const ld = getLevelData();
    document.querySelectorAll('.sname').forEach(el => { ld.subjects[el.dataset.si].name = el.value; });
    document.querySelectorAll('.scode').forEach(el => { ld.subjects[el.dataset.si].code = el.value.trim().toUpperCase(); });
    document.querySelectorAll('.scoef').forEach(el => { ld.subjects[el.dataset.si].coef = parseInt(el.value) || 1; });
    ld.subjects2 = [];
    document.querySelectorAll('.sinc2').forEach(el => {
        if (el.checked) {
            const i = el.dataset.si;
            const coef2 = parseInt(document.querySelectorAll('.scoef2')[i].value) || ld.subjects[i].coef;
            ld.subjects2.push({ name: ld.subjects[i].name, code: ld.subjects[i].code, coef: coef2 });
        }
    });
    ld.coefTotal = ld.subjects.reduce((s, sub) => s + sub.coef, 0);
    ld.coefTotal2 = ld.subjects2.reduce((s, sub) => s + sub.coef, 0);
    ld.seuilAdmis = parseInt(document.getElementById('seuilAdmis').value) || 0;
    ld.seuil2eTour = parseInt(document.getElementById('seuil2eTour').value) || 0;
    ld.seuilAdmis2 = parseInt(document.getElementById('seuilAdmis2').value) || 0;
    saveData();
    toast('Matières et coefficients sauvegardés.', 'success');
}

// ========== DOCUMENTS ==========
function docHeader(title, subtitle) {
    const school = appData.school;
    return `<div style="text-align:center; margin-bottom:15px;">
        <img src="logo.jpg" alt="Logo" style="width:60px; height:60px; border-radius:50%; margin-bottom:8px;">
        <h3 style="color:#3E2415; margin:4px 0;">${school.name}</h3>
        <p style="font-size:0.85em; color:#7a6a58;">IA: ${school.ia} / IEF: ${school.ief} - ${appData.year}</p>
        ${school.dates ? `<p style="font-size:0.85em; color:#5c4a38; margin-top:4px;"><b>Session:</b> ${school.dates}</p>` : ''}
        ${title ? `<h3 style="color:#3E2415; margin-top:8px; padding-top:8px; border-top:2px solid #B8A67A;">${title}</h3>` : ''}
        ${subtitle ? `<p style="font-size:0.9em; color:#5c4a38;">${subtitle}</p>` : ''}
    </div>`;
}

function printDocument(type) {
    const ld = getLevelData(), cfg = LEVELS[currentLevel], school = appData.school;
    let html = '';
    const modalTitle = document.getElementById('printModalTitle');
    const content = document.getElementById('printModalContent');

    if (type === 'releve1') {
        modalTitle.textContent = 'Relevé de notes';
        const total = ld.students.length, perCol = Math.ceil(total / 3);
        html = docHeader('RELEVÉ DE NOTES', cfg.examLabel + ' - ' + cfg.className);
        html += `<p style="text-align:center; margin-bottom:10px;">Matière: _________________ Correcteur: _________________</p>
            <table><thead><tr><th>N ANO</th><th>NOTE</th><th></th><th>N ANO</th><th>NOTE</th><th></th><th>N ANO</th><th>NOTE</th></tr></thead><tbody>`;
        for (let i = 0; i < perCol; i++) {
            html += '<tr>';
            for (let c = 0; c < 3; c++) { const idx = c * perCol + i; html += idx < total ? `<td>${idx+1}</td><td></td>` : '<td></td><td></td>'; if (c < 2) html += '<td></td>'; }
            html += '</tr>';
        }
        html += '</tbody></table>';
    } else if (type === 'listeSalle') {
        modalTitle.textContent = 'Liste de Salle';
        const salles = getSalles();
        html = '';
        let studentIdx = 0;
        salles.forEach((salle, si) => {
            if (si > 0) html += '<div style="page-break-before:always; margin-top:20px;"></div>';
            html += docHeader('LISTE DES CANDIDATS', cfg.className + ' - ' + salle.nom + ' (Capacité: ' + salle.capacite + ')');
            html += `<table><thead><tr><th>N</th><th>PRÉNOM(S)</th><th>NOM</th></tr></thead><tbody>`;
            let count = 0;
            while (studentIdx < ld.students.length && count < salle.capacite) {
                const s = ld.students[studentIdx];
                html += `<tr><td>${count + 1}</td><td style="text-align:left;">${Security.escapeHTML(s.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(s.nom)}</td></tr>`;
                studentIdx++; count++;
            }
            html += `</tbody></table><p><b>Effectif: ${count}</b></p>`;
        });
    } else if (type === 'emargement') {
        modalTitle.textContent = "Liste d'Émargement";
        const sallesE = getSalles();
        html = '';
        let sIdx = 0;
        sallesE.forEach((salle, si) => {
            if (si > 0) html += '<div style="page-break-before:always; margin-top:20px;"></div>';
            html += docHeader("LISTE D'ÉMARGEMENT", salle.nom + ' - ' + cfg.className);
            html += `<table><thead><tr><th>N</th><th>PRÉNOM(S)</th><th>NOM</th><th style="width:200px;">Émargement</th></tr></thead><tbody>`;
            let count = 0;
            while (sIdx < ld.students.length && count < salle.capacite) {
                const s = ld.students[sIdx];
                html += `<tr><td>${count + 1}</td><td style="text-align:left;">${Security.escapeHTML(s.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(s.nom)}</td><td></td></tr>`;
                sIdx++; count++;
            }
            html += `</tbody></table><p><b>Effectif: ${count}</b></p>`;
        });
    } else if (type === 'ficheNote') {
        modalTitle.textContent = 'Fiche de Notes';
        const total = ld.students.length, half = Math.ceil(total / 2);
        html = docHeader('FICHE DE NOTES (' + cfg.examLabel + ')', cfg.className);
        html += `<p style="text-align:center; margin-bottom:10px;">Correcteur: .................. Matière: .................. Tel: ..................</p>
            <table><thead><tr><th>N ANO</th><th>NOTES</th><th></th><th>N ANO</th><th>NOTES</th></tr></thead><tbody>`;
        for (let i = 0; i < half; i++) {
            html += `<tr><td>${i+1}</td><td></td><td></td>`;
            html += (i + half < total) ? `<td>${i+half+1}</td><td></td></tr>` : '<td></td><td></td></tr>';
        }
        html += '</tbody></table>';
    } else if (type === 'admisOffice') {
        modalTitle.textContent = "Admis d'Office";
        const admis = ld.results1.filter(r => r.decision === 'Admis').sort((a, b) => b.moyenne - a.moyenne);
        if (admis.length === 0) { toast('Aucun admis d\'office. Veuillez d\'abord calculer les résultats.', 'warning'); return; }
        html = docHeader("LISTE DES CANDIDATS ADMIS D'OFFICE", cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        html += `<table><thead><tr><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Moyenne</th><th>Rang</th></tr></thead><tbody>`;
        admis.forEach((r, i) => html += `<tr><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td><td>${r.moyenne.toFixed(1)}</td><td>${i+1}</td></tr>`);
        html += `</tbody></table><p><b>Total: ${admis.length}</b></p>`;
    } else if (type === 'admis2e') {
        modalTitle.textContent = 'Admis 2ème Groupe';
        const admis2 = ld.results2.filter(r => r.decision === 'Admis').sort((a, b) => b.moyenne - a.moyenne);
        if (admis2.length === 0) { toast('Aucun admis au 2ème groupe.', 'warning'); return; }
        html = docHeader('LISTE DES CANDIDATS ADMIS AU 2ÈME GROUPE', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        html += `<table><thead><tr><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Moyenne</th><th>Rang</th></tr></thead><tbody>`;
        admis2.forEach((r, i) => html += `<tr><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td><td>${r.moyenne.toFixed(1)}</td><td>${i+1}</td></tr>`);
        html += `</tbody></table><p><b>Total: ${admis2.length}</b></p>`;
    }
    // ===== BULLETIN INDIVIDUEL =====
    if (type === 'bulletin') {
        modalTitle.textContent = 'Bulletins Individuels';
        if (ld.results1.length === 0) { toast('Veuillez d\'abord calculer les résultats.', 'warning'); return; }
        html = '';
        const sorted = [...ld.results1].sort((a, b) => a.student.numTable - b.student.numTable);
        sorted.forEach((r, idx) => {
            const showMentionB = currentLevel !== 'bfem3';
            html += `<div class="bulletin-page" ${idx > 0 ? 'style="page-break-before:always; margin-top:30px;"' : ''}>`;
            html += docHeader('BULLETIN DE NOTES', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
            html += `<div style="display:flex; justify-content:space-between; margin-bottom:12px; padding:10px; background:#f5efe8; border-radius:8px;">
                <div><b>Nom:</b> ${Security.escapeHTML(r.student.nom)}</div>
                <div><b>Prénom(s):</b> ${Security.escapeHTML(r.student.prenom)}</div>
                <div><b>N Table:</b> ${r.student.numTable}</div>
                <div><b>Anonymat:</b> ${Security.escapeHTML(r.student.anonymat || '-')}</div>
            </div>`;
            html += `<table><thead><tr><th>Matière</th><th>Coefficient</th><th>Note /20</th><th>Note x Coef</th></tr></thead><tbody>`;
            let totalPts = 0;
            ld.subjects.forEach(sub => {
                const g = ld.grades1[r.key] && ld.grades1[r.key][sub.code];
                if (g === 'INAPTE') {
                    html += `<tr><td style="text-align:left;">${sub.name}</td><td>-</td><td>INAPTE</td><td>-</td></tr>`;
                    return;
                }
                const note = (g !== undefined && g !== '' && g !== 'ABS') ? parseFloat(g) : null;
                const nxc = note !== null ? (note * sub.coef) : 0;
                totalPts += nxc;
                const noteDisplay = g === 'ABS' ? 'ABS' : (note !== null ? note.toFixed(2) : '-');
                html += `<tr><td style="text-align:left;">${sub.name}</td><td>${sub.coef}</td><td>${noteDisplay}</td><td>${note !== null ? nxc.toFixed(2) : '-'}</td></tr>`;
            });
            html += `</tbody></table>`;
            html += `<div style="display:flex; justify-content:space-between; margin-top:12px; padding:12px; background:#f5efe8; border-radius:8px; font-weight:700;">
                <div>Total: ${r.total}</div>
                <div>Moyenne: ${r.moyenne.toFixed(2)}/20</div>
                <div>Rang: ${r.rang}/${ld.results1.length}</div>
                <div class="${r.decision === 'Admis' ? 'admis' : r.decision === '2ème Tour' ? 'deuxieme-tour' : 'ajourne'}">${r.decision}</div>
                ${showMentionB && r.mention ? `<div><span class="mention-tag ${getMentionClass(r.mention)}">${r.mention}</span></div>` : ''}
            </div>`;
            html += `</div>`;
        });
    }

    // ===== LISTE DES ELEVES PAR NIVEAU =====
    if (type === 'listeEleves') {
        modalTitle.textContent = 'Liste des Élèves par Niveau';
        html = '';
        let totalGlobal = 0;
        const levelKeys = Object.keys(LEVELS);
        let anyData = false;
        levelKeys.forEach((lv, li) => {
            const d = appData.levels[lv];
            if (!d || !d.students || d.students.length === 0) return;
            anyData = true;
            const c = LEVELS[lv];
            const sorted = [...d.students].sort((a, b) => {
                const n = (a.nom || '').localeCompare(b.nom || '', 'fr', { sensitivity: 'base' });
                return n !== 0 ? n : (a.prenom || '').localeCompare(b.prenom || '', 'fr', { sensitivity: 'base' });
            });
            if (li > 0 && totalGlobal > 0) html += '<div style="page-break-before:always; margin-top:20px;"></div>';
            html += docHeader('LISTE DES ÉLÈVES - ' + c.className, c.examLabel + ' ' + appData.year);
            html += `<table><thead><tr><th>N°</th><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Sexe</th></tr></thead><tbody>`;
            sorted.forEach((s, i) => {
                html += `<tr><td>${i + 1}</td><td>${s.numTable}</td><td style="text-align:left;">${Security.escapeHTML(s.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(s.nom)}</td><td>${s.sexe || '-'}</td></tr>`;
            });
            html += `</tbody></table><p><b>Effectif ${c.shortLabel}: ${sorted.length}</b></p>`;
            totalGlobal += sorted.length;
        });
        if (!anyData) { toast('Aucun élève enregistré.', 'warning'); return; }
        html += `<p style="margin-top:15px; font-size:1.05em;"><b>TOTAL GÉNÉRAL : ${totalGlobal} élève(s)</b></p>`;
    }

    // ===== PV DE DELIBERATION =====
    if (type === 'pvDeliberation') {
        modalTitle.textContent = 'PV de Délibération';
        if (ld.results1.length === 0) { toast('Veuillez d\'abord calculer les résultats.', 'warning'); return; }
        const admis1 = ld.results1.filter(r => r.decision === 'Admis');
        const tour2 = ld.results1.filter(r => r.decision === '2ème Tour');
        const ajournés = ld.results1.filter(r => r.decision === 'Ajourné');
        const admis2 = ld.results2 ? ld.results2.filter(r => r.decision === 'Admis') : [];
        const totalAdmis = admis1.length + admis2.length;
        const pctAdmis = ld.results1.length > 0 ? ((totalAdmis / ld.results1.length) * 100).toFixed(1) : '0.0';
        // Définitifs : après le 2ème tour, les ajournés définitifs incluent les ajournés du 1er tour
        // et les candidats du 2ème tour non admis.
        const tour2NonAdmis = ld.results2 ? ld.results2.filter(r => r.decision !== 'Admis').length : 0;
        const ajournesDefinitifs = ajournés.length + tour2NonAdmis;
        const deliberationClose = ld.results2 && ld.results2.length > 0;
        const pctAjDef = ld.results1.length > 0 ? ((ajournesDefinitifs / ld.results1.length) * 100).toFixed(1) : '0.0';

        html = docHeader('PROCÈS-VERBAL DE DÉLIBÉRATION', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        html += `<div style="margin:15px 0; padding:15px; border:2px solid #3E2415; border-radius:8px;">
            <p style="margin-bottom:10px;">Le jury de l'${cfg.examLabel.toLowerCase()} session ${appData.year}, réuni en séance de délibération, a arrêté les résultats suivants :</p>
            <table style="width:100%; margin:10px 0;">
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Nombre d'inscrits</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700;">${ld.students.length}</td></tr>
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Nombre de présents</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700;">${ld.results1.length}</td></tr>
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Admis d'office (1er Tour)</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700; color:#10b981;">${admis1.length}</td></tr>
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Admis au 2ème Groupe</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700; color:#f59e0b;">${tour2.length}</td></tr>
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Ajournés</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700; color:#ef4444;">${ajournés.length}</td></tr>
                ${admis2.length > 0 ? `<tr><td style="padding:6px; border:1px solid #ccc;"><b>Admis au 2ème Tour</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700; color:#059669;">${admis2.length}</td></tr>` : ''}
                <tr style="background:#f5efe8;"><td style="padding:8px; border:1px solid #ccc;"><b>TOTAL ADMIS</b></td><td style="padding:8px; border:1px solid #ccc; text-align:center; font-weight:800; font-size:1.2em;">${totalAdmis} (${pctAdmis}%)</td></tr>
            </table>
            <h4 style="margin:15px 0 6px; color:#3E2415;">Récapitulatif général (définitif) :</h4>
            <table style="width:100%; margin:6px 0;">
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Admis définitifs</b> (1er + 2ème Tour)</td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700; color:#10b981;">${totalAdmis} (${pctAdmis}%)</td></tr>
                <tr><td style="padding:6px; border:1px solid #ccc;"><b>Ajournés définitifs</b></td><td style="padding:6px; border:1px solid #ccc; text-align:center; font-weight:700; color:#ef4444;">${ajournesDefinitifs} (${pctAjDef}%)</td></tr>
                <tr style="background:#f5efe8;"><td style="padding:8px; border:1px solid #ccc;"><b>RÉSULTAT ${deliberationClose ? 'DÉFINITIF' : 'PROVISOIRE (1er Tour)'}</b></td><td style="padding:8px; border:1px solid #ccc; text-align:center; font-weight:800;">Présents : ${ld.results1.length} — Admis : ${totalAdmis} — Ajournés : ${deliberationClose ? ajournesDefinitifs : ajournés.length}${deliberationClose ? '' : ' — 2ème Tour : ' + tour2.length}</td></tr>
            </table>`;

        // Mentions recap for Terminale
        if (currentLevel !== 'bfem3') {
            const allAdmis = [...admis1, ...admis2];
            const mTB = allAdmis.filter(r => r.mention === 'Très Bien').length;
            const mB = allAdmis.filter(r => r.mention === 'Bien').length;
            const mAB = allAdmis.filter(r => r.mention === 'Assez Bien').length;
            const mP = allAdmis.filter(r => r.mention === 'Passable').length;
            html += `<h4 style="margin:12px 0 6px; color:#3E2415;">Répartition des mentions :</h4>
                <table style="width:100%; margin-bottom:10px;">
                    <tr><td style="padding:4px 6px; border:1px solid #ccc;">Très Bien</td><td style="padding:4px 6px; border:1px solid #ccc; text-align:center; font-weight:700;">${mTB}</td></tr>
                    <tr><td style="padding:4px 6px; border:1px solid #ccc;">Bien</td><td style="padding:4px 6px; border:1px solid #ccc; text-align:center; font-weight:700;">${mB}</td></tr>
                    <tr><td style="padding:4px 6px; border:1px solid #ccc;">Assez Bien</td><td style="padding:4px 6px; border:1px solid #ccc; text-align:center; font-weight:700;">${mAB}</td></tr>
                    <tr><td style="padding:4px 6px; border:1px solid #ccc;">Passable</td><td style="padding:4px 6px; border:1px solid #ccc; text-align:center; font-weight:700;">${mP}</td></tr>
                </table>`;
        }

        html += `<p style="margin-top:15px;">Fait à ${school.ia || 'Tambacounda'}, le ____________________</p>
            <p style="margin-top:8px; font-style:italic;">Les membres du jury :</p>
            <div style="display:flex; justify-content:space-between; margin-top:30px; padding:0 20px;">
                <div style="text-align:center; min-width:150px;">
                    <p style="font-size:0.85em; color:#5c4a38;">Le Président du Jury</p>
                    <div style="height:50px;"></div>
                    <p style="border-top:1px solid #ccc; padding-top:4px; font-size:0.8em;">Nom et signature</p>
                </div>
                <div style="text-align:center; min-width:150px;">
                    <p style="font-size:0.85em; color:#5c4a38;">Le Secrétaire</p>
                    <div style="height:50px;"></div>
                    <p style="border-top:1px solid #ccc; padding-top:4px; font-size:0.8em;">Nom et signature</p>
                </div>
                <div style="text-align:center; min-width:150px;">
                    <p style="font-size:0.85em; color:#5c4a38;">Membre</p>
                    <div style="height:50px;"></div>
                    <p style="border-top:1px solid #ccc; padding-top:4px; font-size:0.8em;">Nom et signature</p>
                </div>
            </div>
        </div>`;
    }

    // ===== RÉSULTATS COMPLETS (1er Tour) — équivalent papier de l'export Excel =====
    if (type === 'resultats1') {
        modalTitle.textContent = 'Résultats complets (1er Tour)';
        if (!ld.results1 || ld.results1.length === 0) { toast('Veuillez d\'abord calculer les résultats du 1er tour.', 'warning'); return; }
        const showMentionR = currentLevel !== 'bfem3';
        const decColor = d => d === 'Admis' ? '#10b981' : d === '2ème Tour' ? '#f59e0b' : d === 'Ajourné' ? '#ef4444' : '#3E2415';
        const sorted = [...ld.results1].sort((a, b) => a.rang - b.rang);
        html = docHeader('RÉSULTATS DU 1er TOUR', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        let thead = '<table style="font-size:0.8em;"><thead><tr><th>N Tab</th><th>Prénom(s)</th><th>Nom</th>';
        ld.subjects.forEach(s => { thead += `<th>${Security.escapeHTML(s.name)}<br><small>(${s.coef})</small></th>`; });
        thead += '<th>Total</th><th>Moy.</th><th>Rang</th><th>Décision</th>' + (showMentionR ? '<th>Mention</th>' : '') + '</tr></thead><tbody>';
        html += thead;
        sorted.forEach(r => {
            html += `<tr><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td>`;
            ld.subjects.forEach(sub => {
                const g = ld.grades1[r.key] && ld.grades1[r.key][sub.code];
                let v = '';
                if (g === 'ABS') v = 'ABS'; else if (g === 'INAPTE') v = 'INAPTE'; else if (g !== undefined && g !== '') v = g;
                html += `<td>${Security.escapeHTML(v)}</td>`;
            });
            html += `<td>${r.total}</td><td><b>${r.moyenne.toFixed(2)}</b></td><td>${r.rang}</td><td style="color:${decColor(r.decision)}; font-weight:700;">${Security.escapeHTML(r.decision)}</td>`;
            if (showMentionR) html += `<td>${Security.escapeHTML(r.mention || '')}</td>`;
            html += '</tr>';
        });
        html += '</tbody></table>';
        const a1 = sorted.filter(r => r.decision === 'Admis').length;
        const t2 = sorted.filter(r => r.decision === '2ème Tour').length;
        const aj = sorted.filter(r => r.decision === 'Ajourné').length;
        html += `<p style="margin-top:8px;"><b>Présents :</b> ${sorted.length} &nbsp;—&nbsp; <b>Admis :</b> ${a1} &nbsp;—&nbsp; <b>2ème Tour :</b> ${t2} &nbsp;—&nbsp; <b>Ajournés :</b> ${aj}</p>`;
    }

    // ===== CLASSEMENT PAR ORDRE DE MÉRITE =====
    if (type === 'classement') {
        modalTitle.textContent = 'Classement par mérite';
        if (!ld.results1 || ld.results1.length === 0) { toast('Veuillez d\'abord calculer les résultats.', 'warning'); return; }
        const showMentionC = currentLevel !== 'bfem3';
        const decColorC = d => d === 'Admis' ? '#10b981' : d === '2ème Tour' ? '#f59e0b' : d === 'Ajourné' ? '#ef4444' : '#3E2415';
        const ranked = [...ld.results1].sort((a, b) => b.moyenne - a.moyenne);
        html = docHeader('CLASSEMENT PAR ORDRE DE MÉRITE', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        html += `<table><thead><tr><th>Rang</th><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Moyenne</th><th>Décision</th>${showMentionC ? '<th>Mention</th>' : ''}</tr></thead><tbody>`;
        ranked.forEach((r, i) => {
            html += `<tr><td><b>${i + 1}</b></td><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td><td><b>${r.moyenne.toFixed(2)}</b></td><td style="color:${decColorC(r.decision)}; font-weight:700;">${Security.escapeHTML(r.decision)}</td>${showMentionC ? `<td>${Security.escapeHTML(r.mention || '')}</td>` : ''}</tr>`;
        });
        html += `</tbody></table><p><b>Total classés : ${ranked.length}</b></p>`;
    }

    // ===== CANDIDATS CONVOQUÉS AU 2ème TOUR =====
    if (type === 'convoques2e') {
        modalTitle.textContent = 'Convoqués au 2ème Tour';
        const conv = (ld.results1 || []).filter(r => r.decision === '2ème Tour')
            .sort((a, b) => (a.student.nom || '').localeCompare(b.student.nom || '', 'fr', { sensitivity: 'base' }));
        if (conv.length === 0) { toast('Aucun candidat convoqué au 2ème tour (calculez d\'abord les résultats).', 'warning'); return; }
        html = docHeader('CANDIDATS CONVOQUÉS AU 2ème TOUR', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        html += `<table><thead><tr><th>N°</th><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Moyenne 1er Tour</th></tr></thead><tbody>`;
        conv.forEach((r, i) => html += `<tr><td>${i + 1}</td><td>${r.student.numTable}</td><td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td><td>${r.moyenne.toFixed(2)}</td></tr>`);
        html += `</tbody></table><p><b>Total convoqués : ${conv.length}</b></p>`;
    }

    // ===== AJOURNÉS / ÉCHECS (définitifs : ajournés 1er tour + non-admis du 2ème tour) =====
    if (type === 'ajournes') {
        modalTitle.textContent = 'Ajournés';
        if (!ld.results1 || ld.results1.length === 0) { toast('Veuillez d\'abord calculer les résultats.', 'warning'); return; }
        const aj1 = ld.results1.filter(r => r.decision === 'Ajourné').map(r => ({ st: r.student, moy: r.moyenne, src: '1er Tour' }));
        const aj2 = (ld.results2 || []).filter(r => r.decision !== 'Admis').map(r => ({ st: r.student, moy: r.moyenne, src: '2ème Tour' }));
        const ajournes = [...aj1, ...aj2].sort((a, b) => (a.st.nom || '').localeCompare(b.st.nom || '', 'fr', { sensitivity: 'base' }));
        if (ajournes.length === 0) { toast('Aucun ajourné.', 'info'); return; }
        const has2 = aj2.length > 0;
        html = docHeader('LISTE DES AJOURNÉS', cfg.examLabel + ' ' + appData.year + ' - ' + cfg.className);
        html += `<table><thead><tr><th>N°</th><th>N Tab</th><th>Prénom(s)</th><th>Nom</th><th>Moyenne</th>${has2 ? '<th>Échec après</th>' : ''}</tr></thead><tbody>`;
        ajournes.forEach((a, i) => html += `<tr><td>${i + 1}</td><td>${a.st.numTable}</td><td style="text-align:left;">${Security.escapeHTML(a.st.prenom)}</td><td style="text-align:left;">${Security.escapeHTML(a.st.nom)}</td><td>${a.moy.toFixed(2)}</td>${has2 ? `<td>${a.src}</td>` : ''}</tr>`);
        html += `</tbody></table><p><b>Total ajournés : ${ajournes.length}</b></p>`;
    }

    if (school.prefet || school.principal) {
        html += `<div style="margin-top:30px; display:flex; justify-content:space-between; padding:0 40px;">`;
        if (school.prefet) {
            html += `<div style="text-align:center;">
                <p style="font-size:0.85em; color:#5c4a38;">Le Préfet</p>
                <p style="font-size:0.95em; font-weight:700; color:#3E2415; margin-top:30px;">${school.prefet}</p>
            </div>`;
        }
        if (school.principal) {
            html += `<div style="text-align:center;">
                <p style="font-size:0.85em; color:#5c4a38;">Le Directeur</p>
                <p style="font-size:0.95em; font-weight:700; color:#3E2415; margin-top:30px;">${school.principal}</p>
            </div>`;
        }
        html += `</div>`;
    }
    content.innerHTML = html;
    document.getElementById('printModal').classList.add('show');
}

// ========== EXPORT ==========
function exportAllToExcel() {
    // Generate XLSX-compatible XML spreadsheet
    let hasData = false;
    let sheets = '';
    // Échappe le texte injecté dans le XML : un '&', '<' ou '>' (nom de matière
    // personnalisé, ou nom restauré d'une ancienne sauvegarde) corromprait le fichier.
    const xmlEsc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;' }[c]));
    const school = appData.school || {};

    Object.keys(LEVELS).forEach(lv => {
        const d = appData.levels[lv];
        if (!d || d.students.length === 0) return;
        hasData = true;
        const c = LEVELS[lv];
        const showMention = lv !== 'bfem3';

        let rows = '';
        // En-tête établissement — même présentation que les documents de l'app
        // (docHeader). Le logo n'est pas intégrable dans ce format XML : en-tête textuel.
        rows += `<Row><Cell><Data ss:Type="String">${xmlEsc(school.name || '')}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">${xmlEsc('IA: ' + (school.ia || '') + '   IEF: ' + (school.ief || '') + '   Année: ' + (appData.year || ''))}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">${xmlEsc(c.examLabel + ' - ' + c.className)}</Data></Cell></Row>`;
        if (school.dates) rows += `<Row><Cell><Data ss:Type="String">${xmlEsc('Session: ' + school.dates)}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">RÉSULTATS DU 1er TOUR</Data></Cell></Row>`;
        rows += '<Row></Row>';
        // Header row (colonnes)
        let headerCells = '<Cell><Data ss:Type="String">N Tab</Data></Cell><Cell><Data ss:Type="String">Prénom</Data></Cell><Cell><Data ss:Type="String">Nom</Data></Cell>';
        d.subjects.forEach(s => { headerCells += `<Cell><Data ss:Type="String">${xmlEsc(s.name)} (${s.coef})</Data></Cell>`; });
        headerCells += '<Cell><Data ss:Type="String">Total</Data></Cell><Cell><Data ss:Type="String">Moyenne</Data></Cell><Cell><Data ss:Type="String">Rang</Data></Cell><Cell><Data ss:Type="String">Décision</Data></Cell>';
        if (showMention) headerCells += '<Cell><Data ss:Type="String">Mention</Data></Cell>';
        rows += `<Row>${headerCells}</Row>`;

        // Data rows
        const sorted = [...(d.results1 || [])].sort((a, b) => a.rang - b.rang);
        sorted.forEach(r => {
            let cells = `<Cell><Data ss:Type="Number">${r.student.numTable}</Data></Cell><Cell><Data ss:Type="String">${xmlEsc(r.student.prenom)}</Data></Cell><Cell><Data ss:Type="String">${xmlEsc(r.student.nom)}</Data></Cell>`;
            d.subjects.forEach(sub => {
                const g = d.grades1[r.key] && d.grades1[r.key][sub.code];
                if (g === 'ABS') cells += '<Cell><Data ss:Type="String">ABS</Data></Cell>';
                else if (g === 'INAPTE') cells += '<Cell><Data ss:Type="String">INAPTE</Data></Cell>';
                else if (g !== undefined && g !== '') cells += `<Cell><Data ss:Type="Number">${g}</Data></Cell>`;
                else cells += '<Cell><Data ss:Type="String"></Data></Cell>';
            });
            cells += `<Cell><Data ss:Type="Number">${r.total}</Data></Cell><Cell><Data ss:Type="Number">${r.moyenne.toFixed(2)}</Data></Cell><Cell><Data ss:Type="Number">${r.rang}</Data></Cell><Cell><Data ss:Type="String">${xmlEsc(r.decision)}</Data></Cell>`;
            if (showMention) cells += `<Cell><Data ss:Type="String">${xmlEsc(r.mention || '')}</Data></Cell>`;
            rows += `<Row>${cells}</Row>`;
        });

        // Stats summary rows
        const présents = d.results1.length;
        const a1 = d.results1.filter(r => r.decision === 'Admis').length;
        const t2 = d.results1.filter(r => r.decision === '2ème Tour').length;
        const aj = d.results1.filter(r => r.decision === 'Ajourné').length;
        const a2 = d.results2 ? d.results2.filter(r => r.decision === 'Admis').length : 0;
        rows += '<Row></Row>';
        rows += `<Row><Cell><Data ss:Type="String">STATISTIQUES</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">Inscrits</Data></Cell><Cell><Data ss:Type="Number">${d.students.length}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">Présents</Data></Cell><Cell><Data ss:Type="Number">${présents}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">Admis 1er Tour</Data></Cell><Cell><Data ss:Type="Number">${a1}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">2ème Tour</Data></Cell><Cell><Data ss:Type="Number">${t2}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">Ajournés</Data></Cell><Cell><Data ss:Type="Number">${aj}</Data></Cell></Row>`;
        if (a2 > 0) rows += `<Row><Cell><Data ss:Type="String">Admis 2ème Tour</Data></Cell><Cell><Data ss:Type="Number">${a2}</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">TOTAL ADMIS</Data></Cell><Cell><Data ss:Type="Number">${a1 + a2}</Data></Cell></Row>`;

        // Administration / signataires en bas de page (comme le pied des documents).
        rows += '<Row></Row><Row></Row>';
        rows += `<Row><Cell><Data ss:Type="String">${xmlEsc('Fait à ' + (school.ia || 'Tambacounda') + ', le ____________________')}</Data></Cell></Row>`;
        rows += '<Row></Row>';
        // Préfet à gauche, Directeur à droite — même ordre que le pied des documents imprimés.
        rows += `<Row><Cell><Data ss:Type="String">Le Préfet</Data></Cell><Cell ss:Index="4"><Data ss:Type="String">Le Directeur</Data></Cell></Row>`;
        rows += `<Row><Cell><Data ss:Type="String">${xmlEsc(school.prefet || '')}</Data></Cell><Cell ss:Index="4"><Data ss:Type="String">${xmlEsc(school.principal || '')}</Data></Cell></Row>`;

        const sheetName = c.shortLabel.replace(/[^a-zA-Z0-9 ]/g, '');
        sheets += `<Worksheet ss:Name="${sheetName}"><Table>${rows}</Table></Worksheet>`;
    });

    if (!hasData) { toast('Aucune donnée à exporter.', 'warning'); return; }

    const xml = `<?xml version="1.0" encoding="UTF-8"?><?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
${sheets}
</Workbook>`;

    const blob = new Blob([xml], { type: 'application/vnd.ms-excel' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `Examens_Blancs_${appData.year}.xls`; a.click();
    toast('Fichier Excel exporté !', 'success');
    logActivity('Export Excel généré pour ' + appData.year, 'export');
}

// ========== BACKUP / RESTORE ==========
function showBackupModal() { document.getElementById('backupModal').classList.add('show'); }

// Date du dernier export, pour pouvoir rappeler d'en refaire un.
const DERNIERE_SAUVEGARDE_KEY = 'examBlanc_derniereSauvegarde';
const RAPPEL_SAUVEGARDE_JOURS = 7;

function exportBackupJSON() {
    const json = JSON.stringify(appData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    const date = new Date().toISOString().slice(0, 10);
    a.download = `Backup_ExamBlanc_${date}.json`; a.click();
    try { localStorage.setItem(DERNIERE_SAUVEGARDE_KEY, date); } catch (e) {}
    masquerRappelSauvegarde();
    toast('Sauvegarde JSON exportée.', 'success');
}

// Toutes les données vivent dans le navigateur : un vidage de cache efface
// l'année. Tant que l'application n'a pas de serveur, le seul filet est
// l'export manuel — encore faut-il y penser.
function joursDepuisSauvegarde() {
    let derniere;
    try { derniere = localStorage.getItem(DERNIERE_SAUVEGARDE_KEY); } catch (e) { return null; }
    if (!derniere) return null;
    const ms = Date.now() - new Date(derniere + 'T00:00:00').getTime();
    return Math.floor(ms / 86400000);
}

function masquerRappelSauvegarde() {
    const el = document.getElementById('rappelSauvegarde');
    if (el) el.remove();
}

function verifierRappelSauvegarde() {
    masquerRappelSauvegarde();
    // Rien à sauvegarder tant que l'établissement est vide
    const ec = appData.ecole || {};
    const aDesDonnees = (ec.classes || []).length > 0 ||
        Object.keys(appData.levels || {}).some(lv => (appData.levels[lv].students || []).length > 0);
    if (!aDesDonnees) return;

    const jours = joursDepuisSauvegarde();
    if (jours !== null && jours < RAPPEL_SAUVEGARDE_JOURS) return;

    const banniere = document.createElement('div');
    banniere.id = 'rappelSauvegarde';
    banniere.className = 'alert alert-warning';
    banniere.style.cssText = 'margin:0 0 12px; display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;';
    banniere.innerHTML = `<span>${jours === null
            ? 'Aucune sauvegarde enregistrée. Vos données ne vivent que dans ce navigateur : un vidage de cache les effacerait.'
            : `Dernière sauvegarde il y a <strong>${jours}</strong> jour(s). Pensez à exporter avant de perdre du travail.`}</span>
        <span class="btn-group no-print">
            <button class="btn btn-sm btn-success" onclick="exportBackupJSON()">Sauvegarder maintenant</button>
            <button class="btn btn-sm btn-outline" onclick="masquerRappelSauvegarde()">Plus tard</button>
        </span>`;
    const zone = document.querySelector('.content-area .header');
    if (zone) zone.insertAdjacentElement('afterend', banniere);
}

function importBackupJSON(input) {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            if (!data.levels && !data.school) { toast('Fichier de sauvegarde invalide.', 'error'); return; }
            showConfirm('Restaurer la sauvegarde ?', 'Toutes les données actuelles seront remplacées par celles de la sauvegarde.', () => {
                Object.assign(appData, data);
                sanitizeStudents();
                saveData();
                populateYearSelect();
                updateLevelTags();
                refreshCurrentPage();
                closeModal('backupModal');
                toast('Données restaurées avec succès !', 'success');
            });
        } catch (err) {
            toast('Erreur lors de la lecture du fichier.', 'error');
        }
    };
    reader.readAsText(file);
    input.value = '';
}

function confirmResetData() {
    showConfirm('Réinitialiser ?', 'ATTENTION : Toutes les données seront définitivement supprimées !', () => {
        localStorage.removeItem(STORAGE_KEY);
        appData = { year: '2025-2026', school: { name: 'Collège Jean XXIII', ia: 'Tambacounda', ief: 'Tambacounda', dates: '', principal: '', prefet: '' }, levels: {} };
        updateLevelTags();
        refreshCurrentPage();
        closeModal('backupModal');
        toast('Toutes les données ont été réinitialisées.', 'info');
    });
}

// ========== PERSISTENCE ==========
function saveData() { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(appData)); } catch(e) { toast('Erreur de sauvegarde !', 'error'); } }
function loadData() { try { const s = localStorage.getItem(STORAGE_KEY); if (s) { Object.assign(appData, JSON.parse(s)); return true; } } catch(e) {} return false; }

// Purge les entrées d'élèves invalides (null/non-objet) et force nom/prénom en texte.
// De telles entrées peuvent provenir d'une sauvegarde JSON restaurée à la main ou d'un
// localStorage abîmé ; elles faisaient planter l'ajout (vérif doublons sur s.numTable)
// et le tri (s.nom.localeCompare), ce qui laissait la liste bloquée et tout nouvel élève
// empilé en bas. À appeler après tout chargement de données.
function sanitizeStudents() {
    Object.keys(appData.levels || {}).forEach(lv => {
        const d = appData.levels[lv];
        if (!d || !Array.isArray(d.students)) return;
        d.students = d.students.filter(s => s && typeof s === 'object');
        d.students.forEach(s => {
            if (typeof s.nom !== 'string') s.nom = s.nom == null ? '' : String(s.nom);
            if (typeof s.prenom !== 'string') s.prenom = s.prenom == null ? '' : String(s.prenom);
        });
    });
}

function closeModal(id) { document.getElementById(id).classList.remove('show'); }
document.querySelectorAll('.modal-overlay').forEach(o => o.addEventListener('click', e => { if (e.target === o) o.classList.remove('show'); }));

// Keyboard: Escape to close modals
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.show').forEach(m => m.classList.remove('show'));
    }
});

// Enter to submit in student modal
document.getElementById('studentNom').addEventListener('keydown', e => { if (e.key === 'Enter') saveStudent(); });

// ========== DASHBOARD ==========
function renderDashboard() {
    const container = document.getElementById('dashboardContent');
    let html = '';

    // Overview cards for current level
    const ld = getLevelData();
    const cfg = LEVELS[currentLevel];
    const totalStudents = ld.students.length;
    const gradesEntered = countGradesEntered(ld, 1);
    const totalGrades = totalStudents * ld.subjects.length;
    const pctGrades = totalGrades > 0 ? Math.round((gradesEntered / totalGrades) * 100) : 0;
    const admis1 = ld.results1.filter(r => r.decision === 'Admis').length;
    const tour2 = ld.results1.filter(r => r.decision === '2ème Tour').length;
    const admis2 = ld.results2 ? ld.results2.filter(r => r.decision === 'Admis').length : 0;

    html += `<div class="stats-grid">
        <div class="stat-card blue"><div class="number">${totalStudents}</div><div class="label">Élèves inscrits</div></div>
        <div class="stat-card ${pctGrades === 100 ? 'green' : 'orange'}"><div class="number">${pctGrades}%</div><div class="label">Notes saisies (1er Tour)</div></div>
        <div class="stat-card green"><div class="number">${admis1 + admis2}</div><div class="label">Total Admis</div></div>
        <div class="stat-card orange"><div class="number">${tour2}</div><div class="label">En attente 2e Tour</div></div>
    </div>`;

    // Progress bar for grade entry
    html += `<div class="card" style="margin-top:12px;">
        <h3>Progression de la saisie - 1er Tour</h3>
        <div class="grade-progress-container">`;
    ld.subjects.forEach(sub => {
        let count = 0;
        ld.students.forEach(st => {
            const k = stKey(st);
            const g = ld.grades1[k] && ld.grades1[k][sub.code];
            if (g !== undefined && g !== '') count++;
        });
        const pct = totalStudents > 0 ? Math.round((count / totalStudents) * 100) : 0;
        const color = pct === 100 ? '#10b981' : pct > 50 ? '#f59e0b' : '#ef4444';
        html += `<div class="grade-progress-row">
            <span class="grade-progress-label">${sub.name}</span>
            <div class="bar-track" style="flex:1; height:18px;">
                <div class="bar-fill" style="width:${Math.max(pct, 2)}%; background:${color}; height:100%;">
                    <span class="bar-value" style="font-size:0.68em;">${count}/${totalStudents}</span>
                </div>
            </div>
            <span class="grade-progress-pct">${pct}%</span>
        </div>`;
    });
    html += `</div></div>`;

    // Overview all levels
    html += `<div class="card" style="margin-top:12px;">
        <h3>Résumé de tous les niveaux</h3>
        <table><thead><tr><th>Niveau</th><th>Inscrits</th><th>Notes saisies</th><th>Admis 1er T</th><th>2e Tour</th><th>Admis 2e T</th><th>Total Admis</th><th>Taux</th></tr></thead><tbody>`;
    Object.keys(LEVELS).forEach(lv => {
        const d = appData.levels[lv];
        if (!d) return;
        const c = LEVELS[lv];
        const nb = d.students.length;
        const ge = countGradesEntered(d, 1);
        const tg = nb * d.subjects.length;
        const pg = tg > 0 ? Math.round((ge / tg) * 100) : 0;
        const a1 = d.results1 ? d.results1.filter(r => r.decision === 'Admis').length : 0;
        const t2 = d.results1 ? d.results1.filter(r => r.decision === '2ème Tour').length : 0;
        const a2 = d.results2 ? d.results2.filter(r => r.decision === 'Admis').length : 0;
        const ta = a1 + a2;
        const taux = nb > 0 ? ((ta / nb) * 100).toFixed(1) : '0.0';
        html += `<tr><td style="text-align:left; font-weight:600;">${c.shortLabel}</td><td>${nb}</td><td>${pg}%</td><td class="${a1 > 0 ? 'admis' : ''}">${a1}</td><td>${t2}</td><td>${a2}</td><td style="font-weight:700;">${ta}</td><td style="font-weight:700;">${taux}%</td></tr>`;
    });
    html += `</tbody></table></div>`;

    // Recent activity
    const logs = getActivityLog().slice(0, 5);
    if (logs.length > 0) {
        html += `<div class="card" style="margin-top:12px;">
            <h3>Activité récente</h3>
            <div class="journal-list">`;
        logs.forEach(log => {
            html += `<div class="journal-item">
                <span class="journal-time">${formatLogDate(log.date)}</span>
                <span class="journal-badge journal-badge-${log.type || 'info'}">${log.type || 'info'}</span>
                <span class="journal-msg">${log.message}</span>
            </div>`;
        });
        html += `</div></div>`;
    }

    container.innerHTML = html;
}

function countGradesEntered(levelData, tour) {
    let count = 0;
    const grades = tour === 1 ? levelData.grades1 : levelData.grades2;
    const subjects = tour === 1 ? levelData.subjects : levelData.subjects2;
    const students = tour === 1 ? levelData.students : (levelData.tour2Students || []);
    students.forEach(st => {
        const k = stKey(st);
        subjects.forEach(sub => {
            const g = grades[k] && grades[k][sub.code];
            if (g !== undefined && g !== '') count++;
        });
    });
    return count;
}

// ========== MENTIONS (Terminale only) ==========
function getMention(moyenne, level) {
    if (level === 'bfem3') return '';
    if (moyenne >= 16) return 'Très Bien';
    if (moyenne >= 14) return 'Bien';
    if (moyenne >= 12) return 'Assez Bien';
    if (moyenne >= 10) return 'Passable';
    return '';
}

function getMentionClass(mention) {
    if (mention === 'Très Bien') return 'mention-tb';
    if (mention === 'Bien') return 'mention-b';
    if (mention === 'Assez Bien') return 'mention-ab';
    if (mention === 'Passable') return 'mention-p';
    return '';
}

// ========== GLOBAL SEARCH ==========
function positionGlobalSearchResults() {
    const input = document.getElementById('globalSearch');
    const results = document.getElementById('globalSearchResults');
    if (!input || !results) return;
    const rect = input.getBoundingClientRect();
    results.style.top = (rect.bottom + 6) + 'px';
    results.style.left = rect.left + 'px';
    results.style.width = Math.max(rect.width, 320) + 'px';
}

function performGlobalSearch(query) {
    const results = document.getElementById('globalSearchResults');
    if (!query || query.trim().length < 2) { results.innerHTML = ''; results.style.display = 'none'; return; }
    positionGlobalSearchResults();
    query = query.toLowerCase().trim();
    let html = '';
    let found = 0;
    Object.keys(LEVELS).forEach(lv => {
        const d = appData.levels[lv];
        if (!d) return;
        d.students.forEach(st => {
            if (found >= 10) return;
            const fullName = `${st.prenom} ${st.nom} ${st.numTable} ${st.anonymat || ''}`.toLowerCase();
            if (fullName.includes(query)) {
                found++;
                const res1 = d.results1 ? d.results1.find(r => r.key === stKey(st)) : null;
                const moyStr = res1 ? ` - Moy: ${res1.moyenne.toFixed(2)}` : '';
                const decStr = res1 ? ` - ${res1.decision}` : '';
                html += `<div class="global-search-item" onclick="goToStudent('${lv}', ${st.numTable})">
                    <span class="global-search-level">${LEVELS[lv].shortLabel}</span>
                    <span class="global-search-name">${Security.escapeHTML(st.prenom)} ${Security.escapeHTML(st.nom)}</span>
                    <span class="global-search-info">N${st.numTable}${moyStr}${decStr}</span>
                </div>`;
            }
        });
    });
    if (found === 0) html = '<div class="global-search-item" style="color:var(--text-secondary);">Aucun résultat</div>';
    results.innerHTML = html;
    results.style.display = 'block';
}

// ========== DEBOUNCE (champs de recherche) ==========
// Évite de re-rendre la liste / re-balayer toutes les classes à chaque frappe.
// Le résultat est identique, seul le déclenchement est différé (~150 ms).
function debounce(fn, ms) {
    let t;
    return function(...args) {
        clearTimeout(t);
        t = setTimeout(() => fn.apply(this, args), ms);
    };
}
// Déclarées en `function` (et non `const`) pour rester accessibles depuis les
// attributs oninput="" du HTML, qui ne voient pas les liaisons lexicales globales.
const _debouncedStudentSearch = debounce(renderStudentsTable, 150);
function onStudentSearchInput() { _debouncedStudentSearch(); }
const _debouncedGlobalSearch = debounce(performGlobalSearch, 150);
function onGlobalSearchInput(q) { _debouncedGlobalSearch(q); }

function goToStudent(level, numTable) {
    document.getElementById('globalSearch').value = '';
    document.getElementById('globalSearchResults').style.display = 'none';
    currentLevel = level;
    document.querySelectorAll('.level-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('lvl-' + level).classList.add('active');
    showPage('students');
    setTimeout(() => {
        const searchEl = document.getElementById('studentSearch');
        if (searchEl) { searchEl.value = String(numTable); renderStudentsTable(); }
    }, 100);
}

// Close global search on click outside
document.addEventListener('click', function(e) {
    const wrap = document.querySelector('.global-search-wrap');
    const results = document.getElementById('globalSearchResults');
    if (wrap && !wrap.contains(e.target) && results && !results.contains(e.target)) {
        results.style.display = 'none';
    }
});
window.addEventListener('resize', positionGlobalSearchResults);
window.addEventListener('scroll', positionGlobalSearchResults, true);

// ========== ACTIVITY LOG / JOURNAL ==========
function getActivityLog() {
    try {
        return JSON.parse(localStorage.getItem('examBlanc_journal') || '[]');
    } catch(e) { return []; }
}

function saveActivityLog(logs) {
    try {
        // Keep only last 200 entries
        if (logs.length > 200) logs = logs.slice(0, 200);
        localStorage.setItem('examBlanc_journal', JSON.stringify(logs));
    } catch(e) {}
}

function logActivity(message, type) {
    type = type || 'info';
    const logs = getActivityLog();
    logs.unshift({ date: new Date().toISOString(), message: message, type: type, user: currentUserRole ? currentUserRole.role : 'système' });
    saveActivityLog(logs);
}

function formatLogDate(isoDate) {
    try {
        const d = new Date(isoDate);
        return d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    } catch(e) { return isoDate; }
}

function renderJournal() {
    const container = document.getElementById('journalContent');
    const logs = getActivityLog();
    if (logs.length === 0) { container.innerHTML = '<div class="empty-state"><p>Aucune activité enregistrée.</p></div>'; return; }
    let html = '<div class="journal-list">';
    logs.forEach(log => {
        html += `<div class="journal-item">
            <span class="journal-time">${formatLogDate(log.date)}</span>
            <span class="journal-badge journal-badge-${log.type}">${log.type}</span>
            <span class="journal-user">${log.user || ''}</span>
            <span class="journal-msg">${log.message}</span>
        </div>`;
    });
    html += '</div>';
    container.innerHTML = html;
}

function clearActivityLog() {
    showConfirm('Vider le journal ?', 'Toutes les activités seront supprimées.', () => {
        localStorage.removeItem('examBlanc_journal');
        renderJournal();
        toast('Journal vidé.', 'info');
    });
}

// ========== SALLES D'EXAMEN ==========
function getSalles() {
    if (!appData.salles) appData.salles = [{ nom: 'Salle 1', capacite: 30 }];
    return appData.salles;
}

function renderSallesConfig() {
    const salles = getSalles();
    const container = document.getElementById('sallesConfig');
    if (!container) return;
    let html = '<table><thead><tr><th>Nom de la Salle</th><th>Capacité</th><th>Actions</th></tr></thead><tbody>';
    salles.forEach((s, i) => {
        html += `<tr>
            <td><input type="text" value="${s.nom}" style="width:200px;" data-salle="${i}" class="salle-nom"></td>
            <td><input type="number" value="${s.capacite}" min="1" max="100" style="width:80px;" data-salle="${i}" class="salle-cap"></td>
            <td><button class="btn btn-danger btn-sm" onclick="removeSalle(${i})">Supprimer</button></td>
        </tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function addSalle() {
    const salles = getSalles();
    salles.push({ nom: 'Salle ' + (salles.length + 1), capacite: 30 });
    renderSallesConfig();
    toast('Salle ajoutée.', 'info');
}

function removeSalle(idx) {
    const salles = getSalles();
    if (salles.length <= 1) { toast('Il faut au moins une salle.', 'warning'); return; }
    salles.splice(idx, 1);
    renderSallesConfig();
}

function saveSallesConfig() {
    const salles = getSalles();
    document.querySelectorAll('.salle-nom').forEach(el => { salles[el.dataset.salle].nom = el.value; });
    document.querySelectorAll('.salle-cap').forEach(el => { salles[el.dataset.salle].capacite = parseInt(el.value) || 30; });
    appData.salles = salles;
    saveData();
    logActivity('Salles d\'examen mises à jour', 'config');
    toast('Salles sauvegardées.', 'success');
}

// ========== YEAR SNAPSHOTS (for comparison) ==========
function getYearSnapshots() {
    try { return JSON.parse(localStorage.getItem('examBlanc_snapshots') || '{}'); } catch(e) { return {}; }
}

function saveYearSnapshot() {
    const snapshots = getYearSnapshots();
    const year = appData.year;
    snapshots[year] = {};
    Object.keys(LEVELS).forEach(lv => {
        const d = appData.levels[lv];
        if (!d || d.results1.length === 0) return;
        const a1 = d.results1.filter(r => r.decision === 'Admis').length;
        const a2 = d.results2 ? d.results2.filter(r => r.decision === 'Admis').length : 0;
        let sumMoy = 0;
        d.results1.forEach(r => sumMoy += r.moyenne);
        const moyGen = d.results1.length > 0 ? sumMoy / d.results1.length : 0;
        snapshots[year][lv] = {
            inscrits: d.students.length,
            presents: d.results1.length,
            admis1: a1,
            admis2: a2,
            totalAdmis: a1 + a2,
            moyGen: moyGen
        };
    });
    try { localStorage.setItem('examBlanc_snapshots', JSON.stringify(snapshots)); } catch(e) {}
    toast(`Snapshot ${year} sauvegardé !`, 'success');
    logActivity(`Snapshot annuel sauvegardé pour ${year}`, 'config');
    renderStats('compare');
}

// ========== YEAR SELECT ==========
function getCurrentSchoolYear() {
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth(); // 0-based (0=Jan)
    // School year starts in October: Oct-Dec = year/year+1, Jan-Sep = (year-1)/year
    if (month >= 9) return year + '-' + (year + 1);
    return (year - 1) + '-' + year;
}

function populateYearSelect() {
    const select = document.getElementById('yearSelect');
    const currentYear = getCurrentSchoolYear();
    const startYear = parseInt(currentYear.split('-')[0]);

    // Generate: 2 years before, current, 2 years after
    const years = [];
    for (let y = startYear - 2; y <= startYear + 2; y++) {
        years.push(y + '-' + (y + 1));
    }

    select.innerHTML = '';
    years.forEach(yr => {
        const opt = document.createElement('option');
        opt.value = yr;
        opt.textContent = yr;
        if (yr === currentYear) opt.selected = true;
        select.appendChild(opt);
    });

    // Set to saved year or current
    const saved = appData.year;
    if (saved && years.includes(saved)) {
        select.value = saved;
    } else {
        appData.year = currentYear;
        select.value = currentYear;
    }
}

// ========== INIT ==========
function init() {
    loadTheme();
    loadSidebarState();
    loadData();
    sanitizeStudents();
    ensureEleveIds();
    checkSession();
    applyHiddenModules();
    verifierRappelSauvegarde();
    populateYearSelect();
    updateLevelTags();
    renderDashboard();
    // Restaure le dernier module utilisé (structure CRM multi-espaces)
    const savedModule = localStorage.getItem('examBlanc_module') || 'examens';
    if (savedModule !== 'examens' && MODULES[savedModule]) {
        showModule(savedModule);
    } else {
        syncModuleUI('examens');
    }
}
// NOTE : init() est appelé tout en bas du fichier, après l'initialisation de
// toutes les constantes des modules (sinon erreur "before initialization"
// quand init() restaure un module dont le rendu utilise ces constantes).

// ========== PDF EXPORT ==========
function exportPrintModalToPDF() {
    if (typeof html2pdf === 'undefined') { toast('Bibliothèque PDF non chargée.', 'error'); return; }
    const content = document.getElementById('printModalContent');
    if (!content || !content.innerHTML.trim()) { toast('Aucun contenu à exporter.', 'warning'); return; }
    const title = (document.getElementById('printModalTitle').textContent || 'document')
        .replace(/[^a-zA-Z0-9_\- ]/g, '').trim().replace(/\s+/g, '_');
    const filename = `${title}_${appData.year}.pdf`;
    toast('Génération du PDF en cours...', 'info', 2000);
    // Le document doit toujours être capturé en thème clair (texte foncé sur fond
    // blanc), même si l'utilisateur est en mode sombre : html2pdf force le fond
    // blanc mais pas la couleur du texte, ce qui rendrait le PDF délavé en sombre.
    const html = document.documentElement;
    const prevTheme = html.getAttribute('data-theme');
    html.setAttribute('data-theme', 'light');
    const opt = {
        margin:       [10, 10, 10, 10],
        filename:     filename,
        // JPEG q0.98 au lieu de PNG : un PNG plein-page n'est quasi pas compressé
        // (~8 Mo/page !). En JPEG 0.98 la qualité visuelle du texte est équivalente
        // mais le fichier est ~10× plus léger.
        image:        { type: 'jpeg', quality: 0.98 },
        // scale 3 ≈ 260 DPI (net à l'impression) au lieu de 2 ≈ 174 DPI (flou).
        html2canvas:  { scale: 3, useCORS: true, backgroundColor: '#ffffff', letterRendering: true, logging: false },
        jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait', compress: true },
        // avoid:'tr' empêche une ligne de tableau d'être coupée entre deux pages.
        pagebreak:    { mode: ['css', 'legacy'], before: '.bulletin-page', avoid: 'tr' }
    };
    const restoreTheme = () => {
        if (prevTheme === null) html.removeAttribute('data-theme');
        else html.setAttribute('data-theme', prevTheme);
    };
    html2pdf().set(opt).from(content).save().then(() => {
        toast('PDF exporté !', 'success');
        logActivity('Export PDF : ' + title, 'export');
    }).catch(err => {
        toast('Erreur PDF : ' + err.message, 'error', 5000);
    }).finally(restoreTheme);
}

// ========== PASTE GRADES FROM EXCEL ==========
function showPasteGradesModal(tour) {
    const ld = getLevelData();
    if (tour === 1 && ld.students.length === 0) { toast('Ajoutez d\'abord des élèves.', 'warning'); return; }
    if (tour === 2 && (!ld.tour2Students || ld.tour2Students.length === 0)) { toast('Aucun candidat au 2ème tour.', 'warning'); return; }
    document.getElementById('pasteTour').value = tour;
    document.getElementById('pasteGradesData').value = '';
    document.getElementById('pastePreview').innerHTML = '';
    document.getElementById('pasteHasHeader').checked = true;
    document.getElementById('pasteHasNames').checked = false;
    const subjects = tour === 1 ? ld.subjects : ld.subjects2;
    const codes = subjects.map(s => s.code).join(' | ');
    document.querySelector('#pasteGradesModal .alert-info').innerHTML =
        `Copiez une plage depuis Excel puis collez-la ci-dessous. Les colonnes correspondent aux matières dans l'ordre : <b>${codes}</b>. Utilisez <b>ABS</b> ou <b>INAPTE</b> pour les cas spéciaux.`;
    document.getElementById('pasteGradesModal').classList.add('show');
    setTimeout(() => document.getElementById('pasteGradesData').focus(), 200);
}

function parsePasteData() {
    const raw = document.getElementById('pasteGradesData').value;
    const hasHeader = document.getElementById('pasteHasHeader').checked;
    const hasNames = document.getElementById('pasteHasNames').checked;
    const tour = parseInt(document.getElementById('pasteTour').value);
    const ld = getLevelData();
    const subjects = tour === 1 ? ld.subjects : ld.subjects2;
    const students = tour === 1 ? ld.students : ld.tour2Students;

    const lines = raw.split(/\r?\n/).filter(l => l.trim() !== '');
    if (lines.length === 0) return { error: 'Aucune donnée.' };
    const sep = lines[0].includes('\t') ? '\t' : (lines[0].includes(';') ? ';' : ',');
    const matrix = lines.map(l => l.split(sep).map(c => c.trim()));

    let headerRow = null;
    let dataRows = matrix;
    if (hasHeader) { headerRow = matrix[0]; dataRows = matrix.slice(1); }

    // Build subject->column mapping
    const nameOffset = hasNames ? 1 : 0;
    let mapping = [];
    if (headerRow) {
        const headerCodes = headerRow.slice(nameOffset).map(h => (h || '').toUpperCase().replace(/[^A-Z0-9]/g, ''));
        subjects.forEach((sub, si) => {
            const want = sub.code.toUpperCase().replace(/[^A-Z0-9]/g, '');
            const idx = headerCodes.findIndex(h => h === want);
            mapping.push(idx === -1 ? si : idx); // fallback to positional
        });
    } else {
        mapping = subjects.map((_, i) => i);
    }

    return { matrix, headerRow, dataRows, mapping, subjects, students, hasNames, nameOffset, tour };
}

function previewPasteGrades() {
    const p = parsePasteData();
    const preview = document.getElementById('pastePreview');
    if (p.error) { preview.innerHTML = `<div class="alert alert-warning">${p.error}</div>`; return; }
    let html = '<table style="border-collapse:collapse; font-size:0.82em;"><thead><tr><th style="border:1px solid var(--border-color); padding:4px 8px;">Élève</th>';
    p.subjects.forEach(sub => html += `<th style="border:1px solid var(--border-color); padding:4px 8px;">${sub.code}</th>`);
    html += '</tr></thead><tbody>';
    let matched = 0;
    const limit = Math.min(p.dataRows.length, p.students.length, 10);
    for (let i = 0; i < limit; i++) {
        const row = p.dataRows[i];
        const st = p.hasNames ? findStudentByToken(p.students, row[0]) : p.students[i];
        if (st) matched++;
        html += `<tr><td style="border:1px solid var(--border-color); padding:4px 8px;">${st ? Security.escapeHTML(st.prenom + ' ' + st.nom) : '<em style="color:#ef4444;">Non trouvé</em>'}</td>`;
        p.mapping.forEach((colIdx, si) => {
            const v = row[colIdx + p.nameOffset] || '';
            html += `<td style="border:1px solid var(--border-color); padding:4px 8px;">${Security.escapeHTML(v)}</td>`;
        });
        html += '</tr>';
    }
    html += '</tbody></table>';
    html += `<p style="margin-top:6px; color:var(--text-secondary);">${p.dataRows.length} ligne(s) de données — ${matched}/${limit} élève(s) reconnus dans l'aperçu.</p>`;
    preview.innerHTML = html;
}

function findStudentByToken(students, token) {
    if (!token) return null;
    const t = String(token).trim().toUpperCase();
    // Try numTable
    const n = parseInt(t);
    if (!isNaN(n)) {
        const byNum = students.find(s => s.numTable === n);
        if (byNum) return byNum;
    }
    // Try nom or "prenom nom"
    return students.find(s =>
        (s.nom || '').toUpperCase() === t ||
        (s.prenom + ' ' + s.nom).toUpperCase() === t ||
        (s.nom + ' ' + s.prenom).toUpperCase() === t
    );
}

function applyPasteGrades() {
    const p = parsePasteData();
    if (p.error) { toast(p.error, 'error'); return; }
    const ld = getLevelData();
    const grades = p.tour === 1 ? ld.grades1 : ld.grades2;
    let applied = 0, skipped = 0;
    p.dataRows.forEach((row, i) => {
        const st = p.hasNames ? findStudentByToken(p.students, row[0]) : p.students[i];
        if (!st) { skipped++; return; }
        const k = stKey(st);
        if (!grades[k]) grades[k] = {};
        p.mapping.forEach((colIdx, si) => {
            const raw = (row[colIdx + p.nameOffset] || '').trim();
            if (raw === '') return;
            const u = raw.toUpperCase();
            const code = p.subjects[si].code;
            if (u === 'ABS' || u === 'ABSENT') { grades[k][code] = 'ABS'; return; }
            if (u === 'INAPTE' || u === 'INAPT' || u === 'IN') { grades[k][code] = 'INAPTE'; return; }
            const v = parseFloat(raw.replace(',', '.'));
            if (!isNaN(v) && v >= 0 && v <= 20) { grades[k][code] = v; applied++; }
        });
    });
    saveData();
    closeModal('pasteGradesModal');
    if (p.tour === 1) renderGrades1Table(); else renderGrades2Table();
    toast(`${applied} note(s) collée(s)${skipped ? ' (' + skipped + ' ligne(s) ignorée(s))' : ''}.`, 'success');
    logActivity(`Notes collées depuis Excel (tour ${p.tour}) : ${applied}`, 'import');
}

// ========== ÉLÈVES À RISQUE ==========
function getAtRiskStudents(levelData) {
    // Critères : moyenne < seuil2eTour/coefTotal OR >= 3 notes < 8
    const risk = [];
    levelData.students.forEach(st => {
        const k = stKey(st);
        const grades = levelData.grades1[k] || {};
        let total = 0, coefUsed = 0, hasAny = false;
        let lowCount = 0, noteCount = 0;
        levelData.subjects.forEach(sub => {
            const g = grades[sub.code];
            if (g === 'INAPTE' || g === 'ABS' || g === undefined || g === '') return;
            const v = parseFloat(g);
            if (isNaN(v)) return;
            total += v * sub.coef; coefUsed += sub.coef; hasAny = true;
            noteCount++;
            if (v < 8) lowCount++;
        });
        if (!hasAny || coefUsed === 0) return;
        const moy = total / coefUsed;
        const moyTarget = levelData.seuil2eTour / (levelData.coefTotal || 1);
        const reasons = [];
        if (moy < moyTarget) reasons.push(`moyenne ${moy.toFixed(2)} < ${moyTarget.toFixed(2)}`);
        if (lowCount >= 3) reasons.push(`${lowCount} notes < 8`);
        if (reasons.length > 0) risk.push({ student: st, moyenne: moy, lowCount, noteCount, reasons });
    });
    risk.sort((a, b) => a.moyenne - b.moyenne);
    return risk;
}

function renderRiskSectionHTML(ld, cfg) {
    const risk = getAtRiskStudents(ld);
    if (risk.length === 0) {
        return `<div class="card" style="margin-top:12px;">
            <h3>Élèves à risque <span style="font-size:0.7em; color:var(--text-secondary);">(${cfg.shortLabel})</span></h3>
            <div class="empty-state" style="padding:20px;"><p>Aucun élève à risque détecté (ou notes insuffisantes).</p></div>
        </div>`;
    }
    let html = `<div class="card" style="margin-top:12px;">
        <h3>&#9888; Élèves à risque <span style="font-size:0.7em; color:var(--text-secondary);">(${cfg.shortLabel}) — ${risk.length} détecté(s)</span></h3>
        <div class="alert alert-warning" style="font-size:0.82em;">Critères : moyenne prédictive sous le seuil du 2ème tour <b>ou</b> au moins 3 notes inférieures à 8/20.</div>
        <table><thead><tr><th>N°</th><th>Prénom</th><th>Nom</th><th>Moy. prédictive</th><th>Notes &lt; 8</th><th>Signaux</th></tr></thead><tbody>`;
    risk.slice(0, 20).forEach((r, i) => {
        const color = r.moyenne < 7 ? '#ef4444' : r.moyenne < 9 ? '#f59e0b' : '#eab308';
        html += `<tr>
            <td>${i + 1}</td>
            <td style="text-align:left;">${Security.escapeHTML(r.student.prenom)}</td>
            <td style="text-align:left;">${Security.escapeHTML(r.student.nom)}</td>
            <td style="font-weight:700; color:${color};">${r.moyenne.toFixed(2)}</td>
            <td><b>${r.lowCount}</b> / ${r.noteCount}</td>
            <td style="text-align:left; font-size:0.85em;">${Security.escapeHTML(r.reasons.join(' ; '))}</td>
        </tr>`;
    });
    if (risk.length > 20) html += `<tr><td colspan="6" style="text-align:center; color:var(--text-secondary);">... ${risk.length - 20} autre(s)</td></tr>`;
    html += `</tbody></table></div>`;
    return html;
}

// ========== CHART.JS — DISTRIBUTION INTERACTIVE ==========
let _chartInstances = {};
function destroyChart(id) {
    if (_chartInstances[id]) { try { _chartInstances[id].destroy(); } catch(e) {} delete _chartInstances[id]; }
}

function renderChartJsDistribution(canvasId, ld) {
    if (typeof Chart === 'undefined') return;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const bins = ['[0-4[', '[4-8[', '[8-10[', '[10-12[', '[12-14[', '[14-16[', '[16-20]'];
    const ranges = [[0,4],[4,8],[8,10],[10,12],[12,14],[14,16],[16,20.01]];
    const counts = ranges.map(([mn,mx]) => ld.results1.filter(r => r.moyenne >= mn && r.moyenne < mx).length);
    const colors = ['#7f1d1d','#ef4444','#f59e0b','#84cc16','#10b981','#059669','#047857'];
    destroyChart(canvasId);
    _chartInstances[canvasId] = new Chart(canvas, {
        type: 'bar',
        data: { labels: bins, datasets: [{ label: 'Élèves', data: counts, backgroundColor: colors, borderRadius: 6 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => ctx.parsed.y + ' élève(s)' } } },
            scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
        }
    });
}

function renderChartJsSubjects(canvasId, ld) {
    if (typeof Chart === 'undefined') return;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const labels = ld.subjects.map(s => s.name);
    const avgs = ld.subjects.map(sub => {
        let sum = 0, count = 0;
        ld.results1.forEach(r => {
            const g = ld.grades1[r.key] && ld.grades1[r.key][sub.code];
            if (g !== undefined && g !== '' && g !== 'ABS' && g !== 'INAPTE') {
                sum += parseFloat(g); count++;
            }
        });
        return count > 0 ? +(sum/count).toFixed(2) : 0;
    });
    const colors = avgs.map(a => a >= 12 ? '#10b981' : a >= 10 ? '#84cc16' : a >= 8 ? '#f59e0b' : '#ef4444');
    destroyChart(canvasId);
    _chartInstances[canvasId] = new Chart(canvas, {
        type: 'bar',
        data: { labels, datasets: [{ label: 'Moyenne /20', data: avgs, backgroundColor: colors, borderRadius: 6 }] },
        options: {
            indexAxis: 'y',
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, max: 20 } }
        }
    });
}

// ========== WRAP renderDashboard / renderStats to inject new sections ==========
const _origRenderDashboard = renderDashboard;
renderDashboard = function() {
    _origRenderDashboard();
    const container = document.getElementById('dashboardContent');
    if (!container) return;
    const ld = getLevelData();
    const cfg = LEVELS[currentLevel];
    container.insertAdjacentHTML('beforeend', renderRiskSectionHTML(ld, cfg));
};

const _origRenderStats = renderStats;
renderStats = function(mode, btnEl) {
    _origRenderStats(mode, btnEl);
    // Graphiques génériques (distribution + matières) uniquement sur ces 2 onglets ;
    // les vues spécialisées (heatmap, radar, sankey, boxplot, calendrier) n'en veulent pas.
    if (mode !== 'current' && mode !== 'all') return;
    const container = document.getElementById('statsContent');
    if (!container) return;
    if (typeof Chart === 'undefined') return;
    if (mode === 'all') {
        let html = '<div class="card" style="margin-top:12px;"><h3>Graphiques interactifs (tous niveaux)</h3>';
        Object.keys(LEVELS).forEach(lv => {
            const d = appData.levels[lv];
            if (!d || !d.results1 || d.results1.length === 0) return;
            html += `<h4 style="margin-top:12px;">${LEVELS[lv].label}</h4>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                    <div style="height:280px;"><canvas id="chartDist_${lv}"></canvas></div>
                    <div style="height:${Math.max(280, d.subjects.length * 28)}px;"><canvas id="chartSub_${lv}"></canvas></div>
                </div>`;
        });
        html += '</div>';
        container.insertAdjacentHTML('beforeend', html);
        Object.keys(LEVELS).forEach(lv => {
            const d = appData.levels[lv];
            if (!d || !d.results1 || d.results1.length === 0) return;
            renderChartJsDistribution('chartDist_' + lv, d);
            renderChartJsSubjects('chartSub_' + lv, d);
        });
    } else {
        const ld = getLevelData();
        if (!ld.results1 || ld.results1.length === 0) return;
        const html = `<div class="card" style="margin-top:12px;">
            <h3>Graphiques interactifs</h3>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                <div><h4>Distribution des moyennes</h4><div style="height:280px;"><canvas id="chartDist_current"></canvas></div></div>
                <div><h4>Moyennes par matière</h4><div style="height:${Math.max(280, ld.subjects.length * 28)}px;"><canvas id="chartSub_current"></canvas></div></div>
            </div>
        </div>`;
        container.insertAdjacentHTML('beforeend', html);
        renderChartJsDistribution('chartDist_current', ld);
        renderChartJsSubjects('chartSub_current', ld);
    }
};

// ========== RANG PAR MATIÈRE (ajouté au bulletin) ==========
function getSubjectRanks(ld, key) {
    // Pour chaque matière, calcule le rang de l'élève parmi tous ceux qui ont une note valide
    const ranks = {};
    ld.subjects.forEach(sub => {
        const entries = [];
        ld.students.forEach(st => {
            const k = stKey(st);
            const g = ld.grades1[k] && ld.grades1[k][sub.code];
            if (g !== undefined && g !== '' && g !== 'ABS' && g !== 'INAPTE') {
                entries.push({ k, v: parseFloat(g) });
            }
        });
        entries.sort((a, b) => b.v - a.v);
        const myIdx = entries.findIndex(e => e.k === key);
        ranks[sub.code] = myIdx === -1 ? null : { rang: myIdx + 1, total: entries.length };
    });
    return ranks;
}

// Wrap printDocument for bulletin to inject per-subject rank column
const _origPrintDocument = printDocument;
printDocument = function(type) {
    _origPrintDocument(type);
    if (type !== 'bulletin') return;
    const content = document.getElementById('printModalContent');
    if (!content) return;
    const ld = getLevelData();
    // For each bulletin table, append rank column header and cells
    const pages = content.querySelectorAll('.bulletin-page');
    pages.forEach((page, idx) => {
        const sorted = [...ld.results1].sort((a, b) => a.student.numTable - b.student.numTable);
        const r = sorted[idx];
        if (!r) return;
        const ranks = getSubjectRanks(ld, r.key);
        const table = page.querySelector('table');
        if (!table) return;
        // Add header cell
        const headRow = table.querySelector('thead tr');
        if (headRow && !headRow.querySelector('.rank-col-added')) {
            const th = document.createElement('th');
            th.className = 'rank-col-added';
            th.textContent = 'Rang matière';
            headRow.appendChild(th);
        }
        // Add per-row rank
        const bodyRows = table.querySelectorAll('tbody tr');
        bodyRows.forEach((row, ri) => {
            const sub = ld.subjects[ri];
            if (!sub) return;
            const td = document.createElement('td');
            const rk = ranks[sub.code];
            td.textContent = rk ? `${rk.rang}/${rk.total}` : '-';
            row.appendChild(td);
        });
    });
};

// ========== WIDGETS INTERACTIFS : Jauge, Histogramme/Simulateur, Radar, What-If ==========
(function () {
    // --- Styles injectés une seule fois ---
    if (!document.getElementById('simulator-styles')) {
        const s = document.createElement('style');
        s.id = 'simulator-styles';
        s.textContent = `
        .gauge-wrap { display:flex; align-items:center; gap:24px; flex-wrap:wrap; }
        .gauge-svg { width:200px; height:200px; filter:drop-shadow(0 2px 6px rgba(0,0,0,0.08)); }
        .gauge-bg { fill:none; stroke:var(--gray-200); stroke-width:14; }
        .gauge-fg { fill:none; stroke-width:14; stroke-linecap:round;
            transform:rotate(-90deg); transform-origin:50% 50%;
            transition: stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1); }
        .gauge-text { font-size:2.4em; font-weight:800; fill:var(--primary); text-anchor:middle; dominant-baseline:middle; font-variant-numeric:tabular-nums; }
        .gauge-sub { font-size:0.7em; fill:var(--gray-500); text-anchor:middle; dominant-baseline:middle; }
        .gauge-legend { display:flex; flex-direction:column; gap:6px; font-size:0.9em; }
        .gauge-legend .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; vertical-align:middle; }
        .mini-kpi { display:grid; grid-template-columns:repeat(auto-fit, minmax(110px, 1fr)); gap:10px; margin-top:14px; }
        .mini-kpi .kpi { background:var(--gray-50); border-radius:8px; padding:8px 12px; border-left:3px solid var(--accent); }
        .mini-kpi .kpi .v { font-size:1.3em; font-weight:800; color:var(--primary); font-variant-numeric:tabular-nums; }
        .mini-kpi .kpi .l { font-size:0.7em; color:var(--gray-500); text-transform:uppercase; letter-spacing:0.5px; }

        .sim-layout { display:grid; grid-template-columns: 320px 1fr; gap:20px; align-items:start; }
        @media (max-width:860px) { .sim-layout { grid-template-columns:1fr; } }
        .sim-slider-row { margin:14px 0; }
        .sim-slider-row label { display:flex; justify-content:space-between; font-weight:600; font-size:0.9em; margin-bottom:6px; color:var(--gray-700); }
        .sim-slider-row input[type=range] { width:100%; accent-color:var(--primary); height:6px; }
        .sim-slider-row .sim-val { color:var(--primary); font-variant-numeric:tabular-nums; font-weight:700; }
        .sim-eq { font-size:0.75em; color:var(--gray-500); margin-top:2px; }
        .sim-summary-bars { display:grid; grid-template-columns:80px 1fr 72px; gap:10px; align-items:center; margin:10px 0; }
        .sim-summary-bars .l { font-weight:600; font-size:0.88em; }
        .sim-bar-track { background:var(--gray-100); border-radius:6px; height:22px; overflow:hidden; position:relative; }
        .sim-bar-fill { height:100%; border-radius:6px; transition: width 0.5s cubic-bezier(.22,1,.36,1), background 0.3s;
            display:flex; align-items:center; justify-content:flex-end; padding-right:6px; color:#fff; font-size:0.78em; font-weight:700; }
        .sim-delta { font-size:0.8em; font-weight:700; }
        .sim-delta.up { color:var(--success-dark); }
        .sim-delta.down { color:var(--danger-dark); }
        .sim-delta.zero { color:var(--gray-400); }
        .sim-reset { float:right; font-size:0.78em; background:transparent; border:1px solid var(--gray-300); color:var(--gray-600);
            padding:4px 10px; border-radius:6px; cursor:pointer; }
        .sim-reset:hover { background:var(--gray-100); }

        /* Histogramme de distribution */
        .hist-wrap { position:relative; }
        .hist-svg { width:100%; height:240px; display:block; }
        .hist-bar { transition: fill 0.25s, y 0.4s, height 0.4s; }
        .hist-threshold { stroke-width:2; stroke-dasharray:4 3; transition: x1 0.1s, x2 0.1s, opacity 0.2s; }
        .hist-threshold-label { font-size:11px; font-weight:700; font-family:inherit; transition: x 0.1s; }
        .hist-axis { stroke:var(--gray-300); stroke-width:1; }
        .hist-axis-label { font-size:10px; fill:var(--gray-500); }

        /* What-if individuel */
        .whatif-row { display:grid; grid-template-columns:1fr 70px 90px 1fr; gap:8px; align-items:center;
            padding:6px 10px; border-radius:6px; font-size:0.85em; }
        .whatif-row:nth-child(even) { background:var(--gray-50); }
        .whatif-row .wi-sub { font-weight:600; color:var(--gray-700); }
        .whatif-row .wi-cur { text-align:center; font-variant-numeric:tabular-nums; color:var(--gray-600); }
        .whatif-row .wi-need { text-align:center; font-weight:700; font-variant-numeric:tabular-nums; }
        .whatif-row .wi-need.ok { color:var(--success-dark); }
        .whatif-row .wi-need.hard { color:var(--warning-dark); }
        .whatif-row .wi-need.impossible { color:var(--danger-dark); }
        .whatif-row .wi-bar { height:10px; background:var(--gray-100); border-radius:5px; overflow:hidden; }
        .whatif-row .wi-bar-fill { height:100%; border-radius:5px; transition: width 0.5s; }
        .whatif-header { font-size:0.78em; color:var(--gray-500); text-transform:uppercase; letter-spacing:0.5px; padding:4px 10px; }

        /* Animations de progression Dashboard (extra) */
        @keyframes fadeSlideUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
        .sim-card-anim { animation: fadeSlideUp 0.45s ease-out both; }
        `;
        document.head.appendChild(s);
    }

    // --- Utilitaires ---
    function animateCount(el, from, to, dur, suffix, decimals) {
        if (!el) return;
        const start = performance.now();
        suffix = suffix || '';
        decimals = decimals || 0;
        function step(t) {
            const k = Math.min(1, (t - start) / dur);
            const ease = 1 - Math.pow(1 - k, 3);
            const v = from + (to - from) * ease;
            el.textContent = v.toFixed(decimals) + suffix;
            if (k < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    // --- Jauge animée (Dashboard) ---
    function buildGauge(pct, totalAdmis, totalStudents) {
        const radius = 78;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference * (1 - Math.max(0, Math.min(100, pct)) / 100);
        const gradId = 'gaugeGrad_' + Math.random().toString(36).slice(2, 8);
        const [c1, c2] = pct >= 70 ? ['#10b981', '#059669']
                       : pct >= 40 ? ['#fbbf24', '#d97706']
                                   : ['#f87171', '#dc2626'];
        return `
        <div class="card sim-card-anim" style="margin-top:12px;">
            <h3>Taux de réussite global</h3>
            <div class="gauge-wrap">
                <svg class="gauge-svg" viewBox="0 0 200 200">
                    <defs>
                        <linearGradient id="${gradId}" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="${c1}"/>
                            <stop offset="100%" stop-color="${c2}"/>
                        </linearGradient>
                    </defs>
                    <circle class="gauge-bg" cx="100" cy="100" r="${radius}"></circle>
                    <circle class="gauge-fg" cx="100" cy="100" r="${radius}"
                        style="stroke-dasharray:${circumference}; stroke-dashoffset:${circumference}; stroke:url(#${gradId});"
                        data-target-offset="${offset}"></circle>
                    <text class="gauge-text" x="100" y="96" data-count-to="${pct.toFixed(1)}" data-suffix="%" data-decimals="1">0.0%</text>
                    <text class="gauge-sub" x="100" y="120">${totalAdmis} / ${totalStudents} admis</text>
                </svg>
                <div style="flex:1; min-width:240px;">
                    <div class="gauge-legend">
                        <div><span class="dot" style="background:#10b981;"></span> ≥ 70 % — Excellent</div>
                        <div><span class="dot" style="background:#f59e0b;"></span> 40 % – 70 % — À consolider</div>
                        <div><span class="dot" style="background:#ef4444;"></span> &lt; 40 % — Critique</div>
                    </div>
                    <div class="mini-kpi">
                        <div class="kpi"><div class="v" data-count-to="${totalStudents}">0</div><div class="l">Candidats</div></div>
                        <div class="kpi"><div class="v" data-count-to="${totalAdmis}">0</div><div class="l">Admis</div></div>
                        <div class="kpi"><div class="v" data-count-to="${(totalStudents - totalAdmis)}">0</div><div class="l">Non admis</div></div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    function animateGauge(container) {
        const fg = container.querySelector('.gauge-fg');
        if (fg) {
            const target = fg.getAttribute('data-target-offset');
            requestAnimationFrame(() => { fg.style.strokeDashoffset = target; });
        }
        container.querySelectorAll('[data-count-to]').forEach(el => {
            const to = parseFloat(el.getAttribute('data-count-to'));
            const suf = el.getAttribute('data-suffix') || '';
            const dec = parseInt(el.getAttribute('data-decimals') || '0');
            animateCount(el, 0, to, 1200, suf, dec);
        });
    }

    // Wrap renderDashboard
    if (typeof renderDashboard === 'function') {
        const _prev = renderDashboard;
        renderDashboard = function () {
            _prev();
            const container = document.getElementById('dashboardContent');
            if (!container) return;
            let totalStudents = 0, totalAdmis = 0;
            Object.keys(LEVELS).forEach(lv => {
                const d = appData.levels[lv];
                if (!d) return;
                totalStudents += d.students.length;
                const a1 = d.results1 ? d.results1.filter(r => r.decision === 'Admis').length : 0;
                const a2 = d.results2 ? d.results2.filter(r => r.decision === 'Admis').length : 0;
                totalAdmis += a1 + a2;
            });
            if (totalStudents === 0) return;
            const pct = (totalAdmis / totalStudents) * 100;
            container.insertAdjacentHTML('beforeend', buildGauge(pct, totalAdmis, totalStudents));
            animateGauge(container);
        };
    }

    // --- Histogramme de distribution avec seuils glissants ---
    function buildHistogramSVG(totals, maxTotal, sAdmis, s2eT, binCount) {
        binCount = binCount || 20;
        const w = 600, h = 240, padL = 36, padR = 12, padT = 12, padB = 28;
        const iw = w - padL - padR, ih = h - padT - padB;
        const binSize = maxTotal / binCount;
        const bins = new Array(binCount).fill(0);
        totals.forEach(t => {
            let idx = Math.floor(t / binSize);
            if (idx >= binCount) idx = binCount - 1;
            if (idx < 0) idx = 0;
            bins[idx]++;
        });
        const maxCount = Math.max(1, ...bins);
        const barW = iw / binCount;
        const xFor = v => padL + (v / maxTotal) * iw;
        let bars = '';
        bins.forEach((c, i) => {
            const binStart = i * binSize;
            const binMid = binStart + binSize / 2;
            const color = binMid >= sAdmis ? '#10b981' : binMid >= s2eT ? '#f59e0b' : '#ef4444';
            const bh = (c / maxCount) * ih;
            const x = padL + i * barW;
            const y = padT + ih - bh;
            bars += `<rect class="hist-bar" data-bin-mid="${binMid.toFixed(2)}" data-count="${c}"
                x="${x + 1}" y="${y}" width="${barW - 2}" height="${bh}" fill="${color}" rx="2"></rect>`;
            if (c > 0) {
                bars += `<text x="${x + barW / 2}" y="${y - 2}" text-anchor="middle"
                    style="font-size:9px; fill:var(--gray-500);">${c}</text>`;
            }
        });
        // Axe X — labels à 0, 1/4, 1/2, 3/4, max
        let axisLabels = '';
        [0, 0.25, 0.5, 0.75, 1].forEach(f => {
            const v = Math.round(maxTotal * f);
            axisLabels += `<text class="hist-axis-label" x="${xFor(v)}" y="${h - 8}" text-anchor="middle">${v}</text>`;
        });
        // Seuils
        const x2 = xFor(s2eT), xA = xFor(sAdmis);
        const thresholds = `
            <line class="hist-threshold" id="histThr2" x1="${x2}" x2="${x2}" y1="${padT}" y2="${padT + ih}" stroke="#f59e0b"></line>
            <text class="hist-threshold-label" id="histThr2Lbl" x="${x2 + 4}" y="${padT + 12}" fill="#d97706">2ᵉ Tour</text>
            <line class="hist-threshold" id="histThrA" x1="${xA}" x2="${xA}" y1="${padT}" y2="${padT + ih}" stroke="#059669"></line>
            <text class="hist-threshold-label" id="histThrALbl" x="${xA + 4}" y="${padT + 26}" fill="#059669">Admis</text>
        `;
        return `<svg class="hist-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">
            <line class="hist-axis" x1="${padL}" y1="${padT + ih}" x2="${padL + iw}" y2="${padT + ih}"></line>
            ${bars}
            ${axisLabels}
            <text class="hist-axis-label" x="${padL}" y="${padT + ih + 22}" text-anchor="start">Total (points)</text>
            ${thresholds}
        </svg>`;
    }

    function updateHistogramColors(svg, sAdmis, s2eT, maxTotal) {
        if (!svg) return;
        const xFor = v => {
            const w = 600, padL = 36, padR = 12, iw = w - padL - padR;
            return padL + (v / maxTotal) * iw;
        };
        svg.querySelectorAll('.hist-bar').forEach(bar => {
            const mid = parseFloat(bar.getAttribute('data-bin-mid'));
            const color = mid >= sAdmis ? '#10b981' : mid >= s2eT ? '#f59e0b' : '#ef4444';
            bar.setAttribute('fill', color);
        });
        const thrA = svg.querySelector('#histThrA');
        const thr2 = svg.querySelector('#histThr2');
        const thrALbl = svg.querySelector('#histThrALbl');
        const thr2Lbl = svg.querySelector('#histThr2Lbl');
        if (thrA) { thrA.setAttribute('x1', xFor(sAdmis)); thrA.setAttribute('x2', xFor(sAdmis)); }
        if (thrALbl) thrALbl.setAttribute('x', xFor(sAdmis) + 4);
        if (thr2) { thr2.setAttribute('x1', xFor(s2eT)); thr2.setAttribute('x2', xFor(s2eT)); }
        if (thr2Lbl) thr2Lbl.setAttribute('x', xFor(s2eT) + 4);
    }

    // --- Simulateur de seuils avec histogramme ---
    function buildSimulator(ld, cfg) {
        if (!ld.results1 || ld.results1.length === 0) return '';
        const maxTotal = cfg.coefTotal * 20;
        const totals = ld.results1.map(r => r.total);
        const origAdmis = ld.results1.filter(r => r.decision === 'Admis').length;
        const n = ld.results1.length;
        return `
        <div class="card sim-card-anim" style="margin-top:12px;" id="sim-card">
            <h3>Simulateur interactif de seuils
                <button class="sim-reset" onclick="window.__simReset && window.__simReset()">↺ Réinitialiser</button>
            </h3>
            <p style="font-size:0.85em; color:var(--gray-600); margin-bottom:10px;">
                Déplace les curseurs : les barres de l'histogramme changent de couleur en direct selon les nouveaux seuils.
                <b>Les données officielles ne sont jamais modifiées</b>.
            </p>
            <div class="sim-layout">
                <div>
                    <div class="sim-slider-row">
                        <label><span>Seuil <b style="color:var(--success-dark);">Admis</b> /${maxTotal}</span><span class="sim-val" id="simValAdmis">${ld.seuilAdmis}</span></label>
                        <input type="range" id="simSeuilAdmis" min="0" max="${maxTotal}" step="1" value="${ld.seuilAdmis}">
                        <div class="sim-eq">≈ <span id="simMoyA">${(ld.seuilAdmis/cfg.coefTotal).toFixed(2)}</span> / 20</div>
                    </div>
                    <div class="sim-slider-row">
                        <label><span>Seuil <b style="color:var(--warning-dark);">2ᵉ Tour</b> /${maxTotal}</span><span class="sim-val" id="simVal2eT">${ld.seuil2eTour}</span></label>
                        <input type="range" id="simSeuil2eT" min="0" max="${maxTotal}" step="1" value="${ld.seuil2eTour}">
                        <div class="sim-eq">≈ <span id="simMoy2">${(ld.seuil2eTour/cfg.coefTotal).toFixed(2)}</span> / 20</div>
                    </div>
                    <div class="sim-summary-bars">
                        <span class="l" style="color:var(--success-dark);">Admis</span>
                        <div class="sim-bar-track"><div class="sim-bar-fill" id="simBarAdmis" style="background:#10b981; width:0%;">0</div></div>
                        <span id="simDeltaAdmis" class="sim-delta zero">±0</span>
                    </div>
                    <div class="sim-summary-bars">
                        <span class="l" style="color:var(--warning-dark);">2ᵉ Tour</span>
                        <div class="sim-bar-track"><div class="sim-bar-fill" id="simBar2eT" style="background:#f59e0b; width:0%;">0</div></div>
                        <span id="simDelta2eT" class="sim-delta zero">±0</span>
                    </div>
                    <div class="sim-summary-bars">
                        <span class="l" style="color:var(--danger-dark);">Ajournés</span>
                        <div class="sim-bar-track"><div class="sim-bar-fill" id="simBarAjo" style="background:#ef4444; width:0%;">0</div></div>
                        <span id="simDeltaAjo" class="sim-delta zero">±0</span>
                    </div>
                    <div style="margin-top:12px; padding:10px; background:var(--gray-50); border-radius:8px; font-size:0.85em; line-height:1.6;">
                        Taux simulé : <b id="simTaux">—</b><br>
                        Taux officiel : <b>${((origAdmis / n) * 100).toFixed(1)}%</b> &nbsp;(${origAdmis}/${n})
                    </div>
                </div>
                <div class="hist-wrap" id="histContainer">
                    <div style="font-size:0.82em; color:var(--gray-600); margin-bottom:6px;">Distribution des totaux — les barres se recolorent selon les seuils</div>
                    ${buildHistogramSVG(totals, maxTotal, ld.seuilAdmis, ld.seuil2eTour)}
                </div>
            </div>
        </div>`;
    }

    function wireSimulator(ld, cfg) {
        const elA = document.getElementById('simSeuilAdmis');
        const el2 = document.getElementById('simSeuil2eT');
        if (!elA || !el2) return;
        const origAdmis = ld.results1.filter(r => r.decision === 'Admis').length;
        const orig2eT = ld.results1.filter(r => r.decision === '2ème Tour').length;
        const origAjo = ld.results1.filter(r => r.decision === 'Ajourné').length;
        const maxTotal = cfg.coefTotal * 20;
        const histSvg = document.querySelector('#histContainer svg');

        function setDelta(id, delta) {
            const el = document.getElementById(id);
            if (!el) return;
            el.classList.remove('up', 'down', 'zero');
            if (delta === 0) { el.classList.add('zero'); el.textContent = '±0'; }
            else if (delta > 0) { el.classList.add('up'); el.textContent = '+' + delta; }
            else { el.classList.add('down'); el.textContent = '' + delta; }
        }

        function update() {
            let sA = parseInt(elA.value);
            let s2 = parseInt(el2.value);
            if (s2 > sA) { s2 = sA; el2.value = sA; }
            document.getElementById('simValAdmis').textContent = sA;
            document.getElementById('simVal2eT').textContent = s2;
            document.getElementById('simMoyA').textContent = (sA / cfg.coefTotal).toFixed(2);
            document.getElementById('simMoy2').textContent = (s2 / cfg.coefTotal).toFixed(2);

            let admis = 0, tour2 = 0, ajo = 0;
            ld.results1.forEach(r => {
                const sAd = r.coefUsed < cfg.coefTotal ? r.coefUsed * 10 : sA;
                const s2e = r.coefUsed < cfg.coefTotal ? r.coefUsed * 8 : s2;
                if (r.total >= sAd) admis++;
                else if (r.total >= s2e) tour2++;
                else ajo++;
            });
            const n = ld.results1.length;
            const setBar = (id, val) => {
                const el = document.getElementById(id);
                const pct = n > 0 ? (val / n) * 100 : 0;
                el.style.width = Math.max(pct, 4) + '%';
                el.textContent = val;
            };
            setBar('simBarAdmis', admis);
            setBar('simBar2eT', tour2);
            setBar('simBarAjo', ajo);
            setDelta('simDeltaAdmis', admis - origAdmis);
            setDelta('simDelta2eT', tour2 - orig2eT);
            setDelta('simDeltaAjo', ajo - origAjo);
            document.getElementById('simTaux').textContent = n > 0 ? ((admis / n) * 100).toFixed(1) + '% (' + admis + '/' + n + ')' : '—';
            updateHistogramColors(histSvg, sA, s2, maxTotal);
        }

        elA.addEventListener('input', update);
        el2.addEventListener('input', update);
        window.__simReset = function () {
            elA.value = ld.seuilAdmis;
            el2.value = ld.seuil2eTour;
            update();
        };
        update();
    }

    // --- Radar des moyennes par matière ---
    function buildRadar(ld) {
        if (!ld.subjects || ld.subjects.length < 3) return '';
        return `<div class="card sim-card-anim" style="margin-top:12px;">
            <h3>Profil de classe — Moyennes par matière</h3>
            <p style="font-size:0.82em; color:var(--gray-600); margin-bottom:8px;">
                Vue radar : plus la forme s'étend vers l'extérieur, meilleure est la moyenne de classe sur la matière.
            </p>
            <div style="height:360px; max-width:560px; margin:0 auto;"><canvas id="radarSubjects"></canvas></div>
        </div>`;
    }

    function renderRadar(ld) {
        const cv = document.getElementById('radarSubjects');
        if (!cv || typeof Chart === 'undefined') return;
        // Moyennes par matière sur l'ensemble des élèves (notes valides uniquement)
        const labels = [], data = [];
        ld.subjects.forEach(sub => {
            let sum = 0, cnt = 0;
            ld.students.forEach(st => {
                const k = stKey(st);
                const g = ld.grades1[k] && ld.grades1[k][sub.code];
                if (g !== undefined && g !== '' && g !== 'ABS' && g !== 'INAPTE') {
                    sum += parseFloat(g); cnt++;
                }
            });
            labels.push(sub.name + ' (c' + sub.coef + ')');
            data.push(cnt > 0 ? Math.round((sum / cnt) * 100) / 100 : 0);
        });
        // Enregistré dans _chartInstances et détruit avant recréation, sinon
        // chaque re-rendu de la page Statistiques fuyait une instance Chart.js.
        destroyChart('radarSubjects');
        _chartInstances['radarSubjects'] = new Chart(cv, {
            type: 'radar',
            data: {
                labels,
                datasets: [{
                    label: 'Moyenne de classe',
                    data,
                    backgroundColor: 'rgba(184,166,122,0.25)',
                    borderColor: '#9a8a60',
                    pointBackgroundColor: '#3E2415',
                    pointRadius: 4,
                    borderWidth: 2
                }, {
                    label: 'Cible (10/20)',
                    data: labels.map(() => 10),
                    borderColor: 'rgba(239,68,68,0.7)',
                    borderDash: [4, 4],
                    pointRadius: 0,
                    fill: false
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: { r: { min: 0, max: 20, ticks: { stepSize: 5 } } },
                animation: { duration: 900, easing: 'easeOutQuart' }
            }
        });
    }

    // --- What-if individuel ---
    function buildWhatIf(ld, cfg) {
        const tour2 = ld.results1.filter(r => r.decision === '2ème Tour');
        if (tour2.length === 0) return '';
        const options = tour2.map(r =>
            `<option value="${r.key}">${Security.escapeHTML(r.student.prenom)} ${Security.escapeHTML(r.student.nom)} — ${r.total}/${cfg.coefTotal * 20} (moy ${r.moyenne.toFixed(2)})</option>`
        ).join('');
        return `<div class="card sim-card-anim" style="margin-top:12px;">
            <h3>Simulateur individuel (candidats au 2ᵉ Tour)</h3>
            <p style="font-size:0.82em; color:var(--gray-600); margin-bottom:8px;">
                Sélectionne un candidat : le tableau indique la <b>note minimale</b> à obtenir dans chaque matière au 2ᵉ tour
                pour atteindre le seuil d'admis (${ld.seuilAdmis} pts), à notes des autres matières inchangées.
            </p>
            <select id="whatIfSelect" style="width:100%; max-width:420px; margin-bottom:12px; padding:8px; border-radius:6px; border:1px solid var(--gray-300);">
                ${options}
            </select>
            <div class="whatif-header" style="display:grid; grid-template-columns:1fr 70px 90px 1fr;">
                <span>Matière</span><span style="text-align:center;">Actuelle</span><span style="text-align:center;">Requise</span><span>Effort</span>
            </div>
            <div id="whatIfRows"></div>
        </div>`;
    }

    function renderWhatIfRows(ld, cfg) {
        const sel = document.getElementById('whatIfSelect');
        const rowsEl = document.getElementById('whatIfRows');
        if (!sel || !rowsEl) return;
        function update() {
            const key = sel.value;
            const r = ld.results1.find(x => x.key === key);
            if (!r) { rowsEl.innerHTML = ''; return; }
            const grades = ld.grades1[r.key] || {};
            const seuil = ld.seuilAdmis;
            let html = '';
            ld.subjects.forEach(sub => {
                const g = grades[sub.code];
                const cur = (g === undefined || g === '' || g === 'ABS' || g === 'INAPTE') ? null : parseFloat(g);
                // Sans cette matière, quel serait le total ?
                let totalOthers = 0;
                ld.subjects.forEach(s2 => {
                    if (s2.code === sub.code) return;
                    const g2 = grades[s2.code];
                    if (g2 === 'INAPTE') return;
                    if (g2 !== undefined && g2 !== '' && g2 !== 'ABS') totalOthers += parseFloat(g2) * s2.coef;
                });
                const needed = (seuil - totalOthers) / sub.coef;
                let cls, label, effort;
                if (cur === null) {
                    cls = 'hard'; label = needed > 20 ? 'Imposs.' : needed < 0 ? '0' : needed.toFixed(2);
                    effort = '—';
                } else if (needed > 20) {
                    cls = 'impossible'; label = 'Imposs.'; effort = 'Hors d\'atteinte seul';
                } else if (needed < 0) {
                    cls = 'ok'; label = '0'; effort = 'Déjà suffisant';
                } else {
                    const delta = needed - cur;
                    cls = delta <= 0 ? 'ok' : delta <= 3 ? 'hard' : 'impossible';
                    label = needed.toFixed(2);
                    effort = delta <= 0 ? 'Aucune ↑' : '+' + delta.toFixed(2) + ' pts';
                }
                const barPct = Math.max(0, Math.min(100, ((cur || 0) / 20) * 100));
                const needPct = Math.max(0, Math.min(100, (needed / 20) * 100));
                html += `<div class="whatif-row">
                    <span class="wi-sub">${sub.name} <span style="color:var(--gray-400); font-weight:400;">(c${sub.coef})</span></span>
                    <span class="wi-cur">${cur === null ? '—' : cur.toFixed(2)}</span>
                    <span class="wi-need ${cls}">${label}</span>
                    <div>
                        <div class="wi-bar"><div class="wi-bar-fill" style="width:${barPct}%; background:linear-gradient(90deg, #B8A67A, #3E2415);"></div></div>
                        <div style="font-size:0.72em; color:var(--gray-500); margin-top:2px;">${effort}</div>
                    </div>
                </div>`;
            });
            rowsEl.innerHTML = html;
        }
        sel.addEventListener('change', update);
        update();
    }

    // Wrap renderStats
    if (typeof renderStats === 'function') {
        const _prev = renderStats;
        renderStats = function (mode, btnEl) {
            _prev(mode, btnEl);
            if (mode !== 'current') return;
            const container = document.getElementById('statsContent');
            if (!container) return;
            const ld = getLevelData();
            const cfg = LEVELS[currentLevel];
            if (!ld.results1 || ld.results1.length === 0) return;
            // Simulateur
            container.insertAdjacentHTML('beforeend', buildSimulator(ld, cfg));
            wireSimulator(ld, cfg);
            // Radar
            const radarHtml = buildRadar(ld);
            if (radarHtml) {
                container.insertAdjacentHTML('beforeend', radarHtml);
                renderRadar(ld);
            }
            // What-if individuel
            const wiHtml = buildWhatIf(ld, cfg);
            if (wiHtml) {
                container.insertAdjacentHTML('beforeend', wiHtml);
                renderWhatIfRows(ld, cfg);
            }
        };
    }
})();

/* ===== AI VOICE CHAT ===== */
(function(){
    const state = { mode: 'idle', duration: 0, timer: null, waveTimer: null, recognition: null, lastTranscript: '', voice: null };
    const LS_KEY = 'aichat_claude_api_key';
    const LS_VOICE = 'aichat_voice_name';
    const MODEL = 'claude-opus-4-8';

    function $(id){ return document.getElementById(id); }
    function stage(){ return document.querySelector('#page-aichat .aichat-stage'); }

    function setMode(m){
        state.mode = m;
        const s = stage();
        if (!s) return;
        s.classList.remove('is-idle','is-listening','is-processing','is-speaking');
        s.classList.add('is-' + m);
        const labels = { idle: 'Appuyez pour parler', listening: 'Écoute en cours…', processing: 'Traitement…', speaking: 'Réponse…' };
        const st = $('aichatStatus'); if (st) st.textContent = labels[m];
        const vol = $('aichatVolume'); if (vol) vol.style.display = (m === 'listening') ? 'flex' : 'none';
    }

    function fmtTime(s){
        const m = Math.floor(s/60), sec = s%60;
        return String(m).padStart(2,'0') + ':' + String(sec).padStart(2,'0');
    }

    function buildWaveform(){
        const w = $('aichatWaveform');
        if (!w || w.children.length) return;
        for (let i=0; i<32; i++){
            const b = document.createElement('div');
            b.className = 'aichat-bar';
            w.appendChild(b);
        }
    }

    function buildParticles(){
        const p = $('aichatParticles');
        if (!p || p.children.length) return;
        const rect = p.getBoundingClientRect();
        const W = rect.width || 800, H = rect.height || 560;
        for (let i=0; i<24; i++){
            const el = document.createElement('div');
            el.className = 'aichat-particle';
            el.style.left = Math.random()*W + 'px';
            el.style.top = Math.random()*H + 'px';
            el.style.animationDelay = (Math.random()*2) + 's';
            el.style.animationDuration = (1.5 + Math.random()*2) + 's';
            p.appendChild(el);
        }
    }

    function startTick(){
        stopTick();
        state.timer = setInterval(() => {
            state.duration++;
            const t = $('aichatTimer'); if (t) t.textContent = fmtTime(state.duration);
        }, 1000);
        state.waveTimer = setInterval(() => {
            const bars = document.querySelectorAll('#aichatWaveform .aichat-bar');
            const amp = (state.mode === 'listening' || state.mode === 'speaking') ? 50 : 3;
            bars.forEach(b => { b.style.height = Math.max(4, Math.random()*amp) + 'px'; });
            if (state.mode === 'listening'){
                const v = Math.random()*100;
                const f = $('aichatVolumeFill'); if (f) f.style.width = v + '%';
            }
        }, 120);
    }

    function stopTick(){
        if (state.timer){ clearInterval(state.timer); state.timer = null; }
        if (state.waveTimer){ clearInterval(state.waveTimer); state.waveTimer = null; }
        document.querySelectorAll('#aichatWaveform .aichat-bar').forEach(b => { b.style.height = '4px'; });
    }

    function resetTimer(){
        state.duration = 0;
        const t = $('aichatTimer'); if (t) t.textContent = '00:00';
    }

    function addMsg(text, kind){
        const tr = $('aichatTranscript');
        if (!tr) return;
        const hint = tr.querySelector('.aichat-hint');
        if (hint) hint.remove();
        const div = document.createElement('div');
        div.className = 'aichat-msg aichat-msg-' + kind;
        div.textContent = text;
        tr.appendChild(div);
        tr.scrollTop = tr.scrollHeight;
    }

    function buildContext(){
        try {
            const ctx = { school: appData.school, year: appData.year, currentLevel: currentLevel, levels: {} };
            Object.keys(appData.levels || {}).forEach(lvl => {
                const ld = appData.levels[lvl];
                const cfg = LEVELS[lvl];
                const students = (ld.students || []).map(s => ({
                    numTable: s.numTable, anonymat: s.anonymat, prenom: s.prenom, nom: s.nom, sexe: s.sexe
                }));
                ctx.levels[lvl] = {
                    name: cfg ? cfg.label : lvl,
                    seuilAdmis: ld.seuilAdmis, seuil2eTour: ld.seuil2eTour, seuilAdmis2: ld.seuilAdmis2,
                    subjects: (ld.subjects || []).map(s => ({ code: s.code, nom: s.name, coef: s.coef })),
                    studentsCount: students.length,
                    students: students.slice(0, 200),
                    grades1: ld.grades1 || {},
                    grades2: ld.grades2 || {},
                    results1: (ld.results1 || []).map(r => ({ numTable: r.student.numTable, prenom: r.student.prenom, nom: r.student.nom, moyenne: r.moyenne, total: r.total, statut: r.decision, mention: r.mention })),
                    results2: (ld.results2 || []).map(r => ({ numTable: r.student.numTable, prenom: r.student.prenom, nom: r.student.nom, moyenne: r.moyenne, total: r.total, statut: r.decision, mention: r.mention }))
                };
            });
            let json = JSON.stringify(ctx);
            if (json.length > 60000) json = json.slice(0, 60000) + '... [tronqué]';
            return json;
        } catch(e) { return '{}'; }
    }

    async function askClaude(question){
        const key = localStorage.getItem(LS_KEY);
        if (!key) {
            addMsg('Clé API Claude manquante. Collez-la dans le champ ci-dessous puis cliquez "Enregistrer".', 'err');
            return null;
        }
        const context = buildContext();
        const system = `Tu es l'assistant vocal du Collège Jean XXIII (Tambacounda, Sénégal), plateforme de gestion des examens blancs (BFEM, Bac TS, Bac L2).
Tu réponds en français, de façon concise (2-3 phrases max pour la voix), en te basant UNIQUEMENT sur les données JSON fournies.
IMPORTANT : ta réponse est lue à voix haute. Écris en texte simple, SANS Markdown ni mise en forme — pas d'astérisques (*), de dièses (#), de tirets de liste, de back-ticks ni d'emojis. Énonce les notes naturellement (« 12 sur 20 » plutôt que « 12/20 ») et écris les symboles en toutes lettres (« pour cent », « supérieur à »).
Tu peux raisonner et calculer à partir de ces données : moyennes, classements, taux de réussite, comparaisons entre élèves, matières ou niveaux.
Si l'information n'est pas dans les données, dis-le clairement.
Format des notes : /20. Les moyennes sont sur 20. Dans les résultats, le champ "statut" vaut exactement "Admis", "2ème Tour" ou "Ajourné" ; le champ "mention" (Terminale uniquement) vaut "Très Bien", "Bien", "Assez Bien" ou "Passable". Les notes des matières sont dans "grades1"/"grades2", indexées par une clé "numéro de table_NOM" ; une valeur "ABS" = absent, "INAPTE" = dispensé (EPS).

Données actuelles de l'application :
${context}`;
        try {
            const resp = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    'x-api-key': key,
                    'anthropic-version': '2023-06-01',
                    'anthropic-dangerous-direct-browser-access': 'true'
                },
                body: JSON.stringify({
                    model: MODEL,
                    max_tokens: 400,
                    system: system,
                    messages: [{ role: 'user', content: question }]
                })
            });
            if (!resp.ok) {
                const err = await resp.text();
                throw new Error('HTTP ' + resp.status + ' : ' + err.slice(0, 200));
            }
            const data = await resp.json();
            return data.content?.[0]?.text || '(réponse vide)';
        } catch(e) {
            addMsg('Erreur API : ' + e.message, 'err');
            return null;
        }
    }

    function pickVoice(){
        if (!window.speechSynthesis) return null;
        const voices = window.speechSynthesis.getVoices() || [];
        if (!voices.length) return state.voice; // voix pas encore chargées : on garde l'existante
        // 1) Choix explicite enregistré par l'utilisateur (menu déroulant)
        const saved = localStorage.getItem(LS_VOICE);
        if (saved){
            const found = voices.find(v => v.name === saved);
            if (found){ state.voice = found; return state.voice; }
        }
        // 2) Sinon : voix d'homme française par défaut
        const fr = voices.filter(v => /^fr/i.test(v.lang));
        if (!fr.length) return state.voice;
        // Voix masculines françaises connues (Windows : Paul ; macOS/iOS : Thomas, Nicolas ; etc.)
        const male = /(paul|thomas|nicolas|claude|henri|daniel|mathieu|guillaume|pierre|antoine|male|homme|man)/i;
        // Voix féminines à éviter dans le repli
        const female = /(hortense|julie|caroline|am[ée]lie|audrey|aur[ée]lie|marie|virginie|sandrine|female|femme|woman)/i;
        state.voice = fr.find(v => male.test(v.name))
                   || fr.find(v => !female.test(v.name))
                   || fr[0];
        return state.voice;
    }

    // Nom court d'une voix : "Microsoft Paul - French (France)" -> "Paul"
    function shortVoiceName(v){
        if (!v) return '—';
        const n = v.name.replace(/^(microsoft|google|apple)\s+/i, '').replace(/\s*[-–(].*$/, '').trim();
        return n || v.name;
    }

    // Met à jour le libellé du bouton "Voix" en haut de la page
    function updateVoiceButtonLabel(){
        const el = $('aichatVoiceCurrent');
        if (el) el.textContent = shortVoiceName(pickVoice());
    }

    // Construit la liste cliquable des voix dans le popup (françaises d'abord)
    function renderVoiceList(){
        const box = $('aichatVoiceList');
        if (!box) return;
        const voices = window.speechSynthesis ? (window.speechSynthesis.getVoices() || []) : [];
        box.innerHTML = '';
        if (!voices.length){
            box.innerHTML = '<div class="aichat-voice-group">Aucune voix détectée. Réessayez dans un instant, ou utilisez Chrome / Edge.</div>';
            return;
        }
        const current = pickVoice();
        const activeName = current ? current.name : '';
        const fr = voices.filter(v => /^fr/i.test(v.lang));
        const others = voices.filter(v => !/^fr/i.test(v.lang));
        const addItem = (v) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'aichat-voice-item' + (v.name === activeName ? ' is-active' : '');
            const check = document.createElement('span'); check.className = 'vi-check'; check.textContent = (v.name === activeName ? '✓' : '');
            const name = document.createElement('span'); name.className = 'vi-name'; name.textContent = v.name + ' — ' + v.lang;
            const play = document.createElement('span'); play.className = 'vi-play'; play.textContent = '▶';
            btn.appendChild(check); btn.appendChild(name); btn.appendChild(play);
            btn.onclick = () => window.aichatChooseVoice(v.name);
            box.appendChild(btn);
        };
        const addGroup = (label, list) => {
            if (!list.length) return;
            const h = document.createElement('div'); h.className = 'aichat-voice-group'; h.textContent = label;
            box.appendChild(h);
            list.forEach(addItem);
        };
        addGroup('Français', fr);
        addGroup('Autres langues', others);
    }

    // getVoices() est asynchrone : on attend qu'une voix FR soit prête AVANT de parler,
    // sinon le navigateur lit avec sa voix par défaut (souvent anglaise => prononciation incorrecte).
    function ensureVoice(cb){
        if (pickVoice()) return cb();
        let done = false;
        const finish = () => { if (done) return; done = true; pickVoice(); cb(); };
        try { window.speechSynthesis.addEventListener('voiceschanged', finish, { once: true }); } catch(e){}
        setTimeout(finish, 1200);
    }

    // Nettoie le texte avant lecture : retire Markdown, symboles et emojis lus à voix haute
    function cleanForSpeech(text){
        if (!text) return '';
        let t = String(text);
        t = t.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');              // liens [texte](url) -> texte
        t = t.replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2190}-\u{21FF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}]/gu, ' '); // emojis / pictogrammes / flèches
        t = t.replace(/(\d)\s*\/\s*(\d)/g, '$1 sur $2');            // 12/20 -> 12 sur 20
        t = t.replace(/[*_`~#>|=^{}\[\]<>]/g, ' ');                 // marqueurs Markdown et symboles
        t = t.replace(/^\s*[-•·]\s+/gm, '');                        // puces en début de ligne
        t = t.replace(/\s[-–—]\s/g, ', ');                          // tirets isolés -> virgule
        t = t.replace(/\n{2,}/g, '. ').replace(/\s{2,}/g, ' ');     // espaces / lignes multiples
        return t.trim();
    }

    function speak(text){
        if (!window.speechSynthesis) return;
        text = cleanForSpeech(text);
        if (!text) { setMode('idle'); stopTick(); resetTimer(); return; }
        ensureVoice(function(){
            try {
                window.speechSynthesis.cancel();
                const u = new SpeechSynthesisUtterance(text);
                if (state.voice) { u.voice = state.voice; u.lang = state.voice.lang; }
                else { u.lang = 'fr-FR'; }
                u.rate = 0.95;
                u.pitch = 1.0;
                setMode('speaking');
                u.onend = () => { setMode('idle'); stopTick(); resetTimer(); };
                u.onerror = () => { setMode('idle'); stopTick(); resetTimer(); };
                window.speechSynthesis.speak(u);
            } catch(e) { setMode('idle'); stopTick(); resetTimer(); }
        });
    }

    async function processQuestion(question){
        if (!question || !question.trim()) { setMode('idle'); stopTick(); resetTimer(); return; }
        addMsg(question, 'user');
        setMode('processing');
        const answer = await askClaude(question);
        if (answer) {
            addMsg(answer, 'ai');
            speak(answer);
        } else {
            setMode('idle'); stopTick(); resetTimer();
        }
    }

    function getRecognition(){
        if (state.recognition) return state.recognition;
        const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (!SR) return null;
        const r = new SR();
        r.lang = 'fr-FR';
        r.continuous = false;
        r.interimResults = false;
        r.maxAlternatives = 1;
        r.onresult = (ev) => {
            const t = ev.results[0]?.[0]?.transcript || '';
            state.lastTranscript = t;
        };
        r.onerror = (ev) => {
            addMsg('Erreur micro : ' + (ev.error || 'inconnue'), 'err');
            setMode('idle'); stopTick(); resetTimer();
        };
        r.onend = () => {
            if (state.mode === 'listening') {
                stopTick();
                if (state.lastTranscript) {
                    processQuestion(state.lastTranscript);
                    state.lastTranscript = '';
                } else {
                    setMode('idle'); resetTimer();
                }
            }
        };
        state.recognition = r;
        return r;
    }

    window.aichatToggle = function(){
        if (state.mode === 'listening'){
            try { state.recognition && state.recognition.stop(); } catch(e){}
            return;
        }
        if (state.mode === 'processing' || state.mode === 'speaking'){
            try { window.speechSynthesis?.cancel(); } catch(e){}
            setMode('idle'); stopTick(); resetTimer();
            return;
        }
        const rec = getRecognition();
        if (!rec) {
            addMsg('La reconnaissance vocale n\'est pas supportée par ce navigateur. Utilisez Chrome ou Edge, ou tapez votre question ci-dessous.', 'err');
            return;
        }
        state.lastTranscript = '';
        resetTimer();
        setMode('listening');
        startTick();
        try { rec.start(); } catch(e) { addMsg('Impossible de démarrer le micro : ' + e.message, 'err'); setMode('idle'); stopTick(); }
    };

    window.aichatSaveKey = function(){
        const input = $('aichatApiKey');
        const status = $('aichatKeyStatus');
        if (!input) return;
        const v = input.value.trim();
        if (!v) { localStorage.removeItem(LS_KEY); if (status) status.textContent = 'Clé supprimée'; input.value=''; return; }
        localStorage.setItem(LS_KEY, v);
        input.value = '';
        if (status) status.textContent = '✓ Clé enregistrée';
        setTimeout(() => { if (status) status.textContent = '✓ Clé active'; }, 2000);
    };

    window.aichatSendText = function(){
        const input = $('aichatTextInput');
        if (!input) return;
        const q = input.value.trim();
        if (!q) return;
        input.value = '';
        processQuestion(q);
    };

    window.aichatOpenVoiceModal = function(){
        renderVoiceList();
        const m = $('aichatVoiceModal');
        if (m) m.classList.add('show');
    };

    window.aichatChooseVoice = function(name){
        const voices = window.speechSynthesis ? (window.speechSynthesis.getVoices() || []) : [];
        const v = voices.find(x => x.name === name);
        if (!v) return;
        state.voice = v;
        localStorage.setItem(LS_VOICE, name);
        renderVoiceList();          // rafraîchit la coche dans le popup
        updateVoiceButtonLabel();   // met à jour le bouton en haut
        speak('Bonjour, je suis votre assistant. Voici un aperçu de ma voix.'); // écoute immédiate
    };

    window.aichatInit = function(){
        buildWaveform();
        buildParticles();
        setMode('idle');
        pickVoice();
        updateVoiceButtonLabel();
        if (window.speechSynthesis) window.speechSynthesis.onvoiceschanged = function(){
            pickVoice();
            updateVoiceButtonLabel();
            const m = $('aichatVoiceModal');
            if (m && m.classList.contains('show')) renderVoiceList();
        };
        const status = $('aichatKeyStatus');
        if (status && localStorage.getItem(LS_KEY)) status.textContent = '✓ Clé active';
    };

    function attachObserver(){
        const page = document.getElementById('page-aichat');
        if (!page) { setTimeout(attachObserver, 100); return; }
        const obs = new MutationObserver(() => {
            if (page.classList.contains('active')) window.aichatInit();
        });
        obs.observe(page, { attributes: true, attributeFilter: ['class'] });
        if (page.classList.contains('active')) window.aichatInit();
    }
    attachObserver();
})();

// (Supprimé : ancien curseur "login spline" — les éléments #loginSplineCard /
// #loginSplineCursor n'existent pas dans index.html, donc l'IIFE bouclait
// indéfiniment via setTimeout(init, 200) sans jamais s'attacher.)

// ============================================================
// === V2.0 ADVANCED VISUALIZATIONS ===========================
// ============================================================

function _vizGetNumericGrade(val) {
    if (val === 'ABS' || val === 'INAPTE' || val === '' || val === undefined || val === null) return null;
    const n = parseFloat(val);
    return isNaN(n) ? null : n;
}

function _vizColorForGrade(note) {
    // 0 = rouge (0°), 10 = jaune (60°), 20 = vert (120°)
    if (note === null || note === undefined) return '#f5f5f5';
    const clamped = Math.max(0, Math.min(20, note));
    const hue = (clamped / 20) * 120;
    return `hsl(${hue}, 65%, ${45 + (clamped/20) * 10}%)`;
}

// ============================================================
// 1. HEATMAP - Élèves × Matières
// ============================================================
function renderHeatmapView(container) {
    const ld = getLevelData();
    if (!ld.students || ld.students.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>Aucun élève dans ce niveau.</p></div>';
        return;
    }
    const subjects = ld.subjects;
    const students = ld.students.slice();
    const results = ld.results1 || [];

    // Trier par moyenne décroissante (élèves avec résultats en premier)
    students.sort((a, b) => {
        const ra = results.find(r => r.key === stKey(a));
        const rb = results.find(r => r.key === stKey(b));
        return (rb ? rb.moyenne : -1) - (ra ? ra.moyenne : -1);
    });

    let html = `
        <div class="viz-header">
            <h3>🔥 Heatmap des notes — ${LEVELS[currentLevel].label}</h3>
            <p class="viz-subtitle">Vue d'ensemble : chaque cellule colorée selon la note. Rouge = faible, Vert = excellent.</p>
            <div class="viz-legend">
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(0,65%,45%)"></span>0-5</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(30,65%,48%)"></span>5-8</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(60,65%,51%)"></span>8-10</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(75,65%,53%)"></span>10-12</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(95,65%,55%)"></span>12-15</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(120,65%,55%)"></span>15-20</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:#424242"></span>ABS</span>
                <span class="viz-leg-item"><span class="viz-leg-sw" style="background:#bdbdbd"></span>INAPTE</span>
            </div>
        </div>
        <div class="heatmap-wrap">
            <table class="heatmap-table">
                <thead>
                    <tr>
                        <th class="heatmap-fixed-col">N°</th>
                        <th class="heatmap-fixed-col">Nom / Prénom</th>
    `;
    subjects.forEach(s => {
        html += `<th title="${s.name} (coef ${s.coef})">${s.code}</th>`;
    });
    html += `<th class="heatmap-moy-col">Moy.</th><th>Déc.</th></tr></thead><tbody>`;

    students.forEach((s, idx) => {
        const key = stKey(s);
        const stGrades = (ld.grades1 || {})[key] || {};
        const result = results.find(r => r.key === key);
        const moy = result ? result.moyenne : null;
        const dec = result ? result.decision : '—';
        const decClass = dec === 'Admis' ? 'dec-admis' : dec === '2ème Tour' ? 'dec-tour2' : dec === 'Ajourné' ? 'dec-ajourne' : '';

        html += `<tr>
            <td class="heatmap-fixed-col">${idx+1}</td>
            <td class="heatmap-fixed-col heatmap-name">${Security.escapeHTML(s.nom || '')} ${Security.escapeHTML(s.prenom || '')}</td>`;
        subjects.forEach(subj => {
            const val = stGrades[subj.code];
            if (val === 'ABS') {
                html += `<td class="heatmap-cell heatmap-abs" title="${s.nom} - ${subj.name} : Absent">ABS</td>`;
            } else if (val === 'INAPTE') {
                html += `<td class="heatmap-cell heatmap-inapte" title="${s.nom} - ${subj.name} : Inapte">–</td>`;
            } else {
                const num = _vizGetNumericGrade(val);
                if (num === null) {
                    html += `<td class="heatmap-cell heatmap-empty">·</td>`;
                } else {
                    const color = _vizColorForGrade(num);
                    const textColor = num < 7 || num > 14 ? 'white' : '#222';
                    html += `<td class="heatmap-cell" style="background:${color};color:${textColor}" title="${s.nom} - ${subj.name} (coef ${subj.coef}) : ${num.toFixed(2)}/20">${num.toFixed(1)}</td>`;
                }
            }
        });
        if (moy !== null) {
            const color = _vizColorForGrade(moy);
            const textColor = moy < 7 || moy > 14 ? 'white' : '#222';
            html += `<td class="heatmap-moy-col" style="background:${color};color:${textColor};font-weight:700">${moy.toFixed(2)}</td>`;
        } else {
            html += `<td class="heatmap-moy-col heatmap-empty">—</td>`;
        }
        html += `<td class="heatmap-dec ${decClass}">${dec}</td>`;
        html += `</tr>`;
    });
    html += '</tbody></table></div>';

    // Stats par matière en bas
    html += '<div class="viz-header" style="margin-top:24px;"><h3>Moyennes par matière</h3></div>';
    html += '<div class="heatmap-wrap"><table class="heatmap-table"><thead><tr><th>Matière</th><th>Coef</th><th>Moyenne</th><th>Notés</th><th>Abs</th><th>Échec (&lt;10)</th></tr></thead><tbody>';
    subjects.forEach(subj => {
        let sum = 0, count = 0, abs = 0, fail = 0;
        students.forEach(s => {
            const v = (ld.grades1 || {})[stKey(s)] || {};
            const raw = v[subj.code];
            if (raw === 'ABS') abs++;
            else {
                const n = _vizGetNumericGrade(raw);
                if (n !== null) { sum += n; count++; if (n < 10) fail++; }
            }
        });
        const avg = count > 0 ? sum / count : 0;
        const color = _vizColorForGrade(avg);
        html += `<tr><td style="font-weight:600">${subj.name} (${subj.code})</td><td>${subj.coef}</td><td style="background:${color};color:${avg<7||avg>14?'white':'#222'};font-weight:700">${avg.toFixed(2)}</td><td>${count}</td><td>${abs}</td><td style="color:${fail>count/2?'#c62828':'#666'};font-weight:600">${fail}</td></tr>`;
    });
    html += '</tbody></table></div>';

    container.innerHTML = html;
}

// ============================================================
// 2. RADAR CHART - Profil d'un élève
// ============================================================
function renderRadarView(container) {
    const ld = getLevelData();
    if (!ld.students || ld.students.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>Aucun élève dans ce niveau.</p></div>';
        return;
    }
    const subjects = ld.subjects;
    const students = ld.students.slice().sort((a, b) => (a.nom || '').localeCompare(b.nom || ''));

    let options = students.map(s => `<option value="${stKey(s)}">${Security.escapeHTML(s.nom)} ${Security.escapeHTML(s.prenom)} (n°${s.numTable})</option>`).join('');

    container.innerHTML = `
        <div class="viz-header">
            <h3>🎯 Profil élève — radar par matière</h3>
            <p class="viz-subtitle">Comparez les notes d'un élève à la moyenne de la classe et à la cible (10/20).</p>
            <div style="margin-top:12px;">
                <label style="font-weight:600;margin-right:8px;">Élève :</label>
                <select id="radarStudentSelect" onchange="updateRadarChart()" style="padding:8px 12px;border-radius:6px;border:1px solid #ddd;min-width:300px;">
                    <option value="">-- Choisir un élève --</option>
                    ${options}
                </select>
            </div>
        </div>
        <div class="radar-wrap" style="max-width:700px;margin:20px auto;">
            <canvas id="radarStudentChart" style="max-height:500px;"></canvas>
        </div>
        <div id="radarStudentInfo" style="text-align:center;margin-top:16px;color:#666;"></div>
    `;
}

function updateRadarChart() {
    const ld = getLevelData();
    const key = document.getElementById('radarStudentSelect').value;
    if (!key) return;
    const student = ld.students.find(s => stKey(s) === key);
    if (!student) return;
    const subjects = ld.subjects;
    const stGrades = (ld.grades1 || {})[key] || {};

    // Calcul moyenne classe par matière
    const classAvgs = subjects.map(subj => {
        let sum = 0, n = 0;
        ld.students.forEach(s => {
            const v = (ld.grades1 || {})[stKey(s)] || {};
            const num = _vizGetNumericGrade(v[subj.code]);
            if (num !== null) { sum += num; n++; }
        });
        return n > 0 ? sum / n : 0;
    });
    const studentVals = subjects.map(s => _vizGetNumericGrade(stGrades[s.code]) || 0);
    const targetVals = subjects.map(() => 10);

    destroyChart('radarStudentChart');
    _chartInstances['radarStudentChart'] = new Chart(document.getElementById('radarStudentChart'), {
        type: 'radar',
        data: {
            labels: subjects.map(s => s.code),
            datasets: [
                {
                    label: `${student.prenom} ${student.nom}`,
                    data: studentVals,
                    backgroundColor: 'rgba(102,126,234,0.25)',
                    borderColor: '#667eea',
                    borderWidth: 2,
                    pointBackgroundColor: '#667eea',
                    pointRadius: 4
                },
                {
                    label: 'Moyenne classe',
                    data: classAvgs,
                    backgroundColor: 'rgba(245,158,11,0.15)',
                    borderColor: '#f59e0b',
                    borderWidth: 2,
                    borderDash: [5,5],
                    pointBackgroundColor: '#f59e0b',
                    pointRadius: 3
                },
                {
                    label: 'Cible (10/20)',
                    data: targetVals,
                    backgroundColor: 'rgba(16,185,129,0.05)',
                    borderColor: '#10b981',
                    borderWidth: 1,
                    borderDash: [2,3],
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                r: {
                    min: 0,
                    max: 20,
                    ticks: { stepSize: 5 }
                }
            },
            plugins: {
                legend: { position: 'top' },
                tooltip: {
                    callbacks: {
                        label: ctx => {
                            const subj = subjects[ctx.dataIndex];
                            return `${ctx.dataset.label}: ${ctx.parsed.r.toFixed(2)}/20 (${subj.name})`;
                        }
                    }
                }
            }
        }
    });

    const result = (ld.results1 || []).find(r => r.key === key);
    const info = document.getElementById('radarStudentInfo');
    if (result) {
        info.innerHTML = `<strong>Moyenne générale :</strong> ${result.moyenne.toFixed(2)}/20 · <strong>Décision :</strong> ${result.decision} · <strong>Rang :</strong> ${result.rang}`;
    } else {
        info.innerHTML = `<em>Résultats non calculés pour cet élève.</em>`;
    }
}

// ============================================================
// 3. SANKEY - Flux des résultats
// ============================================================
function renderSankeyView(container) {
    const ld = getLevelData();
    const inscrits = ld.students.length;
    const results1 = ld.results1 || [];
    const results2 = ld.results2 || [];
    const presents = results1.length;
    const absents = inscrits - presents;
    const admis1 = results1.filter(r => r.decision === 'Admis').length;
    const tour2Count = results1.filter(r => r.decision === '2ème Tour').length;
    const ajournes1 = results1.filter(r => r.decision === 'Ajourné').length;
    const admis2 = results2.filter(r => r.decision === 'Admis').length;
    const ajournes2 = tour2Count - admis2;

    if (inscrits === 0) {
        container.innerHTML = '<div class="empty-state"><p>Aucun élève à analyser.</p></div>';
        return;
    }

    const totalH = 500;
    const pxPer = Math.max(1, totalH / Math.max(inscrits, 1));
    const h = n => Math.max(8, n * pxPer);

    container.innerHTML = `
        <div class="viz-header">
            <h3>🌊 Parcours des élèves — ${LEVELS[currentLevel].label}</h3>
            <p class="viz-subtitle">Flux complet : de l'inscription au verdict final. Hauteur = nombre d'élèves.</p>
        </div>
        <div class="sankey-wrap">
            <div class="sankey-col">
                <div class="sankey-col-title">Inscrits</div>
                <div class="sankey-node sankey-node-blue" style="height:${h(inscrits)}px;">
                    <div class="sankey-node-label">Inscrits<br><strong>${inscrits}</strong></div>
                </div>
            </div>
            <svg class="sankey-link" viewBox="0 0 100 ${totalH}" preserveAspectRatio="none">
                <path d="M0,0 C50,0 50,0 100,0 L100,${h(presents)} C50,${h(presents)} 50,0 0,0 Z" fill="rgba(33,150,243,0.35)"/>
                <path d="M0,${h(inscrits)} C50,${h(inscrits)} 50,${h(presents)} 100,${h(presents)} L100,${h(presents) + h(absents)} C50,${h(presents) + h(absents)} 50,${h(inscrits)} 0,${h(inscrits)} Z" fill="rgba(120,120,120,0.25)"/>
            </svg>
            <div class="sankey-col">
                <div class="sankey-col-title">Session</div>
                <div class="sankey-node sankey-node-blue" style="height:${h(presents)}px;">
                    <div class="sankey-node-label">Présents<br><strong>${presents}</strong></div>
                </div>
                ${absents > 0 ? `<div class="sankey-node sankey-node-gray" style="height:${h(absents)}px;margin-top:4px;">
                    <div class="sankey-node-label">Absents<br><strong>${absents}</strong></div>
                </div>` : ''}
            </div>
            <svg class="sankey-link" viewBox="0 0 100 ${totalH}" preserveAspectRatio="none">
                <path d="M0,0 C50,0 50,0 100,0 L100,${h(admis1)} C50,${h(admis1)} 50,0 0,0 Z" fill="rgba(16,185,129,0.35)"/>
                <path d="M0,${h(admis1)} C50,${h(admis1)} 50,${h(admis1)} 100,${h(admis1)} L100,${h(admis1)+h(tour2Count)} C50,${h(admis1)+h(tour2Count)} 50,${h(admis1)} 0,${h(admis1)} Z" fill="rgba(245,158,11,0.35)"/>
                <path d="M0,${h(admis1)+h(tour2Count)} C50,${h(admis1)+h(tour2Count)} 50,${h(admis1)+h(tour2Count)} 100,${h(admis1)+h(tour2Count)} L100,${h(presents)} C50,${h(presents)} 50,${h(admis1)+h(tour2Count)} 0,${h(admis1)+h(tour2Count)} Z" fill="rgba(239,68,68,0.35)"/>
            </svg>
            <div class="sankey-col">
                <div class="sankey-col-title">1er Tour</div>
                <div class="sankey-node sankey-node-green" style="height:${h(admis1)}px;">
                    <div class="sankey-node-label">Admis<br><strong>${admis1}</strong></div>
                </div>
                <div class="sankey-node sankey-node-orange" style="height:${h(tour2Count)}px;margin-top:4px;">
                    <div class="sankey-node-label">2ème Tour<br><strong>${tour2Count}</strong></div>
                </div>
                <div class="sankey-node sankey-node-red" style="height:${h(ajournes1)}px;margin-top:4px;">
                    <div class="sankey-node-label">Ajournés<br><strong>${ajournes1}</strong></div>
                </div>
            </div>
            <svg class="sankey-link" viewBox="0 0 100 ${totalH}" preserveAspectRatio="none">
                <path d="M0,0 C50,0 50,0 100,0 L100,${h(admis1)} C50,${h(admis1)} 50,0 0,0 Z" fill="rgba(16,185,129,0.5)"/>
                <path d="M0,${h(admis1)} C50,${h(admis1)} 50,${h(admis1)} 100,${h(admis1)} L100,${h(admis1)+h(admis2)} C50,${h(admis1)+h(admis2)} 50,${h(admis1)} 0,${h(admis1)} Z" fill="rgba(16,185,129,0.3)"/>
                <path d="M0,${h(admis1)+h(tour2Count)} C50,${h(admis1)+h(tour2Count)} 50,${h(admis1)+h(admis2)} 100,${h(admis1)+h(admis2)} L100,${h(admis1)+h(admis2)+h(ajournes1+ajournes2)} C50,${h(admis1)+h(admis2)+h(ajournes1+ajournes2)} 50,${h(admis1)+h(tour2Count)} 0,${h(admis1)+h(tour2Count)} Z" fill="rgba(239,68,68,0.4)"/>
            </svg>
            <div class="sankey-col">
                <div class="sankey-col-title">Final</div>
                <div class="sankey-node sankey-node-green" style="height:${h(admis1+admis2)}px;">
                    <div class="sankey-node-label">✓ Admis<br><strong>${admis1+admis2}</strong><br><small>${presents>0?((admis1+admis2)/presents*100).toFixed(1):0}%</small></div>
                </div>
                <div class="sankey-node sankey-node-red" style="height:${h(ajournes1+ajournes2)}px;margin-top:4px;">
                    <div class="sankey-node-label">✗ Refusés<br><strong>${ajournes1+ajournes2}</strong><br><small>${presents>0?((ajournes1+ajournes2)/presents*100).toFixed(1):0}%</small></div>
                </div>
            </div>
        </div>
    `;
}

// ============================================================
// 4. BOX PLOTS - Distribution par matière
// ============================================================
function renderBoxPlotView(container) {
    const ld = getLevelData();
    if (!ld.students || ld.students.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>Aucun élève dans ce niveau.</p></div>';
        return;
    }
    const subjects = ld.subjects;

    container.innerHTML = `
        <div class="viz-header">
            <h3>📊 Distribution des notes par matière</h3>
            <p class="viz-subtitle">Pour chaque matière : minimum, 1er quartile, médiane, 3ème quartile, maximum. Détecte les disparités.</p>
        </div>
        <div class="boxplot-wrap" id="boxplotChartWrap"></div>
    `;

    const wrap = document.getElementById('boxplotChartWrap');
    const allStats = subjects.map(subj => {
        const notes = [];
        ld.students.forEach(s => {
            const v = (ld.grades1 || {})[stKey(s)] || {};
            const n = _vizGetNumericGrade(v[subj.code]);
            if (n !== null) notes.push(n);
        });
        notes.sort((a,b) => a - b);
        if (notes.length === 0) return { subj, empty: true };
        const q = p => {
            const idx = (notes.length - 1) * p;
            const lo = Math.floor(idx), hi = Math.ceil(idx);
            return lo === hi ? notes[lo] : notes[lo] + (notes[hi] - notes[lo]) * (idx - lo);
        };
        return {
            subj,
            min: notes[0],
            q1: q(0.25),
            median: q(0.5),
            q3: q(0.75),
            max: notes[notes.length-1],
            count: notes.length,
            mean: notes.reduce((a,b)=>a+b,0) / notes.length
        };
    });

    let html = '<div class="boxplot-list">';
    allStats.forEach(s => {
        if (s.empty) {
            html += `<div class="boxplot-row"><div class="boxplot-label">${s.subj.code}</div><div class="boxplot-track"><span style="color:#999;font-size:12px;">Aucune note</span></div></div>`;
            return;
        }
        const toPct = v => (v / 20) * 100;
        const boxColor = _vizColorForGrade(s.median);
        html += `
            <div class="boxplot-row">
                <div class="boxplot-label" title="${s.subj.name}">${s.subj.code}<br><small style="font-weight:400;color:#888">${s.count} notes</small></div>
                <div class="boxplot-track">
                    <div class="boxplot-scale">
                        <span>0</span><span>5</span><span>10</span><span>15</span><span>20</span>
                    </div>
                    <div class="boxplot-line" style="left:${toPct(s.min)}%;right:${100 - toPct(s.max)}%"></div>
                    <div class="boxplot-box" style="left:${toPct(s.q1)}%;width:${toPct(s.q3) - toPct(s.q1)}%;background:${boxColor};"></div>
                    <div class="boxplot-median" style="left:${toPct(s.median)}%;" title="Médiane : ${s.median.toFixed(2)}"></div>
                    <div class="boxplot-min" style="left:${toPct(s.min)}%" title="Min : ${s.min.toFixed(2)}"></div>
                    <div class="boxplot-max" style="left:${toPct(s.max)}%" title="Max : ${s.max.toFixed(2)}"></div>
                    <div class="boxplot-mean" style="left:${toPct(s.mean)}%" title="Moyenne : ${s.mean.toFixed(2)}"></div>
                </div>
                <div class="boxplot-stats">
                    <span title="Médiane"><strong>${s.median.toFixed(1)}</strong></span>
                    <span title="Min - Max" style="color:#888;font-size:11px;">${s.min.toFixed(1)}-${s.max.toFixed(1)}</span>
                </div>
            </div>
        `;
    });
    html += '</div>';
    html += `
        <div class="viz-legend" style="margin-top:16px;">
            <span class="viz-leg-item"><span class="viz-leg-sw" style="background:#667eea;width:30px;height:8px;"></span>Étendue (min → max)</span>
            <span class="viz-leg-item"><span class="viz-leg-sw" style="background:hsl(75,65%,53%);width:30px;height:14px;"></span>Boîte (Q1 → Q3, 50% des élèves)</span>
            <span class="viz-leg-item"><span class="viz-leg-sw" style="background:#000;width:2px;height:20px;"></span>Médiane</span>
            <span class="viz-leg-item"><span class="viz-leg-sw" style="background:#e91e63;width:8px;height:8px;border-radius:50%;"></span>Moyenne</span>
        </div>
    `;
    wrap.innerHTML = html;
}

// ============================================================
// 5. CALENDAR HEATMAP - Activité de saisie
// ============================================================
function renderCalendarHeatmapView(container) {
    // Reconstituer l'activité depuis le journal (stocké dans localStorage, pas dans appData)
    const log = getActivityLog();
    const counts = {};
    log.forEach(entry => {
        const d = new Date(entry.time || entry.date || Date.now());
        const key = d.toISOString().slice(0,10);
        counts[key] = (counts[key] || 0) + 1;
    });

    // Génération de la grille (12 dernières semaines = 84 jours)
    const today = new Date();
    today.setHours(0,0,0,0);
    const days = [];
    for (let i = 83; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(today.getDate() - i);
        const key = d.toISOString().slice(0,10);
        days.push({ date: new Date(d), key, count: counts[key] || 0 });
    }

    const realMax = Math.max(0, ...days.map(d => d.count));
    const maxCount = Math.max(1, realMax);
    const monthNames = ['Jan','Fév','Mar','Avr','Mai','Jun','Jul','Aoû','Sep','Oct','Nov','Déc'];

    container.innerHTML = `
        <div class="viz-header">
            <h3>📅 Activité de saisie — 12 dernières semaines</h3>
            <p class="viz-subtitle">Chaque carré = un jour. Plus c'est foncé, plus d'actions ont été enregistrées dans le journal.</p>
        </div>
        <div class="calheatmap-wrap">
            <div class="calheatmap-grid" id="calHeatmapGrid"></div>
            <div class="calheatmap-legend">
                <span>Moins</span>
                <span class="calheatmap-leg" style="background:#ebedf0"></span>
                <span class="calheatmap-leg" style="background:#9be9a8"></span>
                <span class="calheatmap-leg" style="background:#40c463"></span>
                <span class="calheatmap-leg" style="background:#30a14e"></span>
                <span class="calheatmap-leg" style="background:#216e39"></span>
                <span>Plus</span>
            </div>
        </div>
        <div class="calheatmap-stats">
            <div class="calheatmap-stat"><div class="number">${log.length}</div><div class="label">Actions totales</div></div>
            <div class="calheatmap-stat"><div class="number">${days.filter(d=>d.count>0).length}</div><div class="label">Jours actifs (84j)</div></div>
            <div class="calheatmap-stat"><div class="number">${realMax}</div><div class="label">Pic d'activité (jour)</div></div>
        </div>
    `;

    const grid = document.getElementById('calHeatmapGrid');
    // Organiser en colonnes (semaines) - dimanche en haut
    let html = '';
    for (let w = 0; w < 12; w++) {
        html += '<div class="calheatmap-week">';
        for (let d = 0; d < 7; d++) {
            const idx = w * 7 + d;
            if (idx >= days.length) { html += '<div class="calheatmap-day-empty"></div>'; continue; }
            const day = days[idx];
            const intensity = day.count === 0 ? 0 : Math.min(4, Math.ceil((day.count / maxCount) * 4));
            const colors = ['#ebedf0','#9be9a8','#40c463','#30a14e','#216e39'];
            const dateStr = day.date.toLocaleDateString('fr-FR', { weekday:'long', day:'numeric', month:'long' });
            html += `<div class="calheatmap-day" style="background:${colors[intensity]}" title="${dateStr} : ${day.count} action${day.count>1?'s':''}"></div>`;
        }
        html += '</div>';
    }
    grid.innerHTML = html;
}

// ============================================================
// 6. PRESENTATION MODE - Délibération plein écran
// ============================================================
function openPresentationMode() {
    const ld = getLevelData();
    if (!ld.results1 || ld.results1.length === 0) {
        alert('Veuillez d\'abord calculer les résultats.');
        return;
    }

    let overlay = document.getElementById('presentationOverlay');
    if (overlay) overlay.remove();

    overlay = document.createElement('div');
    overlay.id = 'presentationOverlay';
    overlay.className = 'presentation-overlay';

    const results = ld.results1.slice().sort((a,b) => b.moyenne - a.moyenne);
    const admis1 = results.filter(r => r.decision === 'Admis').length;
    const tour2 = results.filter(r => r.decision === '2ème Tour').length;
    const ajournes = results.filter(r => r.decision === 'Ajourné').length;
    const totalAdmis = admis1 + ((ld.results2 || []).filter(r => r.decision === 'Admis').length);

    overlay.innerHTML = `
        <div class="presentation-header">
            <div class="presentation-title">
                <div class="presentation-school">Collège Jean XXIII — Tambacounda</div>
                <div class="presentation-exam">${LEVELS[currentLevel].examLabel || 'Examen Blanc'} — ${LEVELS[currentLevel].label}</div>
                <div class="presentation-year">Année ${appData.year || ''}</div>
            </div>
            <button class="presentation-close" onclick="closePresentationMode()" title="Quitter (Esc)">✕</button>
        </div>

        <div class="presentation-counters">
            <div class="presentation-counter presentation-counter-green">
                <div class="presentation-counter-num" data-target="${totalAdmis}">0</div>
                <div class="presentation-counter-label">Total Admis</div>
            </div>
            <div class="presentation-counter presentation-counter-blue">
                <div class="presentation-counter-num" data-target="${admis1}">0</div>
                <div class="presentation-counter-label">Admis 1er Tour</div>
            </div>
            <div class="presentation-counter presentation-counter-orange">
                <div class="presentation-counter-num" data-target="${tour2}">0</div>
                <div class="presentation-counter-label">2ème Tour</div>
            </div>
            <div class="presentation-counter presentation-counter-red">
                <div class="presentation-counter-num" data-target="${ajournes}">0</div>
                <div class="presentation-counter-label">Ajournés</div>
            </div>
        </div>

        <div class="presentation-main">
            <div class="presentation-panel presentation-panel-list">
                <h3>Délibération en cours</h3>
                <div class="presentation-current" id="presentationCurrent">
                    <div class="presentation-current-info">Appuyez sur <kbd>Espace</kbd> pour démarrer</div>
                </div>
                <div class="presentation-progress">
                    <div class="presentation-progress-bar" id="presentationProgressBar"></div>
                </div>
                <div class="presentation-progress-text" id="presentationProgressText">0 / ${results.length}</div>
            </div>
            <div class="presentation-panel presentation-panel-chart">
                <h3>Répartition</h3>
                <div class="presentation-donut" style="background:conic-gradient(
                    #10b981 0% ${results.length>0?(admis1/results.length*100):0}%,
                    #f59e0b ${results.length>0?(admis1/results.length*100):0}% ${results.length>0?((admis1+tour2)/results.length*100):0}%,
                    #ef4444 ${results.length>0?((admis1+tour2)/results.length*100):0}% 100%
                );"></div>
                <div class="presentation-donut-legend">
                    <div><span class="dot" style="background:#10b981"></span>Admis</div>
                    <div><span class="dot" style="background:#f59e0b"></span>2e Tour</div>
                    <div><span class="dot" style="background:#ef4444"></span>Ajourné</div>
                </div>
            </div>
        </div>

        <div class="presentation-footer">
            <span><kbd>Espace</kbd> / <kbd>→</kbd> Suivant</span>
            <span><kbd>←</kbd> Précédent</span>
            <span><kbd>A</kbd> Auto-play</span>
            <span><kbd>Esc</kbd> Quitter</span>
        </div>
    `;
    document.body.appendChild(overlay);

    // Animate counters
    overlay.querySelectorAll('.presentation-counter-num').forEach(el => {
        const target = parseInt(el.dataset.target, 10);
        const start = Date.now();
        const dur = 1200;
        const tick = () => {
            const p = Math.min(1, (Date.now() - start) / dur);
            const eased = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.round(eased * target);
            if (p < 1) requestAnimationFrame(tick);
        };
        tick();
    });

    // Setup keyboard navigation
    _presentationResults = results;
    _presentationIndex = -1;
    _presentationAutoplay = false;
    _presentationKeyHandler = e => {
        if (e.key === 'Escape') { closePresentationMode(); }
        else if (e.key === ' ' || e.key === 'ArrowRight') { e.preventDefault(); _presentationNext(); }
        else if (e.key === 'ArrowLeft') { e.preventDefault(); _presentationPrev(); }
        else if (e.key.toLowerCase() === 'a') { _presentationToggleAutoplay(); }
    };
    document.addEventListener('keydown', _presentationKeyHandler);
    overlay.focus();
}

let _presentationResults = [];
let _presentationIndex = -1;
let _presentationAutoplay = false;
let _presentationAutoplayTimer = null;
let _presentationKeyHandler = null;

function _presentationShowAt(idx) {
    if (idx < 0 || idx >= _presentationResults.length) return;
    _presentationIndex = idx;
    const r = _presentationResults[idx];
    const decColor = r.decision === 'Admis' ? '#10b981' : r.decision === '2ème Tour' ? '#f59e0b' : '#ef4444';
    const decIcon = r.decision === 'Admis' ? '✓' : r.decision === '2ème Tour' ? '⟳' : '✗';
    const target = document.getElementById('presentationCurrent');
    if (!target) return;
    target.innerHTML = `
        <div class="presentation-card presentation-card-anim">
            <div class="presentation-rang">#${r.rang}</div>
            <div class="presentation-student-name">${Security.escapeHTML(r.student.prenom || '')} ${Security.escapeHTML(r.student.nom || '')}</div>
            <div class="presentation-student-num">N° ${r.student.numTable || ''}${r.student.anonymat ? ' · ' + Security.escapeHTML(r.student.anonymat) : ''}</div>
            <div class="presentation-moy" style="color:${decColor}">${r.moyenne.toFixed(2)}<small>/20</small></div>
            <div class="presentation-decision" style="background:${decColor}">${decIcon} ${r.decision}${r.mention ? ' — ' + r.mention : ''}</div>
        </div>
    `;
    const pct = ((idx+1) / _presentationResults.length) * 100;
    document.getElementById('presentationProgressBar').style.width = pct + '%';
    document.getElementById('presentationProgressText').textContent = `${idx+1} / ${_presentationResults.length}`;
}

function _presentationNext() {
    if (_presentationIndex < _presentationResults.length - 1) {
        _presentationShowAt(_presentationIndex + 1);
    } else if (_presentationAutoplay) {
        _presentationToggleAutoplay();
    }
}

function _presentationPrev() {
    if (_presentationIndex > 0) _presentationShowAt(_presentationIndex - 1);
}

function _presentationToggleAutoplay() {
    _presentationAutoplay = !_presentationAutoplay;
    if (_presentationAutoplay) {
        _presentationAutoplayTimer = setInterval(() => _presentationNext(), 1500);
    } else {
        clearInterval(_presentationAutoplayTimer);
    }
}

function closePresentationMode() {
    const ov = document.getElementById('presentationOverlay');
    if (ov) ov.remove();
    if (_presentationKeyHandler) document.removeEventListener('keydown', _presentationKeyHandler);
    if (_presentationAutoplayTimer) clearInterval(_presentationAutoplayTimer);
    _presentationAutoplay = false;
}

// ================================================================
// ========== MODULE ÉCOLE (école, classes, professeurs) ==========
// ================================================================

function getEcoleData() {
    if (!appData.ecole) {
        appData.ecole = {
            infos: { nom: (appData.school && appData.school.name) || '', adresse: '', telephone: '', email: '', bp: '', devise: '' },
            classes: [],
            professeurs: []
        };
    }
    // Rétro-compatibilité si une sauvegarde partielle est importée
    if (!appData.ecole.infos) appData.ecole.infos = { nom: '', adresse: '', telephone: '', email: '', bp: '', devise: '' };
    if (!Array.isArray(appData.ecole.classes)) appData.ecole.classes = [];
    if (!Array.isArray(appData.ecole.professeurs)) appData.ecole.professeurs = [];
    // Direction : un préfet par cycle, un directeur pour l'établissement
    if (!appData.ecole.direction) appData.ecole.direction = { directeur: '', prefetMoyen: '', prefetSecondaire: '' };
    // Ajouté avec le cycle Élémentaire : absent des sauvegardes antérieures.
    if (typeof appData.ecole.direction.directeurElementaire !== 'string') appData.ecole.direction.directeurElementaire = '';
    // Inscriptions en attente de validation par la comptabilité
    if (!Array.isArray(appData.ecole.preinscriptions)) appData.ecole.preinscriptions = [];
    // Anciens élèves : sortis ou diplômés, conservés pour l'historique
    if (!Array.isArray(appData.ecole.sortants)) appData.ecole.sortants = [];
    // Cahier de texte : { classeId: [ { id, date, matiereCode, profId, contenu, devoirs, dateRemise } ] }
    if (!appData.ecole.cahierTexte || typeof appData.ecole.cahierTexte !== 'object') appData.ecole.cahierTexte = {};
    // Matières des bulletins, désormais une grille par cycle.
    // Migration : l'ancien format était un tableau plat commun à tout l'établissement.
    // On le conserve pour le moyen et le secondaire (personnalisations incluses)
    // et on dote l'élémentaire de sa grille par défaut.
    if (Array.isArray(appData.ecole.matieres)) {
        const ancienne = appData.ecole.matieres;
        appData.ecole.matieres = {
            elementaire: JSON.parse(JSON.stringify(ECOLE_MATIERES_PAR_CYCLE.elementaire)),
            moyen: JSON.parse(JSON.stringify(ancienne)),
            secondaire: JSON.parse(JSON.stringify(ancienne))
        };
    }
    if (!appData.ecole.matieres || typeof appData.ecole.matieres !== 'object') appData.ecole.matieres = {};
    Object.keys(CYCLES).forEach(cy => {
        const grille = appData.ecole.matieres[cy];
        if (!Array.isArray(grille) || grille.length === 0) {
            appData.ecole.matieres[cy] = JSON.parse(JSON.stringify(ECOLE_MATIERES_PAR_CYCLE[cy] || []));
        }
    });
    // Emplois du temps : { classeId: { 'Jour|Créneau': { matiereCode, profId } } }
    if (!appData.ecole.emplois) appData.ecole.emplois = {};
    // Appel : { classeId: { 'AAAA-MM-JJ': { eleveId: 'A' (absent) | 'R' (retard) } } }
    // Un élève sans entrée est considéré présent.
    if (!appData.ecole.presences) appData.ecole.presences = {};
    return appData.ecole;
}

function ecoleUid(prefix) {
    return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function formatDateNaissanceFR(iso) {
    // 'AAAA-MM-JJ' (input date) -> 'JJ/MM/AAAA'
    if (!iso || !/^\d{4}-\d{2}-\d{2}$/.test(iso)) return '—';
    return iso.split('-').reverse().join('/');
}

// ---------- Avatars (initiales colorées, façon CRM) ----------
const CRM_AVATAR_COLORS = ['#8d7a4e', '#5a6b4a', '#6b4a5a', '#4a5a6b', '#7a5a3e', '#4e6b62', '#6b5e4a', '#54486b'];

function crmAvatarColor(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
    return CRM_AVATAR_COLORS[h % CRM_AVATAR_COLORS.length];
}

function crmAvatar(prenom, nom, size) {
    const initiales = ((prenom || ' ')[0] + (nom || ' ')[0]).toUpperCase();
    const color = crmAvatarColor((prenom || '') + (nom || ''));
    return `<span class="crm-avatar${size ? ' ' + size : ''}" style="background:${color}">${Security.escapeHTML(initiales)}</span>`;
}

// ---------- Page École (vue d'ensemble CRM) ----------
function renderEcolePage() {
    const ec = getEcoleData();
    document.getElementById('ecoleNom').value = ec.infos.nom || '';
    document.getElementById('ecoleTel').value = ec.infos.telephone || '';
    document.getElementById('ecoleEmail').value = ec.infos.email || '';
    document.getElementById('ecoleAdresse').value = ec.infos.adresse || '';
    document.getElementById('ecoleBP').value = ec.infos.bp || '';
    document.getElementById('ecoleDevise').value = ec.infos.devise || '';
    document.getElementById('dirDirecteur').value = ec.direction.directeur || '';
    document.getElementById('dirDirecteurElementaire').value = ec.direction.directeurElementaire || '';
    document.getElementById('dirPrefetMoyen').value = ec.direction.prefetMoyen || '';
    document.getElementById('dirPrefetSecondaire').value = ec.direction.prefetSecondaire || '';
    const totalEleves = ec.classes.reduce((s, c) => s + c.eleves.length, 0);
    const elevesCycle = cy => ec.classes.filter(c => cycleOfNiveau(c.niveau) === cy).reduce((s, c) => s + c.eleves.length, 0);
    const nbPerm = ec.professeurs.filter(p => (p.statut || 'Permanent') === 'Permanent').length;
    const nbVac = ec.professeurs.length - nbPerm;
    document.getElementById('ecoleStats').innerHTML = `
        <div class="stat-card blue"><div class="number">${ec.classes.length}</div><div class="label">Classes</div></div>
        <div class="stat-card green"><div class="number">${totalEleves}</div><div class="label">Élèves</div></div>
        ${Object.keys(CYCLES).map(cy =>
            `<div class="stat-card blue"><div class="number">${elevesCycle(cy)}</div><div class="label">${CYCLES[cy].label} (${CYCLES[cy].sub})</div></div>`
        ).join('')}
        <div class="stat-card orange"><div class="number">${ec.professeurs.length}</div><div class="label">Professeurs</div><div class="pct">${nbPerm} perm. · ${nbVac} vac.</div></div>`;
    renderEcoleNiveaux(ec);
    renderEcoleActivite();
}

function saveDirection() {
    const ec = getEcoleData();
    ec.direction.directeur = document.getElementById('dirDirecteur').value.trim();
    ec.direction.directeurElementaire = document.getElementById('dirDirecteurElementaire').value.trim();
    ec.direction.prefetMoyen = document.getElementById('dirPrefetMoyen').value.trim();
    ec.direction.prefetSecondaire = document.getElementById('dirPrefetSecondaire').value.trim();
    saveData();
    logActivity('Direction de l\'école mise à jour', 'config');
    toast('Direction sauvegardée.', 'success');
}

function renderEcoleNiveaux(ec) {
    const box = document.getElementById('ecoleNiveaux');
    const esc = Security.escapeHTML;
    if (ec.classes.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucune classe pour le moment.</p></div>';
        return;
    }
    const max = Math.max(...CLASSE_NIVEAUX.map(niv =>
        ec.classes.filter(c => c.niveau === niv).reduce((s, c) => s + c.eleves.length, 0)), 1);
    let html = '';
    Object.keys(CYCLES).forEach(cy => {
        const cycle = CYCLES[cy];
        const counts = cycle.niveaux.map(niv => {
            const classes = ec.classes.filter(c => c.niveau === niv);
            return { niv: niv, classes: classes.length, eleves: classes.reduce((s, c) => s + c.eleves.length, 0) };
        }).filter(x => x.classes > 0);
        if (counts.length === 0) return;
        const totalCycle = counts.reduce((s, x) => s + x.eleves, 0);
        html += `<div class="crm-bar-group-title">${cycle.label} <span>${totalCycle} élève(s)</span></div>`;
        html += counts.map(x => `
            <div class="crm-bar-row">
                <span class="crm-bar-label">${esc(x.niv)}</span>
                <div class="crm-bar-track"><div class="crm-bar-fill" style="width:${Math.max(4, Math.round(x.eleves / max * 100))}%"></div></div>
                <span class="crm-bar-value">${x.eleves} élève(s) · ${x.classes} classe(s)</span>
            </div>`).join('');
    });
    box.innerHTML = html;
}

// Mots-clés des messages du journal qui concernent le module École
const ECOLE_LOG_RX = /classe|élève (ajouté|modifié|supprimé)|professeur|école/i;

function renderEcoleActivite() {
    const box = document.getElementById('ecoleActivite');
    const logs = getActivityLog().filter(l => ECOLE_LOG_RX.test(l.message)).slice(0, 8);
    if (logs.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucune activité pour le moment.</p></div>';
        return;
    }
    box.innerHTML = '<div class="crm-activity">' + logs.map(l => `
        <div class="crm-activity-item">
            <span class="crm-activity-dot"></span>
            <div>
                <div class="crm-activity-msg">${Security.escapeHTML(l.message)}</div>
                <div class="crm-activity-time">${formatLogDate(l.date)}</div>
            </div>
        </div>`).join('') + '</div>';
}

function saveEcoleInfos() {
    const ec = getEcoleData();
    ec.infos.nom = document.getElementById('ecoleNom').value.trim();
    ec.infos.telephone = document.getElementById('ecoleTel').value.trim();
    ec.infos.email = document.getElementById('ecoleEmail').value.trim();
    ec.infos.adresse = document.getElementById('ecoleAdresse').value.trim();
    ec.infos.bp = document.getElementById('ecoleBP').value.trim();
    ec.infos.devise = document.getElementById('ecoleDevise').value.trim();
    saveData();
    logActivity('Informations de l\'école mises à jour', 'config');
    toast('Informations de l\'école sauvegardées.', 'success');
}

// ---------- Classes ----------
// null = liste des classes ; id = fiche détaillée d'une classe (ses élèves)
let currentClasseId = null;

function renderClassesPage() {
    const ec = getEcoleData();
    const classe = currentClasseId ? ec.classes.find(c => c.id === currentClasseId) : null;
    if (classe && classeNotesMode) { renderClasseNotes(classe); return; }
    if (classe) { renderClasseDetail(classe); return; }
    currentClasseId = null;
    document.getElementById('classesTitle').textContent = 'Gestion des Classes';
    const esc = Security.escapeHTML;
    let html = `<div class="btn-group no-print">
        <button class="btn btn-primary" onclick="showAddClasseModal()">+ Ajouter une classe</button>
        <button class="btn btn-success" onclick="showAddEleveModal()">+ Inscrire un élève</button>
        <button class="btn btn-info" onclick="openPassageModal()">Passage de classe</button>
    </div>`;
    if (ec.preinscriptions.length > 0) {
        html += `<div class="alert alert-warning"><strong>${ec.preinscriptions.length}</strong> inscription(s) en attente de validation par la comptabilité.
            <a href="#" onclick="showPage('inscriptions'); return false;">Voir les inscriptions</a></div>`;
    }
    if (ec.classes.length === 0) {
        html += '<div class="empty-state"><p>Aucune classe pour le moment. Cliquez sur « + Ajouter une classe » : elle sera automatiquement rangée dans son cycle (Élémentaire, Moyen ou Secondaire).</p></div>';
    } else {
        // Les classes se structurent automatiquement par cycle, chacun géré par son préfet
        Object.keys(CYCLES).forEach(cy => {
            const cycle = CYCLES[cy];
            const classesCycle = ec.classes
                .filter(c => cycleOfNiveau(c.niveau) === cy)
                .sort((a, b) => (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
            const totalEleves = classesCycle.reduce((s, c) => s + c.eleves.length, 0);
            const prefet = chefOfCycle(ec, cy);
            html += `<div class="cycle-section">
                <div class="cycle-head">
                    <div>
                        <h3>${cycle.label} <span class="cycle-sub">${cycle.sub}</span></h3>
                        <div class="cycle-prefet">${esc(cycle.chefLabel)} : ${prefet ? '<strong>' + esc(prefet) + '</strong>' : '<em>non renseigné</em>'}</div>
                    </div>
                    <div class="cycle-counts">${classesCycle.length} classe(s) · ${totalEleves} élève(s)</div>
                </div>`;
            if (classesCycle.length === 0) {
                html += '<div class="empty-state" style="padding:14px;"><p>Aucune classe dans ce cycle.</p></div>';
            } else {
                html += '<div class="config-grid">';
                classesCycle.forEach(c => {
                    const prof = ec.professeurs.find(p => p.id === c.profId);
                    const stack = c.eleves.slice(0, 5).map(e => crmAvatar(e.prenom, e.nom)).join('')
                        + (c.eleves.length > 5 ? `<span class="crm-avatar crm-avatar-more">+${c.eleves.length - 5}</span>` : '');
                    html += `<div class="classe-card" onclick="openClasseDetail('${c.id}')">
                        <div class="classe-card-head">
                            <h3>${esc(c.nom)}</h3>
                            <span class="classe-niveau-badge">${esc(c.niveau)}</span>
                        </div>
                        <p class="classe-card-info">
                            <strong>${c.eleves.length}</strong> élève(s)
                            ${prof ? '<br>Prof. principal : ' + esc(prof.prenom + ' ' + prof.nom) : ''}
                        </p>
                        ${stack ? '<div class="crm-avatar-stack">' + stack + '</div>' : ''}
                        <div class="btn-group no-print" onclick="event.stopPropagation()">
                            <button class="btn btn-sm btn-info" onclick="openClasseDetail('${c.id}')">Gérer les élèves</button>
                            <button class="btn btn-sm btn-outline" onclick="editClasse('${c.id}')">Modifier</button>
                            <button class="btn btn-sm btn-danger" onclick="confirmDeleteClasse('${c.id}')">Supprimer</button>
                        </div>
                    </div>`;
                });
                html += '</div>';
            }
            html += '</div>';
        });
    }
    document.getElementById('classesContent').innerHTML = html;
}

function renderClasseDetail(classe) {
    const ec = getEcoleData();
    document.getElementById('classesTitle').textContent = 'Classe : ' + classe.nom;
    const prof = ec.professeurs.find(p => p.id === classe.profId);
    const nbF = classe.eleves.filter(e => e.sexe === 'F').length;
    let html = `
        <div class="btn-group no-print">
            <button class="btn btn-outline" onclick="closeClasseDetail()">&larr; Toutes les classes</button>
            <button class="btn btn-primary" onclick="showAddEleveModal('${classe.id}')">+ Inscrire un élève</button>
            <button class="btn btn-info" onclick="openClasseNotes('${classe.id}')">Notes de la classe</button>
            <button class="btn btn-warning" onclick="genererBulletinsClasse('${classe.id}')">Générer les bulletins</button>
            <button class="btn btn-primary" onclick="genererCartesClasse('${classe.id}')">Cartes d'élèves (QR)</button>
        </div>
        <div class="alert alert-info">
            Niveau : <strong>${Security.escapeHTML(classe.niveau)}</strong>
            ${prof ? ' — Prof. principal : <strong>' + Security.escapeHTML(prof.prenom + ' ' + prof.nom) + '</strong>' : ''}
            — <strong>${classe.eleves.length}</strong> élève(s) (${classe.eleves.length - nbF} garçon(s), ${nbF} fille(s))
        </div>`;
    if (classe.eleves.length === 0) {
        html += '<div class="empty-state"><p>Aucun élève dans cette classe. Cliquez sur « + Ajouter un élève ».</p></div>';
    } else {
        html += `<div class="table-wrapper"><table>
            <thead><tr><th>#</th><th>Élève</th><th>Sexe</th><th>Date de naissance</th><th>Tél. tuteur</th><th class="no-print">Actions</th></tr></thead><tbody>`;
        classe.eleves.forEach((e, i) => {
            html += `<tr class="crm-row" onclick="openEleveFiche('${classe.id}', ${i})" title="Voir la fiche">
                <td>${i + 1}</td>
                <td><span class="crm-name-cell">${crmAvatar(e.prenom, e.nom)}<span>${Security.escapeHTML(e.prenom)} <strong>${Security.escapeHTML(e.nom)}</strong></span></span></td>
                <td>${e.sexe === 'F' ? 'Fille' : 'Garçon'}</td>
                <td>${formatDateNaissanceFR(e.dateNaissance)}</td>
                <td>${Security.escapeHTML(e.telephone || '—')}</td>
                <td class="no-print" onclick="event.stopPropagation()">
                    <button class="btn btn-sm btn-info" onclick="editEleve('${classe.id}', ${i})">Modifier</button>
                    <button class="btn btn-sm btn-danger" onclick="confirmDeleteEleve('${classe.id}', ${i})">Supprimer</button>
                </td>
            </tr>`;
        });
        html += '</tbody></table></div>';
    }
    document.getElementById('classesContent').innerHTML = html;
}

function openClasseDetail(id) { currentClasseId = id; classeNotesMode = false; renderClassesPage(); }
function closeClasseDetail() { currentClasseId = null; classeNotesMode = false; renderClassesPage(); }

function populateClasseProfSelect(selectedId) {
    const ec = getEcoleData();
    const sel = document.getElementById('classeProf');
    sel.innerHTML = '<option value="">— Aucun —</option>';
    ec.professeurs.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = p.prenom + ' ' + p.nom;
        if (p.id === selectedId) opt.selected = true;
        sel.appendChild(opt);
    });
}

function showAddClasseModal() {
    document.getElementById('classeModalTitle').textContent = 'Ajouter une classe';
    document.getElementById('editClasseId').value = '';
    document.getElementById('classeNom').value = '';
    document.getElementById('classeNiveau').value = '6ème';
    populateClasseProfSelect('');
    document.getElementById('classeModal').classList.add('show');
}

function editClasse(id) {
    const c = getEcoleData().classes.find(c => c.id === id);
    if (!c) return;
    document.getElementById('classeModalTitle').textContent = 'Modifier la classe';
    document.getElementById('editClasseId').value = c.id;
    document.getElementById('classeNom').value = c.nom;
    document.getElementById('classeNiveau').value = c.niveau;
    populateClasseProfSelect(c.profId || '');
    document.getElementById('classeModal').classList.add('show');
}

function saveClasse() {
    const ec = getEcoleData();
    const id = document.getElementById('editClasseId').value;
    const nom = document.getElementById('classeNom').value.trim();
    if (!nom) { toast('Le nom de la classe est requis.', 'warning'); return; }
    if (ec.classes.some(c => c.id !== id && c.nom.toLowerCase() === nom.toLowerCase())) {
        toast('Une classe porte déjà ce nom.', 'warning'); return;
    }
    const niveau = document.getElementById('classeNiveau').value;
    const profId = document.getElementById('classeProf').value;
    if (id) {
        const c = ec.classes.find(c => c.id === id);
        if (!c) return;
        c.nom = nom; c.niveau = niveau; c.profId = profId;
        logActivity('Classe modifiée : ' + nom, 'config');
        toast('Classe modifiée.', 'success');
    } else {
        ec.classes.push({ id: ecoleUid('cl_'), nom: nom, niveau: niveau, profId: profId, eleves: [] });
        logActivity('Classe créée : ' + nom, 'config');
        toast('Classe ajoutée.', 'success');
    }
    saveData();
    closeModal('classeModal');
    renderClassesPage();
}

function confirmDeleteClasse(id) {
    const ec = getEcoleData();
    const c = ec.classes.find(c => c.id === id);
    if (!c) return;
    showConfirm('Supprimer la classe', `Supprimer la classe « ${c.nom} » et ses ${c.eleves.length} élève(s) ? Cette action est irréversible.`, () => {
        ec.classes = ec.classes.filter(x => x.id !== id);
        // La classe supprimée ne doit plus apparaître chez les professeurs ni dans les EDT
        ec.professeurs.forEach(p => { p.classes = (p.classes || []).filter(cid => cid !== id); });
        delete ec.emplois[id];
        if (currentClasseId === id) currentClasseId = null;
        saveData();
        logActivity('Classe supprimée : ' + c.nom, 'config');
        toast('Classe supprimée.', 'success');
        renderClassesPage();
    });
}

// ---------- Élèves d'une classe ----------
let selectedEleveSexe = 'M';
function selectEleveSexe(s) {
    selectedEleveSexe = s;
    document.querySelectorAll('#eleveSexeToggle .btn-sexe').forEach(b => b.classList.toggle('active', b.dataset.sexe === s));
}

// Remplit le sélecteur de classe du modal élève (groupé par cycle)
function populateEleveClasseSelect(selectedId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('eleveClasse');
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const classesCycle = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (classesCycle.length === 0) return '';
        return `<optgroup label="${CYCLES[cy].label} (${CYCLES[cy].sub})">`
            + classesCycle.map(c => `<option value="${c.id}">${esc(c.nom)} — ${esc(c.niveau)}</option>`).join('')
            + '</optgroup>';
    }).join('');
    if (selectedId && ec.classes.some(c => c.id === selectedId)) sel.value = selectedId;
}

// classeId facultatif : sans lui, c'est une inscription "globale" où l'on
// choisit la classe dans le formulaire (selon l'inscription de l'élève).
function showAddEleveModal(classeId) {
    const ec = getEcoleData();
    if (ec.classes.length === 0) {
        toast('Créez d\'abord une classe avant d\'inscrire un élève.', 'warning');
        return;
    }
    document.getElementById('eleveModalTitle').textContent = 'Inscrire un élève';
    document.getElementById('eleveClasseId').value = classeId || '';
    document.getElementById('editEleveIdx').value = '-1';
    document.getElementById('editPreinscriptionId').value = '';
    populateEleveClasseSelect(classeId || '');
    document.getElementById('elevePrenom').value = '';
    document.getElementById('eleveNom').value = '';
    document.getElementById('eleveIEN').value = '';
    document.getElementById('eleveDateNaissance').value = '';
    document.getElementById('eleveTelTuteur').value = '';
    document.getElementById('eleveAdresse').value = '';
    selectEleveSexe('M');
    document.getElementById('eleveModal').classList.add('show');
}

function editEleve(classeId, idx) {
    const classe = getEcoleData().classes.find(c => c.id === classeId);
    const e = classe && classe.eleves[idx];
    if (!e) return;
    document.getElementById('eleveModalTitle').textContent = 'Modifier l\'élève';
    document.getElementById('eleveClasseId').value = classeId;
    document.getElementById('editEleveIdx').value = String(idx);
    document.getElementById('editPreinscriptionId').value = '';
    populateEleveClasseSelect(classeId);
    document.getElementById('elevePrenom').value = e.prenom;
    document.getElementById('eleveNom').value = e.nom;
    document.getElementById('eleveIEN').value = e.ien || '';
    document.getElementById('eleveDateNaissance').value = e.dateNaissance || '';
    document.getElementById('eleveTelTuteur').value = e.telephone || '';
    document.getElementById('eleveAdresse').value = e.adresse || '';
    selectEleveSexe(e.sexe === 'F' ? 'F' : 'M');
    closeCrmDrawer();
    document.getElementById('eleveModal').classList.add('show');
}

function saveEleve() {
    const ec = getEcoleData();
    // Classe d'inscription choisie dans le formulaire
    const targetClasse = ec.classes.find(c => c.id === document.getElementById('eleveClasse').value);
    if (!targetClasse) { toast('Choisissez une classe d\'inscription.', 'warning'); return; }
    // Classe d'origine (vide pour une nouvelle inscription globale)
    const origClasse = ec.classes.find(c => c.id === document.getElementById('eleveClasseId').value);
    const idx = parseInt(document.getElementById('editEleveIdx').value, 10);
    const prenom = document.getElementById('elevePrenom').value.trim();
    const nom = document.getElementById('eleveNom').value.trim();
    if (!prenom || !nom) { toast('Prénom et nom sont requis.', 'warning'); return; }
    const eleve = {
        prenom: prenom,
        nom: nom,
        // IEN : identifiant attribué par l'Inspection, l'application ne fait que le stocker.
        ien: document.getElementById('eleveIEN').value.trim(),
        sexe: selectedEleveSexe,
        dateNaissance: document.getElementById('eleveDateNaissance').value || '',
        telephone: document.getElementById('eleveTelTuteur').value.trim(),
        adresse: document.getElementById('eleveAdresse').value.trim()
    };
    const preId = document.getElementById('editPreinscriptionId').value;
    if (preId) {
        // Modification d'une inscription encore en attente
        const pre = ec.preinscriptions.find(p => p.id === preId);
        if (!pre) { closeModal('eleveModal'); return; }
        Object.assign(pre, eleve, { classeId: targetClasse.id });
        logActivity(`Inscription modifiée : ${prenom} ${nom} (${targetClasse.nom})`, 'config');
        toast('Inscription modifiée.', 'success');
    } else if (idx >= 0 && origClasse && origClasse.eleves[idx]) {
        // L'id (référence des paiements) et les notes internes (fiche CRM)
        // ne passent pas par ce modal : on les conserve.
        eleve.id = origClasse.eleves[idx].id || ecoleUid('el_');
        eleve.notes = origClasse.eleves[idx].notes || '';
        if (targetClasse.id === origClasse.id) {
            origClasse.eleves[idx] = eleve;
            logActivity(`Élève modifié en ${origClasse.nom} : ${prenom} ${nom}`, 'config');
            toast('Élève modifié.', 'success');
        } else {
            // Transfert : l'élève suit son inscription, ses paiements aussi
            origClasse.eleves.splice(idx, 1);
            targetClasse.eleves.push(eleve);
            getComptaData().paiements.forEach(p => { if (p.eleveId === eleve.id) p.classeId = targetClasse.id; });
            logActivity(`Élève transféré de ${origClasse.nom} vers ${targetClasse.nom} : ${prenom} ${nom}`, 'config');
            toast(`Élève transféré en ${targetClasse.nom}.`, 'success');
        }
        // Liste alphabétique canonique (même convention que le module Examens)
        targetClasse.eleves.sort((a, b) => (a.nom + ' ' + a.prenom).localeCompare(b.nom + ' ' + b.prenom, 'fr'));
    } else {
        // Nouvelle inscription : l'élève n'intègre PAS la classe tout de suite.
        // C'est la comptabilité qui l'affectera après encaissement du paiement.
        ec.preinscriptions.push(Object.assign({ id: ecoleUid('el_'), classeId: targetClasse.id, date: new Date().toISOString().slice(0, 10) }, eleve));
        logActivity(`Inscription en attente : ${prenom} ${nom} (${targetClasse.nom})`, 'config');
        toast('Inscription enregistrée — en attente de validation par la comptabilité.', 'info', 5000);
    }
    saveData();
    closeModal('eleveModal');
    updateInscriptionsBadge();
    if (currentPage === 'classes') renderClassesPage();
    if (currentPage === 'ecole') renderEcolePage();
    if (currentPage === 'inscriptions') renderInscriptionsPage();
}

function confirmDeleteEleve(classeId, idx) {
    const classe = getEcoleData().classes.find(c => c.id === classeId);
    const e = classe && classe.eleves[idx];
    if (!e) return;
    showConfirm('Supprimer l\'élève', `Supprimer ${e.prenom} ${e.nom} de la classe ${classe.nom} ?`, () => {
        closeCrmDrawer();
        classe.eleves.splice(idx, 1);
        saveData();
        logActivity(`Élève supprimé de ${classe.nom} : ${e.prenom} ${e.nom}`, 'config');
        toast('Élève supprimé.', 'success');
        renderClassesPage();
    });
}

// ---------- Professeurs ----------
// Statut d'un professeur (les anciens enregistrements n'en avaient pas)
function profStatut(p) { return p.statut === 'Vacataire' ? 'Vacataire' : 'Permanent'; }

// Filtre courant de la liste : 'tous' | 'Permanent' | 'Vacataire'
let profStatutFilter = 'tous';

function setProfStatutFilter(f, btnEl) {
    profStatutFilter = f;
    document.querySelectorAll('#profsStatutTabs button').forEach(b => b.classList.remove('active'));
    if (btnEl) btnEl.classList.add('active');
    renderProfsTable();
}

function renderProfsTable() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const q = (document.getElementById('profSearch').value || '').toLowerCase();
    const nbPerm = ec.professeurs.filter(p => profStatut(p) === 'Permanent').length;
    document.getElementById('profCount').textContent = ec.professeurs.length;
    document.getElementById('profCountDetail').textContent =
        `${nbPerm} permanent(s), ${ec.professeurs.length - nbPerm} vacataire(s)`;
    const profs = ec.professeurs.filter(p =>
        (profStatutFilter === 'tous' || profStatut(p) === profStatutFilter) &&
        (!q || (p.prenom + ' ' + p.nom + ' ' + (p.matiere || '')).toLowerCase().includes(q)));
    const tbody = document.querySelector('#profsTable tbody');
    if (profs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-secondary);">Aucun professeur.</td></tr>';
        return;
    }
    tbody.innerHTML = profs.map(p => {
        const classesNoms = (p.classes || [])
            .map(cid => { const c = ec.classes.find(c => c.id === cid); return c ? c.nom : null; })
            .filter(Boolean);
        const st = profStatut(p);
        return `<tr class="crm-row" onclick="openProfFiche('${p.id}')" title="Voir la fiche">
            <td><span class="crm-name-cell">${crmAvatar(p.prenom, p.nom)}<span>${esc(p.prenom)}</span></span></td>
            <td><strong>${esc(p.nom)}</strong></td>
            <td>${esc(p.matiere || '—')}</td>
            <td><span class="statut-badge ${st === 'Permanent' ? 'permanent' : 'vacataire'}">${st}</span></td>
            <td>${esc(p.telephone || '—')}</td>
            <td>${esc(p.email || '—')}</td>
            <td>${classesNoms.length ? classesNoms.map(n => '<span class="classe-chip">' + esc(n) + '</span>').join(' ') : '—'}</td>
            <td class="no-print" onclick="event.stopPropagation()">
                <button class="btn btn-sm btn-info" onclick="editProf('${p.id}')">Modifier</button>
                <button class="btn btn-sm btn-danger" onclick="confirmDeleteProf('${p.id}')">Supprimer</button>
            </td>
        </tr>`;
    }).join('');
}

const _debouncedProfSearch = debounce(renderProfsTable, 150);
function onProfSearchInput() { _debouncedProfSearch(); }

function populateProfClassesChecks(selectedIds) {
    const ec = getEcoleData();
    const box = document.getElementById('profClassesChecks');
    if (ec.classes.length === 0) {
        box.innerHTML = '<span style="color:var(--text-secondary); font-size:0.85em;">Aucune classe créée pour le moment.</span>';
        return;
    }
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    box.innerHTML = tri.map(c =>
        `<label class="prof-classe-check"><input type="checkbox" value="${c.id}"${selectedIds.includes(c.id) ? ' checked' : ''}> ${Security.escapeHTML(c.nom)}</label>`
    ).join('');
}

// Permanent -> volume d'heures fixé ; Vacataire -> grille de disponibilités
function toggleProfStatutFields() {
    const vacataire = document.getElementById('profStatut').value === 'Vacataire';
    document.getElementById('profHeuresGroup').style.display = vacataire ? 'none' : '';
    document.getElementById('profDispoGroup').style.display = vacataire ? '' : 'none';
}

function renderProfDispoGrid(selected) {
    const box = document.getElementById('profDispoGrid');
    let html = '<table class="dispo-table"><thead><tr><th></th>' +
        EDT_JOURS.map(j => `<th>${j.slice(0, 3)}</th>`).join('') + '</tr></thead><tbody>';
    EDT_CRENEAUX.forEach(cr => {
        html += `<tr><td class="dispo-creneau">${cr}</td>`;
        EDT_JOURS.forEach(j => {
            const k = edtKey(j, cr);
            html += `<td><input type="checkbox" class="dispo-check" value="${k}"${selected.includes(k) ? ' checked' : ''} title="${j} ${cr}"></td>`;
        });
        html += '</tr>';
    });
    box.innerHTML = html + '</tbody></table>';
}

function showAddProfModal() {
    document.getElementById('profModalTitle').textContent = 'Ajouter un professeur';
    document.getElementById('editProfId').value = '';
    document.getElementById('profPrenom').value = '';
    document.getElementById('profNom').value = '';
    document.getElementById('profMatiere').value = '';
    document.getElementById('profStatut').value = 'Permanent';
    document.getElementById('profHeures').value = '';
    renderProfDispoGrid([]);
    toggleProfStatutFields();
    document.getElementById('profTel').value = '';
    document.getElementById('profEmail').value = '';
    populateProfClassesChecks([]);
    document.getElementById('profModal').classList.add('show');
}

function editProf(id) {
    const p = getEcoleData().professeurs.find(p => p.id === id);
    if (!p) return;
    document.getElementById('profModalTitle').textContent = 'Modifier le professeur';
    document.getElementById('editProfId').value = p.id;
    document.getElementById('profPrenom').value = p.prenom;
    document.getElementById('profNom').value = p.nom;
    document.getElementById('profMatiere').value = p.matiere || '';
    document.getElementById('profStatut').value = profStatut(p);
    document.getElementById('profHeures').value = p.heuresSemaine || '';
    renderProfDispoGrid(p.disponibilites || []);
    toggleProfStatutFields();
    document.getElementById('profTel').value = p.telephone || '';
    document.getElementById('profEmail').value = p.email || '';
    populateProfClassesChecks(p.classes || []);
    closeCrmDrawer();
    document.getElementById('profModal').classList.add('show');
}

function saveProf() {
    const ec = getEcoleData();
    const id = document.getElementById('editProfId').value;
    const prenom = document.getElementById('profPrenom').value.trim();
    const nom = document.getElementById('profNom').value.trim();
    if (!prenom || !nom) { toast('Prénom et nom sont requis.', 'warning'); return; }
    const classes = Array.from(document.querySelectorAll('#profClassesChecks input:checked')).map(i => i.value);
    const data = {
        prenom: prenom,
        nom: nom,
        matiere: document.getElementById('profMatiere').value.trim(),
        statut: document.getElementById('profStatut').value,
        telephone: document.getElementById('profTel').value.trim(),
        email: document.getElementById('profEmail').value.trim(),
        classes: classes,
        heuresSemaine: Math.max(0, parseInt(document.getElementById('profHeures').value, 10) || 0),
        disponibilites: Array.from(document.querySelectorAll('#profDispoGrid .dispo-check:checked')).map(c => c.value)
    };
    if (id) {
        const p = ec.professeurs.find(p => p.id === id);
        if (!p) return;
        Object.assign(p, data);
        logActivity(`Professeur modifié : ${prenom} ${nom}`, 'config');
        toast('Professeur modifié.', 'success');
    } else {
        ec.professeurs.push(Object.assign({ id: ecoleUid('pr_') }, data));
        logActivity(`Professeur ajouté : ${prenom} ${nom}`, 'config');
        toast('Professeur ajouté.', 'success');
    }
    ec.professeurs.sort((a, b) => (a.nom + ' ' + a.prenom).localeCompare(b.nom + ' ' + b.prenom, 'fr'));
    saveData();
    closeModal('profModal');
    renderProfsTable();
}

function confirmDeleteProf(id) {
    const ec = getEcoleData();
    const p = ec.professeurs.find(p => p.id === id);
    if (!p) return;
    showConfirm('Supprimer le professeur', `Supprimer ${p.prenom} ${p.nom} ?`, () => {
        closeCrmDrawer();
        ec.professeurs = ec.professeurs.filter(x => x.id !== id);
        // Retire ce professeur des classes dont il était le prof principal et des EDT
        ec.classes.forEach(c => { if (c.profId === id) c.profId = ''; });
        Object.values(ec.emplois).forEach(grille => {
            Object.keys(grille).forEach(k => { if (grille[k] && grille[k].profId === id) delete grille[k]; });
        });
        saveData();
        logActivity(`Professeur supprimé : ${p.prenom} ${p.nom}`, 'config');
        toast('Professeur supprimé.', 'success');
        renderProfsTable();
    });
}

// ---------- Fiches CRM (panneau latéral) ----------
function openCrmDrawer(html) {
    document.getElementById('crmDrawerContent').innerHTML = html;
    document.getElementById('crmDrawer').classList.add('open');
    document.getElementById('crmDrawer').setAttribute('aria-hidden', 'false');
    document.getElementById('crmDrawerOverlay').classList.add('show');
}

function closeCrmDrawer() {
    const drawer = document.getElementById('crmDrawer');
    if (!drawer) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    document.getElementById('crmDrawerOverlay').classList.remove('show');
}

function crmInfoRow(label, value) {
    return `<div class="crm-info-row"><span class="crm-info-label">${label}</span><span class="crm-info-value">${value}</span></div>`;
}

function openEleveFiche(classeId, idx) {
    const ec = getEcoleData();
    const classe = ec.classes.find(c => c.id === classeId);
    const e = classe && classe.eleves[idx];
    if (!e) return;
    const esc = Security.escapeHTML;
    openCrmDrawer(`
        <div class="crm-fiche-head">
            ${crmAvatar(e.prenom, e.nom, 'xl')}
            <div>
                <h3>${esc(e.prenom)} ${esc(e.nom)}</h3>
                <div class="crm-badges">
                    <span class="classe-chip">${esc(classe.nom)}</span>
                    <span class="classe-chip">${e.sexe === 'F' ? 'Fille' : 'Garçon'}</span>
                </div>
            </div>
        </div>
        <div class="crm-section">
            <h4>Coordonnées</h4>
            ${crmInfoRow('Date de naissance', formatDateNaissanceFR(e.dateNaissance))}
            ${crmInfoRow('Tél. parent / tuteur', esc(e.telephone || '—'))}
            ${crmInfoRow('Adresse', esc(e.adresse || '—'))}
            ${crmInfoRow('Classe', esc(classe.nom + ' (' + classe.niveau + ')'))}
        </div>
        ${crmEleveScolariteHTML(e, classe, classeId, idx)}
        <div class="crm-section">
            <h4>Vie scolaire</h4>
            ${crmInfoRow('Absences (année)', '<strong>' + countPresences(classeId, e.id).abs + '</strong>')}
            ${crmInfoRow('Retards (année)', '<strong>' + countPresences(classeId, e.id).ret + '</strong>')}
        </div>
        <div class="crm-section">
            <h4>Notes internes</h4>
            <textarea id="crmNotesArea" rows="5" placeholder="Observations, suivi, remarques...">${esc(e.notes || '')}</textarea>
            <button class="btn btn-sm btn-success" style="margin-top:8px;" onclick="saveEleveNotes('${classeId}', ${idx})">Enregistrer les notes</button>
        </div>
        <div class="crm-fiche-actions">
            <button class="btn btn-primary" onclick="closeCrmDrawer(); genererCartesClasse('${classeId}', '${e.id}')">Carte QR</button>
            <button class="btn btn-info" onclick="editEleve('${classeId}', ${idx})">Modifier la fiche</button>
            <button class="btn btn-danger" onclick="confirmDeleteEleve('${classeId}', ${idx})">Supprimer</button>
        </div>`);
}

function saveEleveNotes(classeId, idx) {
    const classe = getEcoleData().classes.find(c => c.id === classeId);
    const e = classe && classe.eleves[idx];
    if (!e) return;
    e.notes = document.getElementById('crmNotesArea').value.trim();
    saveData();
    toast('Notes enregistrées.', 'success');
}

function openProfFiche(id) {
    const ec = getEcoleData();
    const p = ec.professeurs.find(p => p.id === id);
    if (!p) return;
    const esc = Security.escapeHTML;
    const classesNoms = (p.classes || [])
        .map(cid => { const c = ec.classes.find(c => c.id === cid); return c ? c.nom : null; })
        .filter(Boolean);
    const principalDe = ec.classes.filter(c => c.profId === id).map(c => c.nom);
    openCrmDrawer(`
        <div class="crm-fiche-head">
            ${crmAvatar(p.prenom, p.nom, 'xl')}
            <div>
                <h3>${esc(p.prenom)} ${esc(p.nom)}</h3>
                <div class="crm-badges">
                    <span class="classe-chip">${esc(p.matiere || 'Matière non renseignée')}</span>
                    <span class="statut-badge ${profStatut(p) === 'Permanent' ? 'permanent' : 'vacataire'}">${profStatut(p)}</span>
                </div>
            </div>
        </div>
        <div class="crm-section">
            <h4>Coordonnées</h4>
            ${crmInfoRow('Téléphone', esc(p.telephone || '—'))}
            ${crmInfoRow('Email', esc(p.email || '—'))}
        </div>
        <div class="crm-section">
            <h4>Classes</h4>
            ${crmInfoRow('Enseigne en', classesNoms.length ? classesNoms.map(n => '<span class="classe-chip">' + esc(n) + '</span>').join(' ') : '—')}
            ${crmInfoRow('Prof. principal de', principalDe.length ? principalDe.map(n => '<span class="classe-chip">' + esc(n) + '</span>').join(' ') : '—')}
        </div>
        <div class="crm-section">
            <h4>Emploi du temps</h4>
            ${crmInfoRow('Heures affectées', '<strong>' + countProfHeures(p.id) + ' h / semaine</strong>')}
            ${crmInfoRow('Heures fixées', p.heuresSemaine ? p.heuresSemaine + ' h / semaine' : '—')}
            ${profStatut(p) === 'Vacataire' ? crmInfoRow('Disponibilités', (p.disponibilites || []).length + ' créneau(x)') : ''}
        </div>
        <div class="crm-section">
            <h4>Notes internes</h4>
            <textarea id="crmNotesArea" rows="5" placeholder="Observations, suivi, remarques...">${esc(p.notes || '')}</textarea>
            <button class="btn btn-sm btn-success" style="margin-top:8px;" onclick="saveProfNotes('${id}')">Enregistrer les notes</button>
        </div>
        <div class="crm-fiche-actions">
            <button class="btn btn-info" onclick="editProf('${id}')">Modifier la fiche</button>
            <button class="btn btn-danger" onclick="confirmDeleteProf('${id}')">Supprimer</button>
        </div>`);
}

function saveProfNotes(id) {
    const p = getEcoleData().professeurs.find(p => p.id === id);
    if (!p) return;
    p.notes = document.getElementById('crmNotesArea').value.trim();
    saveData();
    toast('Notes enregistrées.', 'success');
}

// ---------- Notes de classe & bulletins scolaires ----------
// Vue "Notes" à l'intérieur d'une classe (false = fiche classe normale)
let classeNotesMode = false;
// Trimestre affiché / imprimé
let currentTrimestre = 't1';

function openClasseNotes(id) { currentClasseId = id; classeNotesMode = true; renderClassesPage(); }
function closeClasseNotes() { classeNotesMode = false; renderClassesPage(); }

function setTrimestre(t) { currentTrimestre = t; renderClassesPage(); }

// Notes du trimestre courant pour une classe : { eleveId: { codeMatiere: note } }
function getClasseNotes(classe) {
    if (!classe.notes) classe.notes = {};
    if (!classe.notes[currentTrimestre]) classe.notes[currentTrimestre] = {};
    return classe.notes[currentTrimestre];
}

// Notes d'un trimestre donné, indépendamment du trimestre affiché à l'écran
function notesTrimestre(classe, t) {
    if (!classe.notes) classe.notes = {};
    if (!classe.notes[t]) classe.notes[t] = {};
    return classe.notes[t];
}

// Moyenne pondérée d'un élève sur un trimestre (matières notées uniquement)
function moyenneEleveTrimestre(classe, eleveId, t) {
    const ec = getEcoleData();
    const notes = notesTrimestre(classe, t)[eleveId] || {};
    let pts = 0, coefs = 0;
    matieresOfClasse(ec, classe).forEach(m => {
        const n = parseFloat(notes[m.code]);
        if (!isNaN(n)) { pts += n * (m.coef || 1); coefs += (m.coef || 1); }
    });
    return coefs > 0 ? pts / coefs : null;
}

// Moyenne pondérée d'un élève (sur les matières notées uniquement)
function moyenneEleve(classe, eleveId) {
    return moyenneEleveTrimestre(classe, eleveId, currentTrimestre);
}

// Rang d'un élève dans sa classe pour un trimestre : { rang, sur } ou null
function rangEleveTrimestre(classe, eleveId, t) {
    const classes = classe.eleves
        .map(e => ({ id: e.id, moy: moyenneEleveTrimestre(classe, e.id, t) }))
        .filter(x => x.moy !== null)
        .sort((a, b) => b.moy - a.moy);
    const i = classes.findIndex(x => x.id === eleveId);
    return i < 0 ? null : { rang: i + 1, sur: classes.length };
}

function appreciationNote(n) {
    if (n >= 16) return 'Excellent';
    if (n >= 14) return 'Très Bien';
    if (n >= 12) return 'Bien';
    if (n >= 10) return 'Assez Bien';
    if (n >= 8) return 'Insuffisant';
    return 'Faible';
}

function renderClasseNotes(classe) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    document.getElementById('classesTitle').textContent = 'Notes — ' + classe.nom;
    const notes = getClasseNotes(classe);
    let html = `
        <div class="btn-group no-print">
            <button class="btn btn-outline" onclick="closeClasseNotes()">&larr; Fiche de la classe</button>
            <button class="btn btn-warning" onclick="genererBulletinsClasse('${classe.id}')">Générer les bulletins</button>
        </div>
        <div class="form-row no-print">
            <div class="form-group"><label>Trimestre</label>
                <select onchange="setTrimestre(this.value)" style="width:180px;">
                    ${Object.keys(TRIMESTRES).map(t => `<option value="${t}"${t === currentTrimestre ? ' selected' : ''}>${TRIMESTRES[t]}</option>`).join('')}
                </select>
            </div>
        </div>
        <div class="alert alert-info">Notes sur 20 — sauvegarde automatique. La moyenne est pondérée par les coefficients (modifiables dans Mon École).</div>`;
    html += notesTableHTML(classe);
    document.getElementById('classesContent').innerHTML = html;
}

// Table de saisie des notes d'une classe (partagée entre la vue Classes
// et la page Notes & Bulletins) pour le trimestre courant.
function notesTableHTML(classe) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    if (classe.eleves.length === 0) {
        return '<div class="empty-state"><p>Aucun élève dans cette classe.</p></div>';
    }
    const notes = getClasseNotes(classe);
    const mats = matieresOfClasse(ec, classe);
    let html = '<div class="table-wrapper"><table><thead><tr><th style="text-align:left;">Élève</th>';
    mats.forEach(m => { html += `<th title="${esc(m.nom)} (coef ${m.coef})">${esc(m.code)}</th>`; });
    html += '<th>Moyenne</th></tr></thead><tbody>';
    classe.eleves.forEach(e => {
        const en = notes[e.id] || {};
        html += `<tr><td style="text-align:left; white-space:nowrap;"><span class="crm-name-cell">${crmAvatar(e.prenom, e.nom)}<span>${esc(e.prenom)} <strong>${esc(e.nom)}</strong></span></span></td>`;
        mats.forEach(m => {
            const v = en[m.code] !== undefined ? en[m.code] : '';
            html += `<td><input type="number" class="ecole-note-input" min="0" max="20" step="0.25" value="${v}"
                onchange="setEcoleNote('${classe.id}', '${e.id}', '${m.code}', this.value)"></td>`;
        });
        const moy = moyenneEleve(classe, e.id);
        html += `<td class="ecole-moy-cell" id="moy-${e.id}"><strong>${moy !== null ? moy.toFixed(2) : '—'}</strong></td></tr>`;
    });
    return html + '</tbody></table></div>';
}

// ---------- Page Notes & Bulletins (menu École) ----------
function renderNotesBulletinsPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('nbClasseSelect');
    const selTrim = document.getElementById('nbTrimestreSelect');
    const content = document.getElementById('nbContent');
    selTrim.innerHTML = Object.keys(TRIMESTRES).map(t =>
        `<option value="${t}"${t === currentTrimestre ? ' selected' : ''}>${TRIMESTRES[t]}</option>`).join('');
    if (ec.classes.length === 0) {
        sel.innerHTML = '';
        content.innerHTML = '<div class="empty-state"><p>Créez d\'abord des classes et inscrivez des élèves.</p></div>';
        return;
    }
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    const prev = sel.value;
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const cls = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (cls.length === 0) return '';
        return `<optgroup label="${CYCLES[cy].label}">` +
            cls.map(c => `<option value="${c.id}">${esc(c.nom)} (${c.eleves.length} élève(s))</option>`).join('') + '</optgroup>';
    }).join('');
    if (prev && tri.some(c => c.id === prev)) sel.value = prev;
    const classe = ec.classes.find(c => c.id === sel.value) || tri[0];
    content.innerHTML = notesTableHTML(classe);
}

function genererBulletinsDepuisPage() {
    const cid = document.getElementById('nbClasseSelect').value;
    if (!cid) { toast('Créez d\'abord une classe.', 'warning'); return; }
    genererBulletinsClasse(cid);
}

function setEcoleNote(classeId, eleveId, code, value) {
    const classe = getEcoleData().classes.find(c => c.id === classeId);
    if (!classe) return;
    const notes = getClasseNotes(classe);
    if (!notes[eleveId]) notes[eleveId] = {};
    const n = parseFloat(value);
    if (value === '' || isNaN(n)) {
        delete notes[eleveId][code];
    } else {
        notes[eleveId][code] = Math.max(0, Math.min(20, n));
    }
    debouncedSave();
    const moy = moyenneEleve(classe, eleveId);
    const cell = document.getElementById('moy-' + eleveId);
    if (cell) cell.innerHTML = '<strong>' + (moy !== null ? moy.toFixed(2) : '—') + '</strong>';
}

function genererBulletinsClasse(classeId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    if (classe.eleves.length === 0) { toast('Aucun élève dans cette classe.', 'warning'); return; }
    // Classement de la classe sur le trimestre courant
    const moyennes = classe.eleves
        .map(e => ({ eleve: e, moy: moyenneEleve(classe, e.id) }))
        .filter(x => x.moy !== null)
        .sort((a, b) => b.moy - a.moy);
    if (moyennes.length === 0) {
        toast('Aucune note saisie pour ce trimestre. Saisissez d\'abord les notes de la classe.', 'warning');
        return;
    }
    const rangs = {};
    moyennes.forEach((x, i) => { rangs[x.eleve.id] = i + 1; });
    const cycleClasse = cycleOfNiveau(classe.niveau);
    const prefet = chefOfCycle(ec, cycleClasse);
    // « Le Préfet » au moyen/secondaire, « Le Directeur d'école » à l'élémentaire.
    const prefetTitre = 'Le ' + CYCLES[cycleClasse].chefLabel.toLowerCase();
    const notes = getClasseNotes(classe);
    let html = '';
    classe.eleves.forEach((e, idx) => {
        const en = notes[e.id] || {};
        const moy = moyenneEleve(classe, e.id);
        html += `<div class="bulletin-page" ${idx > 0 ? 'style="page-break-before:always; margin-top:30px;"' : ''}>`;
        html += docHeader('BULLETIN DE NOTES', `Année scolaire ${appData.year} — ${esc(classe.nom)} — ${TRIMESTRES[currentTrimestre]}`);
        html += `<div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; margin-bottom:12px; padding:10px; background:#f5efe8; border-radius:8px;">
            <div><b>Nom :</b> ${esc(e.nom)}</div>
            <div><b>Prénom(s) :</b> ${esc(e.prenom)}</div>
            <div><b>Sexe :</b> ${e.sexe === 'F' ? 'F' : 'M'}</div>
            <div><b>Né(e) le :</b> ${formatDateNaissanceFR(e.dateNaissance)}</div>
            <div><b>Effectif :</b> ${classe.eleves.length}</div>
        </div>`;
        html += `<table><thead><tr><th style="text-align:left;">Matière</th><th>Coef</th><th>Note /20</th><th>Note × Coef</th><th>Appréciation</th></tr></thead><tbody>`;
        let totalPts = 0, totalCoefs = 0;
        matieresOfClasse(ec, classe).forEach(m => {
            const n = parseFloat(en[m.code]);
            if (isNaN(n)) {
                html += `<tr><td style="text-align:left;">${esc(m.nom)}</td><td>${m.coef}</td><td>—</td><td>—</td><td>—</td></tr>`;
            } else {
                totalPts += n * (m.coef || 1);
                totalCoefs += (m.coef || 1);
                html += `<tr><td style="text-align:left;">${esc(m.nom)}</td><td>${m.coef}</td><td>${n.toFixed(2)}</td><td>${(n * (m.coef || 1)).toFixed(2)}</td><td>${appreciationNote(n)}</td></tr>`;
            }
        });
        html += `</tbody></table>`;
        const pres = countPresences(classe.id, e.id);
        html += `<div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; margin-top:12px; padding:12px; background:#f5efe8; border-radius:8px; font-weight:700;">
            <div>Total : ${totalPts.toFixed(2)} / ${totalCoefs * 20}</div>
            <div>Moyenne : ${moy !== null ? moy.toFixed(2) : '—'} / 20</div>
            <div>Rang : ${rangs[e.id] ? rangs[e.id] + ' / ' + moyennes.length : '—'}</div>
            <div>${moy !== null ? appreciationNote(moy) : ''}</div>
        </div>
        <div style="margin-top:8px; padding:8px 12px; background:#faf8f5; border-radius:8px; font-size:0.9em;">
            Assiduité : <b>${pres.abs}</b> absence(s) — <b>${pres.ret}</b> retard(s)
        </div>`;
        html += `<div style="display:flex; justify-content:space-between; margin-top:28px; padding:0 20px; font-size:0.9em;">
            <div style="text-align:center;">${esc(prefetTitre)}<br><br><br>${prefet ? '<b>' + esc(prefet) + '</b>' : ''}</div>
            <div style="text-align:center;">Le Directeur<br><br><br>${ec.direction.directeur ? '<b>' + esc(ec.direction.directeur) + '</b>' : ''}</div>
        </div>`;
        html += `</div>`;
    });
    document.getElementById('printModalTitle').textContent = `Bulletins ${classe.nom} — ${TRIMESTRES[currentTrimestre]}`;
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity(`Bulletins générés : ${classe.nom} (${TRIMESTRES[currentTrimestre]})`, 'export');
}

// ---------- Emplois du temps ----------
// Heures hebdomadaires affectées à un prof, toutes classes confondues
function countProfHeures(profId) {
    const ec = getEcoleData();
    let n = 0;
    Object.values(ec.emplois).forEach(grille => {
        Object.values(grille).forEach(slot => { if (slot && slot.profId === profId) n++; });
    });
    return n;
}

// La classe (autre que classeId) où le prof est déjà occupé sur ce créneau, sinon null
function profOccupeAilleurs(profId, key, classeId) {
    const ec = getEcoleData();
    for (const cid of Object.keys(ec.emplois)) {
        if (cid === classeId) continue;
        const slot = ec.emplois[cid][key];
        if (slot && slot.profId === profId) {
            const c = ec.classes.find(c => c.id === cid);
            return c ? c.nom : 'autre classe';
        }
    }
    return null;
}

function renderEmploiTempsPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('edtClasseSelect');
    const content = document.getElementById('edtContent');
    if (ec.classes.length === 0) {
        sel.innerHTML = '';
        content.innerHTML = '<div class="empty-state"><p>Créez d\'abord des classes dans le module École.</p></div>';
        renderEdtCharge();
        return;
    }
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    const prev = sel.value;
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const cls = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (cls.length === 0) return '';
        return `<optgroup label="${CYCLES[cy].label}">` +
            cls.map(c => `<option value="${c.id}">${esc(c.nom)}</option>`).join('') + '</optgroup>';
    }).join('');
    if (prev && tri.some(c => c.id === prev)) sel.value = prev;
    const classe = ec.classes.find(c => c.id === sel.value) || tri[0];
    if (!ec.emplois[classe.id]) ec.emplois[classe.id] = {};
    const grille = ec.emplois[classe.id];
    let html = `<div class="btn-group no-print">
        <button class="btn btn-info" onclick="imprimerEmploiTemps('${classe.id}')">Imprimer l'emploi du temps</button>
    </div>
    <div class="table-wrapper"><table class="edt-table"><thead><tr><th>Horaire</th>` +
        EDT_JOURS.map(j => `<th>${j}</th>`).join('') + '</tr></thead><tbody>';
    EDT_CRENEAUX.forEach(cr => {
        html += `<tr><td class="edt-horaire">${cr}</td>`;
        EDT_JOURS.forEach(j => {
            const k = edtKey(j, cr);
            const slot = grille[k];
            if (slot) {
                const mat = matieresOfClasse(ec, classe).find(m => m.code === slot.matiereCode);
                const prof = ec.professeurs.find(p => p.id === slot.profId);
                const couleur = crmAvatarColor(slot.matiereCode);
                html += `<td class="edt-cell edt-filled" onclick="openSlotModal('${classe.id}', '${j}', '${cr}')" title="Modifier ce créneau">
                    <span class="edt-matiere" style="background:${couleur}">${esc(mat ? mat.code : slot.matiereCode)}</span>
                    <span class="edt-prof">${prof ? esc(prof.prenom[0] + '. ' + prof.nom) : '—'}${prof && profStatut(prof) === 'Vacataire' ? ' <em>(vac.)</em>' : ''}</span>
                </td>`;
            } else {
                html += `<td class="edt-cell edt-empty" onclick="openSlotModal('${classe.id}', '${j}', '${cr}')" title="Affecter ce créneau">+</td>`;
            }
        });
        html += '</tr>';
    });
    content.innerHTML = html + '</tbody></table></div>';
    renderEdtCharge();
}

// Récapitulatif de la charge horaire de chaque professeur
function renderEdtCharge() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('edtChargeContent');
    if (ec.professeurs.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucun professeur enregistré.</p></div>';
        return;
    }
    box.innerHTML = `<div class="alert alert-info" style="font-size:0.85em;">Saisissez le nombre d'heures hebdomadaires de chaque professeur directement dans la colonne « Heures fixées ».</div>
    <div class="table-wrapper"><table>
        <thead><tr><th style="text-align:left;">Professeur</th><th>Statut</th><th>Heures affectées</th><th>Heures fixées / sem</th><th>Disponibilités</th><th>Situation</th></tr></thead><tbody>` +
        ec.professeurs.map(p => {
            const st = profStatut(p);
            const affectees = countProfHeures(p.id);
            const dispos = (p.disponibilites || []).length;
            let situation;
            if (p.heuresSemaine) {
                if (affectees > p.heuresSemaine) situation = '<span class="pay-badge none">Dépassement</span>';
                else if (affectees === p.heuresSemaine) situation = '<span class="pay-badge ok">Complet</span>';
                else situation = `<span class="pay-badge partial">${p.heuresSemaine - affectees} h restantes</span>`;
            } else if (st === 'Vacataire') {
                situation = dispos === 0 ? '<span class="pay-badge none">Aucune dispo</span>'
                    : `<span class="pay-badge ${affectees >= dispos ? 'ok' : 'partial'}">${affectees}/${dispos} créneau(x) utilisés</span>`;
            } else {
                situation = '<span class="pay-badge">Heures non fixées</span>';
            }
            return `<tr class="crm-row" onclick="openProfFiche('${p.id}')">
                <td><span class="crm-name-cell">${crmAvatar(p.prenom, p.nom)}<span>${esc(p.prenom)} <strong>${esc(p.nom)}</strong></span></span></td>
                <td><span class="statut-badge ${st === 'Permanent' ? 'permanent' : 'vacataire'}">${st}</span></td>
                <td style="text-align:center;"><strong>${affectees} h</strong></td>
                <td onclick="event.stopPropagation()">
                    <input type="number" class="edt-heures-input" min="0" max="40" value="${p.heuresSemaine || ''}"
                        placeholder="—" onchange="setProfHeures('${p.id}', this.value)"> h
                </td>
                <td>${st === 'Vacataire' ? dispos + ' créneau(x) coché(s)' : '—'}</td>
                <td>${situation}</td>
            </tr>`;
        }).join('') + '</tbody></table></div>';
}

// Fixe le volume d'heures hebdomadaire d'un professeur depuis la page EDT
function setProfHeures(profId, value) {
    const p = getEcoleData().professeurs.find(p => p.id === profId);
    if (!p) return;
    p.heuresSemaine = Math.max(0, parseInt(value, 10) || 0);
    saveData();
    logActivity(`Heures fixées pour ${p.prenom} ${p.nom} : ${p.heuresSemaine} h/semaine`, 'config');
    toast(`${p.prenom} ${p.nom} : ${p.heuresSemaine ? p.heuresSemaine + ' h/semaine fixées.' : 'heures effacées.'}`, 'success');
    renderEdtCharge();
}

function openSlotModal(classeId, jour, creneau) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    const k = edtKey(jour, creneau);
    const slot = (ec.emplois[classeId] || {})[k];
    document.getElementById('slotModalTitle').textContent = `${classe.nom} — ${jour} ${creneau}`;
    document.getElementById('slotClasseId').value = classeId;
    document.getElementById('slotJour').value = jour;
    document.getElementById('slotCreneau').value = creneau;
    document.getElementById('slotMatiere').innerHTML = matieresOfClasse(ec, classe).map(m =>
        `<option value="${esc(m.code)}"${slot && slot.matiereCode === m.code ? ' selected' : ''}>${esc(m.nom)}</option>`).join('');
    // Professeurs : les vacataires indisponibles et les profs déjà occupés sont désactivés
    const opts = ec.professeurs.map(p => {
        const st = profStatut(p);
        let label = p.prenom + ' ' + p.nom + (st === 'Vacataire' ? ' (vacataire)' : '');
        let disabled = '';
        if (st === 'Vacataire' && !(p.disponibilites || []).includes(k)) {
            label += ' — indisponible sur ce créneau'; disabled = ' disabled';
        } else {
            const ou = profOccupeAilleurs(p.id, k, classeId);
            if (ou) { label += ` — occupé (${ou})`; disabled = ' disabled'; }
            else if (st === 'Permanent' && p.heuresSemaine && countProfHeures(p.id) >= p.heuresSemaine && !(slot && slot.profId === p.id)) {
                label += ` — quota atteint (${p.heuresSemaine} h)`;
            }
        }
        return `<option value="${p.id}"${slot && slot.profId === p.id ? ' selected' : ''}${disabled}>${esc(label)}</option>`;
    });
    document.getElementById('slotProf').innerHTML = '<option value="">— Choisir un professeur —</option>' + opts.join('');
    document.getElementById('slotInfo').textContent = slot ? 'Ce créneau est déjà affecté : modifiez-le ou libérez-le.' : '';
    document.getElementById('slotModal').classList.add('show');
}

function saveSlot() {
    const ec = getEcoleData();
    const classeId = document.getElementById('slotClasseId').value;
    const k = edtKey(document.getElementById('slotJour').value, document.getElementById('slotCreneau').value);
    const profId = document.getElementById('slotProf').value;
    const matiereCode = document.getElementById('slotMatiere').value;
    if (!profId) { toast('Choisissez un professeur.', 'warning'); return; }
    const prof = ec.professeurs.find(p => p.id === profId);
    if (!prof) return;
    // Revalidation (la situation peut avoir changé depuis l'ouverture du modal)
    if (profStatut(prof) === 'Vacataire' && !(prof.disponibilites || []).includes(k)) {
        toast(`${prof.prenom} ${prof.nom} (vacataire) n'est pas disponible sur ce créneau.`, 'error', 5000);
        return;
    }
    const ou = profOccupeAilleurs(profId, k, classeId);
    if (ou) { toast(`${prof.prenom} ${prof.nom} est déjà occupé(e) sur ce créneau (${ou}).`, 'error', 5000); return; }
    if (!ec.emplois[classeId]) ec.emplois[classeId] = {};
    const dejaCeSlot = ec.emplois[classeId][k] && ec.emplois[classeId][k].profId === profId;
    if (profStatut(prof) === 'Permanent' && prof.heuresSemaine && !dejaCeSlot && countProfHeures(profId) >= prof.heuresSemaine) {
        toast(`Attention : ${prof.prenom} ${prof.nom} dépasse ses ${prof.heuresSemaine} h fixées.`, 'warning', 5000);
    }
    ec.emplois[classeId][k] = { matiereCode: matiereCode, profId: profId };
    saveData();
    logActivity(`EDT : ${k.replace('|', ' ')} affecté à ${prof.prenom} ${prof.nom} (${matiereCode})`, 'config');
    toast('Créneau affecté.', 'success');
    closeModal('slotModal');
    renderEmploiTempsPage();
}

function clearSlot() {
    const ec = getEcoleData();
    const classeId = document.getElementById('slotClasseId').value;
    const k = edtKey(document.getElementById('slotJour').value, document.getElementById('slotCreneau').value);
    if (ec.emplois[classeId]) delete ec.emplois[classeId][k];
    saveData();
    toast('Créneau libéré.', 'info');
    closeModal('slotModal');
    renderEmploiTempsPage();
}

function imprimerEmploiTemps(classeId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    const grille = ec.emplois[classeId] || {};
    let html = docHeader('EMPLOI DU TEMPS', `Année scolaire ${appData.year} — ${esc(classe.nom)} (${esc(classe.niveau)})`);
    html += '<table><thead><tr><th>Horaire</th>' + EDT_JOURS.map(j => `<th>${j}</th>`).join('') + '</tr></thead><tbody>';
    EDT_CRENEAUX.forEach(cr => {
        html += `<tr><td><b>${cr}</b></td>`;
        EDT_JOURS.forEach(j => {
            const slot = grille[edtKey(j, cr)];
            if (slot) {
                const mat = matieresOfClasse(ec, classe).find(m => m.code === slot.matiereCode);
                const prof = ec.professeurs.find(p => p.id === slot.profId);
                html += `<td style="text-align:center;"><b>${esc(mat ? mat.nom : slot.matiereCode)}</b><br><span style="font-size:0.85em;">${prof ? esc(prof.prenom[0] + '. ' + prof.nom) : ''}</span></td>`;
            } else {
                html += '<td></td>';
            }
        });
        html += '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('printModalTitle').textContent = `Emploi du temps — ${classe.nom}`;
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity(`Emploi du temps imprimé : ${classe.nom}`, 'export');
}

// ---------- Cartes d'élèves avec code QR ----------
// Matricule séquentiel et permanent, attribué à la première génération de carte
function ensureMatricule(eleve) {
    const ec = getEcoleData();
    if (!ec.prochainMatricule) ec.prochainMatricule = 1;
    if (!eleve.matricule) {
        const annee = String(appData.year || '').split('-')[0] || new Date().getFullYear();
        eleve.matricule = annee + '-' + String(ec.prochainMatricule++).padStart(4, '0');
    }
    return eleve.matricule;
}

// La bibliothèque qrcodejs calcule mal la capacité avec les caractères
// accentués (multi-octets UTF-8) : on encode le QR en ASCII sans accents.
function qrAscii(str) {
    return String(str).normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^\x20-\x7E\n]/g, '');
}

// Contenu du QR : identité complète, lisible par n'importe quel scanner
function carteQrTexte(eleve, classe) {
    const ecole = getEcoleData().infos.nom || appData.school.name || '';
    return qrAscii([
        ecole.toUpperCase(),
        'Matricule : ' + eleve.matricule,
        'Nom : ' + (eleve.nom || '').toUpperCase(),
        'Prenom(s) : ' + (eleve.prenom || ''),
        'Classe : ' + classe.nom + ' (' + classe.niveau + ')',
        'Ne(e) le : ' + (eleve.dateNaissance ? formatDateNaissanceFR(eleve.dateNaissance) : '-'),
        'Annee scolaire : ' + appData.year
    ].join('\n'));
}

// Génère les cartes de toute la classe (ou d'un seul élève si eleveId fourni)
function genererCartesClasse(classeId, eleveId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    if (typeof QRCode === 'undefined') { toast('Bibliothèque QR non chargée. Vérifiez votre connexion Internet.', 'error', 5000); return; }
    const eleves = eleveId ? classe.eleves.filter(e => e.id === eleveId) : classe.eleves;
    if (eleves.length === 0) { toast('Aucun élève dans cette classe.', 'warning'); return; }
    const ecole = ec.infos.nom || appData.school.name || '';
    const directeur = ec.direction.directeur || '';
    let html = '<div class="cartes-grid">';
    eleves.forEach(e => {
        ensureMatricule(e);
        html += `<div class="carte-eleve">
            <div class="carte-head">
                <img src="logo.jpg" alt="Logo" class="carte-logo">
                <div class="carte-titre">
                    <div class="carte-ecole">${esc(ecole)}</div>
                    <div class="carte-sous">CARTE D'ÉLÈVE — ${esc(appData.year)}</div>
                </div>
            </div>
            <div class="carte-body">
                <div class="carte-avatar" style="background:${crmAvatarColor((e.prenom || '') + (e.nom || ''))}">${esc(((e.prenom || ' ')[0] + (e.nom || ' ')[0]).toUpperCase())}</div>
                <div class="carte-infos">
                    <div class="carte-nom">${esc(e.prenom)} <b>${esc((e.nom || '').toUpperCase())}</b></div>
                    <div class="carte-ligne">Classe : <b>${esc(classe.nom)}</b></div>
                    <div class="carte-ligne">Né(e) le : ${formatDateNaissanceFR(e.dateNaissance)}</div>
                    <div class="carte-ligne">Matricule : <b>${esc(e.matricule)}</b></div>
                    <div class="carte-signature">Le Directeur${directeur ? ' — ' + esc(directeur) : ''}</div>
                </div>
                <div class="carte-qr" data-eleve="${e.id}"></div>
            </div>
        </div>`;
    });
    html += '</div>';
    saveData(); // persiste les matricules attribués
    document.getElementById('printModalTitle').textContent =
        eleveId ? `Carte d'élève — ${eleves[0].prenom} ${eleves[0].nom}` : `Cartes d'élèves — ${classe.nom}`;
    document.getElementById('printModalContent').innerHTML = html;
    // Rendu des QR après injection du HTML
    document.querySelectorAll('#printModalContent .carte-qr').forEach(box => {
        const e = classe.eleves.find(x => x.id === box.dataset.eleve);
        if (e) new QRCode(box, { text: carteQrTexte(e, classe), width: 74, height: 74, correctLevel: QRCode.CorrectLevel.M });
    });
    document.getElementById('printModal').classList.add('show');
    logActivity(`Cartes d'élèves générées : ${eleveId ? eleves[0].prenom + ' ' + eleves[0].nom : classe.nom + ' (' + eleves.length + ' carte(s))'}`, 'export');
}

// ---------- Présences / Appel ----------
function renderPresencesPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('presClasseSelect');
    const dateInp = document.getElementById('presDate');
    const content = document.getElementById('presContent');
    if (!dateInp.value) dateInp.value = new Date().toISOString().slice(0, 10);
    if (ec.classes.length === 0) {
        sel.innerHTML = '';
        content.innerHTML = '<div class="empty-state"><p>Créez d\'abord des classes et inscrivez des élèves.</p></div>';
        return;
    }
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    const prev = sel.value;
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const cls = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (cls.length === 0) return '';
        return `<optgroup label="${CYCLES[cy].label}">` +
            cls.map(c => `<option value="${c.id}">${esc(c.nom)} (${c.eleves.length} élève(s))</option>`).join('') + '</optgroup>';
    }).join('');
    if (prev && tri.some(c => c.id === prev)) sel.value = prev;
    const classe = ec.classes.find(c => c.id === sel.value) || tri[0];
    if (classe.eleves.length === 0) {
        content.innerHTML = '<div class="empty-state"><p>Aucun élève dans cette classe.</p></div>';
        return;
    }
    const jour = (ec.presences[classe.id] || {})[dateInp.value] || {};
    const nbAbs = Object.values(jour).filter(v => v === 'A').length;
    const nbRet = Object.values(jour).filter(v => v === 'R').length;
    let html = `<div class="alert alert-info">
        <strong>${classe.eleves.length - nbAbs}</strong> présent(s) · <strong>${nbAbs}</strong> absent(s) · <strong>${nbRet}</strong> retard(s)
    </div>
    <div class="table-wrapper"><table>
        <thead><tr><th style="text-align:left;">Élève</th><th>Appel</th><th>Total année</th></tr></thead><tbody>`;
    classe.eleves.forEach(e => {
        const etat = jour[e.id] || 'P';
        const tot = countPresences(classe.id, e.id);
        html += `<tr>
            <td style="text-align:left;"><span class="crm-name-cell">${crmAvatar(e.prenom, e.nom)}<span>${esc(e.prenom)} <strong>${esc(e.nom)}</strong></span></span></td>
            <td>
                <div class="pres-toggle">
                    <button class="pres-btn pres-p${etat === 'P' ? ' active' : ''}" onclick="setPresence('${classe.id}', '${e.id}', 'P')">Présent</button>
                    <button class="pres-btn pres-a${etat === 'A' ? ' active' : ''}" onclick="setPresence('${classe.id}', '${e.id}', 'A')">Absent</button>
                    <button class="pres-btn pres-r${etat === 'R' ? ' active' : ''}" onclick="setPresence('${classe.id}', '${e.id}', 'R')">Retard</button>
                </div>
            </td>
            <td style="font-size:0.82em; color:var(--text-secondary);">${tot.abs} abs. · ${tot.ret} ret.</td>
        </tr>`;
    });
    content.innerHTML = html + '</tbody></table></div>';
}

function setPresence(classeId, eleveId, etat) {
    const ec = getEcoleData();
    const date = document.getElementById('presDate').value;
    if (!date) return;
    if (!ec.presences[classeId]) ec.presences[classeId] = {};
    if (!ec.presences[classeId][date]) ec.presences[classeId][date] = {};
    if (etat === 'P') {
        delete ec.presences[classeId][date][eleveId];
    } else {
        ec.presences[classeId][date][eleveId] = etat;
    }
    debouncedSave();
    renderPresencesPage();
}

// Totaux d'absences et de retards d'un élève sur l'année
function countPresences(classeId, eleveId) {
    const jours = getEcoleData().presences[classeId] || {};
    let abs = 0, ret = 0;
    Object.values(jours).forEach(j => {
        if (j[eleveId] === 'A') abs++;
        if (j[eleveId] === 'R') ret++;
    });
    return { abs: abs, ret: ret };
}

// ---------- Espace Élève : dossier scolaire consolidé ----------
// Rassemble sur une page ce qu'un parent consulte sur Planète Élève :
// identité, notes et moyennes des trois trimestres, rang, assiduité.

function renderEspaceElevePage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('espaceClasseSelect');
    if (!sel) return;
    if (ec.classes.length === 0) {
        sel.innerHTML = '';
        document.getElementById('espaceEleveSelect').innerHTML = '';
        document.getElementById('espaceEleveContenu').innerHTML =
            '<div class="empty-state"><p>Aucune classe. Créez une classe et inscrivez des élèves pour consulter leur dossier.</p></div>';
        return;
    }
    const prev = sel.value;
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const cls = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (cls.length === 0) return '';
        return `<optgroup label="${esc(CYCLES[cy].label)}">` +
            cls.map(c => `<option value="${c.id}">${esc(c.nom)}</option>`).join('') + '</optgroup>';
    }).join('');
    if (prev && tri.some(c => c.id === prev)) sel.value = prev;
    onEspaceClasseChange();
}

function onEspaceClasseChange() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === document.getElementById('espaceClasseSelect').value);
    const selEleve = document.getElementById('espaceEleveSelect');
    if (!classe || classe.eleves.length === 0) {
        selEleve.innerHTML = '';
        document.getElementById('espaceEleveContenu').innerHTML =
            '<div class="empty-state"><p>Aucun élève dans cette classe.</p></div>';
        return;
    }
    selEleve.innerHTML = classe.eleves.map(e =>
        `<option value="${e.id}">${esc(e.prenom)} ${esc(e.nom)}</option>`).join('');
    renderEspaceEleve();
}

function renderEspaceEleve() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('espaceEleveContenu');
    const classe = ec.classes.find(c => c.id === document.getElementById('espaceClasseSelect').value);
    if (!classe) { box.innerHTML = ''; return; }
    const eleveId = document.getElementById('espaceEleveSelect').value;
    const e = classe.eleves.find(x => x.id === eleveId);
    if (!e) { box.innerHTML = ''; return; }

    const mats = matieresOfClasse(ec, classe);
    const pres = countPresences(classe.id, e.id);

    // Identité
    let html = `<div class="card" style="margin-top:14px;">
        <h3 style="margin-bottom:10px;">${esc(e.prenom)} ${esc(e.nom)}</h3>
        <div class="crm-fiche-grid">
            <div><b>IEN :</b> ${e.ien ? esc(e.ien) : '<em>non renseigné</em>'}</div>
            <div><b>Classe :</b> ${esc(classe.nom)} (${esc(classe.niveau)})</div>
            <div><b>Sexe :</b> ${e.sexe === 'F' ? 'Fille' : 'Garçon'}</div>
            <div><b>Né(e) le :</b> ${formatDateNaissanceFR(e.dateNaissance)}</div>
            <div><b>Tuteur :</b> ${e.telephone ? esc(e.telephone) : '<em>non renseigné</em>'}</div>
            <div><b>Cycle :</b> ${esc(CYCLES[cycleOfNiveau(classe.niveau)].label)}</div>
        </div>
    </div>`;

    // Assiduité — l'équivalent des rubriques Absences et Retards de Planète Élève
    html += `<div class="stats-grid" style="margin-top:14px;">
        <div class="stat-card ${pres.abs > 0 ? 'orange' : 'green'}"><div class="number">${pres.abs}</div><div class="label">Absences</div></div>
        <div class="stat-card ${pres.ret > 0 ? 'orange' : 'green'}"><div class="number">${pres.ret}</div><div class="label">Retards</div></div>
    </div>`;

    // Notes par trimestre
    const trimestres = Object.keys(TRIMESTRES);
    const moyennes = [];
    trimestres.forEach(t => {
        const notes = notesTrimestre(classe, t)[e.id] || {};
        const moy = moyenneEleveTrimestre(classe, e.id, t);
        const rg = rangEleveTrimestre(classe, e.id, t);
        moyennes.push(moy);
        const lignes = mats.map(m => {
            const n = parseFloat(notes[m.code]);
            return `<tr>
                <td style="text-align:left;">${esc(m.nom)}</td>
                <td>${m.coef}</td>
                <td>${isNaN(n) ? '—' : n.toFixed(2)}</td>
                <td>${isNaN(n) ? '—' : appreciationNote(n)}</td>
            </tr>`;
        }).join('');
        html += `<div class="card" style="margin-top:14px;">
            <h3 style="margin-bottom:8px;">${esc(TRIMESTRES[t])}</h3>
            ${moy === null
                ? '<div class="empty-state"><p>Aucune note saisie pour ce trimestre.</p></div>'
                : `<p style="font-size:0.95em;">Moyenne : <strong>${moy.toFixed(2)}/20</strong>
                     — ${esc(appreciationNote(moy))}
                     ${rg ? ` — rang <strong>${rg.rang}</strong> sur ${rg.sur}` : ''}</p>`}
            <div class="table-wrapper"><table>
                <thead><tr><th style="text-align:left;">Matière</th><th>Coef</th><th>Note /20</th><th>Appréciation</th></tr></thead>
                <tbody>${lignes}</tbody>
            </table></div>
        </div>`;
    });

    // Moyenne annuelle : sur les seuls trimestres notés
    const notees = moyennes.filter(m => m !== null);
    if (notees.length > 0) {
        const annuelle = notees.reduce((s, m) => s + m, 0) / notees.length;
        html += `<div class="alert ${annuelle >= 10 ? 'alert-info' : 'alert-warning'}" style="margin-top:14px;">
            <strong>Moyenne annuelle : ${annuelle.toFixed(2)}/20</strong>
            — ${esc(appreciationNote(annuelle))}
            <span style="opacity:0.8;">(sur ${notees.length} trimestre(s) noté(s))</span>
        </div>`;
    }

    box.innerHTML = html;
}

// Dossier scolaire imprimable / exportable en PDF.
// Planète Élève permet de télécharger le bulletin ; ici c'est l'année entière.
function imprimerDossierEleve() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === document.getElementById('espaceClasseSelect').value);
    if (!classe) { toast('Choisissez une classe.', 'warning'); return; }
    const e = classe.eleves.find(x => x.id === document.getElementById('espaceEleveSelect').value);
    if (!e) { toast('Choisissez un élève.', 'warning'); return; }

    const mats = matieresOfClasse(ec, classe);
    const pres = countPresences(classe.id, e.id);
    let html = docHeader('DOSSIER SCOLAIRE', `${esc(e.prenom)} ${esc(e.nom)} — ${esc(classe.nom)} (${esc(classe.niveau)})`);
    html += `<table style="margin-bottom:12px;"><tbody>
        <tr><td style="text-align:left;"><b>IEN</b></td><td style="text-align:left;">${e.ien ? esc(e.ien) : '—'}</td>
            <td style="text-align:left;"><b>Né(e) le</b></td><td style="text-align:left;">${formatDateNaissanceFR(e.dateNaissance)}</td></tr>
        <tr><td style="text-align:left;"><b>Sexe</b></td><td style="text-align:left;">${e.sexe === 'F' ? 'Fille' : 'Garçon'}</td>
            <td style="text-align:left;"><b>Assiduité</b></td><td style="text-align:left;">${pres.abs} absence(s), ${pres.ret} retard(s)</td></tr>
    </tbody></table>`;

    const moyennes = [];
    Object.keys(TRIMESTRES).forEach(t => {
        const notes = notesTrimestre(classe, t)[e.id] || {};
        const moy = moyenneEleveTrimestre(classe, e.id, t);
        const rg = rangEleveTrimestre(classe, e.id, t);
        moyennes.push(moy);
        html += `<h4 style="margin:12px 0 6px; color:#3E2415;">${esc(TRIMESTRES[t])}</h4>`;
        if (moy === null) { html += '<p style="font-size:0.9em;"><i>Aucune note saisie.</i></p>'; return; }
        html += `<table><thead><tr><th style="text-align:left;">Matière</th><th>Coef</th><th>Note /20</th><th>Note × Coef</th></tr></thead><tbody>`;
        mats.forEach(m => {
            const n = parseFloat(notes[m.code]);
            html += `<tr><td style="text-align:left;">${esc(m.nom)}</td><td>${m.coef}</td>
                <td>${isNaN(n) ? '—' : n.toFixed(2)}</td>
                <td>${isNaN(n) ? '—' : (n * (m.coef || 1)).toFixed(2)}</td></tr>`;
        });
        html += `</tbody></table>
            <p style="font-size:0.9em; margin-top:4px;"><b>Moyenne : ${moy.toFixed(2)}/20</b> — ${esc(appreciationNote(moy))}${rg ? ` — rang ${rg.rang} sur ${rg.sur}` : ''}</p>`;
    });

    const notees = moyennes.filter(m => m !== null);
    if (notees.length > 0) {
        const annuelle = notees.reduce((s, m) => s + m, 0) / notees.length;
        html += `<p style="margin-top:14px; font-size:1.05em;"><b>Moyenne annuelle : ${annuelle.toFixed(2)}/20</b> — ${esc(appreciationNote(annuelle))}
                 <span style="font-size:0.85em;">(sur ${notees.length} trimestre(s) noté(s))</span></p>`;
    }

    const cy = cycleOfNiveau(classe.niveau);
    html += `<div style="display:flex; justify-content:space-between; margin-top:28px; padding:0 20px; font-size:0.9em;">
        <div style="text-align:center;">Le ${esc(CYCLES[cy].chefLabel.toLowerCase())}<br><br><br>${chefOfCycle(ec, cy) ? '<b>' + esc(chefOfCycle(ec, cy)) + '</b>' : ''}</div>
        <div style="text-align:center;">Le Directeur<br><br><br>${ec.direction.directeur ? '<b>' + esc(ec.direction.directeur) + '</b>' : ''}</div>
    </div>`;

    document.getElementById('printModalTitle').textContent = `Dossier scolaire — ${e.prenom} ${e.nom}`;
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity(`Dossier scolaire édité : ${e.prenom} ${e.nom} (${classe.nom})`, 'export');
}

// ---------- Cahier de texte numérique ----------
// Remplace le cahier de texte papier : ce qui a été traité en classe, et les
// devoirs donnés. Planète 3 en fait un argument central ; tous les logiciels
// scolaires sénégalais l'ont. C'est aussi la mémoire de l'année en cas
// d'inspection ou de remplacement d'un professeur.

function seancesDeClasse(ec, classeId) {
    if (!Array.isArray(ec.cahierTexte[classeId])) ec.cahierTexte[classeId] = [];
    return ec.cahierTexte[classeId];
}

function renderCahierTextePage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('cahierClasseSelect');
    if (!sel) return;
    if (ec.classes.length === 0) {
        sel.innerHTML = '';
        document.getElementById('cahierContenu').innerHTML =
            '<div class="empty-state"><p>Aucune classe. Créez une classe pour ouvrir son cahier de texte.</p></div>';
        return;
    }
    const prev = sel.value;
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const cls = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (cls.length === 0) return '';
        return `<optgroup label="${esc(CYCLES[cy].label)}">` +
            cls.map(c => `<option value="${c.id}">${esc(c.nom)}</option>`).join('') + '</optgroup>';
    }).join('');
    if (prev && tri.some(c => c.id === prev)) sel.value = prev;
    renderCahierTexte();
}

function renderCahierTexte() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('cahierContenu');
    const classeId = document.getElementById('cahierClasseSelect').value;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) { box.innerHTML = ''; return; }

    const mats = matieresOfClasse(ec, classe);
    const nomMatiere = code => { const m = mats.find(x => x.code === code); return m ? m.nom : code; };
    const nomProf = id => { const p = ec.professeurs.find(x => x.id === id); return p ? p.prenom + ' ' + p.nom : ''; };

    const seances = [...seancesDeClasse(ec, classeId)].sort((a, b) => String(b.date).localeCompare(String(a.date)));

    // Devoirs encore à rendre : le rappel que le papier ne donne jamais
    const aujourdhui = new Date().toISOString().slice(0, 10);
    const aVenir = seances
        .filter(s => s.devoirs && s.dateRemise && s.dateRemise >= aujourdhui)
        .sort((a, b) => String(a.dateRemise).localeCompare(String(b.dateRemise)));

    let html = `<div class="btn-group no-print" style="margin-bottom:12px;">
        <button class="btn btn-primary" onclick="ouvrirSeanceModal('${classeId}')">+ Nouvelle séance</button>
        <button class="btn btn-info" onclick="imprimerCahierTexte('${classeId}')">Imprimer le cahier</button>
    </div>`;

    if (aVenir.length > 0) {
        html += `<div class="alert alert-warning"><strong>Devoirs à rendre :</strong> ` +
            aVenir.map(s => `${esc(nomMatiere(s.matiereCode))} pour le ${formatDateNaissanceFR(s.dateRemise)}`).join(' · ') +
            `</div>`;
    }

    if (seances.length === 0) {
        box.innerHTML = html + '<div class="empty-state"><p>Aucune séance enregistrée pour cette classe.</p></div>';
        return;
    }

    html += `<p style="font-size:0.9em; color:#5c4a38;"><strong>${seances.length}</strong> séance(s) enregistrée(s).</p>`;
    html += seances.map(s => `<div class="card" style="margin-bottom:10px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
            <div>
                <strong>${formatDateNaissanceFR(s.date)}</strong> —
                <span style="color:#8a6d3b;">${esc(nomMatiere(s.matiereCode))}</span>
                ${s.profId ? `<span style="font-size:0.88em; color:#7a6a58;"> · ${esc(nomProf(s.profId))}</span>` : ''}
            </div>
            <div class="btn-group no-print">
                <button class="btn btn-sm btn-primary" onclick="ouvrirSeanceModal('${classeId}', '${s.id}')">Modifier</button>
                <button class="btn btn-sm btn-danger" onclick="supprimerSeance('${classeId}', '${s.id}')">Supprimer</button>
            </div>
        </div>
        ${s.contenu ? `<p style="margin-top:8px; white-space:pre-wrap;">${esc(s.contenu)}</p>` : ''}
        ${s.devoirs ? `<div style="margin-top:8px; padding:8px 12px; background:#faf8f5; border-radius:8px; font-size:0.92em;">
            <strong>Devoirs :</strong> <span style="white-space:pre-wrap;">${esc(s.devoirs)}</span>
            ${s.dateRemise ? ` <em>— à rendre le ${formatDateNaissanceFR(s.dateRemise)}</em>` : ''}
        </div>` : ''}
    </div>`).join('');

    box.innerHTML = html;
}

function ouvrirSeanceModal(classeId, seanceId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    const s = seanceId ? seancesDeClasse(ec, classeId).find(x => x.id === seanceId) : null;

    document.getElementById('seanceModalTitle').textContent = s ? 'Modifier la séance' : 'Nouvelle séance';
    document.getElementById('seanceClasseId').value = classeId;
    document.getElementById('seanceId').value = s ? s.id : '';
    document.getElementById('seanceDate').value = s ? s.date : new Date().toISOString().slice(0, 10);
    document.getElementById('seanceMatiere').innerHTML = matieresOfClasse(ec, classe).map(m =>
        `<option value="${esc(m.code)}"${s && s.matiereCode === m.code ? ' selected' : ''}>${esc(m.nom)}</option>`).join('');
    document.getElementById('seanceProf').innerHTML = '<option value="">— Non précisé —</option>' +
        ec.professeurs.map(p =>
            `<option value="${p.id}"${s && s.profId === p.id ? ' selected' : ''}>${esc(p.prenom)} ${esc(p.nom)}</option>`).join('');
    document.getElementById('seanceContenu').value = s ? (s.contenu || '') : '';
    document.getElementById('seanceDevoirs').value = s ? (s.devoirs || '') : '';
    document.getElementById('seanceDateRemise').value = s ? (s.dateRemise || '') : '';
    document.getElementById('seanceModal').classList.add('show');
}

function enregistrerSeance() {
    const ec = getEcoleData();
    const classeId = document.getElementById('seanceClasseId').value;
    const date = document.getElementById('seanceDate').value;
    if (!date) { toast('La date de la séance est requise.', 'warning'); return; }
    const contenu = document.getElementById('seanceContenu').value.trim();
    const devoirs = document.getElementById('seanceDevoirs').value.trim();
    if (!contenu && !devoirs) { toast('Renseignez au moins le contenu ou les devoirs.', 'warning'); return; }
    const dateRemise = document.getElementById('seanceDateRemise').value;
    if (dateRemise && dateRemise < date) { toast('La date de remise ne peut pas précéder la séance.', 'warning'); return; }

    const seances = seancesDeClasse(ec, classeId);
    const id = document.getElementById('seanceId').value;
    const donnees = {
        date: date,
        matiereCode: document.getElementById('seanceMatiere').value,
        profId: document.getElementById('seanceProf').value,
        contenu: contenu,
        devoirs: devoirs,
        dateRemise: dateRemise
    };
    if (id) {
        const s = seances.find(x => x.id === id);
        if (!s) return;
        Object.assign(s, donnees);
        logActivity('Séance modifiée au cahier de texte', 'config');
    } else {
        seances.push(Object.assign({ id: ecoleUid('sc_') }, donnees));
        logActivity('Séance ajoutée au cahier de texte', 'config');
    }
    saveData();
    closeModal('seanceModal');
    renderCahierTexte();
    toast('Séance enregistrée.', 'success');
}

function supprimerSeance(classeId, seanceId) {
    showConfirm('Supprimer cette séance ?', 'Elle disparaîtra du cahier de texte.', () => {
        const ec = getEcoleData();
        ec.cahierTexte[classeId] = seancesDeClasse(ec, classeId).filter(s => s.id !== seanceId);
        saveData();
        renderCahierTexte();
        toast('Séance supprimée.', 'success');
    });
}

function imprimerCahierTexte(classeId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    const seances = [...seancesDeClasse(ec, classeId)].sort((a, b) => String(a.date).localeCompare(String(b.date)));
    if (seances.length === 0) { toast('Aucune séance à imprimer.', 'warning'); return; }
    const mats = matieresOfClasse(ec, classe);
    const nomMatiere = code => { const m = mats.find(x => x.code === code); return m ? m.nom : code; };
    const nomProf = id => { const p = ec.professeurs.find(x => x.id === id); return p ? p.prenom + ' ' + p.nom : '—'; };

    let html = docHeader('CAHIER DE TEXTE', `${esc(classe.nom)} (${esc(classe.niveau)}) — Année ${appData.year}`);
    html += `<table><thead><tr>
        <th>Date</th><th>Matière</th><th>Professeur</th>
        <th style="text-align:left;">Contenu de la séance</th><th style="text-align:left;">Devoirs</th>
    </tr></thead><tbody>` +
        seances.map(s => `<tr>
            <td style="white-space:nowrap;">${formatDateNaissanceFR(s.date)}</td>
            <td>${esc(nomMatiere(s.matiereCode))}</td>
            <td>${esc(nomProf(s.profId))}</td>
            <td style="text-align:left;">${esc(s.contenu || '—')}</td>
            <td style="text-align:left;">${s.devoirs ? esc(s.devoirs) + (s.dateRemise ? `<br><i>pour le ${formatDateNaissanceFR(s.dateRemise)}</i>` : '') : '—'}</td>
        </tr>`).join('') + '</tbody></table>';

    document.getElementById('printModalTitle').textContent = `Cahier de texte — ${classe.nom}`;
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity(`Cahier de texte imprimé : ${classe.nom}`, 'export');
}

// ---------- Alertes : ce qu'un portail de consultation ne fait pas ----------
// Planète Élève affiche les notes une fois qu'elles sont là. Ici on repère en
// amont les élèves qui décrochent, pour que l'école agisse avant le conseil.

const ALERTE_SEUIL_MOYENNE = 10;   // sous la moyenne
const ALERTE_SEUIL_ABSENCES = 5;   // absences cumulées sur l'année
const ALERTE_BAISSE = 2;           // points perdus d'un trimestre à l'autre

// Retourne la liste des signaux pour un élève, vide s'il va bien.
function alertesEleve(classe, eleve) {
    const signaux = [];
    const pres = countPresences(classe.id, eleve.id);
    if (pres.abs >= ALERTE_SEUIL_ABSENCES) {
        signaux.push({ type: 'absences', texte: `${pres.abs} absences` });
    }
    const suite = Object.keys(TRIMESTRES)
        .map(t => moyenneEleveTrimestre(classe, eleve.id, t))
        .filter(m => m !== null);
    if (suite.length > 0) {
        const derniere = suite[suite.length - 1];
        if (derniere < ALERTE_SEUIL_MOYENNE) {
            signaux.push({ type: 'moyenne', texte: `moyenne ${derniere.toFixed(2)}/20` });
        }
        if (suite.length >= 2) {
            const chute = suite[suite.length - 2] - derniere;
            if (chute >= ALERTE_BAISSE) {
                signaux.push({ type: 'baisse', texte: `baisse de ${chute.toFixed(2)} pts` });
            }
        }
    }
    return signaux;
}

function renderAlertesPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('alertesContenu');
    if (!box) return;

    const lignes = [];
    ec.classes.forEach(classe => {
        classe.eleves.forEach(eleve => {
            const signaux = alertesEleve(classe, eleve);
            if (signaux.length > 0) lignes.push({ classe, eleve, signaux });
        });
    });
    // Les cas les plus lourds d'abord
    lignes.sort((a, b) => b.signaux.length - a.signaux.length);

    const totalEleves = ec.classes.reduce((s, c) => s + c.eleves.length, 0);
    if (totalEleves === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucun élève inscrit. Les alertes apparaîtront dès que des notes et des absences seront saisies.</p></div>';
        return;
    }
    if (lignes.length === 0) {
        box.innerHTML = `<div class="alert alert-info">Aucun signal d'alerte sur les <strong>${totalEleves}</strong> élève(s) inscrit(s).</div>`;
        return;
    }

    // Orange pour l'assiduité, rouge pour le niveau scolaire.
    const pastille = s => {
        const fond = s.type === 'absences' ? '#c2620f' : '#b91c1c';
        return `<span style="display:inline-block; background:${fond}; color:#fff; padding:2px 9px;
                     border-radius:999px; font-size:0.78em; font-weight:700; margin:0 4px 3px 0;
                     white-space:nowrap;">${esc(s.texte)}</span>`;
    };
    box.innerHTML = `<div class="alert alert-warning">
            <strong>${lignes.length}</strong> élève(s) à suivre sur ${totalEleves} inscrit(s).
            Critères : moyenne sous ${ALERTE_SEUIL_MOYENNE}/20, ${ALERTE_SEUIL_ABSENCES} absences ou plus,
            ou une baisse d'au moins ${ALERTE_BAISSE} points entre deux trimestres.
        </div>
        <div class="table-wrapper"><table>
            <thead><tr><th style="text-align:left;">Élève</th><th>Classe</th><th style="text-align:left;">Signaux</th><th class="no-print">Dossier</th></tr></thead>
            <tbody>${lignes.map(l => `<tr>
                <td style="text-align:left; white-space:nowrap;">${esc(l.eleve.prenom)} <strong>${esc(l.eleve.nom)}</strong></td>
                <td>${esc(l.classe.nom)}</td>
                <td style="text-align:left;">${l.signaux.map(pastille).join('')}</td>
                <td class="no-print"><button class="btn btn-sm btn-info" onclick="ouvrirDossierDepuisAlerte('${l.classe.id}', '${l.eleve.id}')">Voir</button></td>
            </tr>`).join('')}</tbody>
        </table></div>`;
}

function ouvrirDossierDepuisAlerte(classeId, eleveId) {
    showPage('espaceEleve');
    document.getElementById('espaceClasseSelect').value = classeId;
    onEspaceClasseChange();
    document.getElementById('espaceEleveSelect').value = eleveId;
    renderEspaceEleve();
}

// ---------- Registre des sortants ----------
function renderSortantsPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('sortantsContenu');
    if (!box) return;
    const sortants = ec.sortants || [];
    if (sortants.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucun ancien élève enregistré. Le registre se remplit lors des passages de classe.</p></div>';
        return;
    }
    const tri = [...sortants].sort((a, b) =>
        String(b.anneeSortie).localeCompare(String(a.anneeSortie)) ||
        (a.nom + a.prenom).localeCompare(b.nom + b.prenom, 'fr'));
    box.innerHTML = `<p style="font-size:0.9em; color:#5c4a38;"><strong>${sortants.length}</strong> ancien(s) élève(s) archivé(s).</p>
        <div class="table-wrapper"><table>
            <thead><tr><th style="text-align:left;">Élève</th><th>IEN</th><th>Dernière classe</th><th>Année</th><th>Motif</th></tr></thead>
            <tbody>${tri.map(s => `<tr>
                <td style="text-align:left; white-space:nowrap;">${esc(s.prenom)} <strong>${esc(s.nom)}</strong></td>
                <td>${s.ien ? esc(s.ien) : '—'}</td>
                <td>${esc(s.classeSortie || '—')}</td>
                <td>${esc(String(s.anneeSortie || '—'))}</td>
                <td>${esc(s.motif || '—')}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
}

// ---------- Passage de classe (fin d'année) ----------
// Fait monter une promotion d'un niveau au suivant. Chaque élève reçoit une
// décision : il passe, il redouble (il reste sur place), ou il sort de
// l'établissement. Rien n'est supprimé : les sortants sont archivés.

// Décisions par élève pendant que le formulaire est ouvert : { eleveId: 'passe'|'redouble'|'sortie' }
let passageDecisions = {};
let passageClasseId = null;

function niveauSuivant(niveau) {
    const i = CLASSE_NIVEAUX.indexOf(niveau);
    if (i < 0 || i >= CLASSE_NIVEAUX.length - 1) return null; // Terminale : fin de cursus
    return CLASSE_NIVEAUX[i + 1];
}

function openPassageModal() {
    const ec = getEcoleData();
    if (ec.classes.length === 0) { toast('Aucune classe à faire passer.', 'warning'); return; }
    const esc = Security.escapeHTML;
    const sel = document.getElementById('passageClasseSelect');
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    sel.innerHTML = tri.map(c =>
        `<option value="${c.id}">${esc(c.nom)} (${esc(c.niveau)}) — ${c.eleves.length} élève(s)</option>`).join('');
    passageClasseId = tri[0].id;
    sel.value = passageClasseId;
    renderPassageListe();
    document.getElementById('passageModal').classList.add('show');
}

function onPassageClasseChange() {
    passageClasseId = document.getElementById('passageClasseSelect').value;
    passageDecisions = {};
    renderPassageListe();
}

function renderPassageListe() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === passageClasseId);
    const box = document.getElementById('passageContenu');
    if (!classe) { box.innerHTML = ''; return; }

    const suivant = niveauSuivant(classe.niveau);
    const cible = suivant
        ? ec.classes.filter(c => c.niveau === suivant).sort((a, b) => a.nom.localeCompare(b.nom))
        : [];

    let entete;
    if (!suivant) {
        entete = `<div class="alert alert-warning">Classe de <strong>${esc(classe.niveau)}</strong> : fin du cursus.
            Les élèves marqués « passe » seront archivés comme sortants diplômés.</div>`;
    } else {
        const options = cible.map(c => `<option value="${c.id}">${esc(c.nom)}</option>`).join('')
            + `<option value="__nouvelle__">— Créer une nouvelle classe de ${esc(suivant)} —</option>`;
        entete = `<div class="form-group">
            <label>Classe de destination (${esc(suivant)})</label>
            <select id="passageCible" style="width:100%;">${options}</select>
        </div>`;
        if (cible.length === 0) {
            entete += `<div class="alert alert-info">Aucune classe de ${esc(suivant)} n'existe encore : elle sera créée automatiquement.</div>`;
        }
    }

    if (classe.eleves.length === 0) {
        box.innerHTML = entete + '<div class="empty-state"><p>Cette classe n\'a aucun élève.</p></div>';
        return;
    }

    const lignes = classe.eleves.map(e => {
        const d = passageDecisions[e.id] || 'passe';
        const bouton = (val, label, cls) =>
            `<button type="button" class="btn btn-sm ${d === val ? cls : 'btn-outline'}"
                     onclick="setPassageDecision('${e.id}', '${val}')">${label}</button>`;
        return `<tr>
            <td style="text-align:left; white-space:nowrap;">${esc(e.prenom)} <strong>${esc(e.nom)}</strong></td>
            <td class="no-print"><div class="btn-group">
                ${bouton('passe', 'Passe', 'btn-success')}
                ${bouton('redouble', 'Redouble', 'btn-primary')}
                ${bouton('sortie', 'Sortie', 'btn-danger')}
            </div></td>
        </tr>`;
    }).join('');

    const n = v => classe.eleves.filter(e => (passageDecisions[e.id] || 'passe') === v).length;
    box.innerHTML = entete
        + `<p style="font-size:0.9em; color:#5c4a38;">
             <strong>${n('passe')}</strong> passe(nt) · <strong>${n('redouble')}</strong> redouble(nt) · <strong>${n('sortie')}</strong> sortie(s)
           </p>`
        + `<div class="table-wrapper"><table><thead><tr><th style="text-align:left;">Élève</th><th>Décision</th></tr></thead><tbody>${lignes}</tbody></table></div>`;
}

function setPassageDecision(eleveId, decision) {
    passageDecisions[eleveId] = decision;
    // Conserve la classe de destination déjà choisie pendant le re-rendu
    const cibleEl = document.getElementById('passageCible');
    const cible = cibleEl ? cibleEl.value : null;
    renderPassageListe();
    const nouveauCible = document.getElementById('passageCible');
    if (nouveauCible && cible) nouveauCible.value = cible;
}

function appliquerPassage() {
    const ec = getEcoleData();
    const classe = ec.classes.find(c => c.id === passageClasseId);
    if (!classe) return;
    const suivant = niveauSuivant(classe.niveau);

    const passants = classe.eleves.filter(e => (passageDecisions[e.id] || 'passe') === 'passe');
    const sortants = classe.eleves.filter(e => passageDecisions[e.id] === 'sortie');
    if (passants.length === 0 && sortants.length === 0) {
        toast('Aucun élève ne change de classe : tout le monde redouble.', 'info');
        return;
    }

    // Classe de destination : existante ou créée à la volée
    let cible = null;
    if (suivant && passants.length > 0) {
        const choix = (document.getElementById('passageCible') || {}).value;
        if (!choix || choix === '__nouvelle__') {
            cible = { id: ecoleUid('cl_'), nom: suivant + ' A', niveau: suivant, profId: '', eleves: [] };
            // Évite une collision de nom si « 6ème A » existe déjà
            let n = 1;
            while (ec.classes.some(c => c.nom.toLowerCase() === cible.nom.toLowerCase())) {
                cible.nom = suivant + ' ' + String.fromCharCode(65 + n); n++;
            }
            ec.classes.push(cible);
        } else {
            cible = ec.classes.find(c => c.id === choix);
        }
        if (!cible) { toast('Classe de destination introuvable.', 'error'); return; }
    }

    // Les sortants sont archivés, jamais effacés
    if (!Array.isArray(ec.sortants)) ec.sortants = [];
    const diplome = !suivant;
    [...sortants, ...(diplome ? passants : [])].forEach(e => {
        ec.sortants.push(Object.assign({}, e, {
            anneeSortie: appData.year,
            classeSortie: classe.nom,
            motif: diplome && passants.includes(e) ? 'Fin de cursus' : 'Sortie'
        }));
    });

    // Retire de la classe d'origine ceux qui la quittent : les redoublants restent.
    const partants = new Set([...sortants, ...passants].map(e => e.id));
    classe.eleves = classe.eleves.filter(e => !partants.has(e.id));

    // Installe les passants dans la classe de destination
    if (cible) {
        passants.forEach(e => {
            cible.eleves.push(e);
            // Les paiements suivent l'élève dans sa nouvelle classe
            getComptaData().paiements.forEach(p => { if (p.eleveId === e.id) p.classeId = cible.id; });
        });
        cible.eleves.sort((a, b) => (a.nom + ' ' + a.prenom).localeCompare(b.nom + ' ' + b.prenom, 'fr'));
    }

    saveData();
    closeModal('passageModal');
    passageDecisions = {};
    const resume = cible
        ? `${passants.length} élève(s) passé(s) en ${cible.nom}`
        : `${passants.length} élève(s) diplômé(s)`;
    logActivity(`Passage de classe depuis ${classe.nom} : ${resume}, ${sortants.length} sortie(s)`, 'config');
    toast(`${resume}${sortants.length ? ', ' + sortants.length + ' sortie(s)' : ''}.`, 'success', 5000);
    renderClassesPage();
}

// ---------- Matières des bulletins (Mon École) ----------
// Chaque cycle a sa grille ; cette variable retient celle qu'on est en train d'éditer.
let currentMatiereCycle = 'elementaire';

function setMatiereCycle(cy) {
    if (!CYCLES[cy]) return;
    currentMatiereCycle = cy;
    renderEcoleMatieres();
}

function renderEcoleMatieres() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('ecoleMatieres');
    if (!box) return;
    const mats = matieresOfCycle(ec, currentMatiereCycle);
    const onglets = Object.keys(CYCLES).map(cy =>
        `<button class="btn btn-sm ${cy === currentMatiereCycle ? 'btn-primary' : 'btn-outline'}"
                 onclick="setMatiereCycle('${cy}')">${esc(CYCLES[cy].label)} <span style="opacity:0.7;">(${matieresOfCycle(ec, cy).length})</span></button>`
    ).join(' ');
    box.innerHTML = `<div class="btn-group no-print" style="margin-bottom:12px;">${onglets}</div>
        <p style="font-size:0.88em; color:#5c4a38; margin-bottom:10px;">
            Grille appliquée aux classes de <strong>${esc(CYCLES[currentMatiereCycle].sub)}</strong> —
            saisie des notes, bulletins et emplois du temps de ce cycle.
        </p>
        <table><thead><tr><th style="text-align:left;">Matière</th><th>Code</th><th>Coefficient</th><th class="no-print">Actions</th></tr></thead><tbody>` +
        mats.map((m, i) => `<tr>
            <td><input type="text" value="${esc(m.nom)}" data-mat="${i}" class="matiere-nom" style="width:200px;"></td>
            <td><input type="text" value="${esc(m.code)}" data-mat="${i}" class="matiere-code" style="width:80px; text-transform:uppercase;"></td>
            <td><input type="number" value="${m.coef}" min="1" max="10" data-mat="${i}" class="matiere-coef" style="width:70px;"></td>
            <td class="no-print"><button class="btn btn-sm btn-danger" onclick="removeEcoleMatiere(${i})">Supprimer</button></td>
        </tr>`).join('') + '</tbody></table>';
}

function addEcoleMatiere() {
    const mats = matieresOfCycle(getEcoleData(), currentMatiereCycle);
    mats.push({ nom: 'Nouvelle matière', code: 'MAT' + (mats.length + 1), coef: 1 });
    renderEcoleMatieres();
}

function removeEcoleMatiere(idx) {
    const mats = matieresOfCycle(getEcoleData(), currentMatiereCycle);
    if (mats.length <= 1) { toast('Il faut au moins une matière dans ce cycle.', 'warning'); return; }
    mats.splice(idx, 1);
    renderEcoleMatieres();
}

function saveEcoleMatieres() {
    const mats = matieresOfCycle(getEcoleData(), currentMatiereCycle);
    document.querySelectorAll('.matiere-nom').forEach(el => { mats[el.dataset.mat].nom = el.value.trim() || 'Matière'; });
    document.querySelectorAll('.matiere-code').forEach(el => { mats[el.dataset.mat].code = (el.value.trim() || 'MAT').toUpperCase(); });
    document.querySelectorAll('.matiere-coef').forEach(el => { mats[el.dataset.mat].coef = Math.max(1, parseInt(el.value, 10) || 1); });
    saveData();
    logActivity(`Matières mises à jour (${CYCLES[currentMatiereCycle].label})`, 'config');
    toast(`Matières du ${CYCLES[currentMatiereCycle].label.toLowerCase()} sauvegardées.`, 'success');
    renderEcoleMatieres();
}

// ================================================================
// ========== MODULE ADMINISTRATION (personnel) ===================
// ================================================================

function getAdminData() {
    if (!appData.administration) appData.administration = { personnel: [] };
    if (!Array.isArray(appData.administration.personnel)) appData.administration.personnel = [];
    return appData.administration;
}

function renderPersonnelTable() {
    const ad = getAdminData();
    const esc = Security.escapeHTML;
    const q = (document.getElementById('personnelSearch').value || '').toLowerCase();
    document.getElementById('personnelCount').textContent = ad.personnel.length;
    const membres = ad.personnel.filter(p =>
        !q || (p.prenom + ' ' + p.nom + ' ' + (p.fonction || '')).toLowerCase().includes(q));
    const tbody = document.querySelector('#personnelTable tbody');
    if (membres.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-secondary);">Aucun membre du personnel.</td></tr>';
        return;
    }
    tbody.innerHTML = membres.map(p => `<tr class="crm-row" onclick="openPersonnelFiche('${p.id}')" title="Voir la fiche">
        <td><span class="crm-name-cell">${crmAvatar(p.prenom, p.nom)}<span>${esc(p.prenom)}</span></span></td>
        <td><strong>${esc(p.nom)}</strong></td>
        <td><span class="classe-chip">${esc(p.fonction || '—')}</span></td>
        <td>${esc(p.telephone || '—')}</td>
        <td>${esc(p.email || '—')}</td>
        <td class="no-print" onclick="event.stopPropagation()">
            <button class="btn btn-sm btn-info" onclick="editPersonnel('${p.id}')">Modifier</button>
            <button class="btn btn-sm btn-danger" onclick="confirmDeletePersonnel('${p.id}')">Supprimer</button>
        </td>
    </tr>`).join('');
}

const _debouncedPersonnelSearch = debounce(renderPersonnelTable, 150);
function onPersonnelSearchInput() { _debouncedPersonnelSearch(); }

function showAddPersonnelModal() {
    document.getElementById('personnelModalTitle').textContent = 'Ajouter un membre du personnel';
    document.getElementById('editPersonnelId').value = '';
    document.getElementById('personnelPrenom').value = '';
    document.getElementById('personnelNom').value = '';
    document.getElementById('personnelFonction').value = 'Secrétaire';
    document.getElementById('personnelTel').value = '';
    document.getElementById('personnelEmail').value = '';
    document.getElementById('personnelModal').classList.add('show');
}

function editPersonnel(id) {
    const p = getAdminData().personnel.find(p => p.id === id);
    if (!p) return;
    document.getElementById('personnelModalTitle').textContent = 'Modifier le membre du personnel';
    document.getElementById('editPersonnelId').value = p.id;
    document.getElementById('personnelPrenom').value = p.prenom;
    document.getElementById('personnelNom').value = p.nom;
    document.getElementById('personnelFonction').value = p.fonction || 'Autre';
    document.getElementById('personnelTel').value = p.telephone || '';
    document.getElementById('personnelEmail').value = p.email || '';
    closeCrmDrawer();
    document.getElementById('personnelModal').classList.add('show');
}

function savePersonnel() {
    const ad = getAdminData();
    const id = document.getElementById('editPersonnelId').value;
    const prenom = document.getElementById('personnelPrenom').value.trim();
    const nom = document.getElementById('personnelNom').value.trim();
    if (!prenom || !nom) { toast('Prénom et nom sont requis.', 'warning'); return; }
    const data = {
        prenom: prenom,
        nom: nom,
        fonction: document.getElementById('personnelFonction').value,
        telephone: document.getElementById('personnelTel').value.trim(),
        email: document.getElementById('personnelEmail').value.trim()
    };
    if (id) {
        const p = ad.personnel.find(p => p.id === id);
        if (!p) return;
        Object.assign(p, data);
        logActivity(`Personnel modifié : ${prenom} ${nom}`, 'config');
        toast('Membre modifié.', 'success');
    } else {
        ad.personnel.push(Object.assign({ id: ecoleUid('pe_') }, data));
        logActivity(`Personnel ajouté : ${prenom} ${nom} (${data.fonction})`, 'config');
        toast('Membre ajouté.', 'success');
    }
    ad.personnel.sort((a, b) => (a.nom + ' ' + a.prenom).localeCompare(b.nom + ' ' + b.prenom, 'fr'));
    saveData();
    closeModal('personnelModal');
    renderPersonnelTable();
}

function confirmDeletePersonnel(id) {
    const ad = getAdminData();
    const p = ad.personnel.find(p => p.id === id);
    if (!p) return;
    showConfirm('Supprimer le membre', `Supprimer ${p.prenom} ${p.nom} du personnel ?`, () => {
        closeCrmDrawer();
        ad.personnel = ad.personnel.filter(x => x.id !== id);
        saveData();
        logActivity(`Personnel supprimé : ${p.prenom} ${p.nom}`, 'config');
        toast('Membre supprimé.', 'success');
        renderPersonnelTable();
    });
}

function openPersonnelFiche(id) {
    const p = getAdminData().personnel.find(p => p.id === id);
    if (!p) return;
    const esc = Security.escapeHTML;
    openCrmDrawer(`
        <div class="crm-fiche-head">
            ${crmAvatar(p.prenom, p.nom, 'xl')}
            <div>
                <h3>${esc(p.prenom)} ${esc(p.nom)}</h3>
                <div class="crm-badges"><span class="classe-chip">${esc(p.fonction || 'Fonction non renseignée')}</span></div>
            </div>
        </div>
        <div class="crm-section">
            <h4>Coordonnées</h4>
            ${crmInfoRow('Téléphone', esc(p.telephone || '—'))}
            ${crmInfoRow('Email', esc(p.email || '—'))}
        </div>
        <div class="crm-section">
            <h4>Notes internes</h4>
            <textarea id="crmNotesArea" rows="5" placeholder="Observations, suivi, remarques...">${esc(p.notes || '')}</textarea>
            <button class="btn btn-sm btn-success" style="margin-top:8px;" onclick="savePersonnelNotes('${id}')">Enregistrer les notes</button>
        </div>
        <div class="crm-fiche-actions">
            <button class="btn btn-info" onclick="editPersonnel('${id}')">Modifier la fiche</button>
            <button class="btn btn-danger" onclick="confirmDeletePersonnel('${id}')">Supprimer</button>
        </div>`);
}

function savePersonnelNotes(id) {
    const p = getAdminData().personnel.find(p => p.id === id);
    if (!p) return;
    p.notes = document.getElementById('crmNotesArea').value.trim();
    saveData();
    toast('Notes enregistrées.', 'success');
}

// ================================================================
// ========== MODULE COMPTABILITÉ (frais, paiements, dépenses) ====
// ================================================================

// Année scolaire : 9 mensualités d'octobre à juin
const MOIS_SCOLAIRES = ['Octobre', 'Novembre', 'Décembre', 'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin'];

function getComptaData() {
    if (!appData.compta) appData.compta = { fraisParNiveau: {}, paiements: [], depenses: [] };
    const c = appData.compta;
    if (!c.fraisParNiveau) c.fraisParNiveau = {};
    if (!Array.isArray(c.paiements)) c.paiements = [];
    if (!Array.isArray(c.depenses)) c.depenses = [];
    // Numérotation séquentielle des reçus de paiement
    if (!c.prochainRecu) c.prochainRecu = 1;
    // Migration de l'ancien format (montant annuel unique de scolarité)
    // vers le triptyque inscription / mensualité scolarité / mensualité renforcement.
    Object.keys(c.fraisParNiveau).forEach(n => {
        const v = c.fraisParNiveau[n];
        if (typeof v === 'number') {
            c.fraisParNiveau[n] = { inscription: 0, mensualite: Math.round(v / MOIS_SCOLAIRES.length), renforcement: 0 };
        }
    });
    return c;
}

// Chaque élève a un id stable (référencé par les paiements). Les élèves créés
// avant l'arrivée de la comptabilité n'en avaient pas : on complète au chargement.
function ensureEleveIds() {
    if (!appData.ecole) return;
    let changed = false;
    (appData.ecole.classes || []).forEach(c => (c.eleves || []).forEach(e => {
        if (!e.id) { e.id = ecoleUid('el_'); changed = true; }
    }));
    if (changed) saveData();
}

function formatMoney(n) {
    return (Math.round(n) || 0).toLocaleString('fr-FR') + ' F';
}

function findEleveById(id) {
    const ec = getEcoleData();
    for (const c of ec.classes) {
        const e = c.eleves.find(e => e.id === id);
        if (e) return { eleve: e, classe: c };
    }
    return null;
}

function paiementsOf(eleveId) {
    return getComptaData().paiements.filter(p => p.eleveId === eleveId);
}

function totalPaye(eleveId) {
    return paiementsOf(eleveId).reduce((s, p) => s + (p.montant || 0), 0);
}

function fraisPourNiveau(niveau) {
    const f = getComptaData().fraisParNiveau[niveau] || {};
    return {
        inscription: parseInt(f.inscription, 10) || 0,
        mensualite: parseInt(f.mensualite, 10) || 0,
        renforcement: parseInt(f.renforcement, 10) || 0
    };
}

// Coût annuel complet d'un élève du niveau : inscription + 9 mensualités
// de scolarité + 9 mensualités de cours de renforcement (obligatoires).
function totalAnnuelNiveau(niveau) {
    const f = fraisPourNiveau(niveau);
    return f.inscription + MOIS_SCOLAIRES.length * (f.mensualite + f.renforcement);
}

function totalPayeMotif(eleveId, motif) {
    return getComptaData().paiements
        .filter(p => p.eleveId === eleveId && p.motif === motif)
        .reduce((s, p) => s + (p.montant || 0), 0);
}

// Nombre de mensualités couvertes par les paiements (les versements partiels s'additionnent)
function moisPayes(eleveId, motif, mensualite) {
    if (mensualite <= 0) return 0;
    return Math.min(MOIS_SCOLAIRES.length, Math.floor(totalPayeMotif(eleveId, motif) / mensualite));
}

// ---------- Vue d'ensemble ----------
function renderComptaDashboard() {
    const ec = getEcoleData();
    const co = getComptaData();
    let attendu = 0;
    ec.classes.forEach(c => attendu += c.eleves.length * totalAnnuelNiveau(c.niveau));
    const encaisse = co.paiements.reduce((s, p) => s + (p.montant || 0), 0);
    const depenses = co.depenses.reduce((s, d) => s + (d.montant || 0), 0);
    const solde = encaisse - depenses;
    const taux = attendu > 0 ? Math.round(encaisse / attendu * 100) : 0;
    const nbPre = ec.preinscriptions.length;
    document.getElementById('comptaStats').innerHTML = `
        <div class="stat-card ${nbPre > 0 ? 'orange' : 'blue'}" style="cursor:pointer;" onclick="showPage('inscriptions')" title="Voir les inscriptions en attente">
            <div class="number">${nbPre}</div><div class="label">Inscriptions en attente</div></div>
        <div class="stat-card blue"><div class="number">${formatMoney(attendu)}</div><div class="label">Attendu (scolarité)</div></div>
        <div class="stat-card green"><div class="number">${formatMoney(encaisse)}</div><div class="label">Encaissé</div><div class="pct">${taux}% recouvré</div></div>
        <div class="stat-card orange"><div class="number">${formatMoney(depenses)}</div><div class="label">Dépenses</div></div>
        <div class="stat-card ${solde >= 0 ? 'green' : 'red'}"><div class="number">${formatMoney(solde)}</div><div class="label">Solde</div></div>`;
    renderFraisNiveaux();
    renderComptaRecents();
}

function renderFraisNiveaux() {
    const box = document.getElementById('fraisNiveaux');
    const esc = Security.escapeHTML;
    box.innerHTML = `<div class="table-wrapper"><table class="frais-table">
        <thead><tr><th style="text-align:left;">Niveau</th><th>Inscription</th><th>Scolarité / mois</th><th>Renforcement / mois</th><th style="text-align:right;">Total annuel</th></tr></thead><tbody>` +
        CLASSE_NIVEAUX.map(niv => {
            const f = fraisPourNiveau(niv);
            return `<tr>
                <td><strong>${esc(niv)}</strong></td>
                <td><input type="number" min="0" step="500" class="frais-input" data-niveau="${esc(niv)}" data-type="inscription" value="${f.inscription}"></td>
                <td><input type="number" min="0" step="500" class="frais-input" data-niveau="${esc(niv)}" data-type="mensualite" value="${f.mensualite}"></td>
                <td><input type="number" min="0" step="500" class="frais-input" data-niveau="${esc(niv)}" data-type="renforcement" value="${f.renforcement}"></td>
                <td class="money-cell" id="fraisTotal-${esc(niv)}">${formatMoney(totalAnnuelNiveau(niv))}</td>
            </tr>`;
        }).join('') + '</tbody></table></div>';
}

function saveFraisNiveaux() {
    const co = getComptaData();
    document.querySelectorAll('.frais-input').forEach(inp => {
        if (!co.fraisParNiveau[inp.dataset.niveau]) co.fraisParNiveau[inp.dataset.niveau] = { inscription: 0, mensualite: 0, renforcement: 0 };
        co.fraisParNiveau[inp.dataset.niveau][inp.dataset.type] = parseInt(inp.value, 10) || 0;
    });
    saveData();
    logActivity('Frais par niveau mis à jour (inscription, scolarité, renforcement)', 'config');
    toast('Frais sauvegardés.', 'success');
    renderComptaDashboard();
}

function renderComptaRecents() {
    const co = getComptaData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('comptaRecents');
    const recents = [...co.paiements].sort((a, b) => (b.date || '').localeCompare(a.date || '')).slice(0, 8);
    if (recents.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucun paiement enregistré.</p></div>';
        return;
    }
    box.innerHTML = '<div class="crm-activity">' + recents.map(p => {
        const found = findEleveById(p.eleveId);
        const nomEleve = found ? found.eleve.prenom + ' ' + found.eleve.nom : 'Élève supprimé';
        return `
        <div class="crm-activity-item">
            <span class="crm-activity-dot"></span>
            <div style="flex:1;">
                <div class="crm-activity-msg"><strong>${formatMoney(p.montant)}</strong> — ${esc(nomEleve)}${found ? ' (' + esc(found.classe.nom) + ')' : ''}</div>
                <div class="crm-activity-time">${formatDateNaissanceFR(p.date)} · ${esc(p.motif || '')}${p.mois ? ' (' + esc(p.mois) + ')' : ''} · ${esc(p.mode || '')}</div>
            </div>
        </div>`;
    }).join('') + '</div>';
}

// ---------- Paiements par classe ----------
function renderPaiementsPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const sel = document.getElementById('paiementsClasseSelect');
    const content = document.getElementById('paiementsContent');
    if (ec.classes.length === 0) {
        sel.innerHTML = '';
        content.innerHTML = '<div class="empty-state"><p>Créez d\'abord des classes et des élèves dans le module École.</p></div>';
        return;
    }
    const tri = [...ec.classes].sort((a, b) =>
        (CLASSE_NIVEAUX.indexOf(a.niveau) - CLASSE_NIVEAUX.indexOf(b.niveau)) || a.nom.localeCompare(b.nom));
    const prev = sel.value;
    sel.innerHTML = Object.keys(CYCLES).map(cy => {
        const classesCycle = tri.filter(c => cycleOfNiveau(c.niveau) === cy);
        if (classesCycle.length === 0) return '';
        return `<optgroup label="${CYCLES[cy].label} (${CYCLES[cy].sub})">`
            + classesCycle.map(c => `<option value="${c.id}">${esc(c.nom)} (${c.eleves.length} élève(s))</option>`).join('')
            + '</optgroup>';
    }).join('');
    if (prev && tri.some(c => c.id === prev)) sel.value = prev;
    const classe = ec.classes.find(c => c.id === sel.value) || tri[0];
    const frais = fraisPourNiveau(classe.niveau);
    const annuel = totalAnnuelNiveau(classe.niveau);
    if (classe.eleves.length === 0) {
        content.innerHTML = '<div class="empty-state"><p>Aucun élève dans cette classe.</p></div>';
        return;
    }
    let totPaye = 0;
    const totAttendu = annuel * classe.eleves.length;
    let rows = '';
    classe.eleves.forEach((e, i) => {
        const paye = totalPaye(e.id);
        totPaye += paye;
        // Inscription : réglée dès que le montant est couvert
        let insc;
        if (frais.inscription === 0) insc = '—';
        else if (totalPayeMotif(e.id, 'Inscription') >= frais.inscription) insc = '<span class="pay-badge ok">Réglée</span>';
        else insc = '<span class="pay-badge none">Due</span>';
        // Mensualités couvertes (scolarité et renforcement obligatoire)
        const mScol = moisPayes(e.id, 'Scolarité', frais.mensualite);
        const mRenf = moisPayes(e.id, 'Renforcement', frais.renforcement);
        const scol = frais.mensualite === 0 ? '—' : `<span class="pay-badge ${mScol >= MOIS_SCOLAIRES.length ? 'ok' : mScol > 0 ? 'partial' : 'none'}">${mScol}/${MOIS_SCOLAIRES.length} mois</span>`;
        const renf = frais.renforcement === 0 ? '—' : `<span class="pay-badge ${mRenf >= MOIS_SCOLAIRES.length ? 'ok' : mRenf > 0 ? 'partial' : 'none'}">${mRenf}/${MOIS_SCOLAIRES.length} mois</span>`;
        let badge;
        if (annuel === 0) badge = '<span class="pay-badge">—</span>';
        else if (paye >= annuel) badge = '<span class="pay-badge ok">Soldé</span>';
        else if (paye > 0) badge = '<span class="pay-badge partial">En cours</span>';
        else badge = '<span class="pay-badge none">Impayé</span>';
        rows += `<tr class="crm-row" onclick="openEleveFiche('${classe.id}', ${i})" title="Voir la fiche">
            <td><span class="crm-name-cell">${crmAvatar(e.prenom, e.nom)}<span>${esc(e.prenom)} <strong>${esc(e.nom)}</strong></span></span></td>
            <td>${insc}</td>
            <td>${scol}</td>
            <td>${renf}</td>
            <td class="money-cell">${formatMoney(paye)}</td>
            <td class="money-cell">${formatMoney(Math.max(0, annuel - paye))}</td>
            <td>${badge}</td>
            <td class="no-print" onclick="event.stopPropagation()">
                <button class="btn btn-sm btn-success" onclick="showAddPaiementModal('${e.id}')">+ Paiement</button>
            </td>
        </tr>`;
    });
    const pctClasse = totAttendu > 0 ? Math.round(totPaye / totAttendu * 100) : 0;
    content.innerHTML = `
        <div class="btn-group no-print">
            <button class="btn btn-info" onclick="imprimerImpayes('${classe.id}')">Imprimer l'état des impayés</button>
        </div>
        <div class="alert alert-info">
            Niveau <strong>${esc(classe.niveau)}</strong> — Inscription : <strong>${formatMoney(frais.inscription)}</strong> ·
            Scolarité : <strong>${formatMoney(frais.mensualite)}</strong>/mois ·
            Renforcement (obligatoire) : <strong>${formatMoney(frais.renforcement)}</strong>/mois ·
            soit <strong>${formatMoney(annuel)}</strong>/an par élève
            ${annuel === 0 ? ' — <a href="#" onclick="showPage(\'compta\'); return false;">définir les frais</a>' : ''}
            <br>Recouvrement de la classe : <strong>${formatMoney(totPaye)}</strong> / ${formatMoney(totAttendu)} (${pctClasse}%)
        </div>
        <div class="table-wrapper"><table>
            <thead><tr><th>Élève</th><th>Inscription</th><th>Scolarité</th><th>Renforcement</th><th style="text-align:right;">Payé</th><th style="text-align:right;">Restant</th><th>Statut</th><th class="no-print">Actions</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div>`;
}

// Le champ "Mois concerné" n'a de sens que pour les mensualités
function togglePaiementMois() {
    const motif = document.getElementById('paiementMotif').value;
    document.getElementById('paiementMoisGroup').style.display =
        (motif === 'Scolarité' || motif === 'Renforcement') ? '' : 'none';
}

function populatePaiementMois() {
    const sel = document.getElementById('paiementMois');
    // Mois scolaire courant présélectionné (octobre par défaut hors année scolaire)
    const nomMoisFR = new Date().toLocaleDateString('fr-FR', { month: 'long' });
    const courant = MOIS_SCOLAIRES.find(m => m.toLowerCase() === nomMoisFR.toLowerCase()) || MOIS_SCOLAIRES[0];
    sel.innerHTML = MOIS_SCOLAIRES.map(m => `<option value="${m}"${m === courant ? ' selected' : ''}>${m}</option>`).join('');
}

function showAddPaiementModal(eleveId) {
    const found = findEleveById(eleveId);
    if (!found) return;
    document.getElementById('paiementEleveId').value = eleveId;
    document.getElementById('paiementPreId').value = '';
    document.getElementById('paiementEleveNom').textContent =
        found.eleve.prenom + ' ' + found.eleve.nom + ' — ' + found.classe.nom;
    const frais = fraisPourNiveau(found.classe.niveau);
    document.getElementById('paiementMontant').value = frais.mensualite || '';
    document.getElementById('paiementDate').value = new Date().toISOString().slice(0, 10);
    document.getElementById('paiementMotif').value = 'Scolarité';
    document.getElementById('paiementMode').value = 'Espèces';
    document.getElementById('paiementNote').value = '';
    populatePaiementMois();
    togglePaiementMois();
    document.getElementById('paiementModal').classList.add('show');
}

function savePaiement() {
    const co = getComptaData();
    const montant = parseInt(document.getElementById('paiementMontant').value, 10);
    if (!montant || montant <= 0) { toast('Saisissez un montant valide.', 'warning'); return; }
    const motif = document.getElementById('paiementMotif').value;
    const mois = (motif === 'Scolarité' || motif === 'Renforcement') ? document.getElementById('paiementMois').value : '';
    // Validation d'une inscription en attente : l'encaissement affecte l'élève à sa classe
    const preId = document.getElementById('paiementPreId').value;
    if (preId) {
        const res = affecterPreinscription(preId);
        if (!res) return;
        co.paiements.push({
            id: ecoleUid('pa_'),
            recu: co.prochainRecu++,
            eleveId: res.eleve.id,
            classeId: res.classe.id,
            montant: montant,
            date: document.getElementById('paiementDate').value || new Date().toISOString().slice(0, 10),
            motif: motif,
            mois: mois,
            mode: document.getElementById('paiementMode').value,
            note: document.getElementById('paiementNote').value.trim()
        });
        saveData();
        logActivity(`Inscription validée : ${res.eleve.prenom} ${res.eleve.nom} affecté(e) en ${res.classe.nom} (${formatMoney(montant)} encaissés)`, 'config');
        toast(`${res.eleve.prenom} ${res.eleve.nom} affecté(e) en ${res.classe.nom} — paiement encaissé.`, 'success', 5000);
        closeModal('paiementModal');
        updateInscriptionsBadge();
        if (currentPage === 'inscriptions') renderInscriptionsPage();
        if (currentPage === 'compta') renderComptaDashboard();
        return;
    }
    const eleveId = document.getElementById('paiementEleveId').value;
    const found = findEleveById(eleveId);
    if (!found) { closeModal('paiementModal'); return; }
    co.paiements.push({
        id: ecoleUid('pa_'),
        recu: co.prochainRecu++,
        eleveId: eleveId,
        classeId: found.classe.id,
        montant: montant,
        date: document.getElementById('paiementDate').value || new Date().toISOString().slice(0, 10),
        motif: motif,
        mois: mois,
        mode: document.getElementById('paiementMode').value,
        note: document.getElementById('paiementNote').value.trim()
    });
    saveData();
    logActivity(`Paiement : ${formatMoney(montant)} — ${found.eleve.prenom} ${found.eleve.nom} (${found.classe.nom})`, 'config');
    toast('Paiement enregistré.', 'success');
    closeModal('paiementModal');
    if (currentPage === 'paiements') renderPaiementsPage();
    if (currentPage === 'compta') renderComptaDashboard();
    // Si la fiche de l'élève est ouverte, on la rafraîchit
    if (document.getElementById('crmDrawer').classList.contains('open')) {
        const idx = found.classe.eleves.indexOf(found.eleve);
        openEleveFiche(found.classe.id, idx);
    }
}

function confirmDeletePaiement(paiementId) {
    const co = getComptaData();
    const p = co.paiements.find(x => x.id === paiementId);
    if (!p) return;
    const found = findEleveById(p.eleveId);
    showConfirm('Supprimer le paiement', `Supprimer ce paiement de ${formatMoney(p.montant)} ?`, () => {
        co.paiements = co.paiements.filter(x => x.id !== paiementId);
        saveData();
        logActivity(`Paiement supprimé : ${formatMoney(p.montant)}`, 'config');
        toast('Paiement supprimé.', 'success');
        if (currentPage === 'paiements') renderPaiementsPage();
        if (currentPage === 'compta') renderComptaDashboard();
        if (found && document.getElementById('crmDrawer').classList.contains('open')) {
            const idx = found.classe.eleves.indexOf(found.eleve);
            openEleveFiche(found.classe.id, idx);
        }
    });
}

// Section "Scolarité" de la fiche élève (drawer CRM)
function crmEleveScolariteHTML(e, classe, classeId, idx) {
    const esc = Security.escapeHTML;
    const frais = fraisPourNiveau(classe.niveau);
    const annuel = totalAnnuelNiveau(classe.niveau);
    const paye = totalPaye(e.id);
    const restant = Math.max(0, annuel - paye);
    const inscOk = frais.inscription === 0 || totalPayeMotif(e.id, 'Inscription') >= frais.inscription;
    const mScol = moisPayes(e.id, 'Scolarité', frais.mensualite);
    const mRenf = moisPayes(e.id, 'Renforcement', frais.renforcement);
    const paiements = paiementsOf(e.id).sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    let liste = '';
    if (paiements.length) {
        liste = '<div class="crm-paiements-list">' + paiements.map(p => `
            <div class="crm-paiement-item">
                <div>
                    <strong>${formatMoney(p.montant)}</strong>${p.recu ? ' <span class="crm-activity-time">Reçu N° ' + String(p.recu).padStart(5, '0') + '</span>' : ''}
                    <span class="crm-activity-time">${formatDateNaissanceFR(p.date)} · ${esc(p.motif || '')}${p.mois ? ' (' + esc(p.mois) + ')' : ''} · ${esc(p.mode || '')}</span>
                </div>
                <span style="display:flex; gap:4px; flex-shrink:0;">
                    <button class="btn btn-sm btn-outline" onclick="imprimerRecu('${p.id}')" title="Imprimer le reçu">Reçu</button>
                    <button class="btn btn-sm btn-danger" onclick="confirmDeletePaiement('${p.id}')" title="Supprimer">&#10005;</button>
                </span>
            </div>`).join('') + '</div>';
    }
    return `
        <div class="crm-section">
            <h4>Scolarité (${formatMoney(annuel)} / an)</h4>
            ${frais.inscription > 0 ? crmInfoRow('Inscription (' + formatMoney(frais.inscription) + ')', inscOk ? '<span class="pay-badge ok">Réglée</span>' : '<span class="pay-badge none">Due</span>') : ''}
            ${frais.mensualite > 0 ? crmInfoRow('Scolarité (' + formatMoney(frais.mensualite) + '/mois)', `<span class="pay-badge ${mScol >= MOIS_SCOLAIRES.length ? 'ok' : mScol > 0 ? 'partial' : 'none'}">${mScol}/${MOIS_SCOLAIRES.length} mois</span>`) : ''}
            ${frais.renforcement > 0 ? crmInfoRow('Renforcement (' + formatMoney(frais.renforcement) + '/mois)', `<span class="pay-badge ${mRenf >= MOIS_SCOLAIRES.length ? 'ok' : mRenf > 0 ? 'partial' : 'none'}">${mRenf}/${MOIS_SCOLAIRES.length} mois</span>`) : ''}
            ${crmInfoRow('Payé', '<strong>' + formatMoney(paye) + '</strong>')}
            ${crmInfoRow('Restant', restant > 0 ? '<strong style="color:var(--danger,#ef4444);">' + formatMoney(restant) + '</strong>' : '<strong style="color:var(--success,#10b981);">Soldé</strong>')}
            ${liste}
            <button class="btn btn-sm btn-success" style="margin-top:8px;" onclick="showAddPaiementModal('${e.id}')">+ Enregistrer un paiement</button>
        </div>`;
}

// ---------- Inscriptions en attente (validées par la comptabilité) ----------
function updateInscriptionsBadge() {
    const n = getEcoleData().preinscriptions.length;
    // Badge sur la page Inscriptions + rappel sur l'en-tête du module Comptabilité
    ['inscriptionsBadge', 'inscriptionsBadgeModule'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = n;
        el.style.display = n > 0 ? '' : 'none';
    });
}

function renderInscriptionsPage() {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const box = document.getElementById('inscriptionsContent');
    if (ec.preinscriptions.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucune inscription en attente. Les nouvelles inscriptions (module École) apparaîtront ici pour validation.</p></div>';
        return;
    }
    let rows = '';
    ec.preinscriptions.forEach(pre => {
        const classe = ec.classes.find(c => c.id === pre.classeId);
        rows += `<tr>
            <td><span class="crm-name-cell">${crmAvatar(pre.prenom, pre.nom)}<span>${esc(pre.prenom)} <strong>${esc(pre.nom)}</strong></span></span></td>
            <td>${classe ? esc(classe.nom) + ' <span class="classe-niveau-badge">' + esc(classe.niveau) + '</span>' : '<span class="pay-badge none">Classe supprimée</span>'}</td>
            <td>${formatDateNaissanceFR(pre.date)}</td>
            <td>${esc(pre.telephone || '—')}</td>
            <td class="no-print">
                <button class="btn btn-sm btn-success" onclick="validerInscription('${pre.id}')">Encaisser &amp; affecter</button>
                <button class="btn btn-sm btn-outline" onclick="affecterSansPaiement('${pre.id}')">Affecter sans paiement</button>
                <button class="btn btn-sm btn-info" onclick="editPreinscription('${pre.id}')">Modifier</button>
                <button class="btn btn-sm btn-danger" onclick="annulerInscription('${pre.id}')">Annuler</button>
            </td>
        </tr>`;
    });
    box.innerHTML = `
        <div class="alert alert-warning"><strong>${ec.preinscriptions.length}</strong> inscription(s) en attente de validation.</div>
        <div class="table-wrapper"><table>
            <thead><tr><th>Élève</th><th>Classe demandée</th><th>Date d'inscription</th><th>Tél. tuteur</th><th class="no-print">Actions</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div>`;
}

// Déplace une pré-inscription vers sa classe (retourne l'élève affecté ou null)
function affecterPreinscription(preId) {
    const ec = getEcoleData();
    const pre = ec.preinscriptions.find(p => p.id === preId);
    if (!pre) return null;
    const classe = ec.classes.find(c => c.id === pre.classeId);
    if (!classe) { toast('La classe demandée n\'existe plus — modifiez l\'inscription.', 'error'); return null; }
    const eleve = {
        id: pre.id, prenom: pre.prenom, nom: pre.nom, sexe: pre.sexe,
        dateNaissance: pre.dateNaissance || '', telephone: pre.telephone || '',
        adresse: pre.adresse || '', notes: ''
    };
    classe.eleves.push(eleve);
    classe.eleves.sort((a, b) => (a.nom + ' ' + a.prenom).localeCompare(b.nom + ' ' + b.prenom, 'fr'));
    ec.preinscriptions = ec.preinscriptions.filter(p => p.id !== preId);
    return { eleve: eleve, classe: classe };
}

// Ouvre le modal de paiement : l'affectation aura lieu à l'encaissement
function validerInscription(preId) {
    const ec = getEcoleData();
    const pre = ec.preinscriptions.find(p => p.id === preId);
    if (!pre) return;
    if (!ec.classes.some(c => c.id === pre.classeId)) {
        toast('La classe demandée n\'existe plus — modifiez l\'inscription.', 'error');
        return;
    }
    const classePre = ec.classes.find(c => c.id === pre.classeId);
    document.getElementById('paiementPreId').value = preId;
    document.getElementById('paiementEleveId').value = '';
    document.getElementById('paiementEleveNom').textContent =
        pre.prenom + ' ' + pre.nom + ' — inscription en ' + classePre.nom;
    // Montant des frais d'inscription du niveau prérempli
    document.getElementById('paiementMontant').value = fraisPourNiveau(classePre.niveau).inscription || '';
    document.getElementById('paiementDate').value = new Date().toISOString().slice(0, 10);
    document.getElementById('paiementMotif').value = 'Inscription';
    document.getElementById('paiementMode').value = 'Espèces';
    document.getElementById('paiementNote').value = '';
    populatePaiementMois();
    togglePaiementMois();
    document.getElementById('paiementModal').classList.add('show');
}

// Cas particuliers (exonération, paiement déjà réglé ailleurs)
function affecterSansPaiement(preId) {
    const pre = getEcoleData().preinscriptions.find(p => p.id === preId);
    if (!pre) return;
    showConfirm('Affecter sans paiement', `Affecter ${pre.prenom} ${pre.nom} à sa classe sans encaisser de paiement ?`, () => {
        const res = affecterPreinscription(preId);
        if (!res) return;
        saveData();
        logActivity(`Inscription validée sans paiement : ${res.eleve.prenom} ${res.eleve.nom} affecté(e) en ${res.classe.nom}`, 'config');
        toast(`${res.eleve.prenom} ${res.eleve.nom} affecté(e) en ${res.classe.nom}.`, 'success');
        renderInscriptionsPage();
        updateInscriptionsBadge();
    });
}

function editPreinscription(preId) {
    const ec = getEcoleData();
    const pre = ec.preinscriptions.find(p => p.id === preId);
    if (!pre) return;
    document.getElementById('eleveModalTitle').textContent = 'Modifier l\'inscription';
    document.getElementById('eleveClasseId').value = '';
    document.getElementById('editEleveIdx').value = '-1';
    document.getElementById('editPreinscriptionId').value = preId;
    populateEleveClasseSelect(pre.classeId);
    document.getElementById('elevePrenom').value = pre.prenom;
    document.getElementById('eleveNom').value = pre.nom;
    document.getElementById('eleveDateNaissance').value = pre.dateNaissance || '';
    document.getElementById('eleveTelTuteur').value = pre.telephone || '';
    document.getElementById('eleveAdresse').value = pre.adresse || '';
    selectEleveSexe(pre.sexe === 'F' ? 'F' : 'M');
    document.getElementById('eleveModal').classList.add('show');
}

function annulerInscription(preId) {
    const ec = getEcoleData();
    const pre = ec.preinscriptions.find(p => p.id === preId);
    if (!pre) return;
    showConfirm('Annuler l\'inscription', `Annuler l'inscription de ${pre.prenom} ${pre.nom} ? L'élève ne sera affecté à aucune classe.`, () => {
        ec.preinscriptions = ec.preinscriptions.filter(p => p.id !== preId);
        saveData();
        logActivity(`Inscription annulée : ${pre.prenom} ${pre.nom}`, 'config');
        toast('Inscription annulée.', 'info');
        renderInscriptionsPage();
        updateInscriptionsBadge();
    });
}

// ---------- Reçus de paiement (forme officielle) ----------
function imprimerRecu(paiementId) {
    const co = getComptaData();
    const esc = Security.escapeHTML;
    const p = co.paiements.find(x => x.id === paiementId);
    if (!p) return;
    const found = findEleveById(p.eleveId);
    const nomEleve = found ? found.eleve.prenom + ' ' + found.eleve.nom : 'Élève supprimé';
    const nomClasse = found ? found.classe.nom : '';
    const ec = getEcoleData();
    let html = docHeader('REÇU DE PAIEMENT', 'N° ' + String(p.recu || '—').padStart(5, '0'));
    html += `<div style="max-width:520px; margin:0 auto; border:2px solid #3E2415; border-radius:10px; padding:20px;">
        <table style="width:100%; border:none;"><tbody>
            <tr><td style="border:none; text-align:left; padding:6px 4px;"><b>Date :</b></td><td style="border:none; text-align:right; padding:6px 4px;">${formatDateNaissanceFR(p.date)}</td></tr>
            <tr><td style="border:none; text-align:left; padding:6px 4px;"><b>Reçu de :</b></td><td style="border:none; text-align:right; padding:6px 4px;">${esc(nomEleve)}${nomClasse ? ' (' + esc(nomClasse) + ')' : ''}</td></tr>
            <tr><td style="border:none; text-align:left; padding:6px 4px;"><b>Motif :</b></td><td style="border:none; text-align:right; padding:6px 4px;">${esc(p.motif || '')}${p.mois ? ' — mois de ' + esc(p.mois) : ''}</td></tr>
            <tr><td style="border:none; text-align:left; padding:6px 4px;"><b>Mode de paiement :</b></td><td style="border:none; text-align:right; padding:6px 4px;">${esc(p.mode || '')}</td></tr>
            ${p.note ? `<tr><td style="border:none; text-align:left; padding:6px 4px;"><b>Référence :</b></td><td style="border:none; text-align:right; padding:6px 4px;">${esc(p.note)}</td></tr>` : ''}
        </tbody></table>
        <div style="margin-top:14px; padding:12px; background:#f5efe8; border-radius:8px; text-align:center; font-size:1.3em; font-weight:800;">
            ${formatMoney(p.montant)} CFA
        </div>
        <div style="display:flex; justify-content:space-between; margin-top:30px; font-size:0.9em;">
            <div style="text-align:center;">Le payeur<br><br><br>______________</div>
            <div style="text-align:center;">Le comptable<br><br><br>______________</div>
        </div>
    </div>`;
    document.getElementById('printModalTitle').textContent = 'Reçu N° ' + String(p.recu || '—').padStart(5, '0');
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity(`Reçu imprimé : N° ${p.recu} (${formatMoney(p.montant)})`, 'export');
}

// ---------- Journal de caisse (recettes + dépenses) ----------
// Entrées fusionnées et triées, éventuellement filtrées par mois calendaire ('AAAA-MM')
function journalCaisseEntrees(filtreMois) {
    const co = getComptaData();
    const entrees = [];
    co.paiements.forEach(p => {
        const found = findEleveById(p.eleveId);
        entrees.push({
            date: p.date || '', type: 'recette', recu: p.recu || null, mode: p.mode || '',
            montant: p.montant || 0, paiementId: p.id,
            libelle: (found ? found.eleve.prenom + ' ' + found.eleve.nom + ' (' + found.classe.nom + ')' : 'Élève supprimé')
                + ' — ' + (p.motif || '') + (p.mois ? ' ' + p.mois : '')
        });
    });
    co.depenses.forEach(d => {
        entrees.push({
            date: d.date || '', type: 'depense', recu: null, mode: '',
            montant: d.montant || 0, libelle: d.libelle + ' — ' + (d.categorie || 'Autre')
        });
    });
    return entrees
        .filter(e => filtreMois === 'tous' || (e.date || '').slice(0, 7) === filtreMois)
        .sort((a, b) => (b.date || '').localeCompare(a.date || ''));
}

let jcMoisFiltre = 'tous';

function renderJournalCaissePage() {
    const esc = Security.escapeHTML;
    const sel = document.getElementById('jcMoisSelect');
    // Liste des mois présents dans les mouvements
    const moisDispo = [...new Set(journalCaisseEntrees('tous').map(e => (e.date || '').slice(0, 7)).filter(Boolean))].sort().reverse();
    sel.innerHTML = '<option value="tous">Toute la période</option>' + moisDispo.map(m => {
        const [a, mm] = m.split('-');
        const label = new Date(a, mm - 1, 1).toLocaleDateString('fr-FR', { month: 'long', year: 'numeric' });
        return `<option value="${m}"${m === jcMoisFiltre ? ' selected' : ''}>${label}</option>`;
    }).join('');
    if (sel.value) jcMoisFiltre = sel.value;
    const entrees = journalCaisseEntrees(jcMoisFiltre);
    const box = document.getElementById('jcContent');
    if (entrees.length === 0) {
        box.innerHTML = '<div class="empty-state"><p>Aucun mouvement de caisse sur cette période.</p></div>';
        return;
    }
    const recettes = entrees.filter(e => e.type === 'recette').reduce((s, e) => s + e.montant, 0);
    const depenses = entrees.filter(e => e.type === 'depense').reduce((s, e) => s + e.montant, 0);
    box.innerHTML = `
        <div class="stats-grid" style="margin-bottom:14px;">
            <div class="stat-card green"><div class="number">${formatMoney(recettes)}</div><div class="label">Recettes</div></div>
            <div class="stat-card orange"><div class="number">${formatMoney(depenses)}</div><div class="label">Dépenses</div></div>
            <div class="stat-card ${recettes - depenses >= 0 ? 'green' : 'red'}"><div class="number">${formatMoney(recettes - depenses)}</div><div class="label">Solde</div></div>
        </div>
        <div class="table-wrapper"><table>
            <thead><tr><th>Date</th><th>N° Reçu</th><th style="text-align:left;">Libellé</th><th>Type</th><th>Mode</th><th style="text-align:right;">Montant</th><th class="no-print"></th></tr></thead>
            <tbody>` + entrees.map(e => `<tr>
                <td>${formatDateNaissanceFR(e.date)}</td>
                <td>${e.recu ? String(e.recu).padStart(5, '0') : '—'}</td>
                <td style="text-align:left;">${esc(e.libelle)}</td>
                <td><span class="pay-badge ${e.type === 'recette' ? 'ok' : 'none'}">${e.type === 'recette' ? 'Recette' : 'Dépense'}</span></td>
                <td>${esc(e.mode || '—')}</td>
                <td class="money-cell" style="color:${e.type === 'recette' ? '#059669' : '#dc2626'};">${e.type === 'recette' ? '+' : '−'} ${formatMoney(e.montant)}</td>
                <td class="no-print">${e.paiementId ? `<button class="btn btn-sm btn-outline" onclick="imprimerRecu('${e.paiementId}')" title="Imprimer le reçu">Reçu</button>` : ''}</td>
            </tr>`).join('') + '</tbody></table></div>';
}

function imprimerJournalCaisse() {
    const esc = Security.escapeHTML;
    const entrees = journalCaisseEntrees(jcMoisFiltre);
    if (entrees.length === 0) { toast('Aucun mouvement sur cette période.', 'warning'); return; }
    const recettes = entrees.filter(e => e.type === 'recette').reduce((s, e) => s + e.montant, 0);
    const depenses = entrees.filter(e => e.type === 'depense').reduce((s, e) => s + e.montant, 0);
    const periode = jcMoisFiltre === 'tous' ? 'Toute la période'
        : new Date(jcMoisFiltre.split('-')[0], jcMoisFiltre.split('-')[1] - 1, 1).toLocaleDateString('fr-FR', { month: 'long', year: 'numeric' });
    let html = docHeader('JOURNAL DE CAISSE', periode + ' — ' + appData.year);
    html += '<table><thead><tr><th>Date</th><th>N° Reçu</th><th>Libellé</th><th>Type</th><th>Montant</th></tr></thead><tbody>';
    entrees.forEach(e => {
        html += `<tr><td>${formatDateNaissanceFR(e.date)}</td><td>${e.recu ? String(e.recu).padStart(5, '0') : '—'}</td>
            <td style="text-align:left;">${esc(e.libelle)}</td><td>${e.type === 'recette' ? 'Recette' : 'Dépense'}</td>
            <td style="text-align:right;">${e.type === 'recette' ? '+' : '−'} ${formatMoney(e.montant)}</td></tr>`;
    });
    html += `</tbody></table>
        <div style="margin-top:12px; padding:12px; background:#f5efe8; border-radius:8px; display:flex; justify-content:space-between; font-weight:700;">
            <div>Recettes : ${formatMoney(recettes)}</div>
            <div>Dépenses : ${formatMoney(depenses)}</div>
            <div>Solde : ${formatMoney(recettes - depenses)}</div>
        </div>`;
    document.getElementById('printModalTitle').textContent = 'Journal de caisse — ' + periode;
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity('Journal de caisse imprimé (' + periode + ')', 'export');
}

// ---------- État des impayés d'une classe ----------
function imprimerImpayes(classeId) {
    const ec = getEcoleData();
    const esc = Security.escapeHTML;
    const classe = ec.classes.find(c => c.id === classeId);
    if (!classe) return;
    const frais = fraisPourNiveau(classe.niveau);
    const annuel = totalAnnuelNiveau(classe.niveau);
    if (annuel === 0) { toast('Définissez d\'abord les frais du niveau.', 'warning'); return; }
    const retardataires = classe.eleves
        .map(e => ({ e: e, paye: totalPaye(e.id) }))
        .filter(x => x.paye < annuel);
    if (retardataires.length === 0) { toast('Aucun impayé dans cette classe. 🎉', 'success'); return; }
    let html = docHeader('ÉTAT DES IMPAYÉS', `${esc(classe.nom)} — Année scolaire ${appData.year}`);
    html += `<table><thead><tr><th>N°</th><th>Prénom(s)</th><th>Nom</th><th>Inscription</th><th>Scolarité</th><th>Renforcement</th><th>Payé</th><th>Restant dû</th></tr></thead><tbody>`;
    let totalDu = 0;
    retardataires.forEach((x, i) => {
        const inscOk = frais.inscription === 0 || totalPayeMotif(x.e.id, 'Inscription') >= frais.inscription;
        const mScol = moisPayes(x.e.id, 'Scolarité', frais.mensualite);
        const mRenf = moisPayes(x.e.id, 'Renforcement', frais.renforcement);
        const restant = annuel - x.paye;
        totalDu += restant;
        html += `<tr>
            <td>${i + 1}</td>
            <td style="text-align:left;">${esc(x.e.prenom)}</td>
            <td style="text-align:left;">${esc(x.e.nom)}</td>
            <td>${frais.inscription === 0 ? '—' : inscOk ? 'Réglée' : '<b>Due</b>'}</td>
            <td>${frais.mensualite === 0 ? '—' : mScol + '/' + MOIS_SCOLAIRES.length + ' mois'}</td>
            <td>${frais.renforcement === 0 ? '—' : mRenf + '/' + MOIS_SCOLAIRES.length + ' mois'}</td>
            <td style="text-align:right;">${formatMoney(x.paye)}</td>
            <td style="text-align:right;"><b>${formatMoney(restant)}</b></td>
        </tr>`;
    });
    html += `</tbody></table><p style="text-align:right; font-weight:800; margin-top:10px;">Total restant dû : ${formatMoney(totalDu)}</p>`;
    document.getElementById('printModalTitle').textContent = 'État des impayés — ' + classe.nom;
    document.getElementById('printModalContent').innerHTML = html;
    document.getElementById('printModal').classList.add('show');
    logActivity(`État des impayés imprimé : ${classe.nom} (${retardataires.length} élève(s))`, 'export');
}

// ---------- Dépenses ----------
function renderDepensesPage() {
    const co = getComptaData();
    const esc = Security.escapeHTML;
    const tbody = document.querySelector('#depensesTable tbody');
    const total = co.depenses.reduce((s, d) => s + (d.montant || 0), 0);
    document.getElementById('depensesTotal').textContent = formatMoney(total);
    if (co.depenses.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-secondary);">Aucune dépense enregistrée.</td></tr>';
        return;
    }
    const tri = [...co.depenses].sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    tbody.innerHTML = tri.map(d => `<tr>
        <td>${formatDateNaissanceFR(d.date)}</td>
        <td>${esc(d.libelle)}</td>
        <td><span class="classe-chip">${esc(d.categorie || 'Autre')}</span></td>
        <td class="money-cell">${formatMoney(d.montant)}</td>
        <td class="no-print">
            <button class="btn btn-sm btn-info" onclick="editDepense('${d.id}')">Modifier</button>
            <button class="btn btn-sm btn-danger" onclick="confirmDeleteDepense('${d.id}')">Supprimer</button>
        </td>
    </tr>`).join('');
}

function showAddDepenseModal() {
    document.getElementById('depenseModalTitle').textContent = 'Ajouter une dépense';
    document.getElementById('editDepenseId').value = '';
    document.getElementById('depenseDate').value = new Date().toISOString().slice(0, 10);
    document.getElementById('depenseLibelle').value = '';
    document.getElementById('depenseCategorie').value = 'Fournitures';
    document.getElementById('depenseMontant').value = '';
    document.getElementById('depenseModal').classList.add('show');
}

function editDepense(id) {
    const d = getComptaData().depenses.find(d => d.id === id);
    if (!d) return;
    document.getElementById('depenseModalTitle').textContent = 'Modifier la dépense';
    document.getElementById('editDepenseId').value = d.id;
    document.getElementById('depenseDate').value = d.date || '';
    document.getElementById('depenseLibelle').value = d.libelle;
    document.getElementById('depenseCategorie').value = d.categorie || 'Autre';
    document.getElementById('depenseMontant').value = d.montant;
    document.getElementById('depenseModal').classList.add('show');
}

function saveDepense() {
    const co = getComptaData();
    const id = document.getElementById('editDepenseId').value;
    const libelle = document.getElementById('depenseLibelle').value.trim();
    const montant = parseInt(document.getElementById('depenseMontant').value, 10);
    if (!libelle) { toast('Le libellé est requis.', 'warning'); return; }
    if (!montant || montant <= 0) { toast('Saisissez un montant valide.', 'warning'); return; }
    const data = {
        date: document.getElementById('depenseDate').value || new Date().toISOString().slice(0, 10),
        libelle: libelle,
        categorie: document.getElementById('depenseCategorie').value,
        montant: montant
    };
    if (id) {
        const d = co.depenses.find(d => d.id === id);
        if (!d) return;
        Object.assign(d, data);
        logActivity(`Dépense modifiée : ${libelle} (${formatMoney(montant)})`, 'config');
        toast('Dépense modifiée.', 'success');
    } else {
        co.depenses.push(Object.assign({ id: ecoleUid('de_') }, data));
        logActivity(`Dépense ajoutée : ${libelle} (${formatMoney(montant)})`, 'config');
        toast('Dépense ajoutée.', 'success');
    }
    saveData();
    closeModal('depenseModal');
    if (currentPage === 'depenses') renderDepensesPage();
    if (currentPage === 'compta') renderComptaDashboard();
}

function confirmDeleteDepense(id) {
    const co = getComptaData();
    const d = co.depenses.find(d => d.id === id);
    if (!d) return;
    showConfirm('Supprimer la dépense', `Supprimer « ${d.libelle} » (${formatMoney(d.montant)}) ?`, () => {
        co.depenses = co.depenses.filter(x => x.id !== id);
        saveData();
        logActivity(`Dépense supprimée : ${d.libelle}`, 'config');
        toast('Dépense supprimée.', 'success');
        renderDepensesPage();
    });
}
// ========== DÉMARRAGE (après toutes les déclarations) ==========
init();
