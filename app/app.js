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
            if (t === 'Paramètres' || t === 'Journal' || t === 'Tableau de Bord') btn.style.display = 'none';
        });
        const backupBtn = document.querySelector('.btn-outline[onclick*="showBackupModal"]');
        if (backupBtn) backupBtn.style.display = 'none';
        // Redirect to students page instead of dashboard
        showPage('students');
    }
}

function checkSession() {
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
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('#mainNav button').forEach(b => b.classList.remove('active'));
    document.getElementById('page-' + pageId).classList.add('active');
    const pages = ['dashboard','students','grades1','results1','grades2','results2','stats','documents','journal','aichat','config'];
    const idx = pages.indexOf(pageId);
    if (idx >= 0) document.querySelectorAll('#mainNav button')[idx].classList.add('active');
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
    const duplicate = ld.students.findIndex((s, i) => s.numTable === numTable && i !== idx);
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
    ld.students.sort((a, b) => {
        const nomCmp = (a.nom || '').localeCompare(b.nom || '', 'fr', { sensitivity: 'base' });
        if (nomCmp !== 0) return nomCmp;
        return (a.prenom || '').localeCompare(b.prenom || '', 'fr', { sensitivity: 'base' });
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
            if (g === 'INAPTE') return; // Inapte EPS: exclude from calculation
            if (g !== undefined && g !== '' && g !== 'ABS') { total += parseFloat(g) * sub.coef; coefUsed += sub.coef; has = true; }
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
        ld.subjects2.forEach(sub => { const g = grades[sub.code]; if (g === 'INAPTE') return; if (g !== undefined && g !== '' && g !== 'ABS') { total += parseFloat(g) * sub.coef; coefUsed2 += sub.coef; has = true; } else { coefUsed2 += sub.coef; } });
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
            html += `<table><thead><tr><th>N</th><th>PRENOM(S)</th><th>NOM</th></tr></thead><tbody>`;
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
            html += docHeader("LISTE D'EMARGEMENT", salle.nom + ' - ' + cfg.className);
            html += `<table><thead><tr><th>N</th><th>PRENOM(S)</th><th>NOM</th><th style="width:200px;">Émargement</th></tr></thead><tbody>`;
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

    Object.keys(LEVELS).forEach(lv => {
        const d = appData.levels[lv];
        if (!d || d.students.length === 0) return;
        hasData = true;
        const c = LEVELS[lv];
        const showMention = lv !== 'bfem3';

        let rows = '';
        // Header row
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

function exportBackupJSON() {
    const json = JSON.stringify(appData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    const date = new Date().toISOString().slice(0, 10);
    a.download = `Backup_ExamBlanc_${date}.json`; a.click();
    toast('Sauvegarde JSON exportée.', 'success');
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
    checkSession();
    populateYearSelect();
    updateLevelTags();
    renderDashboard();
}
init();

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
        image:        { type: 'png' },
        html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#ffffff' },
        jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' },
        pagebreak:    { mode: ['css', 'legacy'], before: '.bulletin-page' }
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