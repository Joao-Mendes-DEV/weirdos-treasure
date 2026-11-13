
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const WebSocket = require("ws");
const { createClient } = require("@supabase/supabase-js");
const { buildTreasureChestSvg } = require("./treasure-chest");
const {
    validateEnvironment,
    securityHeaders,
    createRateLimiter,
    SupabaseSessionStore,
    SESSION_TTL_MS
} = require("./security");
const registerMinigame = require("./minigame");

validateEnvironment();

const TREASURE_CHEST_SVG = buildTreasureChestSvg();

const app = express();

app.disable("x-powered-by");
app.use(securityHeaders);

// Ícone da aba (W dourado) em todas as páginas HTML
const FAVICON_TAGS = [
    '<link rel="icon" href="/favicon.ico" sizes="any">',
    '<link rel="icon" href="/favicon.svg" type="image/svg+xml">',
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
    '<meta name="theme-color" content="#211912">'
].join("");

app.use((req, res, next) => {
    const originalSend = res.send.bind(res);

    res.send = (body) => {
        if (typeof body === "string" && body.includes("</head>") && !body.includes('rel="icon"')) {
            body = body.replace("</head>", () => FAVICON_TAGS + "</head>");
        }

        return originalSend(body);
    };

    next();
});

// Limites de requisições
// O estado da Arena (consultado 1x por segundo pelo OBS) tem limite próprio
const generalLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    max: 600,
    skip: (req) => /^\/arena\/[^/]+\/state$/.test(req.path)
});
const authLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    max: 20,
    message: "Muitas tentativas de login. Aguarde um minuto e tente novamente."
});
const purchaseLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    max: 10,
    keyFn: (req) => req.session?.twitchUser?.id || req.ip,
    message: "Muitas compras em pouco tempo. Aguarde um minuto e tente novamente."
});
const arenaStateLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 240 });

function requireAdmin(req, res, next) {
    if (!req.session.twitchUser) {
        return res.redirect("/");
    }

    const adminId = process.env.ADMIN_TWITCH_ID;
    const userId = req.session.twitchUser.id;

    if (!adminId || userId !== adminId) {
        return res.status(403).send("Acesso negado.");
    }

    next();
}

let twitchEventSubSocket = null;
let twitchEventSubSessionId = null;
// Vigia da conexão do chat: último sinal recebido e intervalo esperado de "keepalive"
let twitchEventSubLastMessageAt = 0;
let twitchEventSubKeepaliveMs = 10000;
let twitchChatSubscribed = false;
let twitchBroadcasterAccessToken = null;
let twitchBroadcasterId = null;
let twitchSubscribersCache = new Set();
let twitchSubscribersLastUpdate = 0;
let twitchBroadcasterRefreshToken = null;
let twitchBroadcasterTokenExpiresAt = 0;
let twitchTokenRefreshPromise = null;
let twitchTokenPersistencePending = false;


function encryptTwitchToken(token) {
    const key = Buffer.from(
        process.env.TWITCH_TOKEN_ENCRYPTION_KEY,
        "hex"
    );

    if (key.length !== 32) {
        throw new Error("Chave de criptografia inválida.");
    }

    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    const encrypted = Buffer.concat([
        cipher.update(token, "utf8"),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return [
        iv.toString("hex"),
        authTag.toString("hex"),
        encrypted.toString("hex")
    ].join(":");
}


function decryptTwitchToken(encryptedToken) {
    const key = Buffer.from(
        process.env.TWITCH_TOKEN_ENCRYPTION_KEY,
        "hex"
    );

    if (key.length !== 32) {
        throw new Error("Chave de criptografia inválida.");
    }

    const parts = encryptedToken.split(":");

    if (parts.length !== 3) {
        throw new Error("Token criptografado inválido.");
    }

    const [ivHex, authTagHex, encryptedHex] = parts;

    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");

    if (iv.length !== 12 || authTag.length !== 16) {
        throw new Error("Dados de criptografia inválidos.");
    }

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);

    return decrypted.toString("utf8");
}


async function saveTwitchBroadcasterTokens(
    broadcasterId,
    accessToken,
    refreshToken,
    expiresAt
) {
    const { error } = await supabase
        .from("twitch_auth_tokens")
        .upsert({
            id: "broadcaster",
            broadcaster_twitch_id: broadcasterId,
            access_token_encrypted: encryptTwitchToken(accessToken),
            refresh_token_encrypted: encryptTwitchToken(refreshToken),
            expires_at: new Date(expiresAt).toISOString(),
            updated_at: new Date().toISOString()
        }, {
            onConflict: "id"
        });

    if (error) {
        throw new Error(
            `Erro ao salvar tokens da Twitch: ${error.message}`
        );
    }
}


async function loadTwitchBroadcasterTokens() {
    const { data, error } = await supabase
        .from("twitch_auth_tokens")
        .select("*")
        .eq("id", "broadcaster")
        .maybeSingle();

    if (error) {
        throw new Error(
            `Erro ao carregar tokens da Twitch: ${error.message}`
        );
    }

    if (!data) {
        return null;
    }

    return {
        broadcasterId: data.broadcaster_twitch_id,
        accessToken: decryptTwitchToken(data.access_token_encrypted),
        refreshToken: decryptTwitchToken(data.refresh_token_encrypted),
        expiresAt: new Date(data.expires_at).getTime()
    };
}


async function restoreTwitchBroadcasterAuthentication() {
    try {
        const savedTokens = await loadTwitchBroadcasterTokens();

        if (!savedTokens) {
            console.log(
                "Nenhum token administrativo da Twitch encontrado. Faça login para conectar."
            );
            return;
        }

        if (
            process.env.ADMIN_TWITCH_ID &&
            savedTokens.broadcasterId !== process.env.ADMIN_TWITCH_ID
        ) {
            throw new Error(
                "O ID do broadcaster salvo não corresponde ao administrador configurado."
            );
        }

        twitchBroadcasterId = savedTokens.broadcasterId;
        twitchBroadcasterAccessToken = savedTokens.accessToken;
        twitchBroadcasterRefreshToken = savedTokens.refreshToken;
        twitchBroadcasterTokenExpiresAt = savedTokens.expiresAt;

        const accessToken =
            await getValidTwitchBroadcasterAccessToken();

        connectTwitchChat(accessToken, twitchBroadcasterId);

        console.log(
            "Autenticação administrativa da Twitch restaurada."
        );

    } catch (error) {
        console.error(
            "Não foi possível restaurar a autenticação da Twitch:",
            error.message
        );
    }
}

app.use(express.urlencoded({ extended: true, limit: "20kb", parameterLimit: 50 }));

app.use(express.static("public", { dotfiles: "ignore", index: false }));

// Arquivos estáticos ficam fora do limite geral
app.use(generalLimiter);

// ===== Menu lateral das páginas públicas =====
const PUBLIC_SIDEBAR_CSS = `
    body {
        padding-left: 250px;
        box-sizing: border-box;
    }

    .pt-sidebar {
        position: fixed;
        top: 0;
        left: 0;
        bottom: 0;
        width: 250px;
        z-index: 1000;
        display: flex;
        flex-direction: column;
        padding: 20px 15px;
        box-sizing: border-box;
        overflow-y: auto;
        background: linear-gradient(180deg, #30251b, #211912);
        border-right: 2px solid #705332;
        box-shadow: 4px 0 15px rgba(0, 0, 0, .4);
        font-family: Georgia, "Times New Roman", serif;
    }

    .pt-sidebar-logo {
        display: block;
        padding: 15px 5px 25px;
        text-align: center;
        text-decoration: none;
        border-bottom: 1px solid #55412b;
    }

    .pt-sidebar-logo strong {
        display: block;
        color: #d6b77d;
        font-size: 23px;
        letter-spacing: 3px;
    }

    .pt-sidebar-logo small {
        display: block;
        margin-top: 6px;
        color: #a98a58;
        font-size: 11px;
        letter-spacing: 6px;
    }

    .pt-sidebar-nav {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-top: 25px;
    }

    .pt-sidebar-nav a,
    .pt-sidebar-footer a {
        display: block;
        padding: 13px 14px;
        color: #e8dfcf;
        background: linear-gradient(90deg, #33291d, #29251c);
        border: 1px solid #59482e;
        border-radius: 6px;
        text-decoration: none;
        font-size: 14px;
        transition: background .15s, border-color .15s, color .15s, transform .15s;
    }

    .pt-sidebar-nav a:hover,
    .pt-sidebar-footer a:hover,
    .pt-sidebar-nav a.active {
        color: #f0d18b;
        background: #51402a;
        border-color: #d6a85c;
        transform: translateX(3px);
    }

    .pt-sidebar-footer {
        margin-top: auto;
        padding-top: 15px;
        border-top: 1px solid #55412b;
    }

    .pt-sidebar-avatar,
    .pt-sidebar-login {
        display: none;
    }

    .pt-sidebar-user {
        display: block;
        margin-bottom: 10px;
        padding: 0 4px;
        color: #94836c;
        font-size: 12px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    @media (max-width: 900px) {
        body {
            padding-left: 0;
            padding-top: 64px;
        }

        .pt-sidebar {
            right: 0;
            bottom: auto;
            width: auto;
            height: 64px;
            flex-direction: row;
            align-items: center;
            gap: 10px;
            padding: 0 12px;
            overflow: hidden;
            border-right: 0;
            border-bottom: 2px solid #705332;
        }

        /* Ordem no celular: logo, links e, à direita, conta/entrar */
        .pt-sidebar-logo {
            order: 0;
            padding: 0;
            border-bottom: 0;
            flex-shrink: 0;
            line-height: 1.1;
        }

        .pt-sidebar-logo strong {
            font-size: 15px;
            letter-spacing: 2px;
        }

        .pt-sidebar-logo small {
            display: block;
            margin-top: 2px;
            font-size: 8px;
            letter-spacing: 3.4px;
        }

        .pt-sidebar-nav {
            order: 1;
            flex: 1 1 auto;
            min-width: 0;
            flex-direction: row;
            gap: 6px;
            margin-top: 0;
            overflow-x: auto;
            scrollbar-width: none;
        }

        .pt-sidebar-nav::-webkit-scrollbar {
            display: none;
        }

        .pt-sidebar-avatar,
        .pt-sidebar-login {
            order: 2;
            margin-left: auto;
        }

        .pt-sidebar-nav a,
        .pt-sidebar-footer a {
            padding: 9px 12px;
            white-space: nowrap;
        }

        .pt-sidebar-nav a:hover,
        .pt-sidebar-footer a:hover,
        .pt-sidebar-nav a.active {
            transform: none;
        }

        /* No celular o "Sair" fica em Minha conta, para sobrar espaço no topo */
        .pt-sidebar-footer {
            display: none;
        }

        .pt-sidebar-user {
            display: none;
        }

        .pt-sidebar-avatar {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            width: 40px;
            height: 40px;
            overflow: hidden;
            border: 2px solid #d6a85c;
            border-radius: 50%;
            background: #30251b;
            color: #e2bd7b;
            font-size: 18px;
            font-weight: bold;
            text-decoration: none;
        }

        .pt-sidebar-avatar img {
            display: block;
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .pt-sidebar-login {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            gap: 8px;
            padding: 9px 12px;
            background: #9146FF;
            color: #ffffff;
            border: 1px solid #a970ff;
            border-radius: 7px;
            text-decoration: none;
            white-space: nowrap;
            font-family: Arial, sans-serif;
            font-size: 12px;
            font-weight: bold;
        }

        .pt-sidebar-login svg {
            width: 18px;
            height: 18px;
        }

        .pt-sidebar-login {
            gap: 6px;
        }

        /* Em telas estreitas o botão mostra só "Entrar", para caber o menu */
        @media (max-width: 440px) {
            .pt-login-extra {
                display: none;
            }
        }

        /* O menu do topo já traz a logo e a conta, então o cabeçalho da home some no celular */
        .home-header {
            display: none;
        }
    }
`;

function publicSidebarHtml(req, activePath) {
    const user = req.session && req.session.twitchUser;

    const isAdmin = Boolean(
        user &&
        process.env.ADMIN_TWITCH_ID &&
        user.id === process.env.ADMIN_TWITCH_ID
    );

    const links = user
        ? [
            { href: "/", label: "Início" },
            { href: "/dashboard", label: "Minha conta" },
            { href: "/giveaways", label: "Sorteios" },
            { href: "/my-tickets", label: "Meus tickets" },
            { href: "/minigame", label: "Minigame diário" },
            { href: "/regras", label: "Regras" },
            ...(isAdmin ? [{ href: "/admin", label: "Painel administrativo" }] : [])
        ]
        : [
            { href: "/", label: "Início" },
            { href: "/minigame", label: "Minigame diário" },
            { href: "/regras", label: "Regras" }
        ];

    const items = links.map(link => `
        <a href="${link.href}"${link.href === activePath ? ' class="active" aria-current="page"' : ""}>${link.label}</a>
    `).join("");

    const footer = user
        ? `
            <div class="pt-sidebar-footer">
                <span class="pt-sidebar-user">${escapeDashboardHtml(user.displayName || user.login)}</span>
                <a href="/logout">Sair</a>
            </div>
        `
        : "";

    const account = user
        ? `
            <a href="/dashboard" class="pt-sidebar-avatar" title="Minha conta" aria-label="Minha conta">
                ${
                    user.profileImageUrl
                        ? `<img src="${escapeDashboardHtml(user.profileImageUrl)}" alt="Minha conta">`
                        : `<span>${escapeDashboardHtml(String(user.displayName || user.login || "?").charAt(0).toUpperCase())}</span>`
                }
            </a>
        `
        : `
            <a href="/auth/twitch" class="pt-sidebar-login">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path fill="currentColor" d="M6.429 0 2.143 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0H6.429zm13.714 11.143-3.428 3.428h-3.429l-3 3v-3H6.429V1.714h13.714v9.429zM11.571 4.714h1.715v5.143h-1.715V4.714zm4.714 0H18v5.143h-1.715V4.714z"/>
                </svg>
                Entrar<span class="pt-login-extra"> com Twitch</span>
            </a>
        `;

    return `
        <aside class="pt-sidebar">
            <a href="/" class="pt-sidebar-logo">
                <strong>WEIRDO'S</strong>
                <small>TREASURE</small>
            </a>

            ${account}

            <nav class="pt-sidebar-nav">${items}</nav>

            ${footer}
        </aside>
    `;
}

// Injeta o menu lateral (CSS no <head> e HTML logo após o <body>)
function withPublicSidebar(req, html, activePath) {
    return html
        .replace("</head>", () => `<style>${PUBLIC_SIDEBAR_CSS}</style></head>`)
        .replace(/<body[^>]*>/, match => `${match}${publicSidebarHtml(req, activePath)}`);
}

// ===== Gráficos do painel administrativo =====
function brDayKey(date) {
    return new Date(date).toLocaleDateString("en-CA", {
        timeZone: "America/Sao_Paulo"
    });
}

function brDayLabel(key) {
    return `${key.slice(8, 10)}/${key.slice(5, 7)}`;
}

// Busca todas as linhas de uma consulta, página por página (o Supabase limita 1000 por vez)
async function fetchAllRows(buildQuery) {
    const pageSize = 1000;
    const rows = [];

    for (let page = 0; page < 100; page++) {
        const from = page * pageSize;
        const { data, error } = await buildQuery(from, from + pageSize - 1);

        if (error) {
            console.error("Erro ao buscar dados do gráfico:", error.message);
            return rows;
        }

        rows.push(...(data || []));

        if (!data || data.length < pageSize) {
            break;
        }
    }

    return rows;
}

function buildDailySeries(rows, days, getValue) {
    const buckets = new Map();

    for (let i = days - 1; i >= 0; i--) {
        buckets.set(brDayKey(Date.now() - i * 86400000), 0);
    }

    for (const row of rows) {
        if (!row.created_at) continue;

        const key = brDayKey(row.created_at);

        if (buckets.has(key)) {
            buckets.set(key, buckets.get(key) + getValue(row));
        }
    }

    return [...buckets.entries()].map(([key, value]) => ({ key, value }));
}

function renderBarChart({ id, title, unit, series }) {
    const fmt = (number) => Number(number).toLocaleString("pt-BR");
    const total = series.reduce((sum, point) => sum + point.value, 0);
    const maxValue = Math.max(...series.map(point => point.value), 0);

    const header = `
        <div class="chart-card-header">
            <h3>${title}</h3>
            <span class="chart-total">${fmt(total)} ${unit} no período</span>
        </div>
    `;

    if (maxValue === 0) {
        return `
            <article class="chart-card">
                ${header}
                <p class="chart-empty">Nenhum registro neste período.</p>
            </article>
        `;
    }

    // Escala do eixo vertical em 4 divisões "redondas"
    const raw = maxValue / 4;
    const magnitude = 10 ** Math.floor(Math.log10(raw));
    const normalized = raw / magnitude;
    const tickStep = Math.max(
        1,
        (normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10) * magnitude
    );
    const yMax = tickStep * 4;

    const width = 800;
    const height = 260;
    const left = 66;
    const right = 12;
    const top = 14;
    const bottom = 32;
    const innerW = width - left - right;
    const innerH = height - top - bottom;
    const slot = innerW / series.length;
    const barW = Math.max(2, slot * 0.7);
    const labelEvery = series.length <= 10 ? 1 : series.length <= 35 ? 5 : 10;

    let grid = "";

    for (let i = 0; i <= 4; i++) {
        const y = top + innerH - (innerH * i) / 4;

        grid += `
            <line x1="${left}" y1="${y}" x2="${width - right}" y2="${y}" stroke="#55412b" stroke-width="1" ${i === 0 ? "" : 'stroke-dasharray="4 4"'} />
            <text x="${left - 8}" y="${y + 4}" text-anchor="end" font-size="11" fill="#b6a487">${fmt(tickStep * i)}</text>
        `;
    }

    let bars = "";
    let labels = "";

    series.forEach((point, index) => {
        const x = left + slot * index + (slot - barW) / 2;
        const barHeight = (innerH * point.value) / yMax;
        const date = `${brDayLabel(point.key)}/${point.key.slice(0, 4)}`;

        bars += `
            <g>
                <title>${date}: ${fmt(point.value)} ${unit}</title>
                <rect x="${left + slot * index}" y="${top}" width="${slot}" height="${innerH}" fill="transparent" />
                ${point.value > 0 ? `<rect x="${x}" y="${top + innerH - barHeight}" width="${barW}" height="${barHeight}" rx="2" fill="url(#grad-${id})" />` : ""}
            </g>
        `;

        if ((series.length - 1 - index) % labelEvery === 0) {
            labels += `<text x="${left + slot * index + slot / 2}" y="${height - 10}" text-anchor="middle" font-size="11" fill="#b6a487">${brDayLabel(point.key)}</text>`;
        }
    });

    return `
        <article class="chart-card">
            ${header}
            <svg class="chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${title}">
                <defs>
                    <linearGradient id="grad-${id}" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#e2bd76" />
                        <stop offset="100%" stop-color="#98703a" />
                    </linearGradient>
                </defs>
                ${grid}
                ${bars}
                ${labels}
            </svg>
        </article>
    `;
}

// ===== Painel administrativo: estrutura compartilhada =====
const ADMIN_NAV_LINKS = [
    { href: "/admin", label: "Início" },
    { href: "/admin/users", label: "Usuários" },
    { href: "/admin/giveaways", label: "Sorteios" },
    { href: "/admin/tickets", label: "Tickets" },
    { href: "/admin/transactions", label: "Transações" },
    { href: "/admin/reconciliation", label: "Conferência de compras" },
    { href: "/admin/settings", label: "Configurações" }
];

function adminSidebarHtml(activePath) {
    const links = ADMIN_NAV_LINKS.map(link => `
        <a href="${link.href}"${link.href === activePath ? ' class="active" aria-current="page"' : ""}>${link.label}</a>
    `).join("");

    return `
        <aside class="sidebar">
            <div class="logo">
                <h1>WEIRDO'S</h1>
                <span>TREASURE</span>
            </div>

            <nav>${links}</nav>

            <div class="sidebar-footer">
                <a href="/dashboard">Voltar ao site</a>
                <a href="/logout">Sair</a>
            </div>
        </aside>
    `;
}

function renderAdminPage({ title, activePath, content, script = "" }) {
    return `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${escapeDashboardHtml(title)} - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/admin.css">
        </head>
        <body>
            <div class="admin-layout">
                ${adminSidebarHtml(activePath)}
                <main class="main-content">${content}</main>
            </div>
            ${script ? `<script>${script}</script>` : ""}
        </body>
        </html>
    `;
}

const GIVEAWAY_STATUS_LABELS = {
    draft: "Agendado",
    active: "Ativo",
    closed: "Encerrado",
    cancelled: "Cancelado"
};

const TRANSACTION_STATUS_LABELS = {
    completed: "Concluída",
    pending: "Pendente",
    failed: "Falhou",
    reconciliation_required: "Em conferência",
    refund_pending: "Devolução em andamento",
    refunded: "Pontos devolvidos"
};

const DRAW_STATUS_LABELS = {
    awaiting_response: "Aguardando resposta",
    confirmed: "Confirmado",
    expired: "Não respondeu"
};

function adminNumber(value) {
    return Number(value || 0).toLocaleString("pt-BR");
}

function adminDateTime(value) {
    if (!value) return "-";

    return new Date(value).toLocaleString("pt-BR", {
        timeZone: "America/Sao_Paulo",
        dateStyle: "short",
        timeStyle: "short"
    });
}

function adminDate(value) {
    if (!value) return "-";

    return new Date(value).toLocaleDateString("pt-BR", {
        timeZone: "America/Sao_Paulo"
    });
}

function adminBadge(status, labels) {
    const safeStatus = String(status || "").replace(/[^a-z_]/g, "");

    return `<span class="badge badge-${safeStatus}">${escapeDashboardHtml(labels[status] || status || "-")}</span>`;
}

function adminUserName(user) {
    return user?.display_name || user?.twitch_login || "Usuário desconhecido";
}

function adminAvatarHtml(user, size = "small") {
    const name = adminUserName(user);

    return user?.profile_image_url
        ? `<img class="avatar avatar-${size}" src="${escapeDashboardHtml(user.profile_image_url)}" alt="">`
        : `<span class="avatar avatar-${size}">${escapeDashboardHtml(name.charAt(0).toUpperCase())}</span>`;
}

// Lista de inscritos da live; null quando a conta do canal não está conectada ou a Twitch falha
async function getSubscriberIdsSafe() {
    if (!twitchBroadcasterAccessToken || !twitchBroadcasterId) {
        return null;
    }

    try {
        return await getCachedSubscribers();
    } catch (error) {
        console.error("Erro ao consultar inscritos:", error.message);
        return null;
    }
}

function adminSubBadge(subscriberIds, twitchId) {
    if (!subscriberIds) {
        return `<span class="badge badge-muted" title="Conecte a conta do canal para consultar os inscritos">?</span>`;
    }

    return subscriberIds.has(twitchId)
        ? `<span class="badge badge-sub">Sub</span>`
        : `<span class="badge badge-muted">Não</span>`;
}

// Script de busca nas tabelas (campo com data-filter-table="id-da-tabela")
const ADMIN_TABLE_SCRIPT = `
    document.querySelectorAll("[data-filter-table]").forEach(function (input) {
        var table = document.getElementById(input.dataset.filterTable);
        if (!table || !table.tBodies[0]) return;
        var rows = Array.prototype.slice.call(table.tBodies[0].rows).filter(function (row) {
            return !row.classList.contains("empty-row");
        });
        var counter = document.querySelector('[data-filter-count="' + input.dataset.filterTable + '"]');

        input.addEventListener("input", function () {
            var term = input.value.trim().toLowerCase();
            var visible = 0;

            rows.forEach(function (row) {
                var match = !term || row.textContent.toLowerCase().indexOf(term) !== -1;
                row.hidden = !match;
                if (match) visible++;
            });

            if (counter) counter.textContent = visible.toLocaleString("pt-BR");
        });
    });

    document.querySelectorAll("table[data-sortable]").forEach(function (table) {
        var headers = table.querySelectorAll("th[data-sort]");

        headers.forEach(function (th) {
            th.tabIndex = 0;

            var sort = function () {
                var type = th.dataset.sort;
                var dir = th.dataset.dir === "desc" ? "asc" : "desc";
                headers.forEach(function (other) { delete other.dataset.dir; });
                th.dataset.dir = dir;

                var body = table.tBodies[0];
                var index = th.cellIndex;
                var value = function (row) {
                    var cell = row.cells[index];
                    var raw = cell ? (cell.dataset.value !== undefined ? cell.dataset.value : cell.textContent) : "";
                    return type === "number" ? (Number(raw) || 0) : String(raw).trim().toLowerCase();
                };

                Array.prototype.slice.call(body.rows)
                    .sort(function (a, b) {
                        var x = value(a), y = value(b);
                        var result = x < y ? -1 : x > y ? 1 : 0;
                        return dir === "asc" ? result : -result;
                    })
                    .forEach(function (row) { body.appendChild(row); });
            };

            th.addEventListener("click", sort);
            th.addEventListener("keydown", function (event) {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    sort();
                }
            });
        });
    });
`;

// ===== Sorteios no admin: seleção, calendário e resumo =====
async function loadAdminGiveaways() {
    const { data, error } = await supabase
        .from("giveaways")
        .select("id, title, status, starts_at, ends_at")
        .order("starts_at", { ascending: false });

    if (error) throw error;

    return data || [];
}

// Sem escolha explícita: o sorteio ativo; senão o último encerrado; senão o mais recente
function pickAdminGiveaway(giveaways, requestedId) {
    if (typeof requestedId === "string") {
        const requested = giveaways.find(giveaway => giveaway.id === requestedId);
        if (requested) return requested;
    }

    const lastClosed = giveaways
        .filter(giveaway => giveaway.status === "closed")
        .sort((a, b) => new Date(b.ends_at) - new Date(a.ends_at))[0];

    return giveaways.find(giveaway => giveaway.status === "active")
        || lastClosed
        || giveaways[0]
        || null;
}

function addDaysToKey(key, amount) {
    const [year, month, day] = key.split("-").map(Number);
    return new Date(Date.UTC(year, month - 1, day + amount)).toISOString().slice(0, 10);
}

function buildGiveawayBrowserHtml({ giveaways, selected, showAll, monthParam, basePath }) {
    const todayKey = brDayKey(Date.now());
    const fallbackKey = selected ? brDayKey(selected.ends_at || selected.starts_at) : todayKey;
    const monthKey = /^\d{4}-(0[1-9]|1[0-2])$/.test(monthParam || "")
        ? monthParam
        : fallbackKey.slice(0, 7);

    const [year, month] = monthKey.split("-").map(Number);
    const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
    const firstWeekday = new Date(Date.UTC(year, month - 1, 1)).getUTCDay();
    const monthStart = `${monthKey}-01`;
    const monthEnd = `${monthKey}-${String(daysInMonth).padStart(2, "0")}`;

    const monthLabelRaw = new Date(Date.UTC(year, month - 1, 1)).toLocaleDateString("pt-BR", {
        month: "long",
        year: "numeric",
        timeZone: "UTC"
    });
    const monthLabel = monthLabelRaw.charAt(0).toUpperCase() + monthLabelRaw.slice(1);

    const shiftMonth = (delta) => new Date(Date.UTC(year, month - 1 + delta, 1)).toISOString().slice(0, 7);
    const currentParam = showAll ? "todos" : selected?.id;

    const link = ({ sorteio, mes }) => {
        const params = new URLSearchParams();
        if (sorteio) params.set("sorteio", sorteio);
        if (mes) params.set("mes", mes);
        return `${basePath}?${params.toString()}`;
    };

    const ranged = giveaways
        .filter(giveaway => giveaway.starts_at || giveaway.ends_at)
        .map(giveaway => ({
            giveaway,
            start: brDayKey(giveaway.starts_at || giveaway.ends_at),
            end: brDayKey(giveaway.ends_at || giveaway.starts_at)
        }));

    let cells = "";

    for (let i = 0; i < firstWeekday; i++) {
        cells += `<span class="cal-day is-empty" aria-hidden="true"></span>`;
    }

    for (let day = 1; day <= daysInMonth; day++) {
        const key = `${monthKey}-${String(day).padStart(2, "0")}`;
        const covering = ranged.filter(item => item.start <= key && key <= item.end);
        const classes = ["cal-day"];

        if (key === todayKey) classes.push("is-today");

        if (!covering.length) {
            cells += `<span class="${classes.join(" ")}">${day}</span>`;
            continue;
        }

        const ending = covering.filter(item => item.end === key);
        const isSelectedHere = !showAll && covering.some(item => item.giveaway.id === selected?.id);
        const target = (
            (isSelectedHere && covering.find(item => item.giveaway.id === selected.id)) ||
            ending[0] ||
            covering[0]
        ).giveaway;

        classes.push("has-giveaway");
        if (ending.length) classes.push("is-draw-day");
        if (isSelectedHere) classes.push("is-selected");

        const tooltip = covering
            .map(item => `${item.giveaway.title}${item.end === key ? " (encerramento)" : ""}`)
            .join(" • ");

        cells += `
            <a href="${link({ sorteio: target.id, mes: monthKey })}" class="${classes.join(" ")}" title="${escapeDashboardHtml(tooltip)}">
                ${day}${covering.length > 1 ? `<small>${covering.length}</small>` : ""}
            </a>
        `;
    }

    const monthGiveaways = ranged
        .filter(item => item.start <= monthEnd && item.end >= monthStart)
        .sort((a, b) => a.start.localeCompare(b.start));

    const monthList = monthGiveaways.length
        ? `<ul class="month-giveaways">${monthGiveaways.map(({ giveaway }) => `
            <li>
                <a href="${link({ sorteio: giveaway.id, mes: monthKey })}" class="${!showAll && giveaway.id === selected?.id ? "is-selected" : ""}">
                    <strong>${escapeDashboardHtml(giveaway.title)}</strong>
                    <span>${adminDate(giveaway.starts_at)} → ${adminDate(giveaway.ends_at)}</span>
                    ${adminBadge(giveaway.status, GIVEAWAY_STATUS_LABELS)}
                </a>
            </li>
        `).join("")}</ul>`
        : `<p class="muted-note">Nenhum sorteio neste mês.</p>`;

    const options = giveaways.map(giveaway => `
        <option value="${escapeDashboardHtml(giveaway.id)}"${!showAll && giveaway.id === selected?.id ? " selected" : ""}>
            ${escapeDashboardHtml(giveaway.title)} — ${adminDate(giveaway.ends_at)} (${escapeDashboardHtml(GIVEAWAY_STATUS_LABELS[giveaway.status] || giveaway.status)})
        </option>
    `).join("");

    return `
        <section class="giveaway-browser">
            <div class="calendar-card">
                <div class="calendar-header">
                    <a href="${link({ sorteio: currentParam, mes: shiftMonth(-1) })}" class="calendar-nav" aria-label="Mês anterior">‹</a>
                    <strong>${monthLabel}</strong>
                    <a href="${link({ sorteio: currentParam, mes: shiftMonth(1) })}" class="calendar-nav" aria-label="Próximo mês">›</a>
                </div>

                <div class="calendar-weekdays" aria-hidden="true">
                    <span>D</span><span>S</span><span>T</span><span>Q</span><span>Q</span><span>S</span><span>S</span>
                </div>

                <div class="calendar-grid">${cells}</div>

                <div class="calendar-legend">
                    <span><i class="legend-period"></i>Período do sorteio</span>
                    <span><i class="legend-draw"></i>Encerramento</span>
                    <span><i class="legend-selected"></i>Selecionado</span>
                </div>
            </div>

            <div class="giveaway-picker">
                <form method="GET" action="${basePath}" class="giveaway-select-form">
                    <label for="giveaway-select">Ir para o sorteio</label>
                    <div class="giveaway-select-row">
                        <select id="giveaway-select" name="sorteio" onchange="this.form.submit()">
                            <option value="todos"${showAll ? " selected" : ""}>Todos os sorteios</option>
                            ${options}
                        </select>
                        <noscript><button type="submit">Abrir</button></noscript>
                    </div>
                </form>

                <h3>Sorteios em ${monthLabel}</h3>
                ${monthList}
            </div>
        </section>
    `;
}

function computeGiveawayStats(tickets, transactions) {
    const completed = transactions.filter(transaction => transaction.status === "completed");

    return {
        tickets: tickets.length,
        participants: new Set(tickets.map(ticket => ticket.twitch_id)).size,
        points: completed.reduce((sum, transaction) => sum + (Number(transaction.points_spent) || 0), 0),
        purchases: completed.length
    };
}

function buildGiveawaySummaryHtml({ giveaway, showAll, stats, draws, namesById, basePath }) {
    const otherPage = basePath === "/admin/tickets"
        ? { href: "/admin/transactions", label: "Ver transações deste sorteio" }
        : { href: "/admin/tickets", label: "Ver tickets deste sorteio" };
    const param = showAll ? "todos" : giveaway?.id;

    const winners = (draws || []).length
        ? `
            <div class="summary-winners">
                <span class="eyebrow">RODADAS DO SORTEIO</span>
                <ul>
                    ${draws.map(draw => `
                        <li>
                            <strong>Rodada ${escapeDashboardHtml(draw.round_number)}</strong>
                            <a href="/admin/users/${encodeURIComponent(draw.winner_twitch_id)}">${escapeDashboardHtml(namesById.get(draw.winner_twitch_id) || draw.winner_twitch_id)}</a>
                            <span>ticket #${escapeDashboardHtml(draw.winning_ticket_number)}</span>
                            ${adminBadge(draw.status, DRAW_STATUS_LABELS)}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `
        : "";

    return `
        <section class="giveaway-summary-card">
            <div class="summary-head">
                <div>
                    <span class="eyebrow">${showAll ? "VISÃO GERAL" : "SORTEIO SELECIONADO"}</span>
                    <h2>${showAll ? "Todos os sorteios" : escapeDashboardHtml(giveaway.title)}</h2>
                    ${showAll ? "" : `<p>${adminDateTime(giveaway.starts_at)} até ${adminDateTime(giveaway.ends_at)}</p>`}
                </div>
                ${showAll ? "" : adminBadge(giveaway.status, GIVEAWAY_STATUS_LABELS)}
            </div>

            <div class="summary-stats">
                <div><span>Participantes</span><strong>${adminNumber(stats.participants)}</strong></div>
                <div><span>Tickets</span><strong>${adminNumber(stats.tickets)}</strong></div>
                <div><span>Pontos arrecadados</span><strong>${adminNumber(stats.points)}</strong></div>
                <div><span>Compras concluídas</span><strong>${adminNumber(stats.purchases)}</strong></div>
            </div>

            ${winners}

            <a class="summary-link" href="${otherPage.href}?sorteio=${encodeURIComponent(param || "")}">${otherPage.label} →</a>
        </section>
    `;
}

// ===== Gráficos do painel administrativo (início) =====
function niceChartScale(maxValue) {
    const raw = Math.max(maxValue, 1) / 4;
    const magnitude = 10 ** Math.floor(Math.log10(raw));
    const normalized = raw / magnitude;
    const step = Math.max(
        1,
        (normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10) * magnitude
    );

    return { step, max: step * 4 };
}

// Área acumulada desde o primeiro registro até hoje
function renderCumulativeChart({ id, title, unit, rows, getValue }) {
    const fmt = (number) => Number(number).toLocaleString("pt-BR");
    const perDay = new Map();

    for (const row of rows) {
        if (!row.created_at) continue;
        const key = brDayKey(row.created_at);
        perDay.set(key, (perDay.get(key) || 0) + getValue(row));
    }

    const total = [...perDay.values()].reduce((sum, value) => sum + value, 0);

    const header = `
        <div class="chart-card-header">
            <h3>${title}</h3>
            <span class="chart-total">${fmt(total)} ${unit} no total</span>
        </div>
    `;

    if (!perDay.size) {
        return `<article class="chart-card">${header}<p class="chart-empty">Nenhum registro ainda.</p></article>`;
    }

    const firstKey = [...perDay.keys()].sort()[0];
    const lastKey = brDayKey(Date.now());
    const points = [];
    let running = 0;

    // Começa um dia antes do primeiro registro, com zero
    for (let key = addDaysToKey(firstKey, -1); key <= lastKey; key = addDaysToKey(key, 1)) {
        running += perDay.get(key) || 0;
        points.push({ key, value: running });
        if (points.length > 3660) break;
    }

    const { step, max } = niceChartScale(running);
    const width = 800;
    const height = 260;
    const left = 66;
    const right = 14;
    const top = 14;
    const bottom = 32;
    const innerW = width - left - right;
    const innerH = height - top - bottom;
    const xAt = (index) => left + (points.length === 1 ? innerW / 2 : (innerW * index) / (points.length - 1));
    const yAt = (value) => top + innerH - (innerH * value) / max;
    const spansYears = firstKey.slice(0, 4) !== lastKey.slice(0, 4);
    const label = (key) => spansYears ? `${brDayLabel(key)}/${key.slice(2, 4)}` : brDayLabel(key);

    let grid = "";

    for (let i = 0; i <= 4; i++) {
        const y = top + innerH - (innerH * i) / 4;
        grid += `
            <line x1="${left}" y1="${y}" x2="${width - right}" y2="${y}" stroke="#55412b" stroke-width="1" ${i === 0 ? "" : 'stroke-dasharray="4 4"'} />
            <text x="${left - 8}" y="${y + 4}" text-anchor="end" font-size="11" fill="#b6a487">${fmt(step * i)}</text>
        `;
    }

    const line = points.map((point, index) => `${xAt(index).toFixed(1)},${yAt(point.value).toFixed(1)}`).join(" ");
    const area = `M${xAt(0).toFixed(1)},${top + innerH} L${line.replace(/ /g, " L")} L${xAt(points.length - 1).toFixed(1)},${top + innerH} Z`;

    const labelCount = Math.min(6, points.length);
    let labels = "";

    for (let i = 0; i < labelCount; i++) {
        const index = labelCount === 1 ? 0 : Math.round((i * (points.length - 1)) / (labelCount - 1));
        const anchor = i === 0 ? "start" : i === labelCount - 1 ? "end" : "middle";
        labels += `<text x="${xAt(index)}" y="${height - 10}" text-anchor="${anchor}" font-size="11" fill="#b6a487">${label(points[index].key)}</text>`;
    }

    const slot = innerW / points.length;
    const hovers = points.map((point, index) => `
        <rect x="${(xAt(index) - slot / 2).toFixed(1)}" y="${top}" width="${slot.toFixed(2)}" height="${innerH}" fill="transparent"><title>${brDayLabel(point.key)}/${point.key.slice(0, 4)}: ${fmt(point.value)} ${unit}</title></rect>
    `).join("");

    return `
        <article class="chart-card">
            ${header}
            <svg class="chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${title}">
                <defs>
                    <linearGradient id="area-${id}" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#d6a85c" stop-opacity="0.45" />
                        <stop offset="100%" stop-color="#d6a85c" stop-opacity="0.03" />
                    </linearGradient>
                </defs>
                ${grid}
                <path d="${area}" fill="url(#area-${id})" />
                <polyline points="${line}" fill="none" stroke="#e2bd76" stroke-width="2" stroke-linejoin="round" />
                ${labels}
                ${hovers}
            </svg>
        </article>
    `;
}

// Barras horizontais por sorteio (títulos longos cabem melhor assim)
function renderGiveawayBars({ title, unit, items }) {
    const maxValue = Math.max(0, ...items.map(item => item.value));
    const total = items.reduce((sum, item) => sum + item.value, 0);

    const header = `
        <div class="chart-card-header">
            <h3>${title}</h3>
            <span class="chart-total">${adminNumber(total)} ${unit} nos sorteios listados</span>
        </div>
    `;

    if (!items.length || maxValue === 0) {
        return `<article class="chart-card">${header}<p class="chart-empty">Nenhum sorteio com registros ainda.</p></article>`;
    }

    const rows = items.map(item => `
        <a class="hbar-row" href="${item.href}" title="${escapeDashboardHtml(item.label)}: ${adminNumber(item.value)} ${unit}">
            <span class="hbar-label">
                <strong>${escapeDashboardHtml(item.label)}</strong>
                <small>${escapeDashboardHtml(item.sublabel)}</small>
            </span>
            <span class="hbar-track"><span class="hbar-fill" style="width:${((item.value / maxValue) * 100).toFixed(1)}%"></span></span>
            <span class="hbar-value">${adminNumber(item.value)}</span>
        </a>
    `).join("");

    return `<article class="chart-card">${header}<div class="hbar-list">${rows}</div></article>`;
}

function buildAdminInsightsHtml({ users, tickets, transactions, giveaways, draws }) {
    const namesById = new Map(users.map(user => [user.twitch_id, adminUserName(user)]));

    // Agregados por sorteio
    const perGiveaway = new Map(giveaways.map(giveaway => [giveaway.id, {
        tickets: 0,
        participants: new Set(),
        points: 0,
        winners: []
    }]));

    for (const ticket of tickets) {
        const stats = perGiveaway.get(ticket.giveaway_id);
        if (!stats) continue;
        stats.tickets++;
        stats.participants.add(ticket.twitch_id);
    }

    for (const transaction of transactions) {
        const stats = perGiveaway.get(transaction.giveaway_id);
        if (stats) stats.points += Number(transaction.points_spent) || 0;
    }

    for (const draw of draws) {
        const stats = perGiveaway.get(draw.giveaway_id);
        if (stats && draw.status === "confirmed") {
            stats.winners.push(namesById.get(draw.winner_twitch_id) || draw.winner_twitch_id);
        }
    }

    // Os 15 sorteios mais recentes que tiveram movimento, do mais antigo ao mais novo
    const chartGiveaways = [...giveaways]
        .filter(giveaway => perGiveaway.get(giveaway.id).tickets > 0 || giveaway.status === "active")
        .sort((a, b) => new Date(b.starts_at) - new Date(a.starts_at))
        .slice(0, 15)
        .reverse();

    const giveawayItems = (getValue) => chartGiveaways.map(giveaway => ({
        label: giveaway.title,
        sublabel: `${adminDate(giveaway.ends_at)} · ${GIVEAWAY_STATUS_LABELS[giveaway.status] || giveaway.status}`,
        value: getValue(perGiveaway.get(giveaway.id)),
        href: `/admin/tickets?sorteio=${encodeURIComponent(giveaway.id)}`
    }));

    const dailyViews = (metric, title, unit, rows, getValue) => {
        const ranges = [7, 30, 90];

        return `
            <div class="range-filter">
                ${ranges.map(days => `<button type="button" data-days-tab="${days}"${days === 30 ? ' class="active"' : ""}>${days} dias</button>`).join("")}
            </div>
            ${ranges.map(days => `
                <div data-days="${days}"${days === 30 ? "" : " hidden"}>
                    ${renderBarChart({ id: `${metric}-d${days}`, title, unit, series: buildDailySeries(rows, days, getValue) })}
                </div>
            `).join("")}
        `;
    };

    const chartPanel = ({ metric, heading, day, giveaway, total }) => `
        <div class="insight-panel" data-panel="${metric}" hidden>
            <div class="insight-toolbar">
                <h2>${heading}</h2>
                <div class="view-tabs" role="tablist">
                    <button type="button" role="tab" data-view-tab="day" class="active" aria-selected="true">Por dia</button>
                    <button type="button" role="tab" data-view-tab="giveaway" aria-selected="false">Por sorteio</button>
                    <button type="button" role="tab" data-view-tab="total" aria-selected="false">Desde o início</button>
                </div>
            </div>
            <div data-view="day">${day}</div>
            <div data-view="giveaway" hidden>${giveaway}</div>
            <div data-view="total" hidden>${total}</div>
        </div>
    `;

    const usersPanel = chartPanel({
        metric: "users",
        heading: "Usuários",
        day: dailyViews("users", "Novos cadastros por dia", "cadastros", users, () => 1),
        giveaway: renderGiveawayBars({ title: "Participantes por sorteio", unit: "participantes", items: giveawayItems(stats => stats.participants.size) }),
        total: renderCumulativeChart({ id: "users-total", title: "Total de usuários cadastrados", unit: "usuários", rows: users, getValue: () => 1 })
    });

    const ticketsPanel = chartPanel({
        metric: "tickets",
        heading: "Tickets",
        day: dailyViews("tickets", "Tickets vendidos por dia", "tickets", tickets, () => 1),
        giveaway: renderGiveawayBars({ title: "Tickets por sorteio", unit: "tickets", items: giveawayItems(stats => stats.tickets) }),
        total: renderCumulativeChart({ id: "tickets-total", title: "Tickets vendidos desde o início", unit: "tickets", rows: tickets, getValue: () => 1 })
    });

    const pointsPanel = chartPanel({
        metric: "points",
        heading: "Pontos",
        day: dailyViews("points", "Pontos movimentados por dia", "pontos", transactions, row => Number(row.points_spent) || 0),
        giveaway: renderGiveawayBars({ title: "Pontos arrecadados por sorteio", unit: "pontos", items: giveawayItems(stats => stats.points) }),
        total: renderCumulativeChart({ id: "points-total", title: "Pontos movimentados desde o início", unit: "pontos", rows: transactions, getValue: row => Number(row.points_spent) || 0 })
    });

    const giveawayRows = [...giveaways]
        .sort((a, b) => new Date(b.starts_at) - new Date(a.starts_at))
        .map(giveaway => {
            const stats = perGiveaway.get(giveaway.id);

            return `
                <tr>
                    <td><a href="/admin/tickets?sorteio=${encodeURIComponent(giveaway.id)}">${escapeDashboardHtml(giveaway.title)}</a></td>
                    <td>${adminBadge(giveaway.status, GIVEAWAY_STATUS_LABELS)}</td>
                    <td>${adminDate(giveaway.starts_at)} → ${adminDate(giveaway.ends_at)}</td>
                    <td>${adminNumber(stats.participants.size)}</td>
                    <td>${adminNumber(stats.tickets)}</td>
                    <td>${adminNumber(stats.points)}</td>
                    <td>${stats.winners.length ? escapeDashboardHtml(stats.winners.join(", ")) : "—"}</td>
                </tr>
            `;
        }).join("");

    const giveawaysPanel = `
        <div class="insight-panel" data-panel="giveaways" hidden>
            <div class="insight-toolbar">
                <h2>Resumo por sorteio</h2>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Sorteio</th>
                            <th>Status</th>
                            <th>Período</th>
                            <th>Participantes</th>
                            <th>Tickets</th>
                            <th>Pontos</th>
                            <th>Vencedor</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${giveawayRows || `<tr class="empty-row"><td colspan="7">Nenhum sorteio criado.</td></tr>`}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    return `
        <section class="insights" id="insights" hidden>
            <button type="button" class="insights-close" data-insights-close aria-label="Fechar gráfico">Fechar ✕</button>
            ${usersPanel}
            ${giveawaysPanel}
            ${ticketsPanel}
            ${pointsPanel}
        </section>
    `;
}

const ADMIN_INSIGHTS_SCRIPT = `
    (function () {
        var insights = document.getElementById("insights");
        if (!insights) return;

        var cards = document.querySelectorAll(".stat-card[data-metric]");
        var panels = insights.querySelectorAll(".insight-panel");

        var open = function (metric, scroll) {
            var found = false;

            cards.forEach(function (card) {
                var on = card.dataset.metric === metric;
                card.classList.toggle("is-active", on);
                card.setAttribute("aria-expanded", on ? "true" : "false");
            });

            panels.forEach(function (panel) {
                var on = panel.dataset.panel === metric;
                panel.hidden = !on;
                if (on) found = true;
            });

            insights.hidden = !found;

            try {
                history.replaceState(null, "", found ? "#grafico-" + metric : location.pathname + location.search);
            } catch (error) {}

            if (found && scroll) {
                insights.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        };

        cards.forEach(function (card) {
            card.addEventListener("click", function () {
                open(card.classList.contains("is-active") ? null : card.dataset.metric, true);
            });
        });

        insights.querySelector("[data-insights-close]").addEventListener("click", function () {
            open(null, false);
        });

        panels.forEach(function (panel) {
            var viewTabs = panel.querySelectorAll("[data-view-tab]");
            var dayTabs = panel.querySelectorAll("[data-days-tab]");

            viewTabs.forEach(function (tab) {
                tab.addEventListener("click", function () {
                    viewTabs.forEach(function (other) {
                        var on = other === tab;
                        other.classList.toggle("active", on);
                        other.setAttribute("aria-selected", on ? "true" : "false");
                    });
                    panel.querySelectorAll("[data-view]").forEach(function (view) {
                        view.hidden = view.dataset.view !== tab.dataset.viewTab;
                    });
                });
            });

            dayTabs.forEach(function (tab) {
                tab.addEventListener("click", function () {
                    dayTabs.forEach(function (other) { other.classList.toggle("active", other === tab); });
                    panel.querySelectorAll("[data-days]").forEach(function (view) {
                        view.hidden = view.dataset.days !== tab.dataset.daysTab;
                    });
                });
            });
        });

        var initial = location.hash.match(/^#grafico-(\\w+)$/);
        if (initial) open(initial[1], false);
    })();
`;


if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    throw new Error("Configuração do Supabase ausente no .env");
}

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
);

app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

app.use(session({
    name: "wt.sid",
    secret: process.env.SESSION_SECRET,
    store: new SupabaseSessionStore(supabase),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: SESSION_TTL_MS
    }
}));

// Gerar ou recuperar o token CSRF da sessão
function getCsrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    }

    return req.session.csrfToken;
}

// Validar o token CSRF nas requisições POST
function requireCsrf(req, res, next) {
    const sessionToken = req.session?.csrfToken;
    const submittedToken = req.body?._csrf;

    if (
        typeof sessionToken !== "string" ||
        typeof submittedToken !== "string"
    ) {
        return res.status(403).send("Requisição inválida.");
    }

    const sessionBuffer = Buffer.from(sessionToken);
    const submittedBuffer = Buffer.from(submittedToken);

    if (
        sessionBuffer.length !== submittedBuffer.length ||
        !crypto.timingSafeEqual(sessionBuffer, submittedBuffer)
    ) {
        return res.status(403).send("Token CSRF inválido.");
    }

    next();
}

// Tamanho máximo dos textos de um sorteio
const GIVEAWAY_TITLE_MAX = 120;
const GIVEAWAY_DESCRIPTION_MAX = 2000;

// Cópia de teste no PC: DISABLE_TWITCH_CHAT=1 impede conectar ao chat e salvar tokens do canal
// (o site no ar já usa essa conexão; duas cópias conectadas duplicariam o chat)
const TWITCH_CHAT_DISABLED = process.env.DISABLE_TWITCH_CHAT === "1";

// Arena: duração do giro e tempo para o vencedor responder (contado a partir da revelação)
const ARENA_SPIN_MS = 14000;
const ARENA_RESPONSE_MS = 40000;

// Status da live (Helix GET /streams com token de aplicativo)
const LIVE_CHANNEL_LOGIN = "joao_weird";
const LIVE_CACHE_MS = 60 * 1000;
const LIVE_FETCH_TIMEOUT_MS = 2500;

let twitchAppToken = null;
let twitchAppTokenExpiresAt = 0;
let liveStreamCache = { data: null, fetchedAt: 0 };
let liveStreamPromise = null;

async function getTwitchAppToken() {
    if (twitchAppToken && Date.now() < twitchAppTokenExpiresAt - 60 * 1000) {
        return twitchAppToken;
    }

    const response = await fetch("https://id.twitch.tv/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: process.env.TWITCH_CLIENT_ID,
            client_secret: process.env.TWITCH_CLIENT_SECRET,
            grant_type: "client_credentials"
        }),
        signal: AbortSignal.timeout(LIVE_FETCH_TIMEOUT_MS)
    });

    if (!response.ok) {
        throw new Error(`Falha ao obter token de aplicativo da Twitch (${response.status}).`);
    }

    const data = await response.json();
    twitchAppToken = data.access_token;
    twitchAppTokenExpiresAt = Date.now() + (Number(data.expires_in) || 3600) * 1000;

    return twitchAppToken;
}

async function twitchHelixGet(pathAndQuery, retry = true) {
    const token = await getTwitchAppToken();

    const response = await fetch(`https://api.twitch.tv/helix/${pathAndQuery}`, {
        headers: {
            "Client-Id": process.env.TWITCH_CLIENT_ID,
            Authorization: `Bearer ${token}`
        },
        signal: AbortSignal.timeout(LIVE_FETCH_TIMEOUT_MS)
    });

    if (response.status === 401 && retry) {
        twitchAppToken = null;
        return twitchHelixGet(pathAndQuery, false);
    }

    if (!response.ok) {
        throw new Error(`Falha ao consultar a Twitch (${response.status}).`);
    }

    return response.json();
}

// Foto e id do canal mudam pouco: cache de 6 horas
let liveChannelProfileCache = { data: null, fetchedAt: 0 };

async function getLiveChannelProfile() {
    if (liveChannelProfileCache.data && Date.now() - liveChannelProfileCache.fetchedAt < 6 * 60 * 60 * 1000) {
        return liveChannelProfileCache.data;
    }

    const data = await twitchHelixGet(`users?login=${encodeURIComponent(LIVE_CHANNEL_LOGIN)}`);
    const user = Array.isArray(data.data) ? data.data[0] : null;

    if (!user) {
        throw new Error("Canal não encontrado na Twitch.");
    }

    liveChannelProfileCache = {
        data: {
            id: user.id,
            displayName: user.display_name || LIVE_CHANNEL_LOGIN,
            profileImageUrl: user.profile_image_url || ""
        },
        fetchedAt: Date.now()
    };

    return liveChannelProfileCache.data;
}

// { online: true, ... } quando ao vivo; { online: false, ... } quando offline
async function fetchLiveStream() {
    const data = await twitchHelixGet(`streams?user_login=${encodeURIComponent(LIVE_CHANNEL_LOGIN)}`);
    const stream = Array.isArray(data.data) ? data.data[0] : null;

    if (stream && stream.type === "live") {
        return {
            online: true,
            title: stream.title || "",
            gameName: stream.game_name || "",
            viewerCount: Number(stream.viewer_count) || 0,
            thumbnailUrl: String(stream.thumbnail_url || "")
                .replace("{width}", "160")
                .replace("{height}", "90")
        };
    }

    const offline = { online: false, displayName: LIVE_CHANNEL_LOGIN, profileImageUrl: "", lastTitle: "", lastGame: "" };

    // Foto do canal e título/jogo da última live; se falhar, a faixa aparece só com o básico
    try {
        const profile = await getLiveChannelProfile();
        offline.displayName = profile.displayName;
        offline.profileImageUrl = profile.profileImageUrl;

        const channelData = await twitchHelixGet(`channels?broadcaster_id=${encodeURIComponent(profile.id)}`);
        const channel = Array.isArray(channelData.data) ? channelData.data[0] : null;

        if (channel) {
            offline.lastTitle = channel.title || "";
            offline.lastGame = channel.game_name || "";
        }
    } catch (error) {
        console.error("Erro ao buscar dados do canal offline:", error.message);
    }

    return offline;
}

// Nunca lança erro: em caso de falha a página simplesmente não mostra a faixa.
async function getLiveStreamStatus() {
    if (Date.now() - liveStreamCache.fetchedAt < LIVE_CACHE_MS) {
        return liveStreamCache.data;
    }

    if (!liveStreamPromise) {
        liveStreamPromise = fetchLiveStream()
            .then((data) => {
                liveStreamCache = { data, fetchedAt: Date.now() };
                return data;
            })
            .catch((error) => {
                console.error("Erro ao verificar a live:", error.message);
                // Evita repetir a consulta a cada acesso enquanto a API falha.
                liveStreamCache = { data: null, fetchedAt: Date.now() };
                return null;
            })
            .finally(() => {
                liveStreamPromise = null;
            });
    }

    return liveStreamPromise;
}

// Página inicial
app.get("/", async (req, res) => {
    const now = new Date().toISOString();

    const escapeHtml = (value) => String(value ?? "").replace(
        /[&<>"']/g,
        (char) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[char]
    );

    const formatDate = (date) => {
        if (!date) return "-";

        return new Date(date).toLocaleString("pt-BR", {
            timeZone: "America/Sao_Paulo",
            dateStyle: "short",
            timeStyle: "short"
        });
    };

    // Sorteio ativo, próximos sorteios agendados e status da live, em paralelo
    const [activeResult, upcomingResult, liveStream] = await Promise.all([
        supabase
            .from("giveaways")
            .select("id, title, description, starts_at, ends_at")
            .eq("status", "active")
            .order("starts_at", { ascending: false })
            .limit(1)
            .maybeSingle(),
        supabase
            .from("giveaways")
            .select("id, title, description, starts_at, ends_at")
            .eq("status", "draft")
            .gt("starts_at", now)
            .order("starts_at", { ascending: true })
            .limit(3),
        getLiveStreamStatus()
    ]);

    const { data: activeGiveaway, error: activeError } = activeResult;

    if (activeError) {
        console.error("Erro ao buscar sorteio ativo:", activeError.message);
        return res.status(500).send("Não foi possível carregar os sorteios.");
    }

    const { data: upcomingData, error: upcomingError } = upcomingResult;

    if (upcomingError) {
        console.error("Erro ao buscar próximos sorteios:", upcomingError.message);
        return res.status(500).send("Não foi possível carregar os sorteios.");
    }

    const upcomingGiveaways = upcomingData || [];

    const purchaseUrl = req.session.twitchUser
    ? "/giveaways"
    : "/auth/twitch?returnTo=%2Fgiveaways";

    const renderTreasureBanner = (giveaway, isActive) => `
        <article class="treasure-banner${isActive ? "" : " treasure-banner-upcoming"}">
            <div class="treasure-art">
                ${TREASURE_CHEST_SVG}
            </div>

            <div class="treasure-info">
                <span class="giveaway-status ${isActive ? "active-status" : "next-status"}">
                    ${isActive ? "SORTEIO ATIVO" : "PRÓXIMO SORTEIO"}
                </span>

                <h3>${escapeHtml(giveaway.title)}</h3>

                <div class="treasure-prize">
                    <span class="treasure-label">PRÊMIO / DETALHES</span>
                    <p>${escapeHtml(giveaway.description || "Um grande tesouro espera pelo vencedor!")}</p>
                </div>

                <div class="treasure-dates">
                    <div>
                        <span>INÍCIO</span>
                        <strong>${formatDate(giveaway.starts_at)}</strong>
                    </div>

                    <div>
                        <span>ENCERRAMENTO</span>
                        <strong>${formatDate(giveaway.ends_at)}</strong>
                    </div>
                </div>

                ${isActive
                    ? `<a href="${purchaseUrl}" class="treasure-buy-button">COMPRE SEUS TICKETS</a>`
                    : `<button type="button" class="treasure-buy-button treasure-buy-button-disabled" disabled>EM BREVE</button>`}
            </div>
        </article>
    `;

    const offlineStrip = liveStream && !liveStream.online ? `
        <a href="https://www.twitch.tv/${LIVE_CHANNEL_LOGIN}" target="_blank" rel="noopener noreferrer" class="live-strip live-strip-offline" aria-label="Abrir o canal na Twitch">
            ${liveStream.profileImageUrl
                ? `<img src="${escapeHtml(liveStream.profileImageUrl)}" alt="" class="live-strip-avatar">`
                : ""}
            <span class="live-strip-badge is-offline"><i></i>OFFLINE</span>
            <span class="live-strip-text">
                <strong>A live está offline no momento</strong>
                <small>${liveStream.lastTitle
                    ? `Última live: ${escapeHtml(liveStream.lastTitle)}${liveStream.lastGame ? ` · ${escapeHtml(liveStream.lastGame)}` : ""}`
                    : "Siga o canal para ser avisado quando a live começar."}</small>
            </span>
            <span class="live-strip-cta">Ir para o canal ↗</span>
        </a>
    ` : "";

    const liveStrip = !liveStream ? "" : !liveStream.online ? offlineStrip : `
        <a href="https://www.twitch.tv/${LIVE_CHANNEL_LOGIN}" target="_blank" rel="noopener noreferrer" class="live-strip" aria-label="Assistir à live na Twitch">
            ${liveStream.thumbnailUrl
                ? `<img src="${escapeHtml(liveStream.thumbnailUrl)}" alt="" class="live-strip-thumb">`
                : ""}
            <span class="live-strip-badge"><i></i>AO VIVO</span>
            <span class="live-strip-text">
                <strong>${escapeHtml(liveStream.title || "Live no ar!")}</strong>
                ${liveStream.gameName ? `<small>${escapeHtml(liveStream.gameName)}</small>` : ""}
            </span>
            <span class="live-strip-viewers" title="Espectadores">
                👁 ${liveStream.viewerCount.toLocaleString("pt-BR")}
            </span>
        </a>
    `;

    const sessionUser = req.session.twitchUser;

    const headerAccount = sessionUser
        ? `
            <a href="/dashboard" class="user-avatar-link" title="Minha conta" aria-label="Minha conta">
                ${
                    sessionUser.profileImageUrl
                        ? `<img src="${escapeHtml(sessionUser.profileImageUrl)}" alt="Minha conta">`
                        : `<span>${escapeHtml(String(sessionUser.displayName || sessionUser.login || "?").charAt(0).toUpperCase())}</span>`
                }
            </a>
        `
        : `
                <a href="/auth/twitch" class="twitch-login">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path fill="currentColor" d="M6.429 0 2.143 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0H6.429zm13.714 11.143-3.428 3.428h-3.429l-3 3v-3H6.429V1.714h13.714v9.429zM11.571 4.714h1.715v5.143h-1.715V4.714zm4.714 0H18v5.143h-1.715V4.714z"/>
                    </svg>
                    Entrar com Twitch
                </a>
        `;

    res.send(withPublicSidebar(req, `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/home.css">
            <style>
                .user-avatar-link {
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    width: 52px;
                    height: 52px;
                    overflow: hidden;
                    border: 2px solid #d6a85c;
                    border-radius: 50%;
                    background: #30251b;
                    color: #e2bd7b;
                    font-size: 22px;
                    font-weight: bold;
                    text-decoration: none;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, .4);
                    transition: transform .2s, box-shadow .2s;
                }

                .user-avatar-link:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 0 0 3px rgba(214, 168, 92, .25), 0 4px 12px rgba(0, 0, 0, .5);
                }

                .user-avatar-link img {
                    display: block;
                    width: 100%;
                    height: 100%;
                    object-fit: cover;
                }

                .hero-rules {
                    width: 100%;
                    max-width: 650px;
                    margin-top: 10px;
                    text-align: left;
                }

                .hero-rules-title {
                    display: block;
                    margin-bottom: 14px;
                    color: #d6ad69;
                    text-align: center;
                    font-size: 13px;
                    font-weight: bold;
                    letter-spacing: 3px;
                }

                .hero-rules ul {
                    display: grid;
                    gap: 10px;
                    margin: 0;
                    padding: 0;
                    list-style: none;
                }

                .hero-rules li {
                    position: relative;
                    padding: 12px 14px 12px 40px;
                    background: rgba(0, 0, 0, 0.22);
                    border-left: 3px solid #b78b4b;
                    color: #c5b69f;
                    font-size: 15px;
                    line-height: 1.6;
                }

                .hero-rules li::before {
                    content: "✦";
                    position: absolute;
                    left: 14px;
                    top: 12px;
                    color: #d6a85c;
                }
            </style>
        </head>

        <body>
            <header class="home-header">
                <a href="/" class="home-logo">
                    <span>WEIRDO'S</span>
                    <small>TREASURE</small>
                </a>

                ${headerAccount}
            </header>

            <main class="home-content">
                ${liveStrip}

<section class="giveaways-section">
    <h2>O Tesouro da Vez</h2>
    <p class="section-description">
        Uma nova oportunidade de conquistar grandes tesouros!
    </p>

    ${activeGiveaway
        ? renderTreasureBanner(activeGiveaway, true)
        : `
            <div class="empty-giveaway">
                <h3>Nenhum sorteio ativo no momento</h3>
                <p>Fique de olho! Novos tesouros podem surgir em breve.</p>
            </div>
        `}

    ${upcomingGiveaways.length ? `
        <div class="upcoming-giveaways">
            <h3 class="upcoming-title">✦ Próximos Sorteios</h3>
            ${upcomingGiveaways.map((giveaway) => renderTreasureBanner(giveaway, false)).join("")}
        </div>
    ` : ""}
</section>

                <section class="hero">
                    <p class="hero-eyebrow">AVENTURE-SE E CONQUISTE</p>
                    <h1>WEIRDO'S TREASURE</h1>
                    <div class="hero-rules">
                        <span class="hero-rules-title">COMO PARTICIPAR?</span>
                        <ul>
                            <li>Para participar dos sorteios, acumule pontos assistindo à live. Pode deixá-la mutada!</li>
                            <li>Na hora do sorteio, você precisa estar seguindo o canal.</li>
                            <li>Fique online: se for sorteado, você precisa responder no chat da live.</li>
                        </ul>
                    </div>
                    <a href="${sessionUser ? "/dashboard" : "/auth/twitch"}" class="hero-button">Começar minha aventura</a>
                </section>
            </main>

            <footer class="home-footer">
                <span>WEIRDO'S TREASURE</span>
                <p>Que a sorte esteja ao seu lado, aventureiro!</p>
            </footer>
        </body>
        </html>
    `, "/"));
});

/// Permissões necessárias só para a conta do canal (chat e lista de inscritos)
const BROADCASTER_SCOPES = ["channel:read:subscriptions", "user:read:chat"];

// Iniciar login com Twitch
// Usuários comuns não precisam de nenhuma permissão extra.
// /auth/twitch?canal=1 pede as permissões do canal (usado só pelo administrador).
app.get("/auth/twitch", authLimiter, (req, res) => {
    // Só destinos internos conhecidos
    const returnTo = req.query.returnTo;
    const connectChannel = req.query.canal === "1";

    req.session.postLoginRedirect = connectChannel
        ? "/admin/giveaways"
        : ["/giveaways", "/minigame"].includes(returnTo) ? returnTo : "/dashboard";

    const state = crypto.randomBytes(16).toString("hex");

    req.session.oauthState = state;
    req.session.oauthConnectChannel = connectChannel;

    const params = new URLSearchParams({
        client_id: process.env.TWITCH_CLIENT_ID,
        redirect_uri: process.env.TWITCH_REDIRECT_URI,
        response_type: "code",
        scope: connectChannel ? BROADCASTER_SCOPES.join(" ") : "",
        state: state
    });

    if (connectChannel) {
        params.set("force_verify", "true");
    }

    res.redirect(
        `https://id.twitch.tv/oauth2/authorize?${params.toString()}`
    );
});

// Recriar a sessão no login (evita fixação de sessão)
function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((error) => error ? reject(error) : resolve());
    });
}

// Retorno da Twitch
app.get("/auth/twitch/callback", authLimiter, async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        return res.status(400).send("Autorização cancelada.");
    }

    if (
        typeof code !== "string" ||
        typeof state !== "string" ||
        typeof req.session.oauthState !== "string" ||
        state !== req.session.oauthState
    ) {
        return res.status(400).send("Falha na validação do login.");
    }

    const postLoginRedirect = req.session.postLoginRedirect || "/dashboard";
    const connectChannel = req.session.oauthConnectChannel === true;

    delete req.session.oauthState;
    delete req.session.oauthConnectChannel;

    try {
        // Trocar o código por um token
        const tokenResponse = await fetch(
            "https://id.twitch.tv/oauth2/token",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: new URLSearchParams({
                    client_id: process.env.TWITCH_CLIENT_ID,
                    client_secret: process.env.TWITCH_CLIENT_SECRET,
                    code: code,
                    grant_type: "authorization_code",
                    redirect_uri: process.env.TWITCH_REDIRECT_URI
                })
            }
        );

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok || !tokenData.access_token) {
            console.error("Erro ao obter token da Twitch:", tokenResponse.status);
            return res.status(401).send("Não foi possível validar a autorização.");
        }

        // Validar o token na Twitch
        const validationResponse = await fetch(
            "https://id.twitch.tv/oauth2/validate",
            {
                headers: {
                    "Authorization": `OAuth ${tokenData.access_token}`
                }
            }
        );

        const validationData = await validationResponse.json();

        if (
            !validationResponse.ok ||
            validationData.client_id !== process.env.TWITCH_CLIENT_ID
        ) {
            return res.status(401).send("Token inválido.");
        }

        // Buscar os dados do usuário
        const userResponse = await fetch(
            "https://api.twitch.tv/helix/users",
            {
                headers: {
                    "Client-Id": process.env.TWITCH_CLIENT_ID,
                    "Authorization": `Bearer ${tokenData.access_token}`
                }
            }
        );

        const userData = await userResponse.json();

        if (!userResponse.ok || !userData.data?.length) {
            return res.status(401).send("Não foi possível identificar o usuário.");
        }

        const user = userData.data[0];

        const { error: userSaveError } = await supabase
            .from("users")
            .upsert({
                twitch_id: user.id,
                twitch_login: user.login,
                display_name: user.display_name,
                profile_image_url: user.profile_image_url
            }, {
                onConflict: "twitch_id"
            });

        if (userSaveError) {
            console.error("Erro ao salvar usuário:", userSaveError.message);
            return res.status(500).send("Não foi possível salvar seu cadastro.");
        }

        const isAdmin = Boolean(
            process.env.ADMIN_TWITCH_ID &&
            user.id === process.env.ADMIN_TWITCH_ID
        );

        // Conectar o canal (chat e inscritos) somente quando o administrador
        // entrou pelo link do canal e autorizou todas as permissões
        const grantedScopes = Array.isArray(validationData.scopes) ? validationData.scopes : [];
        const hasBroadcasterScopes = BROADCASTER_SCOPES.every(scope => grantedScopes.includes(scope));

        if (isAdmin && connectChannel && hasBroadcasterScopes && tokenData.refresh_token && !TWITCH_CHAT_DISABLED) {
            const expiresAt = Date.now() + (Number(tokenData.expires_in) * 1000);

            await saveTwitchBroadcasterTokens(
                user.id,
                tokenData.access_token,
                tokenData.refresh_token,
                expiresAt
            );

            twitchBroadcasterAccessToken = tokenData.access_token;
            twitchBroadcasterRefreshToken = tokenData.refresh_token;
            twitchBroadcasterTokenExpiresAt = expiresAt;
            twitchBroadcasterId = user.id;
            twitchSubscribersLastUpdate = 0;

            connectTwitchChat(tokenData.access_token, user.id);

            console.log("Canal da Twitch conectado pelo administrador.");
        }

        // Nova sessão a cada login; os tokens do usuário não ficam guardados nela
        await regenerateSession(req);

        req.session.twitchUser = {
            id: user.id,
            login: user.login,
            displayName: user.display_name,
            profileImageUrl: user.profile_image_url
        };

        req.session.save(() => res.redirect(postLoginRedirect));

    } catch (err) {
        console.error("Erro na autenticação:", err.message);
        res.status(500).send("Erro interno durante a autenticação.");
    }
});

function escapeDashboardHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

// Painel do usuário
app.get("/dashboard", async (req, res) => {

    // Verificar se o usuário está autenticado
    if (!req.session.twitchUser) {
        return res.redirect("/");
    }

    const user = req.session.twitchUser;

    // Consultar saldo no StreamElements
    let points = null;

    try {
        const channelId = await getStreamElementsChannelId();
        points = await getStreamElementsPoints(channelId, user.login);
    } catch (error) {
        console.error("Erro ao buscar pontos:", error.message);
    }

    // Histórico do usuário: compras, tickets, sorteios vencidos, cadastro e configurações
    const [transactions, ticketCountResult, drawsResult, profileResult, settingsResult, subscriberIds] = await Promise.all([
        fetchAllRows((from, to) => supabase
            .from("transactions")
            .select("giveaway_id, points_spent, tickets_purchased, status, created_at")
            .eq("twitch_id", user.id)
            .order("created_at", { ascending: false })
            .range(from, to)),
        supabase
            .from("tickets")
            .select("id", { count: "exact", head: true })
            .eq("twitch_id", user.id),
        supabase
            .from("giveaway_draws")
            .select("giveaway_id, status, drawn_at, response_deadline_at, winner_responded_at")
            .eq("winner_twitch_id", user.id)
            .order("drawn_at", { ascending: false }),
        supabase
            .from("users")
            .select("created_at")
            .eq("twitch_id", user.id)
            .maybeSingle(),
        supabase
            .from("system_settings")
            .select("points_per_ticket, subscriber_multiplier")
            .eq("id", 1)
            .maybeSingle(),
        getSubscriberIdsSafe()
    ]);

    if (ticketCountResult.error) console.error("Erro ao contar tickets do usuário:", ticketCountResult.error.message);
    if (drawsResult.error) console.error("Erro ao buscar sorteios do usuário:", drawsResult.error.message);

    const draws = drawsResult.data || [];
    const completedTransactions = transactions.filter(transaction => transaction.status === "completed");
    const totalTickets = ticketCountResult.count || 0;
    const totalPointsSpent = completedTransactions.reduce((sum, transaction) => sum + Number(transaction.points_spent || 0), 0);
    const giveawaysJoined = new Set(completedTransactions.map(transaction => transaction.giveaway_id)).size;
    const wins = draws.filter(draw => draw.status === "confirmed");
    const pendingDraw = draws.find(draw =>
        draw.status === "awaiting_response" &&
        (!draw.response_deadline_at || new Date(draw.response_deadline_at) > new Date())
    );
    const memberSince = profileResult.data?.created_at || null;

    const pointsPerTicket = Number(settingsResult.data?.points_per_ticket || 0);
    const subscriberMultiplier = Number(settingsResult.data?.subscriber_multiplier || 1);
    const affordableTickets = points !== null && pointsPerTicket > 0 ? Math.floor(points / pointsPerTicket) : null;
    const isSubscriber = subscriberIds ? subscriberIds.has(user.id) : null;

    // Títulos dos sorteios citados nas compras e vitórias
    const recentTransactions = transactions.slice(0, 6);
    const titleIds = [...new Set([
        ...recentTransactions.map(transaction => transaction.giveaway_id),
        ...draws.map(draw => draw.giveaway_id)
    ].filter(Boolean))];
    const giveawayTitles = new Map();

    if (titleIds.length > 0) {
        const { data: titleRows, error: titleError } = await supabase
            .from("giveaways")
            .select("id, title")
            .in("id", titleIds);

        if (titleError) console.error("Erro ao buscar títulos dos sorteios:", titleError.message);

        for (const row of titleRows || []) giveawayTitles.set(row.id, row.title);
    }

    const giveawayTitle = (id) => escapeDashboardHtml(giveawayTitles.get(id) || "Sorteio removido");

    const subscriberHtml = isSubscriber === null
        ? ""
        : isSubscriber
            ? `<div class="account-sub account-sub-yes">
                    <strong>★ Você é sub da live</strong>
                    <span>${subscriberMultiplier > 1 ? `Cada ticket seu vale ${adminNumber(subscriberMultiplier)}x chances no sorteio.` : "Obrigado pelo apoio ao canal!"}</span>
               </div>`
            : `<div class="account-sub">
                    <strong>Você ainda não é sub</strong>
                    <span>${subscriberMultiplier > 1 ? `Subs têm ${adminNumber(subscriberMultiplier)}x chances com cada ticket.` : "Seja sub e apoie o canal!"}</span>
               </div>`;

    const pendingDrawHtml = pendingDraw ? `
        <section class="account-alert">
            <span class="account-alert-icon">🏆</span>
            <div>
                <strong>Você foi sorteado em ${giveawayTitle(pendingDraw.giveaway_id)}!</strong>
                <p>Responda no chat da live${pendingDraw.response_deadline_at ? ` até <b>${escapeDashboardHtml(adminDateTime(pendingDraw.response_deadline_at))}</b>` : ""} para confirmar o prêmio.</p>
            </div>
            <a href="https://www.twitch.tv/${LIVE_CHANNEL_LOGIN}" target="_blank" rel="noopener noreferrer">Ir para a live ↗</a>
        </section>
    ` : "";

    const transactionStatusText = {
        completed: "Concluída",
        pending: "Processando",
        failed: "Não concluída",
        reconciliation_required: "Em conferência",
        refund_pending: "Devolução em andamento",
        refunded: "Pontos devolvidos"
    };

    const purchasesHtml = recentTransactions.length === 0
        ? `<p class="account-empty">Você ainda não comprou tickets. <a href="/giveaways">Ver sorteios</a></p>`
        : `<ul class="account-list">
            ${recentTransactions.map(transaction => `
                <li>
                    <div>
                        <strong>${giveawayTitle(transaction.giveaway_id)}</strong>
                        <span>${escapeDashboardHtml(adminDateTime(transaction.created_at))}</span>
                    </div>
                    <div class="account-list-right">
                        <strong>${adminNumber(transaction.tickets_purchased)} ${Number(transaction.tickets_purchased) === 1 ? "ticket" : "tickets"}</strong>
                        <span>${adminNumber(transaction.points_spent)} pontos</span>
                        ${transaction.status !== "completed"
                            ? `<em class="account-status account-status-${String(transaction.status).replace(/[^a-z_]/g, "")}">${escapeDashboardHtml(transactionStatusText[transaction.status] || transaction.status)}</em>`
                            : ""}
                    </div>
                </li>
            `).join("")}
           </ul>`;

    const winsHtml = wins.length === 0
        ? `<p class="account-empty">Nenhuma vitória ainda. Continue participando, o próximo tesouro pode ser seu!</p>`
        : `<ul class="account-list">
            ${wins.map(draw => `
                <li>
                    <div>
                        <strong>🏆 ${giveawayTitle(draw.giveaway_id)}</strong>
                        <span>Sorteado em ${escapeDashboardHtml(adminDate(draw.drawn_at))}</span>
                    </div>
                </li>
            `).join("")}
           </ul>`;

    res.send(withPublicSidebar(req, `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Minha conta - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/home.css">

<style>
    .dashboard-page {
        width: min(100% - 40px, 1100px);
        margin: 45px auto;
        color: #e8d8bd;
    }

    .dashboard-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        align-items: center;
        gap: 30px;
        padding: 30px;
        margin-bottom: 25px;
        background: linear-gradient(145deg, #30251b, #1d1712);
        border: 2px solid #8b683c;
        border-radius: 10px;
        box-shadow: 0 8px 25px rgba(0,0,0,.3);
    }

    .dashboard-eyebrow {
        color: #d6ad69;
        font-size: 11px;
        letter-spacing: 2px;
        font-weight: bold;
    }

    .dashboard-header h1 {
        margin: 12px 0;
        color: #e2bd76;
        font-size: clamp(27px, 4vw, 38px);
    }

    .dashboard-header p {
        color: #c8baa4;
        line-height: 1.6;
    }

    .dashboard-header-row {
        display: flex;
        flex-wrap: wrap;
        align-items: stretch;
        gap: 14px;
        margin-top: 22px;
    }

    .dashboard-balance {
        padding: 16px 24px;
        background: rgba(0, 0, 0, 0.22);
        border-left: 3px solid #b78b4b;
    }

    .dashboard-balance span {
        display: block;
        color: #d6ad69;
        font-size: 12px;
        letter-spacing: 2px;
    }

    .dashboard-balance strong {
        display: block;
        margin-top: 8px;
        color: #f0d49b;
        font-size: 34px;
    }

    .dashboard-balance small {
        display: block;
        margin-top: 6px;
        color: #a99578;
        font-size: 13px;
    }

    .account-sub {
        display: flex;
        flex-direction: column;
        justify-content: center;
        gap: 6px;
        max-width: 280px;
        padding: 16px 20px;
        background: rgba(0, 0, 0, 0.22);
        border: 1px solid #51402a;
        border-radius: 7px;
    }

    .account-sub strong {
        color: #e2bd76;
        font-size: 15px;
    }

    .account-sub span {
        color: #c8baa4;
        font-size: 13px;
        line-height: 1.5;
    }

    .dashboard-profile .account-sub {
        margin-top: 6px;
        max-width: 230px;
        padding: 12px 14px;
        text-align: center;
    }

    .dashboard-profile .account-sub span {
        display: block;
        color: #c8baa4;
        font-size: 12px;
    }

    .account-sub-yes {
        border-color: #8a6bc4;
        background: rgba(120, 90, 180, .14);
    }

    .account-sub-yes strong {
        color: #cdb6f5;
    }

    .dashboard-profile {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 10px;
        min-width: 150px;
        padding-left: 30px;
        text-align: center;
        border-left: 1px solid rgba(198,157,92,.3);
    }

    .dashboard-profile img {
        width: 90px;
        height: 90px;
        object-fit: cover;
        border: 2px solid #d6ad69;
        border-radius: 50%;
    }

    .dashboard-avatar-fallback {
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        width: 90px;
        height: 90px;
        background: #211912;
        border: 2px solid #d6ad69;
        border-radius: 50%;
        color: #e2bd76;
        font-size: 38px;
        font-weight: bold;
    }

    .dashboard-profile strong {
        display: block;
        color: #e2bd76;
        font-size: 19px;
        margin-bottom: 6px;
    }

    .dashboard-profile div > span {
        display: block;
        color: #c8baa4;
        font-size: 13px;
    }

    .dashboard-profile small {
        display: block;
        margin-top: 4px;
        color: #a99578;
        font-size: 12px;
    }

    .account-alert {
        display: flex;
        align-items: center;
        gap: 18px;
        margin-bottom: 25px;
        padding: 20px 24px;
        background: linear-gradient(145deg, #4a3818, #2a1f12);
        border: 2px solid #e2bd76;
        border-radius: 10px;
        box-shadow: 0 0 22px rgba(226,189,118,.25);
    }

    .account-alert-icon {
        font-size: 34px;
    }

    .account-alert div {
        flex: 1;
        min-width: 0;
    }

    .account-alert strong {
        color: #f0d49b;
        font-size: 18px;
        overflow-wrap: anywhere;
    }

    .account-alert p {
        margin: 6px 0 0;
        color: #e8dfcf;
        line-height: 1.5;
    }

    .account-alert a {
        padding: 11px 18px;
        background: linear-gradient(180deg, #c99b53, #98703a);
        border: 1px solid #f0d49b;
        border-radius: 6px;
        color: #21170c;
        font-weight: bold;
        text-decoration: none;
        white-space: nowrap;
    }

    .dashboard-section-title {
        margin: 30px 0 18px;
        color: #e2bd76;
        font-size: 20px;
    }

    .account-stats {
        display: grid;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        gap: 14px;
    }

    .account-stat {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding: 18px;
        background: linear-gradient(145deg, #30251b, #1d1712);
        border: 1px solid #705332;
        border-radius: 9px;
    }

    .account-stat span {
        color: #a99578;
        font-size: 10px;
        font-weight: bold;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    .account-stat strong {
        color: #f0d49b;
        font-size: 26px;
    }

    .account-panels {
        display: grid;
        grid-template-columns: 3fr 2fr;
        gap: 18px;
        margin-top: 30px;
    }

    .account-panel {
        padding: 22px;
        background: linear-gradient(145deg, #30251b, #1d1712);
        border: 1px solid #8b683c;
        border-radius: 10px;
    }

    .account-panel-header {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 14px;
    }

    .account-panel h2 {
        margin: 0;
        color: #e2bd76;
        font-size: 18px;
    }

    .account-panel-header a,
    .account-empty a {
        color: #d6a85c;
        font-size: 13px;
    }

    .account-list {
        display: grid;
        gap: 8px;
        margin: 0;
        padding: 0;
        list-style: none;
    }

    .account-list li {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 14px;
        padding: 12px 14px;
        background: rgba(0,0,0,.22);
        border-left: 3px solid #705332;
        border-radius: 4px;
    }

    .account-list li > div {
        display: flex;
        flex-direction: column;
        gap: 4px;
        min-width: 0;
    }

    .account-list strong {
        color: #e8dfcf;
        font-size: 15px;
        overflow-wrap: anywhere;
    }

    .account-list span {
        color: #a99578;
        font-size: 12px;
    }

    .account-list .account-list-right {
        align-items: flex-end;
        text-align: right;
        flex-shrink: 0;
    }

    .account-list-right strong {
        color: #e2bd76;
    }

    .account-status {
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-style: normal;
        background: rgba(201,155,83,.15);
        color: #e2bd76;
    }

    .account-status-failed {
        background: rgba(170,60,50,.2);
        color: #f0a59a;
    }

    .account-empty {
        margin: 0;
        color: #c8baa4;
        font-style: italic;
        line-height: 1.6;
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 18px;
    }

    .dashboard-card {
        display: flex;
        flex-direction: column;
        justify-content: center;
        min-height: 120px;
        padding: 22px;
        box-sizing: border-box;
        background: linear-gradient(145deg, #30251b, #1d1712);
        border: 1px solid #8b683c;
        border-radius: 9px;
        color: #e2bd76;
        text-decoration: none;
        transition: transform .2s, border-color .2s, filter .2s;
    }

    .dashboard-card:hover {
        transform: translateY(-4px);
        border-color: #e2bd76;
        filter: brightness(1.15);
    }

    .dashboard-card strong {
        margin-bottom: 10px;
        font-size: 17px;
    }

    .dashboard-card span {
        color: #c8baa4;
        font-size: 13px;
        line-height: 1.5;
    }

    .dashboard-logout {
        display: inline-flex;
        margin-top: 30px;
        padding: 12px 22px;
        border: 1px solid #806039;
        border-radius: 6px;
        color: #d6ad69;
        text-decoration: none;
        transition: background .2s;
    }

    .dashboard-logout:hover {
        background: rgba(198,157,92,.12);
    }

    @media(max-width: 900px) {
        .account-stats {
            grid-template-columns: repeat(3, minmax(0, 1fr));
        }

        .account-panels {
            grid-template-columns: 1fr;
        }
    }

    @media(max-width: 600px) {
        .dashboard-page {
            width: calc(100% - 24px);
            margin: 25px auto;
        }

        .dashboard-header {
            grid-template-columns: 1fr;
            gap: 20px;
            padding: 20px;
        }

        .dashboard-profile {
            order: -1;
            flex-direction: row;
            justify-content: flex-start;
            gap: 16px;
            min-width: 0;
            padding: 0 0 18px;
            text-align: left;
            border-left: 0;
            border-bottom: 1px solid rgba(198,157,92,.3);
        }

        .dashboard-profile img,
        .dashboard-avatar-fallback {
            width: 60px;
            height: 60px;
        }

        .dashboard-avatar-fallback {
            font-size: 26px;
        }

        .dashboard-profile {
            flex-wrap: wrap;
        }

        .dashboard-balance,
        .account-sub,
        .dashboard-profile .account-sub {
            flex: 1 1 100%;
            max-width: none;
            text-align: left;
        }

        .account-alert {
            flex-wrap: wrap;
            padding: 18px;
        }

        .account-alert a {
            width: 100%;
            text-align: center;
        }

        .account-stats {
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }

        .account-stat {
            padding: 14px;
        }

        .account-stat strong {
            font-size: 22px;
        }

        .account-stat:last-child {
            grid-column: 1 / -1;
        }

        .account-panel {
            padding: 18px 16px;
        }

        .account-list li {
            padding: 10px 12px;
        }
    }
</style>
        </head>
<body>
    <main class="dashboard-page">

        ${pendingDrawHtml}

        <header class="dashboard-header">
            <div class="dashboard-header-main">
                <span class="dashboard-eyebrow">WEIRDO'S TREASURE</span>

                <h1>Seu Refúgio, Aventureiro!</h1>

                <p>
                    Bem-vindo de volta, ${escapeDashboardHtml(user.displayName)}!
                    Prepare-se para novas aventuras e conquiste grandes tesouros.
                </p>

                <div class="dashboard-header-row">
                    <div class="dashboard-balance">
                        <span>✦ SEU SALDO DE PONTOS ✦</span>

                        <strong>
                            ${points !== null
                                ? Number(points).toLocaleString("pt-BR")
                                : "Indisponível"}
                        </strong>

                        ${affordableTickets !== null
                            ? `<small>Dá para comprar até ${adminNumber(affordableTickets)} ${affordableTickets === 1 ? "ticket" : "tickets"} (${adminNumber(pointsPerTicket)} pontos cada)</small>`
                            : ""}
                    </div>
                </div>
            </div>

            <div class="dashboard-profile">
                ${user.profileImageUrl
                    ? `<img src="${escapeDashboardHtml(user.profileImageUrl)}" alt="Foto de perfil">`
                    : `<span class="dashboard-avatar-fallback">${escapeDashboardHtml(String(user.displayName || user.login || "?").charAt(0).toUpperCase())}</span>`}

                <div>
                    <strong>${escapeDashboardHtml(user.displayName)}</strong>
                    <span>Usuário Twitch: ${escapeDashboardHtml(user.login)}</span>
                    ${memberSince ? `<small>Aventureiro desde ${escapeDashboardHtml(adminDate(memberSince))}</small>` : ""}
                </div>

                ${subscriberHtml}
            </div>
        </header>

        <h2 class="dashboard-section-title">✦ Sua Jornada</h2>

        <section class="account-stats">
            <div class="account-stat">
                <span>Tickets comprados</span>
                <strong>${adminNumber(totalTickets)}</strong>
            </div>
            <div class="account-stat">
                <span>Pontos investidos</span>
                <strong>${adminNumber(totalPointsSpent)}</strong>
            </div>
            <div class="account-stat">
                <span>Sorteios que participou</span>
                <strong>${adminNumber(giveawaysJoined)}</strong>
            </div>
            <div class="account-stat">
                <span>Vitórias</span>
                <strong>${adminNumber(wins.length)}</strong>
            </div>
            <div class="account-stat">
                <span>Compras feitas</span>
                <strong>${adminNumber(completedTransactions.length)}</strong>
            </div>
        </section>

        <section class="account-panels">
            <div class="account-panel">
                <div class="account-panel-header">
                    <h2>✦ Últimas compras</h2>
                    ${recentTransactions.length > 0 ? `<a href="/my-tickets">Ver meus tickets →</a>` : ""}
                </div>
                ${purchasesHtml}
            </div>

            <div class="account-panel">
                <div class="account-panel-header">
                    <h2>✦ Suas conquistas</h2>
                </div>
                ${winsHtml}
            </div>
        </section>

        <h2 class="dashboard-section-title">✦ Suas Aventuras</h2>

        <section class="dashboard-grid">

            <a href="/giveaways" class="dashboard-card">
                <strong>✦ Comprar Tickets</strong>
                <span>Participe dos sorteios e concorra aos tesouros.</span>
            </a>

            <a href="/my-tickets" class="dashboard-card">
                <strong>✦ Meus Tickets</strong>
                <span>Confira seus tickets e acompanhe suas participações.</span>
            </a>

            <a href="/minigame" class="dashboard-card">
                <strong>✦ Minigame Diário</strong>
                <span>Descubra a palavra secreta e ganhe até 180 pontos a cada 20 horas.</span>
            </a>

            <a href="https://www.twitch.tv/${LIVE_CHANNEL_LOGIN}" target="_blank" rel="noopener noreferrer" class="dashboard-card">
                <strong>✦ Assistir à Live ↗</strong>
                <span>Assista à live para acumular pontos. Pode deixá-la mutada!</span>
            </a>

        </section>

        <a href="/logout" class="dashboard-logout">
            Sair da conta
        </a>

    </main>
</body>
        </html>
    `, "/dashboard"));
});

// Sair da conta
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.get("/admin", requireAdmin, async (req, res) => {
    try {
        const [users, tickets, transactions, giveaways, drawsResult] = await Promise.all([
            fetchAllRows((from, to) => supabase
                .from("users")
                .select("twitch_id, twitch_login, display_name, created_at")
                .order("created_at", { ascending: true })
                .range(from, to)),

            fetchAllRows((from, to) => supabase
                .from("tickets")
                .select("twitch_id, giveaway_id, created_at")
                .order("created_at", { ascending: true })
                .range(from, to)),

            fetchAllRows((from, to) => supabase
                .from("transactions")
                .select("giveaway_id, points_spent, created_at")
                .eq("status", "completed")
                .order("created_at", { ascending: true })
                .range(from, to)),

            loadAdminGiveaways(),

            supabase
                .from("giveaway_draws")
                .select("giveaway_id, round_number, winner_twitch_id, status")
                .order("round_number", { ascending: true })
        ]);

        if (drawsResult.error) {
            console.error("Erro ao buscar rodadas:", drawsResult.error.message);
        }

        const activeCount = giveaways.filter(giveaway => giveaway.status === "active").length;
        const totalPoints = transactions.reduce((sum, row) => sum + (Number(row.points_spent) || 0), 0);

        const card = (metric, label, value) => `
            <button type="button" class="stat-card" data-metric="${metric}" aria-controls="insights" aria-expanded="false">
                <span>${label}</span>
                <h2>${value}</h2>
                <small class="stat-card-hint">Ver gráfico <i aria-hidden="true">▾</i></small>
            </button>
        `;

        const content = `
            <h1>Painel administrativo</h1>
            <p>Clique em um card para ver os gráficos.</p>

            <div class="stats-grid">
                ${card("users", "Usuários cadastrados", adminNumber(users.length))}
                ${card("giveaways", "Sorteios ativos", adminNumber(activeCount))}
                ${card("tickets", "Tickets vendidos", adminNumber(tickets.length))}
                ${card("points", "Pontos movimentados", adminNumber(totalPoints))}
            </div>

            ${buildAdminInsightsHtml({
                users,
                tickets,
                transactions,
                giveaways,
                draws: drawsResult.data || []
            })}
        `;

        res.send(renderAdminPage({
            title: "Administração",
            activePath: "/admin",
            content,
            script: ADMIN_INSIGHTS_SCRIPT
        }));
    } catch (error) {
        console.error("Erro ao carregar o painel administrativo:", error);
        res.status(500).send("Erro ao carregar o painel administrativo.");
    }
});

app.get("/admin/settings", requireAdmin, async (req, res) => {
    const csrfToken = getCsrfToken(req);

    const { data: settings, error } = await supabase
        .from("system_settings")
        .select("points_per_ticket, subscriber_multiplier")
        .eq("id", 1)
        .single();

    if (error) {
        console.error("Erro ao buscar configurações:", error.message);
        return res.status(500).send("Erro ao carregar configurações.");
    }

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Configurações - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/admin.css">
        </head>

<script>
function changeNumber(id, amount) {
    const input = document.getElementById(id);

    const currentValue = Number(input.value);
    const min = Number(input.min);
    const max = input.max === "" ? Infinity : Number(input.max);

    const newValue = Math.min(
        max,
        Math.max(min, currentValue + amount)
    );

    input.value = newValue;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
}
</script>

        <body>
            <div class="admin-layout">
                <aside class="sidebar">
                    <div class="logo">
                        <h1>WEIRDO'S</h1>
                        <span>TREASURE</span>
                    </div>

                    <nav>
                        <a href="/admin">Início</a>
                        <a href="/admin/users">Usuários</a>
                        <a href="/admin/giveaways">Sorteios</a>
                        <a href="/admin/tickets">Tickets</a>
                        <a href="/admin/transactions">Transações</a>
                        <a href="/admin/reconciliation">Conferência de compras</a>
                        <a href="/admin/settings">Configurações</a>
                    </nav>

                    <div class="sidebar-footer">
                        <a href="/dashboard">Voltar ao site</a>
                        <a href="/logout">Sair</a>
                    </div>
                </aside>

                <main class="main-content">
                    <h1>Configurações do sistema</h1>
                    <p>Gerencie as regras de participação nos sorteios.</p>

                    <form action="/admin/settings" method="POST"
                        style="background:#211c17; border:1px solid #51402a; border-radius:12px; padding:25px; max-width:600px;">

                        <input type="hidden" name="_csrf" value="${csrfToken}">

                        <label for="points_per_ticket">
                            Pontos necessários por ticket
                        </label>
        
<div class="number-stepper">
    <button type="button" class="stepper-button"
        onclick="changeNumber('points_per_ticket', -1)">−</button>

    <input
        type="number"
        id="points_per_ticket"
        name="points_per_ticket"
        min="1"
        step="1"
        value="${settings.points_per_ticket}"
        required
    >

    <button type="button" class="stepper-button"
        onclick="changeNumber('points_per_ticket', 1)">+</button>
</div>

                        <label for="subscriber_multiplier">
                            Multiplicador de chance para inscritos
                        </label>
                
<div class="number-stepper">
    <button type="button" class="stepper-button"
        onclick="changeNumber('subscriber_multiplier', -1)">−</button>

    <input
        type="number"
        id="subscriber_multiplier"
        name="subscriber_multiplier"
        min="1"
        max="10"
        step="1"
        value="${settings.subscriber_multiplier}"
        required
    >

    <button type="button" class="stepper-button"
        onclick="changeNumber('subscriber_multiplier', 1)">+</button>
</div>

                        <button type="submit">
                            Salvar configurações
                        </button>
                    </form>
                </main>
            </div>
        </body>
        </html>
    `);
});

app.post("/admin/settings", requireAdmin, requireCsrf, async (req, res) => {

    const pointsPerTicket = Number(req.body.points_per_ticket);
    const subscriberMultiplier = Number(req.body.subscriber_multiplier);

    if (
        !Number.isSafeInteger(pointsPerTicket) ||
        pointsPerTicket < 1 ||
        !Number.isSafeInteger(subscriberMultiplier) ||
        subscriberMultiplier < 1 ||
        subscriberMultiplier > 10
    ) {
        return res.status(400).send("Configurações inválidas.");
    }

    const { error } = await supabase
        .from("system_settings")
        .update({
            points_per_ticket: pointsPerTicket,
            subscriber_multiplier: subscriberMultiplier,
            updated_at: new Date().toISOString()
        })
        .eq("id", 1);

    if (error) {
        console.error("Erro ao salvar configurações:", error.message);
        return res.status(500).send("Não foi possível salvar as configurações.");
    }

    return res.redirect("/admin/settings");
});

app.post(
    "/admin/transactions/:id/reconcile",
    requireAdmin,
    requireCsrf,
    async (req, res) => {
        try {
            // Exigir confirmação explícita do administrador
            if (
                req.body.points_debited !== "yes" ||
                req.body.confirmation !== "CONFIRMO"
            ) {
                return res.status(400).send(
                    "Confirmação inválida. A regularização não foi executada."
                );
            }

            const transactionId = req.params.id;

            // Executar a função protegida no Supabase
            const { data: ticketsAdded, error } = await supabase.rpc(
                "reconcile_ticket_purchase",
                {
                    p_transaction_id: transactionId
                }
            );

            if (error) {
                console.error(
                    "Erro ao regularizar compra:",
                    error.message
                );

                // Verificar se a operação foi concluída apesar de uma falha na resposta
                const { data: transaction, error: statusError } = await supabase
                    .from("transactions")
                    .select("status, tickets_purchased")
                    .eq("id", transactionId)
                    .maybeSingle();

                if (!statusError && transaction?.status === "completed") {
                    const { count, error: countError } = await supabase
                        .from("tickets")
                        .select("id", { count: "exact", head: true })
                        .eq("transaction_id", transactionId);

                    if (
                        !countError &&
                        count === Number(transaction.tickets_purchased)
                    ) {
                        return res.send(`
                            <h1>Compra já regularizada</h1>
                            <p>Todos os tickets estão registrados.</p>
                            <a href="/admin/transactions/${encodeURIComponent(transactionId)}/reconcile">
                                Voltar à conferência
                            </a>
                        `);
                    }
                }

                return res.status(202).send(
                    "Não foi possível confirmar o resultado da regularização. Não tente novamente agora. Verifique a transação no painel."
                );
            }

            console.log(
                `Compra ${transactionId} regularizada. Tickets adicionados: ${ticketsAdded}`
            );

            return res.send(`
                <!DOCTYPE html>
                <html lang="pt-BR">
                <head>
                    <meta charset="UTF-8">
                    <title>Compra regularizada</title>
                </head>
                <body style="background:#15120f;color:#e8dfcf;font-family:Arial;padding:30px;">
                    <h1 style="color:#d6a85c;">Regularização concluída!</h1>
                    <p>Tickets adicionados: ${Number(ticketsAdded)}</p>
                    <a href="/admin/transactions/${encodeURIComponent(transactionId)}/reconcile"
                       style="color:#d6a85c;">
                        Voltar à conferência
                    </a>
                </body>
                </html>
            `);

        } catch (error) {
            console.error(
                "Erro inesperado na regularização:",
                error.message
            );

            return res.status(500).send(
                "Não foi possível processar a regularização."
            );
        }
    }
);

app.post(
    "/admin/transactions/:id/reconcile-manual",
    requireAdmin,
    requireCsrf,
    async (req, res) => {
        try {
            // Exigir confirmação explícita
            if (
                req.body.points_debited !== "yes" ||
                req.body.confirmation !== "CONFIRMO EXCEÇÃO"
            ) {
                return res.status(400).send(
                    "Confirmação inválida. A regularização não foi executada."
                );
            }

            const justification =
                typeof req.body.justification === "string"
                    ? req.body.justification.trim()
                    : "";

            if (
                justification.length < 15 ||
                justification.length > 1000
            ) {
                return res.status(400).send(
                    "A justificativa deve ter entre 15 e 1000 caracteres."
                );
            }

            // Identificar o administrador pela sessão autenticada
            const adminTwitchId = req.session.twitchUser.id;

            const transactionId = req.params.id;

            // Executar a função SQL exclusiva da exceção manual
            const { data: ticketsAdded, error } = await supabase.rpc(
                "reconcile_ticket_purchase_manual",
                {
                    p_transaction_id: transactionId,
                    p_admin_twitch_id: adminTwitchId,
                    p_justification: justification
                }
            );

            if (error) {
                console.error(
                    "Erro na regularização excepcional:",
                    error.message
                );

                // Conferir se a operação foi concluída apesar de erro na resposta
                const { data: transaction, error: statusError } = await supabase
                    .from("transactions")
                    .select("status, tickets_purchased")
                    .eq("id", transactionId)
                    .maybeSingle();

                if (!statusError && transaction?.status === "completed") {
                    const { count, error: countError } = await supabase
                        .from("tickets")
                        .select("id", { count: "exact", head: true })
                        .eq("transaction_id", transactionId);

                    if (
                        !countError &&
                        count === Number(transaction.tickets_purchased)
                    ) {
                        return res.send(`
                            <h1>Compra já regularizada</h1>
                            <p>Todos os tickets estão registrados.</p>
                            <a href="/admin/transactions/${encodeURIComponent(transactionId)}/reconcile">
                                Voltar à conferência
                            </a>
                        `);
                    }
                }

                return res.status(202).send(
                    "Não foi possível confirmar o resultado. Não tente novamente agora. Verifique a transação no painel."
                );
            }

            console.log(
                `Regularização excepcional da compra ${transactionId}. ` +
                `Administrador: ${adminTwitchId}. ` +
                `Tickets adicionados: ${ticketsAdded}`
            );

            return res.send(`
                <!DOCTYPE html>
                <html lang="pt-BR">
                <head>
                    <meta charset="UTF-8">
                    <title>Regularização excepcional</title>
                </head>
                <body style="background:#15120f;color:#e8dfcf;font-family:Arial;padding:30px;">
                    <h1 style="color:#d6a85c;">Regularização excepcional concluída!</h1>
                    <p>Tickets adicionados: ${Number(ticketsAdded)}</p>
                    <p>A operação foi registrada na auditoria com a identificação do administrador.</p>
                    <a href="/admin/transactions/${encodeURIComponent(transactionId)}/reconcile"
                       style="color:#d6a85c;">
                        Voltar à conferência
                    </a>
                </body>
                </html>
            `);

        } catch (error) {
            console.error(
                "Erro inesperado na regularização excepcional:",
                error.message
            );

            return res.status(500).send(
                "Não foi possível processar a regularização excepcional."
            );
        }
    }
);

// Página simples de resultado das ações de devolução
function refundResultPage(transactionId, title, message, isError = false) {
    return `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>${escapeDashboardHtml(title)}</title>
        </head>
        <body style="background:#15120f;color:#e8dfcf;font-family:Arial;padding:30px;">
            <h1 style="color:${isError ? "#f0a48f" : "#d6a85c"};">${escapeDashboardHtml(title)}</h1>
            <p>${escapeDashboardHtml(message)}</p>
            <a href="/admin/transactions/${encodeURIComponent(transactionId)}/reconcile" style="color:#d6a85c;">
                Voltar à conferência
            </a>
        </body>
        </html>
    `;
}

// Devolver os pontos de uma compra que não pôde emitir tickets.
// 1) o banco marca a transação como "refund_pending" (impede devolução dupla)
// 2) o StreamElements devolve os pontos
// 3) o banco marca como "refunded"
// Se o passo 2 falhar, a transação fica "refund_pending" para conferência manual.
app.post("/admin/transactions/:id/refund", requireAdmin, requireCsrf, async (req, res) => {
    const transactionId = req.params.id;
    const adminTwitchId = req.session.twitchUser.id;
    const isRetry = req.body.retry === "1";

    const confirmed = req.body.confirmation === "DEVOLVER" && (
        isRetry
            ? req.body.points_not_returned === "yes"
            : req.body.points_debited === "yes"
    );

    if (!confirmed) {
        return res.status(400).send(refundResultPage(transactionId, "Confirmação inválida", "A devolução não foi executada.", true));
    }

    try {
        const { data: transaction, error: transactionError } = await supabase
            .from("transactions")
            .select("id, twitch_id, points_spent, status, users ( twitch_login )")
            .eq("id", transactionId)
            .maybeSingle();

        if (transactionError) throw transactionError;

        if (!transaction) {
            return res.status(404).send(refundResultPage(transactionId, "Transação não encontrada", "Confira o endereço.", true));
        }

        const username = transaction.users?.twitch_login;

        if (!username) {
            return res.status(409).send(refundResultPage(transactionId, "Usuário não identificado", "Não foi possível identificar o usuário desta compra.", true));
        }

        let pointsToReturn;

        if (isRetry) {
            if (transaction.status !== "refund_pending") {
                return res.status(409).send(refundResultPage(transactionId, "Status mudou", "Esta transação não está mais com devolução em andamento.", true));
            }

            pointsToReturn = Number(transaction.points_spent);

            await supabase.from("audit_logs").insert({
                twitch_id: adminTwitchId,
                action: "ticket_purchase_refund_retried",
                details: { transaction_id: transactionId, customer_twitch_id: transaction.twitch_id }
            });
        } else {
            const { data: startedPoints, error: startError } = await supabase.rpc(
                "start_ticket_purchase_refund",
                {
                    p_transaction_id: transactionId,
                    p_admin_twitch_id: adminTwitchId
                }
            );

            if (startError) {
                console.error("Devolução recusada pelo banco:", startError.message);
                return res.status(409).send(refundResultPage(transactionId, "Devolução não iniciada", startError.message, true));
            }

            pointsToReturn = Number(startedPoints);
        }

        try {
            const channelId = await getStreamElementsChannelId();
            await addStreamElementsPoints(channelId, username, pointsToReturn);
        } catch (refundError) {
            console.error("StreamElements não confirmou a devolução:", refundError.message);

            return res.status(202).send(refundResultPage(
                transactionId,
                "Devolução não confirmada",
                "O StreamElements não confirmou a devolução. Confira o saldo do usuário antes de qualquer nova ação.",
                true
            ));
        }

        const { error: completeError } = await supabase.rpc(
            "complete_ticket_purchase_refund",
            {
                p_transaction_id: transactionId,
                p_admin_twitch_id: adminTwitchId
            }
        );

        if (completeError) {
            console.error("Pontos devolvidos, mas a transação não foi finalizada:", completeError.message);

            return res.status(202).send(refundResultPage(
                transactionId,
                "Pontos devolvidos — falta finalizar",
                "Os pontos foram devolvidos, mas o status não foi atualizado. Use \"Marcar como devolvida\" na conferência. NÃO tente devolver de novo.",
                true
            ));
        }

        return res.send(refundResultPage(
            transactionId,
            "Pontos devolvidos!",
            pointsToReturn.toLocaleString("pt-BR") + " pontos foram devolvidos a " + username + "."
        ));

    } catch (error) {
        console.error("Erro inesperado na devolução:", error.message);
        return res.status(500).send(refundResultPage(transactionId, "Erro na devolução", "Confira a transação antes de qualquer nova ação.", true));
    }
});

// Marcar como devolvida depois de conferir manualmente no StreamElements
app.post("/admin/transactions/:id/refund-complete", requireAdmin, requireCsrf, async (req, res) => {
    const transactionId = req.params.id;

    if (req.body.points_returned !== "yes") {
        return res.status(400).send(refundResultPage(transactionId, "Confirmação inválida", "Nada foi alterado.", true));
    }

    const { error } = await supabase.rpc(
        "complete_ticket_purchase_refund",
        {
            p_transaction_id: transactionId,
            p_admin_twitch_id: req.session.twitchUser.id
        }
    );

    if (error) {
        console.error("Erro ao finalizar devolução:", error.message);
        return res.status(409).send(refundResultPage(transactionId, "Não foi possível finalizar", error.message, true));
    }

    return res.send(refundResultPage(transactionId, "Devolução finalizada", "A transação foi marcada como \"Pontos devolvidos\"."));
});

// Carrega o sorteio escolhido (ou todos) com tickets, transações e rodadas
async function loadAdminGiveawayData(req) {
    const giveaways = await loadAdminGiveaways();
    const showAll = req.query.sorteio === "todos";
    const selected = showAll ? null : pickAdminGiveaway(giveaways, req.query.sorteio);
    const hasScope = showAll || Boolean(selected);
    const scoped = (query) => selected ? query.eq("giveaway_id", selected.id) : query;

    const [tickets, transactions, drawsResult] = hasScope
        ? await Promise.all([
            fetchAllRows((from, to) => scoped(supabase
                .from("tickets")
                .select("ticket_number, twitch_id, giveaway_id, created_at, users ( display_name, twitch_login )"))
                .order(selected ? "ticket_number" : "created_at", { ascending: Boolean(selected) })
                .range(from, to)),

            fetchAllRows((from, to) => scoped(supabase
                .from("transactions")
                .select("id, twitch_id, giveaway_id, points_spent, tickets_purchased, status, created_at, users ( display_name, twitch_login )"))
                .order("created_at", { ascending: false })
                .range(from, to)),

            scoped(supabase
                .from("giveaway_draws")
                .select("giveaway_id, round_number, winner_twitch_id, winning_ticket_number, status, drawn_at"))
                .order("round_number", { ascending: true })
        ])
        : [[], [], { data: [] }];

    if (drawsResult.error) {
        console.error("Erro ao buscar rodadas:", drawsResult.error.message);
    }

    const namesById = new Map();

    for (const row of [...tickets, ...transactions]) {
        if (row.users && !namesById.has(row.twitch_id)) {
            namesById.set(row.twitch_id, adminUserName(row.users));
        }
    }

    const titlesById = new Map(giveaways.map(giveaway => [giveaway.id, giveaway.title]));

    return {
        giveaways,
        showAll,
        selected,
        hasScope,
        tickets,
        transactions,
        draws: showAll ? [] : (drawsResult.data || []),
        namesById,
        titlesById
    };
}

function adminGiveawayHeaderHtml(data, basePath, monthParam) {
    if (!data.giveaways.length) {
        return `<div class="empty-state">Nenhum sorteio criado ainda.</div>`;
    }

    return `
        ${buildGiveawayBrowserHtml({
            giveaways: data.giveaways,
            selected: data.selected,
            showAll: data.showAll,
            monthParam,
            basePath
        })}

        ${buildGiveawaySummaryHtml({
            giveaway: data.selected,
            showAll: data.showAll,
            stats: computeGiveawayStats(data.tickets, data.transactions),
            draws: data.draws,
            namesById: data.namesById,
            basePath
        })}
    `;
}

app.get("/admin/transactions", requireAdmin, async (req, res) => {
    try {
        const data = await loadAdminGiveawayData(req);
        const { transactions, showAll, titlesById } = data;

        // Totais por status
        const byStatus = new Map();

        for (const transaction of transactions) {
            const entry = byStatus.get(transaction.status) || { count: 0, points: 0 };
            entry.count++;
            entry.points += Number(transaction.points_spent) || 0;
            byStatus.set(transaction.status, entry);
        }

        const statusChips = [...byStatus.entries()].map(([status, entry]) => `
            <div class="status-chip">
                ${adminBadge(status, TRANSACTION_STATUS_LABELS)}
                <strong>${adminNumber(entry.count)}</strong>
                <span>${adminNumber(entry.points)} pontos</span>
            </div>
        `).join("");

        const needsReview = (status) => status === "pending" || status === "reconciliation_required" || status === "refund_pending";

        const rows = transactions.map(transaction => `
            <tr>
                <td><a href="/admin/users/${encodeURIComponent(transaction.twitch_id)}">${escapeDashboardHtml(adminUserName(transaction.users))}</a></td>
                ${showAll ? `<td>${escapeDashboardHtml(titlesById.get(transaction.giveaway_id) || "Sorteio não encontrado")}</td>` : ""}
                <td data-value="${Number(transaction.points_spent) || 0}">${adminNumber(transaction.points_spent)}</td>
                <td data-value="${Number(transaction.tickets_purchased) || 0}">${adminNumber(transaction.tickets_purchased)}</td>
                <td>${adminBadge(transaction.status, TRANSACTION_STATUS_LABELS)}</td>
                <td data-value="${escapeDashboardHtml(transaction.created_at || "")}">${adminDateTime(transaction.created_at)}</td>
                <td>${needsReview(transaction.status)
                    ? `<a href="/admin/transactions/${encodeURIComponent(transaction.id)}/reconcile">Conferir compra</a>`
                    : ""}</td>
            </tr>
        `).join("");

        const columns = showAll ? 7 : 6;

        const content = `
            <h1>Transações</h1>
            <p>Escolha um dia marcado no calendário para ver as compras daquele sorteio.</p>

            ${adminGiveawayHeaderHtml(data, "/admin/transactions", req.query.mes)}

            ${data.hasScope ? `
                ${statusChips ? `<div class="status-chips">${statusChips}</div>` : ""}

                <div class="table-toolbar">
                    <h2>Compras <span class="count-pill" data-filter-count="transactions-table">${adminNumber(transactions.length)}</span></h2>
                    <input type="search" class="table-search" placeholder="Buscar usuário ou status..." data-filter-table="transactions-table" aria-label="Buscar transações">
                </div>

                <div class="table-wrap">
                    <table id="transactions-table" data-sortable>
                        <thead>
                            <tr>
                                <th data-sort="text">Usuário</th>
                                ${showAll ? `<th data-sort="text">Sorteio</th>` : ""}
                                <th data-sort="number">Pontos</th>
                                <th data-sort="number">Tickets</th>
                                <th data-sort="text">Status</th>
                                <th data-sort="text">Data</th>
                                <th>Ação</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows || `<tr class="empty-row"><td colspan="${columns}">Nenhuma transação neste sorteio.</td></tr>`}
                        </tbody>
                    </table>
                </div>
            ` : ""}
        `;

        res.send(renderAdminPage({
            title: "Transações",
            activePath: "/admin/transactions",
            content,
            script: ADMIN_TABLE_SCRIPT
        }));
    } catch (error) {
        console.error("Erro ao carregar transações:", error);
        res.status(500).send("Erro ao carregar transações.");
    }
});

app.post("/admin/giveaways", requireAdmin, requireCsrf, async (req, res) => {
    
    const { title, description, starts_at, ends_at } = req.body;

    if (
        typeof title !== "string" ||
        typeof starts_at !== "string" ||
        typeof ends_at !== "string" ||
        (description !== undefined && typeof description !== "string") ||
        !title.trim() ||
        !starts_at.trim() ||
        !ends_at.trim()
    ) {
        return res.status(400).send("Preencha o título e as duas datas.");
    }

    if (title.trim().length > GIVEAWAY_TITLE_MAX || (description || "").trim().length > GIVEAWAY_DESCRIPTION_MAX) {
        return res.status(400).send(
            `O título pode ter até ${GIVEAWAY_TITLE_MAX} caracteres e a descrição até ${GIVEAWAY_DESCRIPTION_MAX}.`
        );
    }

    const startDate = new Date(starts_at);
    const endDate = new Date(ends_at);

    if (
        Number.isNaN(startDate.getTime()) ||
        Number.isNaN(endDate.getTime()) ||
        endDate <= startDate
    ) {
        return res.status(400).send("As datas informadas são inválidas.");
    }

    const { error } = await supabase
        .from("giveaways")
        .insert({
            title: title.trim(),
            description: description?.trim() || null,
            starts_at: startDate.toISOString(),
            ends_at: endDate.toISOString(),
            status: "draft"
        });

    if (error) {
        console.error("Erro ao cadastrar sorteio:", error.message);
        return res.status(500).send("Não foi possível cadastrar o sorteio.");
    }

    res.redirect("/admin/giveaways");
});

app.post("/admin/giveaways/:id/activate", requireAdmin, requireCsrf, async (req, res) => {

    const { data: giveaway, error: fetchError } = await supabase
        .from("giveaways")
        .select("id, status, ends_at")
        .eq("id", req.params.id)
        .maybeSingle();

    if (fetchError) {
        console.error("Erro ao consultar sorteio:", fetchError.message);
        return res.status(500).send("Erro ao consultar sorteio.");
    }

    if (!giveaway) {
        return res.status(404).send("Sorteio não encontrado.");
    }

    if (giveaway.status !== "draft") {
        return res.status(400).send("Somente sorteios em rascunho podem ser ativados.");
    }

    if (!giveaway.ends_at || new Date(giveaway.ends_at) <= new Date()) {
        return res.status(400).send("A data de encerramento precisa estar no futuro.");
    }

    const { error: updateError } = await supabase
        .from("giveaways")
        .update({ status: "active" })
        .eq("id", giveaway.id)
        .eq("status", "draft");

    if (updateError) {
        console.error("Erro ao ativar sorteio:", updateError.message);
        return res.status(500).send("Não foi possível ativar o sorteio.");
    }

    res.redirect("/admin/giveaways");
});

app.post("/admin/giveaways/:id/close", requireAdmin, requireCsrf, async (req, res) => {
    
    const { data: giveaway, error: fetchError } = await supabase
        .from("giveaways")
        .select("id, status")
        .eq("id", req.params.id)
        .maybeSingle();

    if (fetchError) {
        console.error("Erro ao consultar sorteio:", fetchError.message);
        return res.status(500).send("Erro ao consultar sorteio.");
    }

    if (!giveaway) {
        return res.status(404).send("Sorteio não encontrado.");
    }

    if (giveaway.status !== "active") {
        return res.status(400).send("Somente sorteios ativos podem ser encerrados.");
    }

    const { error: updateError } = await supabase
        .from("giveaways")
        .update({ status: "closed" })
        .eq("id", giveaway.id)
        .eq("status", "active");

    if (updateError) {
        console.error("Erro ao encerrar sorteio:", updateError.message);
        return res.status(500).send("Não foi possível encerrar o sorteio.");
    }

    res.redirect("/admin/giveaways");
});

app.post("/admin/giveaways/:id/cancel", requireAdmin, requireCsrf, async (req, res) => {

    const { data: giveaway, error: fetchError } = await supabase
        .from("giveaways")
        .select("id, status")
        .eq("id", req.params.id)
        .maybeSingle();

    if (fetchError) {
        console.error("Erro ao consultar sorteio:", fetchError.message);
        return res.status(500).send("Erro ao consultar sorteio.");
    }

    if (!giveaway) {
        return res.status(404).send("Sorteio não encontrado.");
    }

    if (!["draft", "active"].includes(giveaway.status)) {
        return res.status(400).send("Este sorteio não pode ser cancelado.");
    }

    const { data: updatedGiveaway, error: updateError } = await supabase
        .from("giveaways")
        .update({ status: "cancelled" })
        .eq("id", giveaway.id)
        .in("status", ["draft", "active"])
        .select("id");

    if (updateError) {
        console.error("Erro ao cancelar sorteio:", updateError.message);
        return res.status(500).send("Não foi possível cancelar o sorteio.");
    }

    if (!updatedGiveaway || updatedGiveaway.length === 0) {
        return res.status(409).send("O status do sorteio mudou. Atualize a página.");
    }

    res.redirect("/admin/giveaways");
});

app.get("/admin/giveaways/:id/edit", requireAdmin, async (req, res) => {
    const csrfToken = getCsrfToken(req);

    const { data: giveaway, error } = await supabase
        .from("giveaways")
        .select("*")
        .eq("id", req.params.id)
        .maybeSingle();

    if (error) {
        console.error("Erro ao buscar sorteio:", error.message);
        return res.status(500).send("Erro ao carregar sorteio.");
    }

    if (!giveaway) {
        return res.status(404).send("Sorteio não encontrado.");
    }

    if (giveaway.status !== "draft") {
        return res.status(400).send("Somente sorteios em rascunho podem ser editados.");
    }

    const escapeHtml = (value) => String(value ?? "").replace(
        /[&<>"']/g,
        (char) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[char]
    );

    const toLocalDateTime = (date) => {
        const localDate = new Date(
            new Date(date).getTime() - new Date(date).getTimezoneOffset() * 60000
        );

        return localDate.toISOString().slice(0, 16);
    };

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Editar sorteio - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/admin.css">
        </head>

        <body>
            <main>
                <h1>Editar sorteio</h1>

                <form class="giveaway-form"
                      action="/admin/giveaways/${encodeURIComponent(giveaway.id)}/edit"
                      method="POST">

                    <input type="hidden" name="_csrf" value="${csrfToken}">

                    <div class="giveaway-field">
                        <label for="title">Nome do sorteio</label>
                        <input
                            type="text"
                            id="title"
                            name="title"
                            value="${escapeHtml(giveaway.title)}"
                            maxlength="100"
                            required
                        >
                    </div>

                    <div class="giveaway-field">
                        <label for="description">Descrição</label>
                        <textarea
                            id="description"
                            name="description"
                            rows="4"
                        >${escapeHtml(giveaway.description)}</textarea>
                    </div>

                    <div class="giveaway-field">
                        <label for="starts_at">Data e horário de início</label>
                        <input
                            type="datetime-local"
                            id="starts_at"
                            name="starts_at"
                            value="${toLocalDateTime(giveaway.starts_at)}"
                            required
                        >
                    </div>

                    <div class="giveaway-field">
                        <label for="ends_at">Data e horário de encerramento</label>
                        <input
                            type="datetime-local"
                            id="ends_at"
                            name="ends_at"
                            value="${toLocalDateTime(giveaway.ends_at)}"
                            required
                        >
                    </div>

                    <button type="submit">Salvar alterações</button>
                </form>

                <p>
                    <a href="/admin/giveaways">Voltar aos sorteios</a>
                </p>
            </main>
        </body>
        </html>
    `);
});

app.post("/admin/giveaways/:id/edit", requireAdmin, requireCsrf, async (req, res) => {
    
    const { title, description, starts_at, ends_at } = req.body;

    if (
    typeof title !== "string" ||
    typeof starts_at !== "string" ||
    typeof ends_at !== "string" ||
    (description !== undefined && typeof description !== "string") ||
    !title.trim() ||
    !starts_at.trim() ||
    !ends_at.trim()
) {
    return res.status(400).send("Preencha corretamente o título e as duas datas.");
}

    if (title.trim().length > GIVEAWAY_TITLE_MAX || (description || "").trim().length > GIVEAWAY_DESCRIPTION_MAX) {
        return res.status(400).send(
            `O título pode ter até ${GIVEAWAY_TITLE_MAX} caracteres e a descrição até ${GIVEAWAY_DESCRIPTION_MAX}.`
        );
    }

    const startDate = new Date(starts_at);
    const endDate = new Date(ends_at);

    if (
        Number.isNaN(startDate.getTime()) ||
        Number.isNaN(endDate.getTime()) ||
        endDate <= startDate
    ) {
        return res.status(400).send("As datas informadas são inválidas.");
    }

    const { data: giveaway, error: fetchError } = await supabase
        .from("giveaways")
        .select("id, status")
        .eq("id", req.params.id)
        .maybeSingle();

    if (fetchError) {
        console.error("Erro ao buscar sorteio:", fetchError.message);
        return res.status(500).send("Erro ao buscar sorteio.");
    }

    if (!giveaway) {
        return res.status(404).send("Sorteio não encontrado.");
    }

    if (giveaway.status !== "draft") {
        return res.status(400).send("Somente sorteios em rascunho podem ser editados.");
    }

    const { data: updatedGiveaway, error: updateError } = await supabase
    .from("giveaways")
    .update({
        title: title.trim(),
        description: description?.trim() || null,
        starts_at: startDate.toISOString(),
        ends_at: endDate.toISOString()
    })
    .eq("id", giveaway.id)
    .eq("status", "draft")
    .select("id");

if (updateError) {
    console.error("Erro ao atualizar sorteio:", updateError.message);
    return res.status(500).send("Não foi possível atualizar o sorteio.");
}

if (!updatedGiveaway || updatedGiveaway.length === 0) {
    return res.status(409).send("O sorteio não está mais em rascunho. Atualize a página.");
}

    
    res.redirect("/admin/giveaways");
});

// Página individual de conferência de uma compra
app.get("/admin/transactions/:id/reconcile", requireAdmin, async (req, res) => {
    try {
        const csrfToken = getCsrfToken(req);
        const escapeHtml = (value) => String(value ?? "").replace(
            /[&<>"']/g,
            char => ({
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;"
            })[char]
        );

        // Buscar transação
        const { data: transaction, error: transactionError } = await supabase
            .from("transactions")
            .select(`
                id,
                twitch_id,
                giveaway_id,
                points_spent,
                tickets_purchased,
                status,
                created_at,
                users (
                    display_name,
                    twitch_login
                ),
                giveaways (
                    title,
                    status,
                    ends_at
                )
            `)
            .eq("id", req.params.id)
            .maybeSingle();

        if (transactionError) {
            throw transactionError;
        }

        if (!transaction) {
            return res.status(404).send("Transação não encontrada.");
        }

        // Consultar se existe auditoria automática do débito
const {
    data: debitAudits,
    error: debitAuditError
} = await supabase
    .from("audit_logs")
    .select("details")
    .eq("twitch_id", transaction.twitch_id)
    .eq("action", "streamElements_points_debited")
    .filter("details->>transaction_id", "eq", transaction.id);

if (debitAuditError) {
    throw debitAuditError;
}

        // Contar tickets realmente emitidos
        const { count: emittedTickets, error: ticketsError } = await supabase
            .from("tickets")
            .select("id", { count: "exact", head: true })
            .eq("transaction_id", transaction.id);

        if (ticketsError) {
            throw ticketsError;
        }

        // Consultar saldo atual no StreamElements
        const username = transaction.users?.twitch_login;

        if (!username) {
            return res.status(409).send(
                "Não foi possível identificar o usuário Twitch desta transação."
            );
        }

        const channelId = await getStreamElementsChannelId();

        const currentPoints = await getStreamElementsPoints(
            channelId,
            username
        );

        const purchased = Number(transaction.tickets_purchased);
        const emitted = Number(emittedTickets || 0);
        const pointsSpent = Number(transaction.points_spent);

        const hasAutomaticAudit = (debitAudits || []).length > 0;

const hasValidAutomaticAudit = (debitAudits || []).some((audit) => {
    const details = audit.details || {};
    const debitedPoints = Number(details.points_debited);

    return (
        details.confirmed_by_api === true &&
        Number.isFinite(debitedPoints) &&
        debitedPoints === pointsSpent
    );
});

const canReconcileNormal =
    ["pending", "reconciliation_required"].includes(transaction.status) &&
    emitted < purchased &&
    hasValidAutomaticAudit;

const canReconcileManual =
    ["pending", "reconciliation_required"].includes(transaction.status) &&
    emitted < purchased &&
    !hasAutomaticAudit;

        // A emissão só é possível com o sorteio ainda ativo e dentro do prazo
        const giveawayOpen =
            transaction.giveaways?.status === "active" &&
            new Date(transaction.giveaways?.ends_at || 0) > new Date();

        // Compra pendente há pouco tempo pode ainda estar sendo processada
        const pendingIsStale =
            transaction.status !== "pending" ||
            Date.now() - new Date(transaction.created_at).getTime() > 15 * 60 * 1000;

        // Devolução: só sem nenhum ticket emitido
        const canStartRefund =
            ["pending", "reconciliation_required"].includes(transaction.status) &&
            pendingIsStale &&
            emitted === 0;

        const refundInProgress = transaction.status === "refund_pending";

        let emissionStatus;

if (emitted === purchased) {
    emissionStatus = "Quantidade confere";
} else if (emitted === 0) {
    emissionStatus = "Nenhum ticket emitido";
} else if (emitted < purchased) {
    emissionStatus = "Emissão parcial";
} else {
    emissionStatus = "Quantidade divergente";
}

        return res.send(`
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Conferência de compra</title>
            </head>

            <body style="
                margin:0;
                padding:30px;
                background:#15120f;
                color:#e8dfcf;
                font-family:Arial,sans-serif;
            ">
                <main style="
                    max-width:750px;
                    margin:auto;
                    background:#211c17;
                    border:1px solid #51402a;
                    border-radius:12px;
                    padding:25px;
                ">
                    <h1 style="color:#d6a85c;">
                        Conferência de compra
                    </h1>

                    <p>
                        <strong>ID:</strong>
                        ${escapeHtml(transaction.id)}
                    </p>

                    <p>
                        <strong>Usuário:</strong>
                        ${escapeHtml(transaction.users?.display_name || username)}
                        (${escapeHtml(username)})
                    </p>

                    <p>
                        <strong>Sorteio:</strong>
                        ${escapeHtml(transaction.giveaways?.title || "Não encontrado")}
                    </p>

                    <hr style="border-color:#51402a;">

                    <h2>Dados da compra</h2>

                    <p>
                        <strong>Tickets comprados:</strong>
                        ${purchased}
                    </p>

                    <p>
                        <strong>Tickets emitidos:</strong>
                        ${emitted}
                    </p>

                    <p>
                        <strong>Conferência:</strong>
                        <span style="color:${emitted === purchased ? "#7bd88f" : "#ff7777"};">
    ${escapeHtml(emissionStatus)}
</span>
                    </p>

                    <p>
                        <strong>Pontos registrados como gastos:</strong>
                        ${pointsSpent.toLocaleString("pt-BR")}
                    </p>

                    <p>
                        <strong>Status da transação:</strong>
                        ${escapeHtml(transaction.status)}
                    </p>

                    <hr style="border-color:#51402a;">

                    <h2>StreamElements</h2>

                    <p>
                        <strong>Saldo atual:</strong>
                        ${currentPoints.toLocaleString("pt-BR")} pontos
                    </p>

                    <p style="color:#b9ad9b;">
                        Este é o saldo atual da conta, não um registro histórico
                        do saldo no momento da compra.
                    </p>

${(canReconcileNormal || canReconcileManual) && !giveawayOpen ? `
    <hr style="border-color:#51402a;">
    <p style="color:#f0a48f;">
        O sorteio desta compra não está mais aberto, então não é possível emitir tickets.
        Se os pontos foram descontados, use a <strong>devolução de pontos</strong> abaixo.
    </p>
` : ""}

${canReconcileNormal && giveawayOpen ? `
    <hr style="border-color:#51402a;">

    <h2>Regularizar compra</h2>

    <p>
        Esta ação emitirá somente os tickets que estiverem faltando.
        Nenhum ponto será descontado novamente.
    </p>

    <form
        action="/admin/transactions/${encodeURIComponent(transaction.id)}/reconcile"
        method="POST"
        style="background:#15120f;padding:20px;border:1px solid #51402a;border-radius:8px;"
    >
        <input type="hidden" name="_csrf" value="${csrfToken}">

        <label>
            <input type="checkbox" name="points_debited" value="yes" required>
            Confirmei no StreamElements que os pontos desta compra foram descontados.
        </label>

        <p>Digite CONFIRMO para autorizar a regularização:</p>

        <input
            type="text"
            name="confirmation"
            required
            autocomplete="off"
            style="padding:10px;background:#211c17;color:#e8dfcf;border:1px solid #51402a;border-radius:6px;"
        >

        <button type="submit"
            style="display:block;margin-top:18px;padding:12px 20px;background:#d6a85c;color:#15120f;border:0;border-radius:6px;cursor:pointer;">
            Regularizar compra
        </button>
    </form>
` : ""}

${canReconcileManual && giveawayOpen ? `
    <hr style="border-color:#8b493d;margin-top:30px;">

    <h2 style="color:#d68b70;">Regularização excepcional manual</h2>

    <p>
        Utilize esta opção somente quando não existir auditoria automática
        do débito e você tiver verificado evidências confiáveis de que os
        pontos foram descontados no StreamElements.
    </p>

    <form
        action="/admin/transactions/${encodeURIComponent(transaction.id)}/reconcile-manual"
        method="POST"
        style="background:#15120f;padding:20px;border:1px solid #8b493d;border-radius:8px;"
    >
        <input type="hidden" name="_csrf" value="${csrfToken}">

        <label>
            <input type="checkbox" name="points_debited" value="yes" required>
            Verifiquei evidências do débito desta compra no StreamElements.
        </label>

        <p>Justificativa e descrição das evidências verificadas:</p>

        <textarea
            name="justification"
            required
            minlength="15"
            maxlength="1000"
            rows="5"
            placeholder="Descreva como o débito foi verificado, o valor e as informações disponíveis para conferência."
            style="display:block;width:100%;box-sizing:border-box;padding:10px;background:#211c17;color:#e8dfcf;border:1px solid #51402a;border-radius:6px;"
        ></textarea>

        <p>Digite CONFIRMO EXCEÇÃO para autorizar:</p>

        <input
            type="text"
            name="confirmation"
            required
            autocomplete="off"
            style="padding:10px;background:#211c17;color:#e8dfcf;border:1px solid #51402a;border-radius:6px;"
        >

        <button type="submit"
            style="display:block;margin-top:18px;padding:12px 20px;background:#8b493d;color:#fff;border:0;border-radius:6px;cursor:pointer;">
            Autorizar regularização excepcional
        </button>
    </form>
` : ""}

${canStartRefund ? `
    <hr style="border-color:#51402a;margin-top:30px;">

    <h2 style="color:#8fb8e0;">Devolver pontos</h2>

    <p>
        Use quando os pontos foram descontados mas os tickets não puderam ser emitidos
        (por exemplo, o sorteio encerrou no meio da compra). Devolve
        <strong>${pointsSpent.toLocaleString("pt-BR")} pontos</strong> no StreamElements
        e encerra a transação como "Pontos devolvidos".
    </p>

    <form
        action="/admin/transactions/${encodeURIComponent(transaction.id)}/refund"
        method="POST"
        style="background:#15120f;padding:20px;border:1px solid #3d5f80;border-radius:8px;"
    >
        <input type="hidden" name="_csrf" value="${csrfToken}">

        <label>
            <input type="checkbox" name="points_debited" value="yes" required>
            Confirmei no StreamElements que os pontos desta compra foram descontados.
        </label>

        <p>Digite DEVOLVER para autorizar:</p>

        <input
            type="text"
            name="confirmation"
            required
            autocomplete="off"
            style="padding:10px;background:#211c17;color:#e8dfcf;border:1px solid #51402a;border-radius:6px;"
        >

        <button type="submit"
            style="display:block;margin-top:18px;padding:12px 20px;background:#3d5f80;color:#fff;border:0;border-radius:6px;cursor:pointer;">
            Devolver pontos
        </button>
    </form>
` : ""}

${refundInProgress ? `
    <hr style="border-color:#51402a;margin-top:30px;">

    <h2 style="color:#8fb8e0;">Devolução em andamento</h2>

    <p style="color:#f0a48f;">
        A devolução foi iniciada, mas o StreamElements não confirmou. Confira o saldo
        do usuário no StreamElements antes de escolher uma opção.
    </p>

    <form
        action="/admin/transactions/${encodeURIComponent(transaction.id)}/refund-complete"
        method="POST"
        style="background:#15120f;padding:20px;border:1px solid #3d5f80;border-radius:8px;margin-bottom:16px;"
    >
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <label>
            <input type="checkbox" name="points_returned" value="yes" required>
            Conferi: os ${pointsSpent.toLocaleString("pt-BR")} pontos JÁ voltaram para o usuário.
        </label>
        <button type="submit"
            style="display:block;margin-top:14px;padding:10px 18px;background:#3d5f80;color:#fff;border:0;border-radius:6px;cursor:pointer;">
            Marcar como devolvida
        </button>
    </form>

    <form
        action="/admin/transactions/${encodeURIComponent(transaction.id)}/refund"
        method="POST"
        style="background:#15120f;padding:20px;border:1px solid #8b493d;border-radius:8px;"
    >
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <input type="hidden" name="retry" value="1">
        <label>
            <input type="checkbox" name="points_not_returned" value="yes" required>
            Conferi: os pontos NÃO voltaram. Tentar devolver novamente.
        </label>
        <p>Digite DEVOLVER para autorizar:</p>
        <input
            type="text"
            name="confirmation"
            required
            autocomplete="off"
            style="padding:10px;background:#211c17;color:#e8dfcf;border:1px solid #51402a;border-radius:6px;"
        >
        <button type="submit"
            style="display:block;margin-top:14px;padding:10px 18px;background:#8b493d;color:#fff;border:0;border-radius:6px;cursor:pointer;">
            Tentar devolver novamente
        </button>
    </form>
` : ""}

                    <a href="/admin/reconciliation" style="color:#d6a85c;">
                        Voltar à conferência de compras
                    </a>
                </main>
            </body>
            </html>
        `);

    } catch (error) {
        console.error("Erro na conferência da transação:", error.message);

        return res.status(500).send(
            "Não foi possível realizar a conferência desta compra."
        );
    }
});


app.get("/admin/users", requireAdmin, async (req, res) => {
    try {
        const [users, tickets, transactions, drawsResult, activeResult, subscriberIds, minigameWins] = await Promise.all([
            fetchAllRows((from, to) => supabase
                .from("users")
                .select("twitch_id, twitch_login, display_name, profile_image_url, created_at")
                .order("created_at", { ascending: false })
                .range(from, to)),

            fetchAllRows((from, to) => supabase
                .from("tickets")
                .select("twitch_id, giveaway_id")
                .order("created_at", { ascending: true })
                .range(from, to)),

            fetchAllRows((from, to) => supabase
                .from("transactions")
                .select("twitch_id, points_spent, created_at")
                .eq("status", "completed")
                .order("created_at", { ascending: true })
                .range(from, to)),

            supabase
                .from("giveaway_draws")
                .select("winner_twitch_id, status"),

            supabase
                .from("giveaways")
                .select("id")
                .eq("status", "active"),

            getSubscriberIdsSafe(),

            // Partidas ganhas no minigame diário
            fetchAllRows((from, to) => supabase
                .from("daily_word_games")
                .select("twitch_id, points_awarded")
                .eq("status", "won")
                .order("started_at", { ascending: true })
                .range(from, to))
        ]);

        if (drawsResult.error) console.error("Erro ao buscar rodadas:", drawsResult.error.message);
        if (activeResult.error) console.error("Erro ao buscar sorteio ativo:", activeResult.error.message);

        const activeIds = new Set((activeResult.data || []).map(giveaway => giveaway.id));
        const stats = new Map();
        const statsFor = (id) => {
            if (!stats.has(id)) {
                stats.set(id, { tickets: 0, activeTickets: 0, giveaways: new Set(), points: 0, wins: 0, minigameWins: 0, minigamePoints: 0 });
            }
            return stats.get(id);
        };

        for (const ticket of tickets) {
            const entry = statsFor(ticket.twitch_id);
            entry.tickets++;
            entry.giveaways.add(ticket.giveaway_id);
            if (activeIds.has(ticket.giveaway_id)) entry.activeTickets++;
        }

        for (const transaction of transactions) {
            const entry = statsFor(transaction.twitch_id);
            entry.points += Number(transaction.points_spent) || 0;
        }

        for (const game of minigameWins) {
            const entry = statsFor(game.twitch_id);
            entry.minigameWins++;
            entry.minigamePoints += Number(game.points_awarded) || 0;
        }

        for (const draw of drawsResult.data || []) {
            if (draw.status === "confirmed") statsFor(draw.winner_twitch_id).wins++;
        }

        const subCount = subscriberIds
            ? users.filter(user => subscriberIds.has(user.twitch_id)).length
            : null;
        const participantsCount = users.filter(user => stats.get(user.twitch_id)?.tickets > 0).length;
        const winnersCount = users.filter(user => stats.get(user.twitch_id)?.wins > 0).length;

        const rows = users.map(user => {
            const entry = stats.get(user.twitch_id) || { tickets: 0, activeTickets: 0, giveaways: new Set(), points: 0, wins: 0, minigameWins: 0, minigamePoints: 0 };
            const isSub = subscriberIds ? subscriberIds.has(user.twitch_id) : null;

            return `
                <tr>
                    <td data-value="${escapeDashboardHtml(adminUserName(user))}">
                        <a class="user-cell" href="/admin/users/${encodeURIComponent(user.twitch_id)}">
                            ${adminAvatarHtml(user)}
                            <span>
                                <strong>${escapeDashboardHtml(adminUserName(user))}</strong>
                                <small>@${escapeDashboardHtml(user.twitch_login)}</small>
                            </span>
                        </a>
                    </td>
                    <td data-value="${isSub === null ? -1 : isSub ? 1 : 0}">${adminSubBadge(subscriberIds, user.twitch_id)}</td>
                    <td data-value="${entry.tickets}">${adminNumber(entry.tickets)}</td>
                    <td data-value="${entry.activeTickets}">${adminNumber(entry.activeTickets)}</td>
                    <td data-value="${entry.giveaways.size}">${adminNumber(entry.giveaways.size)}</td>
                    <td data-value="${entry.points}">${adminNumber(entry.points)}</td>
                    <td data-value="${entry.wins}">${entry.wins ? `<span class="badge badge-winner">🏆 ${adminNumber(entry.wins)}</span>` : "—"}</td>
                    <td data-value="${entry.minigameWins}">${adminNumber(entry.minigameWins)}</td>
                    <td data-value="${entry.minigamePoints}">${adminNumber(entry.minigamePoints)}</td>
                    <td data-value="${escapeDashboardHtml(user.created_at || "")}">${adminDate(user.created_at)}</td>
                </tr>
            `;
        }).join("");

        const content = `
            <h1>Usuários</h1>
            <p>Clique em um usuário para ver tudo sobre ele. Clique no título de uma coluna para ordenar.</p>

            <div class="stats-grid">
                <div class="stat-card stat-card-static"><span>Usuários cadastrados</span><h2>${adminNumber(users.length)}</h2></div>
                <div class="stat-card stat-card-static"><span>Inscritos (subs)</span><h2>${subCount === null ? "—" : adminNumber(subCount)}</h2>${subCount === null ? `<small class="stat-card-hint">Conta do canal não conectada</small>` : ""}</div>
                <div class="stat-card stat-card-static"><span>Já compraram tickets</span><h2>${adminNumber(participantsCount)}</h2></div>
                <div class="stat-card stat-card-static"><span>Já venceram</span><h2>${adminNumber(winnersCount)}</h2></div>
            </div>

            <div class="table-toolbar">
                <h2>Jogadores <span class="count-pill" data-filter-count="users-table">${adminNumber(users.length)}</span></h2>
                <input type="search" class="table-search" placeholder="Buscar por nome ou usuário..." data-filter-table="users-table" aria-label="Buscar usuários">
            </div>

            <div class="table-wrap">
                <table id="users-table" data-sortable>
                    <thead>
                        <tr>
                            <th data-sort="text">Usuário</th>
                            <th data-sort="number">Sub</th>
                            <th data-sort="number">Tickets</th>
                            <th data-sort="number">No sorteio ativo</th>
                            <th data-sort="number">Sorteios</th>
                            <th data-sort="number">Pontos gastos</th>
                            <th data-sort="number">Vitórias</th>
                            <th data-sort="number">Acertos no minigame</th>
                            <th data-sort="number">Pontos no minigame</th>
                            <th data-sort="text">Cadastro</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows || `<tr class="empty-row"><td colspan="10">Nenhum usuário cadastrado.</td></tr>`}
                    </tbody>
                </table>
            </div>
        `;

        res.send(renderAdminPage({
            title: "Usuários",
            activePath: "/admin/users",
            content,
            script: ADMIN_TABLE_SCRIPT
        }));
    } catch (error) {
        console.error("Erro ao carregar usuários:", error);
        res.status(500).send("Erro ao carregar usuários.");
    }
});

app.get("/admin/users/:twitchId", requireAdmin, async (req, res) => {
    const twitchId = req.params.twitchId;

    const notFound = () => res.status(404).send(renderAdminPage({
        title: "Usuário não encontrado",
        activePath: "/admin/users",
        content: `
            <a href="/admin/users" class="back-link">← Voltar aos usuários</a>
            <h1>Usuário não encontrado</h1>
            <p>Este usuário não existe ou ainda não entrou no site.</p>
        `
    }));

    if (!/^\d{1,20}$/.test(twitchId)) {
        return notFound();
    }

    try {
        const { data: user, error: userError } = await supabase
            .from("users")
            .select("twitch_id, twitch_login, display_name, profile_image_url, created_at")
            .eq("twitch_id", twitchId)
            .maybeSingle();

        if (userError) throw userError;
        if (!user) return notFound();

        const [giveaways, tickets, transactions, drawsResult, subscriberIds, balance] = await Promise.all([
            loadAdminGiveaways(),

            fetchAllRows((from, to) => supabase
                .from("tickets")
                .select("giveaway_id, ticket_number, created_at")
                .eq("twitch_id", twitchId)
                .order("ticket_number", { ascending: true })
                .range(from, to)),

            fetchAllRows((from, to) => supabase
                .from("transactions")
                .select("id, giveaway_id, points_spent, tickets_purchased, status, created_at")
                .eq("twitch_id", twitchId)
                .order("created_at", { ascending: false })
                .range(from, to)),

            supabase
                .from("giveaway_draws")
                .select("giveaway_id, round_number, winning_ticket_number, status, drawn_at")
                .eq("winner_twitch_id", twitchId)
                .order("drawn_at", { ascending: false }),

            getSubscriberIdsSafe(),

            (async () => {
                try {
                    const channelId = await getStreamElementsChannelId();
                    const points = Number(await getStreamElementsPoints(channelId, user.twitch_login));
                    return Number.isFinite(points) ? points : null;
                } catch (error) {
                    console.error("Erro ao buscar saldo do usuário:", error.message);
                    return null;
                }
            })()
        ]);

        if (drawsResult.error) console.error("Erro ao buscar rodadas do usuário:", drawsResult.error.message);

        const draws = drawsResult.data || [];
        const giveawaysById = new Map(giveaways.map(giveaway => [giveaway.id, giveaway]));
        const titleOf = (id) => giveawaysById.get(id)?.title || "Sorteio não encontrado";

        // Participação por sorteio
        const perGiveaway = new Map();

        for (const ticket of tickets) {
            const entry = perGiveaway.get(ticket.giveaway_id) || { tickets: 0, points: 0 };
            entry.tickets++;
            perGiveaway.set(ticket.giveaway_id, entry);
        }

        const completed = transactions.filter(transaction => transaction.status === "completed");

        for (const transaction of completed) {
            const entry = perGiveaway.get(transaction.giveaway_id) || { tickets: 0, points: 0 };
            entry.points += Number(transaction.points_spent) || 0;
            perGiveaway.set(transaction.giveaway_id, entry);
        }

        // Total de tickets de cada sorteio, para mostrar a fatia do usuário
        const giveawayIds = [...perGiveaway.keys()];
        const totals = new Map(await Promise.all(giveawayIds.map(async (id) => {
            const { count, error } = await supabase
                .from("tickets")
                .select("id", { count: "exact", head: true })
                .eq("giveaway_id", id);

            if (error) console.error("Erro ao contar tickets do sorteio:", error.message);

            return [id, error ? null : count || 0];
        })));

        const wins = draws.filter(draw => draw.status === "confirmed");
        const totalPoints = completed.reduce((sum, transaction) => sum + (Number(transaction.points_spent) || 0), 0);
        const purchaseDates = completed.map(transaction => transaction.created_at).filter(Boolean).sort();
        const isSub = subscriberIds ? subscriberIds.has(twitchId) : null;

        const resultFor = (giveawayId) => {
            const giveawayDraws = draws.filter(draw => draw.giveaway_id === giveawayId);
            if (!giveawayDraws.length) return "—";
            return giveawayDraws.map(draw => draw.status === "confirmed"
                ? `<span class="badge badge-winner">🏆 Venceu</span>`
                : adminBadge(draw.status, DRAW_STATUS_LABELS)).join(" ");
        };

        const participationRows = giveawayIds
            .map(id => ({ id, giveaway: giveawaysById.get(id), ...perGiveaway.get(id) }))
            .sort((a, b) => new Date(b.giveaway?.starts_at || 0) - new Date(a.giveaway?.starts_at || 0))
            .map(item => {
                const total = totals.get(item.id);
                const share = total ? (item.tickets / total) * 100 : null;

                return `
                    <tr>
                        <td><a href="/admin/tickets?sorteio=${encodeURIComponent(item.id)}">${escapeDashboardHtml(titleOf(item.id))}</a></td>
                        <td>${item.giveaway ? adminBadge(item.giveaway.status, GIVEAWAY_STATUS_LABELS) : "-"}</td>
                        <td>${adminDate(item.giveaway?.ends_at)}</td>
                        <td>${adminNumber(item.tickets)}${total ? ` <small class="muted-inline">de ${adminNumber(total)}</small>` : ""}</td>
                        <td>${share === null ? "-" : `${share.toLocaleString("pt-BR", { maximumFractionDigits: 1 })}%`}</td>
                        <td>${adminNumber(item.points)}</td>
                        <td>${resultFor(item.id)}</td>
                    </tr>
                `;
            }).join("");

        const drawRows = draws.map(draw => `
            <tr>
                <td><a href="/admin/tickets?sorteio=${encodeURIComponent(draw.giveaway_id)}">${escapeDashboardHtml(titleOf(draw.giveaway_id))}</a></td>
                <td>${escapeDashboardHtml(draw.round_number)}</td>
                <td>#${escapeDashboardHtml(draw.winning_ticket_number)}</td>
                <td>${draw.status === "confirmed" ? `<span class="badge badge-winner">🏆 Confirmado</span>` : adminBadge(draw.status, DRAW_STATUS_LABELS)}</td>
                <td>${adminDateTime(draw.drawn_at)}</td>
            </tr>
        `).join("");

        const purchaseRows = transactions.map(transaction => `
            <tr>
                <td>${adminDateTime(transaction.created_at)}</td>
                <td>${escapeDashboardHtml(titleOf(transaction.giveaway_id))}</td>
                <td>${adminNumber(transaction.tickets_purchased)}</td>
                <td>${adminNumber(transaction.points_spent)}</td>
                <td>${adminBadge(transaction.status, TRANSACTION_STATUS_LABELS)}</td>
                <td>${transaction.status === "pending" || transaction.status === "reconciliation_required" || transaction.status === "refund_pending"
                    ? `<a href="/admin/transactions/${encodeURIComponent(transaction.id)}/reconcile">Conferir compra</a>`
                    : ""}</td>
            </tr>
        `).join("");

        const content = `
            <a href="/admin/users" class="back-link">← Voltar aos usuários</a>

            <section class="user-profile-card">
                ${adminAvatarHtml(user, "large")}
                <div class="user-profile-info">
                    <h1>${escapeDashboardHtml(adminUserName(user))}</h1>
                    <p>
                        @${escapeDashboardHtml(user.twitch_login)} ·
                        <a href="https://www.twitch.tv/${encodeURIComponent(user.twitch_login)}" target="_blank" rel="noopener noreferrer">Abrir na Twitch ↗</a>
                    </p>
                    <div class="user-profile-badges">
                        ${isSub === null
                            ? `<span class="badge badge-muted" title="Conecte a conta do canal para consultar os inscritos">Sub: indisponível</span>`
                            : isSub ? `<span class="badge badge-sub">Sub da live</span>` : `<span class="badge badge-muted">Não é sub</span>`}
                        ${wins.length ? `<span class="badge badge-winner">🏆 Venceu ${adminNumber(wins.length)} ${wins.length === 1 ? "sorteio" : "sorteios"}</span>` : `<span class="badge badge-muted">Nunca venceu</span>`}
                    </div>
                    <dl class="user-profile-dates">
                        <div><dt>Cadastro</dt><dd>${adminDateTime(user.created_at)}</dd></div>
                        <div><dt>Primeira compra</dt><dd>${adminDateTime(purchaseDates[0])}</dd></div>
                        <div><dt>Última compra</dt><dd>${adminDateTime(purchaseDates[purchaseDates.length - 1])}</dd></div>
                    </dl>
                </div>
            </section>

            <div class="stats-grid stats-grid-6">
                <div class="stat-card stat-card-static"><span>Saldo atual</span><h2>${balance === null ? "—" : adminNumber(balance)}</h2><small class="stat-card-hint">${balance === null ? "StreamElements indisponível" : "pontos no StreamElements"}</small></div>
                <div class="stat-card stat-card-static"><span>Tickets comprados</span><h2>${adminNumber(tickets.length)}</h2></div>
                <div class="stat-card stat-card-static"><span>Pontos gastos</span><h2>${adminNumber(totalPoints)}</h2></div>
                <div class="stat-card stat-card-static"><span>Sorteios participados</span><h2>${adminNumber(giveawayIds.length)}</h2></div>
                <div class="stat-card stat-card-static"><span>Vitórias</span><h2>${adminNumber(wins.length)}</h2></div>
                <div class="stat-card stat-card-static"><span>Compras concluídas</span><h2>${adminNumber(completed.length)}</h2></div>
            </div>

            <h2>Participação por sorteio</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Sorteio</th>
                            <th>Status</th>
                            <th>Encerramento</th>
                            <th>Tickets</th>
                            <th>% dos tickets</th>
                            <th>Pontos</th>
                            <th>Resultado</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${participationRows || `<tr class="empty-row"><td colspan="7">Ainda não participou de nenhum sorteio.</td></tr>`}
                    </tbody>
                </table>
            </div>

            ${drawRows ? `
                <h2>Vezes em que foi sorteado</h2>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Sorteio</th>
                                <th>Rodada</th>
                                <th>Ticket</th>
                                <th>Resultado</th>
                                <th>Data</th>
                            </tr>
                        </thead>
                        <tbody>${drawRows}</tbody>
                    </table>
                </div>
            ` : ""}

            <h2>Histórico de compras</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Data</th>
                            <th>Sorteio</th>
                            <th>Tickets</th>
                            <th>Pontos</th>
                            <th>Status</th>
                            <th>Ação</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${purchaseRows || `<tr class="empty-row"><td colspan="6">Nenhuma compra registrada.</td></tr>`}
                    </tbody>
                </table>
            </div>
        `;

        res.send(renderAdminPage({
            title: adminUserName(user),
            activePath: "/admin/users",
            content
        }));
    } catch (error) {
        console.error("Erro ao carregar usuário:", error);
        res.status(500).send("Erro ao carregar o usuário.");
    }
});

app.get("/admin/tickets", requireAdmin, async (req, res) => {
    try {
        const data = await loadAdminGiveawayData(req);
        const { tickets, showAll, titlesById, draws } = data;

        const winnerIds = new Set(draws.filter(draw => draw.status === "confirmed").map(draw => draw.winner_twitch_id));

        // Participantes agrupados
        const participants = new Map();

        for (const ticket of tickets) {
            const entry = participants.get(ticket.twitch_id) || { user: ticket.users, count: 0, first: ticket.created_at };
            entry.count++;
            if (ticket.created_at && (!entry.first || ticket.created_at < entry.first)) entry.first = ticket.created_at;
            participants.set(ticket.twitch_id, entry);
        }

        const participantRows = [...participants.entries()]
            .sort((a, b) => b[1].count - a[1].count)
            .map(([twitchId, entry], index) => `
                <tr>
                    <td data-value="${index + 1}">${index + 1}</td>
                    <td data-value="${escapeDashboardHtml(adminUserName(entry.user))}">
                        <a href="/admin/users/${encodeURIComponent(twitchId)}">${escapeDashboardHtml(adminUserName(entry.user))}</a>
                        ${winnerIds.has(twitchId) ? ` <span class="badge badge-winner">🏆 Vencedor</span>` : ""}
                    </td>
                    <td data-value="${entry.count}">${adminNumber(entry.count)}</td>
                    <td data-value="${tickets.length ? entry.count / tickets.length : 0}">${tickets.length
                        ? `${((entry.count / tickets.length) * 100).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}%`
                        : "-"}</td>
                    <td data-value="${escapeDashboardHtml(entry.first || "")}">${adminDateTime(entry.first)}</td>
                </tr>
            `).join("");

        const ticketRows = tickets.map(ticket => `
            <tr>
                <td data-value="${Number(ticket.ticket_number) || 0}">#${escapeDashboardHtml(ticket.ticket_number)}</td>
                <td><a href="/admin/users/${encodeURIComponent(ticket.twitch_id)}">${escapeDashboardHtml(adminUserName(ticket.users))}</a></td>
                ${showAll ? `<td>${escapeDashboardHtml(titlesById.get(ticket.giveaway_id) || "Sorteio não encontrado")}</td>` : ""}
                <td data-value="${escapeDashboardHtml(ticket.created_at || "")}">${adminDateTime(ticket.created_at)}</td>
            </tr>
        `).join("");

        const content = `
            <h1>Tickets</h1>
            <p>Escolha um dia marcado no calendário para ver os tickets daquele sorteio.</p>

            ${adminGiveawayHeaderHtml(data, "/admin/tickets", req.query.mes)}

            ${data.hasScope ? `
                <div class="table-toolbar">
                    <h2>Participantes <span class="count-pill" data-filter-count="participants-table">${adminNumber(participants.size)}</span></h2>
                    <input type="search" class="table-search" placeholder="Buscar participante..." data-filter-table="participants-table" aria-label="Buscar participantes">
                </div>

                <div class="table-wrap">
                    <table id="participants-table" data-sortable>
                        <thead>
                            <tr>
                                <th data-sort="number">#</th>
                                <th data-sort="text">Usuário</th>
                                <th data-sort="number">Tickets</th>
                                <th data-sort="number">% dos tickets</th>
                                <th data-sort="text">Primeira compra</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${participantRows || `<tr class="empty-row"><td colspan="5">Nenhum participante ainda.</td></tr>`}
                        </tbody>
                    </table>
                </div>

                <div class="table-toolbar">
                    <h2>Tickets emitidos <span class="count-pill" data-filter-count="tickets-table">${adminNumber(tickets.length)}</span></h2>
                    <input type="search" class="table-search" placeholder="Buscar número ou usuário..." data-filter-table="tickets-table" aria-label="Buscar tickets">
                </div>

                <div class="table-wrap">
                    <table id="tickets-table" data-sortable>
                        <thead>
                            <tr>
                                <th data-sort="number">Número</th>
                                <th data-sort="text">Usuário</th>
                                ${showAll ? `<th data-sort="text">Sorteio</th>` : ""}
                                <th data-sort="text">Emissão</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${ticketRows || `<tr class="empty-row"><td colspan="${showAll ? 4 : 3}">Nenhum ticket emitido neste sorteio.</td></tr>`}
                        </tbody>
                    </table>
                </div>
            ` : ""}
        `;

        res.send(renderAdminPage({
            title: "Tickets",
            activePath: "/admin/tickets",
            content,
            script: ADMIN_TABLE_SCRIPT
        }));
    } catch (error) {
        console.error("Erro ao carregar tickets:", error);
        res.status(500).send("Erro ao carregar tickets.");
    }
});

app.get("/admin/reconciliation", requireAdmin, async (req, res) => {

    // Buscar transações que precisam de conferência
    const { data: transactions, error: transactionsError } = await supabase
        .from("transactions")
        .select(`
            id,
            twitch_id,
            giveaway_id,
            points_spent,
            tickets_purchased,
            status,
            created_at,
            users (
                display_name,
                twitch_login
            ),
            giveaways (
                title
            )
        `)
        .in("status", ["pending", "reconciliation_required", "refund_pending"])
        .order("created_at", { ascending: false });

    if (transactionsError) {
        console.error("Erro ao buscar transações:", transactionsError.message);
        return res.status(500).send("Erro ao carregar conferência.");
    }

    // Buscar tickets emitidos para essas transações
    const { data: tickets, error: ticketsError } = await supabase
        .from("tickets")
        .select("transaction_id");

    if (ticketsError) {
        console.error("Erro ao buscar tickets:", ticketsError.message);
        return res.status(500).send("Erro ao conferir tickets.");
    }

    const emittedTicketsByTransaction = (tickets || []).reduce((counts, ticket) => {
        if (ticket.transaction_id) {
            counts[ticket.transaction_id] =
                (counts[ticket.transaction_id] || 0) + 1;
        }

        return counts;
    }, {});

    const getTicketEmissionStatus = (transaction) => {
        const emitted = emittedTicketsByTransaction[transaction.id] || 0;
        const purchased = Number(transaction.tickets_purchased);

        if (emitted === purchased) {
            return "Quantidade confere";
        }

        if (emitted === 0) {
            return "Nenhum ticket emitido";
        }

        if (emitted < purchased) {
            return "Emissão parcial";
        }

        return "Quantidade divergente";
    };

    const escapeHtml = (value) => String(value ?? "").replace(
        /[&<>"']/g,
        (char) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[char]
    );

    const reconciliationRows = (transactions || []).map(transaction => `
        <tr>
            <td>${escapeHtml(transaction.id)}</td>
            <td>${escapeHtml(transaction.users?.display_name || transaction.users?.twitch_login || "Usuário desconhecido")}</td>
            <td>${escapeHtml(transaction.giveaways?.title || "Sorteio não encontrado")}</td>
            <td>${escapeHtml(transaction.points_spent)}</td>
            <td>${escapeHtml(transaction.tickets_purchased)}</td>
            <td>${emittedTicketsByTransaction[transaction.id] || 0}</td>
            <td>${getTicketEmissionStatus(transaction)}</td>
            <td>${escapeHtml(transaction.status)}</td>
            <td>${transaction.created_at ? new Date(transaction.created_at).toLocaleString("pt-BR") : "-"}</td>
            <td>
                <a href="/admin/transactions/${encodeURIComponent(transaction.id)}/reconcile">
                    Conferir compra
                </a>
            </td>
        </tr>
    `).join("");

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Conferência de compras - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/admin.css">
        </head>
        <body>

            <aside class="sidebar">
                <div class="logo">
                    <h1>WEIRDO'S</h1>
                    <span>TREASURE</span>
                </div>

                <nav>
                    <a href="/admin">Início</a>
                    <a href="/admin/users">Usuários</a>
                    <a href="/admin/giveaways">Sorteios</a>
                    <a href="/admin/tickets">Tickets</a>
                    <a href="/admin/transactions">Transações</a>
                    <a href="/admin/reconciliation">Conferência de compras</a>
                    <a href="/admin/settings">Configurações</a>
                </nav>

                <div class="sidebar-footer">
                    <a href="/dashboard">Voltar ao site</a>
                    <a href="/logout">Sair</a>
                </div>
            </aside>

            <main class="main-content">
                <h1>Conferência de compras</h1>
                <p>Compras pendentes ou que precisam de verificação.</p>

                <table>
                    <thead>
                        <tr>
                            <th>ID da transação</th>
                            <th>Usuário</th>
                            <th>Sorteio</th>
                            <th>Pontos</th>
                            <th>Tickets comprados</th>
                            <th>Tickets emitidos</th>
                            <th>Conferência</th>
                            <th>Status</th>
                            <th>Data</th>
                            <th>Ação</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${reconciliationRows || "<tr><td colspan='10'>Nenhuma compra precisa de conferência.</td></tr>"}
                    </tbody>
                </table>
            </main>

        </body>
        </html>
    `);
});

app.get("/admin/giveaways", requireAdmin, async (req, res) => {

    const csrfToken = getCsrfToken(req);

    const { data: giveaways, error } = await supabase
        .from("giveaways")
        .select("*")
        .order("created_at", { ascending: false });

    if (error) {
        console.error("Erro ao buscar sorteios:", error.message);
        return res.status(500).send("Erro ao carregar sorteios.");
    }

    const escapeHtml = (value) => String(value ?? "").replace(
    /[&<>"']/g,
    (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]
);

    
const giveawayRows = (giveaways || []).map(giveaway => `
    <tr>
        <td>${escapeHtml(giveaway.title)}</td>
        <td>${escapeHtml(giveaway.status)}</td>
        <td>${giveaway.starts_at ? new Date(giveaway.starts_at).toLocaleString("pt-BR") : "-"}</td>
        <td>${giveaway.ends_at ? new Date(giveaway.ends_at).toLocaleString("pt-BR") : "-"}</td>
        
<td>
    <div class="giveaway-actions">
        ${
            giveaway.status === "draft" ? `
                <a class="giveaway-action-button"
                   href="/admin/giveaways/${encodeURIComponent(giveaway.id)}/edit">
                    Editar
                </a>

                <form class="giveaway-action-form"
                      action="/admin/giveaways/${encodeURIComponent(giveaway.id)}/activate"
                      method="POST">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <button type="submit">Ativar sorteio</button>
                </form>

                <form class="giveaway-action-form"
                      action="/admin/giveaways/${encodeURIComponent(giveaway.id)}/cancel"
                      method="POST">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <button type="submit">Cancelar sorteio</button>
                </form>
            ` : giveaway.status === "active" ? `
                <form class="giveaway-action-form"
                      action="/admin/giveaways/${encodeURIComponent(giveaway.id)}/close"
                      method="POST">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <button type="submit">Encerrar sorteio</button>
                </form>

                <form class="giveaway-action-form"
                      action="/admin/giveaways/${encodeURIComponent(giveaway.id)}/cancel"
                      method="POST">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <button type="submit">Cancelar sorteio</button>
                </form>
            ` : giveaway.status === "closed" ? `
    <button
        type="button"
        class="giveaway-action-button"
        onclick="window.open(
            '/arena/${encodeURIComponent(giveaway.id)}',
            '_blank',
            'width=950,height=750'
        )">
        Iniciar sorteio
    </button>
` : ""
        }
    </div>
</td>

    </tr>
`).join("");

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
    <meta charset="UTF-8">
    <title>Sorteios - Weirdo's Treasure</title>
    <link rel="stylesheet" href="/css/admin.css">
</head>
        <body>

    <aside class="sidebar">
        <div class="logo">
            <h1>WEIRDO'S</h1>
            <span>TREASURE</span>
        </div>

        <nav>
            <a href="/admin">Início</a>
            <a href="/admin/users">Usuários</a>
            <a href="/admin/giveaways">Sorteios</a>
            <a href="/admin/tickets">Tickets</a>
            <a href="/admin/transactions">Transações</a>
            <a href="/admin/reconciliation">Conferência de compras</a>
            <a href="/admin/settings">Configurações</a>
        </nav>

        <div class="sidebar-footer">
            <a href="/dashboard">Voltar ao site</a>
            <a href="/logout">Sair</a>
        </div>
    </aside>

    <main class="main-content">
        <h1>Sorteios</h1>
            <p>Gerenciamento de sorteios do Weirdo's Treasure.</p>

            <p><a href="/admin">Voltar ao painel</a></p>

            <section style="background:#211c17; border:1px solid ${twitchBroadcasterAccessToken ? "#4f7a46" : "#8b493d"}; border-radius:12px; padding:20px 25px; max-width:640px; margin:10px 0 26px;">
                <h2 style="margin:0 0 8px; font-size:18px; color:#d6a85c;">Canal da Twitch</h2>
                <p style="margin:0 0 14px; color:#c8baa4; line-height:1.5;">
                    ${twitchBroadcasterAccessToken
                        ? "✔ Conectado. O chat (confirmação dos vencedores) e a lista de inscritos estão funcionando."
                        : "✖ Não conectado. Conecte antes de sortear: sem isso o sorteio não consulta os inscritos e o vencedor não consegue confirmar pelo chat."}
                </p>
                <a href="/auth/twitch?canal=1" style="display:inline-block; padding:10px 18px; background:linear-gradient(180deg,#c99b53,#98703a); color:#21170c; border-radius:6px; font-weight:bold; text-decoration:none;">
                    ${twitchBroadcasterAccessToken ? "Reconectar canal" : "Conectar canal"}
                </a>
                <p style="margin:14px 0 0; color:#a99578; font-size:13px; line-height:1.5;">
                    Quando a data de encerramento chega, o sorteio só fecha a compra de tickets.
                    O giro é sempre manual: clique em "Iniciar sorteio" e depois em "Iniciar giro" na Arena.
                </p>
            </section>

<h2>Criar novo sorteio</h2>

<form action="/admin/giveaways" method="POST" class="giveaway-form">
    <input type="hidden" name="_csrf" value="${csrfToken}">

    <div class="giveaway-field">
        <label for="title">Nome do sorteio</label>
        <input
            type="text"
            id="title"
            name="title"
            placeholder="Ex: Sorteio de 30 dias de VIP"
            maxlength="100"
            required
        >
    </div>

    <div class="giveaway-field">
        <label for="description">Descrição</label>
        <textarea
            id="description"
            name="description"
            placeholder="Descreva o prêmio e as regras do sorteio."
            rows="4"
        ></textarea>
    </div>

    <div class="giveaway-field">
        <label for="starts_at">Data e horário de início</label>
        <input
            type="datetime-local"
            id="starts_at"
            name="starts_at"
            required
        >
    </div>

    <div class="giveaway-field">
        <label for="ends_at">Data e horário de encerramento</label>
        <input
            type="datetime-local"
            id="ends_at"
            name="ends_at"
            required
        >
    </div>

    <button type="submit">Cadastrar sorteio</button>
</form>

<h2>Sorteios cadastrados</h2>

            <table>
                <thead>
                    <tr>
                        <th>Título</th>
                        <th>Status</th>
                        <th>Início</th>
                        <th>Encerramento</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    ${giveawayRows || '<tr><td colspan="5">Nenhum sorteio cadastrado.</td></tr>'}
                </tbody>
            </table>
            </main>
        </body>
        </html>
    `);
});

async function getAllSubscribers(accessToken, broadcasterId) {
    const subscribers = new Set();
    let cursor = null;

    do {
        const url = new URL(
            "https://api.twitch.tv/helix/subscriptions"
        );

        url.searchParams.set("broadcaster_id", broadcasterId);
        url.searchParams.set("first", "100");

        if (cursor) {
            url.searchParams.set("after", cursor);
        }

        const response = await fetch(url, {
            headers: {
                "Client-Id": process.env.TWITCH_CLIENT_ID,
                "Authorization": `Bearer ${accessToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                `Erro ao consultar inscritos: ${JSON.stringify(data)}`
            );
        }

        for (const subscriber of data.data) {
            subscribers.add(subscriber.user_id);
        }

        cursor = data.pagination?.cursor || null;

    } while (cursor);

    return subscribers;
}

async function getValidTwitchBroadcasterAccessToken() {
    const refreshMargin = 5 * 60 * 1000;

    if (
        !twitchBroadcasterId ||
        !twitchBroadcasterAccessToken ||
        !twitchBroadcasterRefreshToken
    ) {
        throw new Error(
            "A conta administradora da Twitch não está autenticada."
        );
    }

    // Tentar salvar tokens novos que ficaram pendentes
if (twitchTokenPersistencePending) {
    await saveTwitchBroadcasterTokens(
        twitchBroadcasterId,
        twitchBroadcasterAccessToken,
        twitchBroadcasterRefreshToken,
        twitchBroadcasterTokenExpiresAt
    );

    twitchTokenPersistencePending = false;

    console.log("Tokens da Twitch sincronizados com o Supabase.");
}

// Reutilizar o token se ainda estiver válido por mais de 5 minutos
if (
    Date.now() < twitchBroadcasterTokenExpiresAt - refreshMargin
) {
    return twitchBroadcasterAccessToken;
}

    // Evitar várias renovações simultâneas
    if (!twitchTokenRefreshPromise) {
        twitchTokenRefreshPromise = (async () => {
            const response = await fetch(
                "https://id.twitch.tv/oauth2/token",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    body: new URLSearchParams({
                        client_id: process.env.TWITCH_CLIENT_ID,
                        client_secret: process.env.TWITCH_CLIENT_SECRET,
                        grant_type: "refresh_token",
                        refresh_token: twitchBroadcasterRefreshToken
                    })
                }
            );

            const tokenData = await response.json();

            if (
                !response.ok ||
                !tokenData.access_token ||
                !tokenData.refresh_token ||
                !Number.isSafeInteger(tokenData.expires_in) ||
                tokenData.expires_in <= 0
            ) {
                throw new Error(
                    `Falha ao renovar token da Twitch: ${
                        tokenData.message || response.status
                    }`
                );
            }

            // Atualizar os tokens e a expiração em memória
twitchBroadcasterAccessToken = tokenData.access_token;
twitchBroadcasterRefreshToken = tokenData.refresh_token;

twitchBroadcasterTokenExpiresAt =
    Date.now() + (tokenData.expires_in * 1000);

// Marcar como pendente até confirmar o salvamento
twitchTokenPersistencePending = true;

// Persistir os novos tokens criptografados
await saveTwitchBroadcasterTokens(
    twitchBroadcasterId,
    twitchBroadcasterAccessToken,
    twitchBroadcasterRefreshToken,
    twitchBroadcasterTokenExpiresAt
);

twitchTokenPersistencePending = false;

console.log("Token administrativo da Twitch renovado e salvo.");

return twitchBroadcasterAccessToken;
        })();
    }

    try {
        return await twitchTokenRefreshPromise;
    } finally {
        twitchTokenRefreshPromise = null;
    }
}

async function getCachedSubscribers() {
    const cacheDuration = 60 * 1000; // 60 segundos

    const now = Date.now();

    // Reutilizar a lista armazenada se ainda estiver atualizada
    if (now - twitchSubscribersLastUpdate < cacheDuration) {
        return twitchSubscribersCache;
    }

    // Verificar se a conta administradora está conectada
    if (!twitchBroadcasterAccessToken || !twitchBroadcasterId) {
        return new Set();
    }

    // Buscar a lista atualizada na Twitch
    const accessToken = await getValidTwitchBroadcasterAccessToken();

const subscribers = await getAllSubscribers(
    accessToken,
    twitchBroadcasterId
);

    twitchSubscribersCache = subscribers;
    twitchSubscribersLastUpdate = now;

    return twitchSubscribersCache;
}

// O giro agora começa pelo botão da própria Arena; a página antiga só redireciona
app.get("/admin/giveaways/:id/prepare", requireAdmin, (req, res) => {
    return res.redirect("/arena/" + encodeURIComponent(req.params.id));
});

app.post("/admin/giveaways/:id/draw", requireAdmin, requireCsrf, async (req, res) => {

    const user = req.session.twitchUser;

    // A Arena chama esta rota via fetch e espera JSON; o formulário antigo recebe texto/redirecionamento
    const wantsJson = req.get("X-Requested-With") === "fetch";
    const fail = (status, message) => wantsJson
        ? res.status(status).json({ ok: false, error: message })
        : res.status(status).send(message);

    try {
        const giveawayId = req.params.id;

        // Confirmar que o sorteio está encerrado
        const { data: giveaway, error: giveawayError } = await supabase
            .from("giveaways")
            .select("id, status")
            .eq("id", giveawayId)
            .single();

        if (giveawayError || !giveaway || giveaway.status !== "closed") {
            return fail(400, "O sorteio precisa estar encerrado para ser realizado.");
        }

        // Não permitir nova rodada enquanto o vencedor atual ainda pode responder
        const { data: latestDraw, error: latestDrawError } = await supabase
            .from("giveaway_draws")
            .select("status, response_deadline_at")
            .eq("giveaway_id", giveawayId)
            .order("round_number", { ascending: false })
            .limit(1)
            .maybeSingle();

        if (latestDrawError) throw latestDrawError;

        if (
            latestDraw &&
            latestDraw.status === "awaiting_response" &&
            new Date(latestDraw.response_deadline_at).getTime() > Date.now()
        ) {
            return fail(409, "Aguarde o vencedor atual responder ou o tempo acabar.");
        }

        // Buscar todos os vencedores das rodadas anteriores
const { data: previousWinners, error: winnersError } = await supabase
    .from("giveaway_draws")
    .select("winner_twitch_id")
    .eq("giveaway_id", giveawayId);

if (winnersError) throw winnersError;

const previousWinnerIds = new Set(
    (previousWinners || []).map(winner => winner.winner_twitch_id)
);

// Buscar todos os tickets, sem depender do limite padrão
let tickets = [];
let from = 0;
const batchSize = 1000;

while (true) {
    const { data, error } = await supabase
        .from("tickets")
        .select("twitch_id, ticket_number")
        .eq("giveaway_id", giveawayId)
        .order("ticket_number", { ascending: true })
        .range(from, from + batchSize - 1);

    if (error) throw error;

    tickets.push(...data);

    if (data.length < batchSize) break;

    from += batchSize;
}

// Remover todos os tickets de quem já venceu
tickets = tickets.filter(
    ticket => !previousWinnerIds.has(ticket.twitch_id)
);

if (tickets.length === 0) {
    return fail(400, "Não existem mais participantes elegíveis para vencer este sorteio.");
}

// Consultar inscritos ativos na Twitch
        if (!twitchBroadcasterAccessToken || !twitchBroadcasterId) {
            return fail(503, "Conecte o canal da Twitch na página Sorteios do painel antes de sortear.");
        }

        const accessToken = await getValidTwitchBroadcasterAccessToken();

const subscribers = await getAllSubscribers(
    accessToken,
    user.id
);

const { data: settings, error: settingsError } = await supabase
    .from("system_settings")
    .select("points_per_ticket, subscriber_multiplier")
    .eq("id", 1)
    .single();

if (settingsError || !settings) {
    throw new Error("Não foi possível carregar as configurações do sorteio.");
}

const subscriberMultiplier = Number(settings.subscriber_multiplier);

if (
    !Number.isSafeInteger(subscriberMultiplier) ||
    subscriberMultiplier < 1
) {
    throw new Error(
        "Multiplicador de inscritos inválido. Verifique as configurações."
    );
}

        // Calcular participantes e chances
        const participantIds = new Set(
            tickets.map(ticket => ticket.twitch_id)
        );

        const subscriberParticipants = new Set(
            [...participantIds].filter(id => subscribers.has(id))
        );

        const totalWeightedEntries = tickets.reduce(
    (total, ticket) =>
        total + (subscribers.has(ticket.twitch_id) ? subscriberMultiplier : 1),
    0
);

        // Sortear uma posição dentro do total de chances
        let winningPosition = crypto.randomInt(totalWeightedEntries);
        let winningTicket = null;

        for (const ticket of tickets) {
            const weight = subscribers.has(ticket.twitch_id)
    ? subscriberMultiplier
    : 1;

            if (winningPosition < weight) {
                winningTicket = ticket;
                break;
            }

            winningPosition -= weight;
        }

        if (!winningTicket) {
            throw new Error("Não foi possível identificar o ticket vencedor.");
        }

        // Registrar o resultado atomicamente no Supabase
const { data: roundNumber, error: finalizeError } = await supabase.rpc(
    "finalize_giveaway_draw",
    {
        p_giveaway_id: giveawayId,
        p_admin_twitch_id: user.id,
        p_winner_twitch_id: winningTicket.twitch_id,
        p_winner_ticket_number: winningTicket.ticket_number,
        p_total_tickets: tickets.length,
        p_total_participants: participantIds.size,
        p_total_weighted_entries: totalWeightedEntries,
        p_subscriber_count: subscriberParticipants.size
    }
);

if (finalizeError) throw finalizeError;

console.log(`Rodada ${roundNumber} registrada com sucesso.`);

        // O prazo de resposta passa a contar depois do giro da Arena
        // (só estende; nunca encurta o prazo definido no banco).
        try {
            const { data: newDraw, error: newDrawError } = await supabase
                .from("giveaway_draws")
                .select("id, drawn_at, response_deadline_at")
                .eq("giveaway_id", giveawayId)
                .eq("round_number", roundNumber)
                .maybeSingle();

            if (newDrawError) throw newDrawError;

            if (newDraw) {
                const wantedDeadline = new Date(
                    new Date(newDraw.drawn_at).getTime() + ARENA_SPIN_MS + ARENA_RESPONSE_MS
                );

                if (!newDraw.response_deadline_at || new Date(newDraw.response_deadline_at) < wantedDeadline) {
                    const { error: deadlineError } = await supabase
                        .from("giveaway_draws")
                        .update({ response_deadline_at: wantedDeadline.toISOString() })
                        .eq("id", newDraw.id)
                        .eq("status", "awaiting_response");

                    if (deadlineError) throw deadlineError;
                }
            }
        } catch (deadlineError) {
            console.error("Não foi possível ajustar o prazo de resposta:", deadlineError.message);
        }

        invalidateArenaState(giveawayId);

        if (wantsJson) {
            return res.json({ ok: true, round: roundNumber });
        }

        return res.redirect(
    "/arena/" + encodeURIComponent(giveawayId)
);

    } catch (error) {
        console.error("Erro ao realizar sorteio:", error);
        return fail(500, "Não foi possível realizar o sorteio. Consulte o terminal do servidor.");
    }
});

app.get("/giveaways", async (req, res) => {
    if (!req.session.twitchUser) {
        return res.redirect("/");
    }

    try {
        const now = new Date().toISOString();

        const { data: settings, error: settingsError } = await supabase
            .from("system_settings")
            .select("points_per_ticket")
            .eq("id", 1)
            .single();

        if (settingsError || !settings) {
            throw new Error("Não foi possível carregar o preço dos tickets.");
        }

        const pointsPerTicket = settings.points_per_ticket;

        if (!req.session.csrfToken) {
            req.session.csrfToken = crypto.randomBytes(32).toString("hex");
        }

        const csrfToken = req.session.csrfToken;

        const { data: giveaways, error } = await supabase
            .from("giveaways")
            .select("id, title, description, starts_at, ends_at")
            .eq("status", "active")
            .lte("starts_at", now)
            .gte("ends_at", now)
            .order("ends_at", { ascending: true });

        if (error) throw error;

        const sessionUser = req.session.twitchUser;
        const activeGiveaways = giveaways || [];

        // Saldo do usuário (se falhar, a página mostra "indisponível" e o servidor valida na compra)
        const userPointsPromise = (async () => {
            try {
                const channelId = await getStreamElementsChannelId();
                const value = Number(await getStreamElementsPoints(channelId, sessionUser.login));
                return Number.isFinite(value) ? value : null;
            } catch (pointsError) {
                console.error("Erro ao buscar saldo na página de sorteios:", pointsError.message);
                return null;
            }
        })();

        // Quantidade de tickets do usuário em cada sorteio
        const ticketCountsPromise = Promise.all(activeGiveaways.map(async (giveaway) => {
            const { count, error: countError } = await supabase
                .from("tickets")
                .select("id", { count: "exact", head: true })
                .eq("giveaway_id", giveaway.id)
                .eq("twitch_id", sessionUser.id);

            if (countError) {
                console.error("Erro ao contar tickets do usuário:", countError.message);
                return null;
            }

            return count || 0;
        }));

        const [userPoints, ticketCounts] = await Promise.all([
            userPointsPromise,
            ticketCountsPromise
        ]);

        const price = Number(pointsPerTicket);
        const formatPoints = (value) => Number(value).toLocaleString("pt-BR");
        const hasBalance = userPoints !== null;
        const maxAffordable = hasBalance && price > 0 ? Math.min(MAX_TICKETS_PER_PURCHASE, Math.floor(userPoints / price)) : 0;
        const initialMissing = hasBalance ? Math.max(0, price - userPoints) : 0;
        const initialCanBuy = !hasBalance || initialMissing === 0;

        const escapeGiveawayText = (value) =>
            String(value ?? "").replace(/[&<>"']/g, char => ({
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;"
            })[char]);

        const giveawayCards = activeGiveaways.map((giveaway, index) => {
            const purchaseKey = crypto.randomUUID();
            const quantityId = `quantity-${escapeGiveawayText(giveaway.id)}`;
            const userTickets = ticketCounts[index];

            return `
                <article
                    class="giveaway-card"
                    data-price="${price}"
                    data-balance="${hasBalance ? userPoints : ""}"
                >
                    <div class="giveaway-card-art">
                        <span class="giveaway-active-status">● EM ANDAMENTO</span>
                        <h2>${escapeGiveawayText(giveaway.title)}</h2>
                        ${TREASURE_CHEST_SVG}
                    </div>

                    <p class="giveaway-description">${escapeGiveawayText(giveaway.description || "Nenhuma descrição disponível para este tesouro.")}</p>

                    <div class="giveaway-facts">
                        <div class="giveaway-fact">
                            <span>⌛ ENCERRA EM</span>
                            <strong>${escapeGiveawayText(new Date(giveaway.ends_at).toLocaleString("pt-BR", {
                                timeZone: "America/Sao_Paulo",
                                dateStyle: "short",
                                timeStyle: "short"
                            }))}</strong>
                        </div>

                        <div class="giveaway-fact giveaway-fact-highlight">
                            <span>🎟 SEUS TICKETS</span>
                            <strong>${userTickets === null ? "—" : formatPoints(userTickets)}</strong>
                        </div>
                    </div>

                    <div class="giveaway-purchase-area">
                        <div class="giveaway-wallet">
                            <div>
                                <span>SEU SALDO</span>
                                <strong>${hasBalance ? `${formatPoints(userPoints)} pontos` : "Indisponível"}</strong>
                            </div>
                            <div>
                                <span>PREÇO DO TICKET</span>
                                <strong>${formatPoints(price)} pontos</strong>
                            </div>
                        </div>

                        <label for="${quantityId}">Quantidade de tickets</label>

                        <div class="quantity-stepper">
                            <button type="button" class="stepper-button" data-step="-1" aria-label="Diminuir quantidade" disabled>−</button>
                            <input
                                type="number"
                                id="${quantityId}"
                                class="ticket-quantity"
                                min="1"
                                max="${MAX_TICKETS_PER_PURCHASE}"
                                step="1"
                                value="1"
                                inputmode="numeric"
                            >
                            <button type="button" class="stepper-button" data-step="1" aria-label="Aumentar quantidade">+</button>
                        </div>

                        <div class="quantity-shortcuts">
                            <button type="button" data-set="1">1</button>
                            <button type="button" data-set="5">5</button>
                            <button type="button" data-set="10">10</button>
                            <button type="button" data-set="max" ${maxAffordable >= 1 ? "" : "disabled"}>Máx</button>
                        </div>

                        <div class="giveaway-summary">
                            <div>
                                <span>TOTAL DA COMPRA</span>
                                <strong class="ticket-total">${formatPoints(price)} pontos</strong>
                            </div>
                            ${hasBalance ? `
                                <div>
                                    <span>SALDO APÓS A COMPRA</span>
                                    <strong class="balance-after${initialCanBuy ? "" : " is-negative"}">${initialCanBuy ? `${formatPoints(userPoints - price)} pontos` : "—"}</strong>
                                </div>
                            ` : ""}
                        </div>

                        <p class="giveaway-missing" ${initialCanBuy ? "hidden" : ""}>
                            Saldo insuficiente: faltam <strong class="missing-points">${formatPoints(initialMissing)}</strong> pontos.
                        </p>

                        <form
                            action="/giveaways/${encodeURIComponent(giveaway.id)}/purchase"
                            method="POST"
                        >
                            <input
                                type="hidden"
                                name="_csrf"
                                value="${csrfToken}"
                            >

                            <input
                                type="hidden"
                                name="idempotency_key"
                                value="${purchaseKey}"
                            >

                            <input
                                type="hidden"
                                name="quantity"
                                class="purchase-quantity"
                                value="1"
                            >

                            <button type="submit" class="giveaway-buy-button" ${initialCanBuy ? "" : "disabled"}>
                                ✦ COMPRAR TICKETS ✦
                            </button>
                        </form>

                        <p class="giveaway-purchase-note">
                            A compra será realizada utilizando seus pontos do canal.
                        </p>
                    </div>
                </article>
            `;
        }).join("");

        return res.send(withPublicSidebar(req, `
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Sorteios disponíveis | Weirdo's Treasure</title>
                <link rel="stylesheet" href="/css/home.css">

                <style>
                    .giveaways-page {
                        width: min(100% - 40px, 1100px);
                        margin: 45px auto;
                    }

                    .giveaways-title {
                        margin: 0 0 24px;
                        color: #e2bd76;
                        font-size: clamp(27px, 4vw, 38px);
                    }

                    .giveaways-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
                        gap: 22px;
                        align-items: start;
                    }

                    .giveaway-card {
                        margin: 0;
                        padding: 0;
                        overflow: hidden;
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border: 1px solid #8b683c;
                        border-radius: 10px;
                        box-shadow: 0 7px 20px rgba(0,0,0,.3);
                    }

                    .giveaway-card-art {
                        position: relative;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        gap: 14px;
                        padding: 46px 20px 18px;
                        background:
                            radial-gradient(ellipse at center, rgba(211,157,65,.32), transparent 65%),
                            linear-gradient(145deg, #51402a, #211912 75%);
                        border-bottom: 1px solid #806039;
                    }

                    .giveaway-card-art .treasure-chest {
                        display: block;
                        width: 200px;
                        max-width: 70%;
                        height: auto;
                        image-rendering: pixelated;
                        filter: drop-shadow(0 10px 14px rgba(0,0,0,.45));
                    }

                    .giveaway-active-status {
                        position: absolute;
                        top: 12px;
                        right: 12px;
                        padding: 5px 9px;
                        background: #365b36;
                        border: 1px solid #5b8c51;
                        border-radius: 4px;
                        color: #c4edb8;
                        font-family: Arial, sans-serif;
                        font-size: 10px;
                        font-weight: bold;
                        letter-spacing: 1px;
                    }

                    .giveaway-card h2 {
                        margin: 0;
                        color: #e7c586;
                        font-size: 23px;
                        text-align: center;
                        text-shadow: 0 2px 6px rgba(0,0,0,.5);
                        overflow-wrap: anywhere;
                    }

                    .giveaway-description {
                        margin: 22px 22px 20px;
                        color: #c8baa4;
                        font-size: 14px;
                        line-height: 1.7;
                        white-space: pre-wrap;
                        overflow-wrap: anywhere;
                    }

                    .giveaway-facts {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 10px;
                        margin: 0 22px 22px;
                    }

                    .giveaway-fact {
                        display: flex;
                        flex-direction: column;
                        gap: 6px;
                        padding: 12px 14px;
                        background: rgba(0,0,0,.22);
                        border: 1px solid #51402a;
                        border-radius: 7px;
                    }

                    .giveaway-fact span {
                        color: #a99578;
                        font-size: 10px;
                        font-weight: bold;
                        letter-spacing: 1px;
                    }

                    .giveaway-fact strong {
                        color: #e8dfcf;
                        font-size: 14px;
                    }

                    .giveaway-fact-highlight {
                        border-color: #806039;
                        background: rgba(214,168,92,.1);
                    }

                    .giveaway-fact-highlight strong {
                        color: #e2bd7b;
                        font-size: 20px;
                    }

                    .giveaway-purchase-area {
                        padding: 22px;
                        background: rgba(0,0,0,.18);
                        border-top: 1px solid rgba(198,157,92,.25);
                    }

                    .giveaway-wallet,
                    .giveaway-summary {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 10px;
                    }

                    .giveaway-wallet {
                        margin-bottom: 20px;
                    }

                    .giveaway-wallet div,
                    .giveaway-summary div {
                        display: flex;
                        flex-direction: column;
                        gap: 5px;
                    }

                    .giveaway-wallet span,
                    .giveaway-summary span {
                        color: #a99578;
                        font-size: 10px;
                        font-weight: bold;
                        letter-spacing: 1px;
                    }

                    .giveaway-wallet strong {
                        color: #e2bd76;
                        font-size: 16px;
                    }

                    .giveaway-purchase-area label {
                        display: block;
                        margin-bottom: 9px;
                        color: #e1d3bd;
                        font-size: 13px;
                    }

                    .quantity-stepper {
                        display: flex;
                        align-items: stretch;
                        width: 100%;
                        max-width: 220px;
                        height: 46px;
                        overflow: hidden;
                        background: #15120f;
                        border: 1px solid #806039;
                        border-radius: 6px;
                    }

                    .quantity-stepper:focus-within {
                        border-color: #d6ad69;
                        box-shadow: 0 0 0 2px rgba(214,173,105,.15);
                    }

                    .stepper-button {
                        flex: 0 0 46px;
                        background: linear-gradient(180deg, #3a2d20, #251c14);
                        border: none;
                        color: #e2bd76;
                        font-size: 22px;
                        line-height: 1;
                        cursor: pointer;
                    }

                    .stepper-button:first-child {
                        border-right: 1px solid #705332;
                    }

                    .stepper-button:last-child {
                        border-left: 1px solid #705332;
                    }

                    .stepper-button:hover:not(:disabled) {
                        background: linear-gradient(180deg, #4a3a28, #33281c);
                    }

                    .stepper-button:disabled {
                        color: #6b5a44;
                        cursor: not-allowed;
                    }

                    .giveaway-purchase-area .ticket-quantity {
                        flex: 1;
                        min-width: 0;
                        padding: 0 8px;
                        background: transparent;
                        border: none;
                        color: #f0dfbd;
                        font-family: inherit;
                        font-size: 18px;
                        font-weight: bold;
                        text-align: center;
                        outline: none;
                        -moz-appearance: textfield;
                    }

                    .ticket-quantity::-webkit-outer-spin-button,
                    .ticket-quantity::-webkit-inner-spin-button {
                        -webkit-appearance: none;
                        margin: 0;
                    }

                    .quantity-shortcuts {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 8px;
                        margin-top: 10px;
                    }

                    .quantity-shortcuts button {
                        min-width: 46px;
                        min-height: 34px;
                        padding: 6px 12px;
                        background: rgba(0,0,0,.25);
                        border: 1px solid #705332;
                        border-radius: 5px;
                        color: #e2bd7b;
                        font-family: inherit;
                        font-size: 13px;
                        font-weight: bold;
                        cursor: pointer;
                        transition: border-color .2s, background .2s;
                    }

                    .quantity-shortcuts button:hover:not(:disabled),
                    .quantity-shortcuts button.is-selected {
                        background: rgba(214,168,92,.15);
                        border-color: #d6a85c;
                    }

                    .quantity-shortcuts button:disabled {
                        color: #6b5a44;
                        border-color: #4a3a28;
                        cursor: not-allowed;
                    }

                    .giveaway-summary {
                        margin: 20px 0 14px;
                        padding: 15px;
                        background: rgba(214,173,105,.08);
                        border: 1px solid #806039;
                        border-radius: 7px;
                    }

                    .giveaway-summary strong {
                        color: #e2bd76;
                        font-size: 18px;
                    }

                    .giveaway-summary .balance-after {
                        color: #e8dfcf;
                    }

                    .giveaway-summary .balance-after.is-negative {
                        color: #8f7d63;
                    }

                    .giveaway-missing {
                        margin: 0 0 14px;
                        padding: 10px 12px;
                        background: rgba(194,85,63,.12);
                        border: 1px solid #8a3b2c;
                        border-radius: 6px;
                        color: #f0a48f;
                        font-size: 13px;
                        line-height: 1.5;
                    }

                    .giveaway-missing strong {
                        color: #f6b6a3;
                    }

                    .giveaway-buy-button {
                        display: block;
                        width: 100%;
                        min-height: 48px;
                        padding: 13px 18px;
                        background: linear-gradient(180deg, #e2bd76, #a77a3d);
                        border: 1px solid #f0d49b;
                        border-radius: 6px;
                        color: #21170c;
                        font-family: inherit;
                        font-size: 13px;
                        font-weight: bold;
                        letter-spacing: 1px;
                        cursor: pointer;
                        transition: filter .2s, transform .2s;
                    }

                    .giveaway-buy-button:hover:not(:disabled) {
                        filter: brightness(1.15);
                        transform: translateY(-2px);
                    }

                    .giveaway-buy-button:disabled {
                        background: linear-gradient(180deg, #4a3a28, #33281c);
                        border-color: #705332;
                        color: #8f7d63;
                        cursor: not-allowed;
                    }

                    .giveaway-purchase-note {
                        margin: 13px 0 0;
                        color: #998a75;
                        font-size: 11px;
                        line-height: 1.5;
                        text-align: center;
                    }

                    .giveaways-empty {
                        padding: 50px 25px;
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border: 1px dashed #8b683c;
                        border-radius: 10px;
                        text-align: center;
                    }

                    .giveaways-empty-symbol {
                        color: #d6ad69;
                        font-size: 42px;
                    }

                    .giveaways-empty h2 {
                        color: #e2bd76;
                    }

                    .giveaways-empty p {
                        color: #c8baa4;
                        line-height: 1.6;
                    }

                    .giveaways-footer {
                        margin-top: 30px;
                    }

                    .giveaways-footer a {
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        min-height: 44px;
                        padding: 12px 20px;
                        box-sizing: border-box;
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border: 1px solid #806039;
                        border-radius: 6px;
                        color: #e2bd76;
                        font-size: 13px;
                        font-weight: bold;
                        text-decoration: none;
                        transition: filter .2s, transform .2s;
                    }

                    .giveaways-footer a:hover {
                        filter: brightness(1.2);
                        transform: translateY(-2px);
                    }

                    @media(max-width: 600px) {
                        .giveaways-page {
                            width: calc(100% - 24px);
                            margin: 25px auto;
                        }

                        .giveaway-card h2 {
                            font-size: 20px;
                        }

                        .giveaway-facts {
                            margin-left: 16px;
                            margin-right: 16px;
                        }

                        .giveaway-description {
                            margin-left: 16px;
                            margin-right: 16px;
                        }

                        .giveaway-purchase-area {
                            padding: 18px 16px;
                        }

                        .quantity-stepper {
                            max-width: none;
                        }

                        .quantity-shortcuts button {
                            flex: 1;
                        }

                        .giveaway-summary strong {
                            font-size: 16px;
                        }

                        .giveaways-footer a {
                            width: 100%;
                        }
                    }
                </style>
            </head>

            <body>
                <main class="giveaways-page">
                    <h1 class="giveaways-title">Sorteios disponíveis</h1>

                    ${
                        giveaways && giveaways.length > 0
                            ? `<div class="giveaways-grid">${giveawayCards}</div>`
                            : `
                                <section class="giveaways-empty">
                                    <span class="giveaways-empty-symbol">✦</span>
                                    <h2>Nenhum sorteio disponível</h2>
                                    <p>
                                        Os tesouros estão sendo preparados.
                                        Volte em breve para participar das próximas aventuras!
                                    </p>
                                </section>
                            `
                    }

                    <footer class="giveaways-footer">
                        <a href="/dashboard">VOLTAR AO PAINEL</a>
                    </footer>
                </main>

                <script>
                    document.querySelectorAll(".giveaway-card").forEach(card => {
                        const price = Number(card.dataset.price);
                        const hasBalance = card.dataset.balance !== "";
                        const balance = hasBalance ? Number(card.dataset.balance) : null;
                        const maxAffordable = hasBalance && price > 0 ? Math.min(1000, Math.floor(balance / price)) : 0;

                        const input = card.querySelector(".ticket-quantity");
                        const minusButton = card.querySelector('[data-step="-1"]');
                        const totalElement = card.querySelector(".ticket-total");
                        const balanceAfterElement = card.querySelector(".balance-after");
                        const missingElement = card.querySelector(".giveaway-missing");
                        const missingPointsElement = card.querySelector(".missing-points");
                        const purchaseQuantity = card.querySelector(".purchase-quantity");
                        const buyButton = card.querySelector(".giveaway-buy-button");
                        const shortcuts = card.querySelectorAll("[data-set]");
                        const format = value => value.toLocaleString("pt-BR");

                        const readQuantity = () => {
                            const raw = Number(input.value);
                            return Number.isSafeInteger(raw) && raw >= 1 ? Math.min(1000, raw) : 1;
                        };

                        const update = () => {
                            const quantity = readQuantity();
                            const total = quantity * price;

                            totalElement.textContent = format(total) + " pontos";
                            purchaseQuantity.value = quantity;
                            minusButton.disabled = quantity <= 1;

                            shortcuts.forEach(button => {
                                const target = button.dataset.set === "max"
                                    ? maxAffordable
                                    : Number(button.dataset.set);
                                button.classList.toggle("is-selected", target >= 1 && target === quantity);
                            });

                            if (!hasBalance) {
                                buyButton.disabled = false;
                                return;
                            }

                            const remaining = balance - total;
                            const canBuy = remaining >= 0;

                            balanceAfterElement.textContent = canBuy ? format(remaining) + " pontos" : "—";
                            balanceAfterElement.classList.toggle("is-negative", !canBuy);
                            missingElement.hidden = canBuy;
                            missingPointsElement.textContent = format(Math.max(0, -remaining));
                            buyButton.disabled = !canBuy;
                        };

                        const setQuantity = quantity => {
                            input.value = Math.min(1000, Math.max(1, quantity));
                            update();
                        };

                        card.querySelectorAll("[data-step]").forEach(button => {
                            button.addEventListener("click", () => {
                                setQuantity(readQuantity() + Number(button.dataset.step));
                            });
                        });

                        shortcuts.forEach(button => {
                            button.addEventListener("click", () => {
                                setQuantity(button.dataset.set === "max" ? maxAffordable : Number(button.dataset.set));
                            });
                        });

                        input.addEventListener("input", update);
                        input.addEventListener("blur", () => setQuantity(readQuantity()));

                        update();
                    });
                </script>
            </body>
            </html>
        `, "/giveaways"));

    } catch (error) {
        console.error("Erro ao carregar sorteios:", error);
        return res.status(500).send("Não foi possível carregar os sorteios.");
    }
});

async function handleTicketPurchase(req, res) {
    if (!req.session.twitchUser) {
        return res.redirect("/");
    }

    try {
        // Página visual de resultado da compra
        const sendPurchaseResult = ({
            title,
            giveawayTitle,
            quantity,
            totalPoints,
            ticketNumbers,
            message,
            status = 200,
            variant = "success",
            requiredPoints,
            currentPoints
        }) => {
            const isError = variant === "error";
            const formatPoints = (value) => Number(value).toLocaleString("pt-BR");

            const escapeHtml = (value) => String(value ?? "").replace(
                /[&<>"']/g,
                (char) => ({
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#39;"
                })[char]
            );

            return res.status(status).send(withPublicSidebar(req, `
                <!DOCTYPE html>
                <html lang="pt-BR">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>${escapeHtml(title)} - Weirdo's Treasure</title>
                    <link rel="stylesheet" href="/css/home.css">

                    <style>
                        .purchase-result {
                            max-width: 650px;
                            margin: 70px auto;
                            padding: 35px;
                            background: linear-gradient(145deg, #30251b, #1d1712);
                            border: 2px solid #8b683c;
                            border-radius: 12px;
                            box-shadow: 0 8px 25px rgba(0,0,0,.4);
                            color: #e8dcc5;
                            text-align: center;
                        }

                        .purchase-result-icon {
                            width: 75px;
                            height: 75px;
                            margin: 0 auto 20px;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            border: 2px solid #c99b53;
                            border-radius: 50%;
                            color: #e2bd76;
                            font-size: 42px;
                        }

                        .purchase-result h1 {
                            color: #e2bd76;
                            font-size: 28px;
                            margin-bottom: 12px;
                        }

                        .purchase-result-error {
                            border-color: #8a3b2c;
                        }

                        .purchase-result-error .purchase-result-icon {
                            border-color: #c2553f;
                            background: rgba(194, 85, 63, .12);
                            color: #e8705a;
                            font-weight: bold;
                        }

                        .purchase-result-error h1 {
                            color: #e8a08a;
                        }

                        .purchase-result-details .purchase-result-missing {
                            margin-top: 16px;
                            padding-top: 14px;
                            border-top: 1px solid #5a4329;
                            color: #f0a48f;
                        }

                        .purchase-result-details .purchase-result-missing strong {
                            color: #f0a48f;
                        }

                        .purchase-result-description {
                            color: #c8baa4;
                            line-height: 1.6;
                            margin-bottom: 25px;
                        }

                        .purchase-result-details {
                            padding: 20px;
                            margin: 20px 0;
                            background: rgba(0,0,0,.25);
                            border: 1px solid #806039;
                            border-radius: 8px;
                            text-align: left;
                        }

                        .purchase-result-details p {
                            margin: 12px 0;
                            color: #e8dcc5;
                            line-height: 1.5;
                            overflow-wrap: anywhere;
                        }

                        .purchase-result-details strong {
                            color: #e2bd76;
                        }

                        .purchase-result-button {
                            display: inline-block;
                            margin-top: 15px;
                            padding: 14px 25px;
                            background: linear-gradient(180deg, #e2bd76, #a77a3d);
                            border: 1px solid #f0d49b;
                            border-radius: 6px;
                            color: #21170c;
                            font-weight: bold;
                            text-decoration: none;
                            transition: filter .2s, transform .2s;
                        }

                        .purchase-result-button:hover {
                            filter: brightness(1.15);
                            transform: translateY(-2px);
                        }

                        @media(max-width: 700px) {
                            .purchase-result {
                                margin: 25px 15px;
                                padding: 25px 18px;
                            }

                            .purchase-result h1 {
                                font-size: 23px;
                            }
                        }
                    </style>
                </head>

                <body>
                    <main class="purchase-result${isError ? " purchase-result-error" : ""}">
                        <div class="purchase-result-icon">${isError ? "!" : "✓"}</div>

                        <h1>${escapeHtml(title)}</h1>

                        <p class="purchase-result-description">
                            ${escapeHtml(message || (isError
                                ? "Você ainda não tem pontos suficientes para esta compra."
                                : "Sua aventura acaba de ganhar novos tesouros!"))}
                        </p>

                        <div class="purchase-result-details">
                            <p><strong>Sorteio:</strong> ${escapeHtml(giveawayTitle)}</p>
                            <p><strong>Quantidade:</strong> ${escapeHtml(quantity)} tickets</p>

                            ${isError ? `
                                <p><strong>Pontos necessários:</strong> ${escapeHtml(formatPoints(requiredPoints))} pontos</p>
                                <p><strong>Saldo atual:</strong> ${escapeHtml(formatPoints(currentPoints))} pontos</p>
                                <p class="purchase-result-missing"><strong>Faltam:</strong> ${escapeHtml(formatPoints(Math.max(0, requiredPoints - currentPoints)))} pontos</p>
                            ` : `
                                ${
                                    totalPoints !== undefined
                                        ? `<p><strong>Total descontado:</strong> ${escapeHtml(totalPoints)} pontos</p>`
                                        : ""
                                }

                                <p><strong>Seus tickets:</strong> ${escapeHtml(ticketNumbers)}</p>
                            `}
                        </div>

                        <a href="/giveaways" class="purchase-result-button">
                            VOLTAR AOS SORTEIOS
                        </a>
                    </main>
                </body>
                </html>
            `, "/giveaways"));
        };

        // Validar token de segurança
        const submittedToken = req.body._csrf;
        const sessionToken = req.session.csrfToken;

        if (
            typeof submittedToken !== "string" ||
            typeof sessionToken !== "string" ||
            submittedToken.length !== sessionToken.length ||
            !crypto.timingSafeEqual(
                Buffer.from(submittedToken),
                Buffer.from(sessionToken)
            )
        ) {
            return res.status(403).send("Falha na validação de segurança.");
        }

        // Validar quantidade
        const quantityText = req.body.quantity;

        if (
            typeof quantityText !== "string" ||
            !/^[1-9]\d*$/.test(quantityText)
        ) {
            return res.status(400).send("Quantidade de tickets inválida.");
        }

        const quantity = Number(quantityText);

        if (!Number.isSafeInteger(quantity) || quantity > MAX_TICKETS_PER_PURCHASE) {
            return res.status(400).send(
                "Quantidade inválida. O máximo por compra é " + MAX_TICKETS_PER_PURCHASE.toLocaleString("pt-BR") + " tickets."
            );
        }

        // Consultar sorteio
        const now = new Date().toISOString();

        const { data: giveaway, error: giveawayError } = await supabase
            .from("giveaways")
            .select("id, title, status, starts_at, ends_at")
            .eq("id", req.params.id)
            .eq("status", "active")
            .lte("starts_at", now)
            .gte("ends_at", now)
            .single();

        if (giveawayError || !giveaway) {
            return res.status(400).send(
                "Este sorteio não está disponível para compras."
            );
        }

        // Consultar preço atual
        const { data: settings, error: settingsError } = await supabase
            .from("system_settings")
            .select("points_per_ticket")
            .eq("id", 1)
            .single();

        if (settingsError || !settings) {
            throw new Error("Não foi possível consultar o preço dos tickets.");
        }

        const pointsPerTicket = Number(settings.points_per_ticket);

        if (
            !Number.isSafeInteger(pointsPerTicket) ||
            pointsPerTicket <= 0
        ) {
            throw new Error("Preço dos tickets inválido nas configurações.");
        }

        const totalPoints = quantity * pointsPerTicket;

        if (!Number.isSafeInteger(totalPoints) || totalPoints <= 0) {
            return res.status(400).send(
                "O valor total da compra é inválido."
            );
        }

        const channelId = await getStreamElementsChannelId();

        const currentPoints = await getStreamElementsPoints(
            channelId,
            req.session.twitchUser.login
        );

        if (currentPoints < totalPoints) {
            return sendPurchaseResult({
                status: 400,
                variant: "error",
                title: "Saldo insuficiente",
                giveawayTitle: giveaway.title,
                quantity: quantity,
                requiredPoints: totalPoints,
                currentPoints: currentPoints
            });
        }

        const idempotencyKey = req.body.idempotency_key;

        if (
            typeof idempotencyKey !== "string" ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idempotencyKey)
        ) {
            return res.status(400).send(
                "Chave de compra inválida. Atualize a página e tente novamente."
            );
        }

        const { data: transaction, error: transactionError } = await supabase
            .from("transactions")
            .insert({
                twitch_id: req.session.twitchUser.id,
                giveaway_id: giveaway.id,
                points_spent: totalPoints,
                tickets_purchased: quantity,
                status: "pending",
                idempotency_key: idempotencyKey
            })
            .select("id")
            .single();

        if (transactionError || !transaction) {

            // Verificar se a falha ocorreu porque a chave já foi utilizada
            if (transactionError?.code === "23505") {

                const { data: existingTransaction, error: existingError } =
                    await supabase
                        .from("transactions")
                        .select(`
                            id,
                            twitch_id,
                            giveaway_id,
                            points_spent,
                            tickets_purchased,
                            status
                        `)
                        .eq("idempotency_key", idempotencyKey)
                        .eq("twitch_id", req.session.twitchUser.id)
                        .maybeSingle();

                if (existingError) {
                    console.error(
                        "Erro ao consultar compra anterior:",
                        existingError.message
                    );

                    return res.status(202).send(
                        "Não foi possível confirmar sua compra anterior. Não tente comprar novamente agora."
                    );
                }

                if (existingTransaction) {

                    // Confirmar que a chave pertence exatamente à mesma compra
                    if (
                        existingTransaction.giveaway_id !== giveaway.id ||
                        Number(existingTransaction.tickets_purchased) !== quantity ||
                        Number(existingTransaction.points_spent) !== totalPoints
                    ) {
                        return res.status(409).send(
                            "Esta chave já está vinculada a outra solicitação de compra. Atualize a página para iniciar uma nova tentativa."
                        );
                    }

                    if (existingTransaction.status === "completed") {

                        const { data: existingTickets, error: existingTicketsError } =
                            await supabase
                                .from("tickets")
                                .select("ticket_number")
                                .eq("transaction_id", existingTransaction.id)
                                .order("ticket_number", { ascending: true });

                        if (existingTicketsError) {
                            console.error(
                                "Erro ao consultar tickets da compra anterior:",
                                existingTicketsError.message
                            );

                            return res.status(202).send(
                                "Sua compra consta como concluída, mas não foi possível consultar seus tickets. Não tente comprar novamente."
                            );
                        }

                        if (
                            !existingTickets ||
                            existingTickets.length !== quantity
                        ) {
                            return res.status(202).send(
                                "A compra consta como concluída, mas a quantidade de tickets precisa ser conferida. Não tente comprar novamente."
                            );
                        }

                        const ticketNumbers = existingTickets
                            .map(ticket => `#${ticket.ticket_number}`)
                            .join(", ");

                        return sendPurchaseResult({
                            title: "Compra já concluída!",
                            giveawayTitle: giveaway.title,
                            quantity: quantity,
                            ticketNumbers: ticketNumbers,
                            message: "Esta solicitação já havia sido processada. Nenhum novo desconto foi realizado."
                        });
                    }

                    if (existingTransaction.status === "pending") {
                        return res.status(202).send(
                            "Sua compra já está em processamento. Aguarde a conclusão e não tente comprar novamente."
                        );
                    }

                    if (existingTransaction.status === "reconciliation_required") {
                        return res.status(202).send(
                            "Sua compra já está em conferência. Não tente comprar novamente."
                        );
                    }

                    if (existingTransaction.status === "failed") {
                        return res.status(409).send(
                            "Esta tentativa anterior foi encerrada sem conclusão. Atualize a página para iniciar uma nova tentativa."
                        );
                    }

                    return res.status(409).send(
                        "Esta solicitação já existe e precisa ser verificada. Não tente comprar novamente."
                    );
                }
            }

            console.error(
                "Erro ao registrar transação:",
                transactionError?.message
            );

            return res.status(409).send(
                "Não foi possível iniciar a compra. Verifique se existe outra compra pendente."
            );
        }

        // Conferir novamente o saldo antes do desconto
        let latestPoints;

        try {
            latestPoints = await getStreamElementsPoints(
                channelId,
                req.session.twitchUser.login
            );
        } catch (balanceError) {
            console.error(
                "Erro na segunda consulta de saldo:",
                balanceError.message
            );

            const { error: updateError } = await supabase
                .from("transactions")
                .update({ status: "failed" })
                .eq("id", transaction.id)
                .eq("status", "pending");

            if (updateError) {
                console.error(
                    "Erro ao atualizar transação:",
                    updateError.message
                );

                return res.status(202).send(
                    "Não foi possível confirmar seu saldo. A compra precisa de conferência. Não tente novamente agora."
                );
            }

            return res.status(503).send(
                "Não foi possível consultar seu saldo. Nenhum desconto foi solicitado. Tente novamente mais tarde."
            );
        }

        if (latestPoints < totalPoints) {
            const { error: updateError } = await supabase
                .from("transactions")
                .update({ status: "failed" })
                .eq("id", transaction.id)
                .eq("status", "pending");

            if (updateError) {
                console.error(
                    "Erro ao cancelar transação sem saldo:",
                    updateError.message
                );

                return res.status(202).send(
                    "A compra precisa de conferência. Não tente novamente agora."
                );
            }

            return sendPurchaseResult({
                status: 400,
                variant: "error",
                title: "Saldo insuficiente",
                giveawayTitle: giveaway.title,
                quantity: quantity,
                requiredPoints: totalPoints,
                currentPoints: latestPoints
            });
        }

        try {
            await removeStreamElementsPoints(
                channelId,
                req.session.twitchUser.login,
                totalPoints
            );

            const { error: auditError } = await supabase
                .from("audit_logs")
                .insert({
                    twitch_id: req.session.twitchUser.id,
                    action: "streamElements_points_debited",
                    details: {
                        transaction_id: transaction.id,
                        giveaway_id: giveaway.id,
                        username: req.session.twitchUser.login,
                        points_debited: totalPoints,
                        confirmed_by_api: true
                    }
                });

            if (auditError) {
                console.error(
                    "Erro ao registrar confirmação do débito:",
                    auditError.message
                );

                throw new Error(
                    "O desconto foi confirmado, mas não foi possível registrar sua auditoria."
                );
            }

        } catch (debitError) {
            console.error(
                "Resultado do desconto precisa ser conferido:",
                debitError.message
            );

            const { error: updateError } = await supabase
                .from("transactions")
                .update({
                    status: "reconciliation_required"
                })
                .eq("id", transaction.id)
                .eq("status", "pending");

            if (updateError) {
                console.error(
                    "Não foi possível atualizar o status da transação:",
                    updateError.message
                );

                return res.status(202).send(
                    "Não foi possível confirmar o resultado da compra. Sua transação permanece pendente de conferência. Não tente comprar novamente."
                );
            }

            return res.status(202).send(
                "Sua compra está em conferência. Não tente comprar novamente."
            );
        }

        const { error: finalizeError } = await supabase.rpc(
            "finalize_ticket_purchase",
            {
                p_transaction_id: transaction.id
            }
        );

        if (finalizeError) {
            console.error(
                "Erro ao finalizar compra:",
                finalizeError.message
            );

            // Consultar o estado real da transação no banco
            const { data: transactionStatus, error: statusError } = await supabase
                .from("transactions")
                .select("status")
                .eq("id", transaction.id)
                .maybeSingle();

            if (statusError || !transactionStatus) {
                console.error(
                    "Não foi possível confirmar o estado da transação:",
                    statusError?.message
                );

                return res.status(202).send(
                    "Não foi possível confirmar o resultado da compra. Não tente comprar novamente. A transação precisa de conferência."
                );
            }

            // O banco concluiu a compra, mesmo que a resposta da RPC tenha falhado
            if (transactionStatus.status === "completed") {
                console.log(
                    "Compra concluída no banco. Resposta da RPC foi perdida ou apresentou erro."
                );
            } else {
                // O banco ainda não concluiu: encaminhar para conferência
                const { error: updateError } = await supabase
                    .from("transactions")
                    .update({
                        status: "reconciliation_required"
                    })
                    .eq("id", transaction.id)
                    .eq("status", "pending");

                if (updateError) {
                    console.error(
                        "Erro ao atualizar status para conferência:",
                        updateError.message
                    );
                }

                return res.status(202).send(
                    "O desconto foi realizado, mas a emissão dos tickets precisa de conferência. Não tente comprar novamente."
                );
            }
        }

        const { data: purchasedTickets, error: ticketsError } = await supabase
            .from("tickets")
            .select("ticket_number")
            .eq("transaction_id", transaction.id)
            .order("ticket_number", { ascending: true });

        if (ticketsError) {
            console.error("Erro ao consultar tickets:", ticketsError.message);
        }

        const ticketNumbers = !ticketsError && purchasedTickets?.length
            ? purchasedTickets.map(ticket => `#${ticket.ticket_number}`).join(", ")
            : "Compra concluída. Consulte seus tickets na área de tickets.";

        return sendPurchaseResult({
            title: "Compra concluída!",
            giveawayTitle: giveaway.title,
            quantity: quantity,
            totalPoints: totalPoints,
            ticketNumbers: ticketNumbers,
            message: "Seus tickets foram emitidos com sucesso. Boa sorte no sorteio!"
        });

    } catch (error) {
        console.error("Erro ao validar compra:", error);
        return res.status(500).send("Não foi possível validar o pedido.");
    }
}

// Compras em andamento por usuário (segunda camada além do índice do banco)
const purchasesInProgress = new Set();
const MAX_TICKETS_PER_PURCHASE = 1000;

app.post("/giveaways/:id/purchase", purchaseLimiter, async (req, res) => {
    const userId = req.session?.twitchUser?.id;

    if (!userId) {
        return res.redirect("/");
    }

    if (purchasesInProgress.has(userId)) {
        return res.status(409).send(
            "Você já tem uma compra em andamento. Aguarde a conclusão e não tente comprar novamente."
        );
    }

    purchasesInProgress.add(userId);

    try {
        return await handleTicketPurchase(req, res);
    } finally {
        purchasesInProgress.delete(userId);
    }
});

// O ID do canal no StreamElements não muda: guardar depois da primeira consulta
let streamElementsChannelIdCache = null;

async function getStreamElementsChannelId() {
    if (streamElementsChannelIdCache) {
        return streamElementsChannelIdCache;
    }

    const response = await fetch(
        "https://api.streamelements.com/kappa/v2/channels/me",
        {
            headers: {
                Authorization: `Bearer ${process.env.STREAMELEMENTS_JWT}`,
                Accept: "application/json"
            },
            signal: AbortSignal.timeout(10000)
        }
    );

    const data = await response.json();

    if (!response.ok || !data._id) {
        throw new Error("Não foi possível identificar o canal no StreamElements.");
    }

    streamElementsChannelIdCache = data._id;

    return data._id;
}

async function addStreamElementsPoints(channelId, username, amount) {
    if (!Number.isSafeInteger(amount) || amount <= 0) {
        throw new Error("Quantidade de pontos inválida para devolução.");
    }

    if (
        typeof channelId !== "string" ||
        !channelId.trim() ||
        typeof username !== "string" ||
        !username.trim() ||
        !process.env.STREAMELEMENTS_JWT
    ) {
        throw new Error("Dados necessários para a devolução são inválidos.");
    }

    const response = await fetch(
        `https://api.streamelements.com/kappa/v2/points/${encodeURIComponent(channelId)}/${encodeURIComponent(username)}/${amount}`,
        {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${process.env.STREAMELEMENTS_JWT}`,
                Accept: "application/json"
            },
            signal: AbortSignal.timeout(15000)
        }
    );

    if (!response.ok) {
        throw new Error(`StreamElements recusou a devolução. HTTP ${response.status}`);
    }

    return true;
}

async function getStreamElementsPoints(channelId, username) {
    if (
        typeof channelId !== "string" ||
        !channelId.trim() ||
        typeof username !== "string" ||
        !username.trim() ||
        !process.env.STREAMELEMENTS_JWT
    ) {
        throw new Error("Dados necessários para consultar o saldo são inválidos.");
    }

    const url =
        `https://api.streamelements.com/kappa/v2/points/${encodeURIComponent(channelId)}/${encodeURIComponent(username)}`;

    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, 15000);

    try {
        const response = await fetch(url, {
            headers: {
                Authorization: `Bearer ${process.env.STREAMELEMENTS_JWT}`,
                Accept: "application/json"
            },
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(
                `Erro ao consultar StreamElements. HTTP ${response.status}`
            );
        }

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error("StreamElements retornou uma resposta inválida.");
        }

        const points = Number(data.points);

        if (!Number.isSafeInteger(points) || points < 0) {
            throw new Error("Saldo de pontos retornado é inválido.");
        }

        return points;

    } finally {
        clearTimeout(timeout);
    }
}

async function removeStreamElementsPoints(channelId, username, amount) {
    if (!Number.isSafeInteger(amount) || amount <= 0) {
        throw new Error("Quantidade de pontos inválida para desconto.");
    }

    if (
        typeof channelId !== "string" ||
        !channelId.trim() ||
        typeof username !== "string" ||
        !username.trim() ||
        !process.env.STREAMELEMENTS_JWT
    ) {
        throw new Error("Dados necessários para o desconto são inválidos.");
    }

    const url =
        `https://api.streamelements.com/kappa/v2/points/${encodeURIComponent(channelId)}/${encodeURIComponent(username)}/-${amount}`;

    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, 15000);

    try {
        const response = await fetch(url, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${process.env.STREAMELEMENTS_JWT}`,
                Accept: "application/json"
            },
            signal: controller.signal
        });

        const responseBody = await response.text();

        if (!response.ok) {
            throw new Error(
                `StreamElements recusou o desconto. HTTP ${response.status}: ${responseBody.slice(0, 500)}`
            );
        }

        return true;

    } finally {
        clearTimeout(timeout);
    }
}

app.get("/my-tickets", async (req, res) => {
    if (!req.session.twitchUser) {
        return res.redirect("/");
    }

    try {
        const twitchId = req.session.twitchUser.id;

        // Buscar somente os tickets do usuário conectado (paginado)
        const tickets = [];

        for (let from = 0; from < 100000; from += 1000) {
            const { data, error: ticketsError } = await supabase
                .from("tickets")
                .select("ticket_number, created_at, giveaway_id")
                .eq("twitch_id", twitchId)
                .order("ticket_number", { ascending: true })
                .range(from, from + 999);

            if (ticketsError) {
                throw ticketsError;
            }

            tickets.push(...(data || []));

            if (!data || data.length < 1000) {
                break;
            }
        }

        // Escapar textos para evitar inserção de HTML
        const escapeHtml = (value) =>
            String(value ?? "").replace(/[&<>"']/g, char => ({
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;"
            })[char]);

        const formatNumber = (value) => Number(value || 0).toLocaleString("pt-BR");
        const formatDate = (value) => value
            ? new Date(value).toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" })
            : "—";

        // Sorteios dos tickets + sorteios em andamento, pontos gastos e vitórias
        const giveawayIds = [...new Set(tickets.map(ticket => ticket.giveaway_id))];

        const [giveawaysResult, activeResult, transactionsResult, winsResult] = await Promise.all([
            giveawayIds.length > 0
                ? supabase.from("giveaways").select("id, title, status, ends_at").in("id", giveawayIds)
                : Promise.resolve({ data: [], error: null }),
            supabase
                .from("giveaways")
                .select("id, title, status, ends_at")
                .eq("status", "active")
                .order("ends_at", { ascending: true }),
            supabase
                .from("transactions")
                .select("giveaway_id, points_spent")
                .eq("twitch_id", twitchId)
                .eq("status", "completed"),
            supabase
                .from("giveaway_draws")
                .select("giveaway_id")
                .eq("winner_twitch_id", twitchId)
                .eq("status", "confirmed")
        ]);

        if (giveawaysResult.error) throw giveawaysResult.error;
        if (activeResult.error) throw activeResult.error;

        // Pontos e vitórias são complementares: se falharem, a página continua
        if (transactionsResult.error) console.error("Erro ao buscar pontos gastos:", transactionsResult.error.message);
        if (winsResult.error) console.error("Erro ao buscar vitórias:", winsResult.error.message);

        const giveawayMap = new Map();
        for (const giveaway of [...(giveawaysResult.data || []), ...(activeResult.data || [])]) {
            giveawayMap.set(giveaway.id, giveaway);
        }

        const pointsByGiveaway = new Map();
        for (const transaction of transactionsResult.data || []) {
            pointsByGiveaway.set(
                transaction.giveaway_id,
                (pointsByGiveaway.get(transaction.giveaway_id) || 0) + Number(transaction.points_spent || 0)
            );
        }

        const wonGiveaways = new Set((winsResult.data || []).map(draw => draw.giveaway_id));

        // Agrupar tickets por sorteio
        const ticketsByGiveaway = new Map();
        for (const ticket of tickets) {
            if (!ticketsByGiveaway.has(ticket.giveaway_id)) {
                ticketsByGiveaway.set(ticket.giveaway_id, []);
            }
            ticketsByGiveaway.get(ticket.giveaway_id).push(ticket);
        }

        const activeGiveaways = activeResult.data || [];
        const activeIds = new Set(activeGiveaways.map(giveaway => giveaway.id));

        const pastGroups = [...ticketsByGiveaway.entries()]
            .filter(([giveawayId]) => !activeIds.has(giveawayId))
            .map(([giveawayId, groupTickets]) => {
                const giveaway = giveawayMap.get(giveawayId) || {};
                return {
                    title: giveaway.title || "Sorteio não encontrado",
                    status: giveaway.status || "",
                    endsAt: giveaway.ends_at || null,
                    tickets: groupTickets,
                    points: pointsByGiveaway.get(giveawayId) || 0,
                    won: wonGiveaways.has(giveawayId)
                };
            })
            .sort((a, b) => new Date(b.endsAt || 0) - new Date(a.endsAt || 0));

        const renderTicketNumbers = (groupTickets) => `
            <div class="ticket-number-grid">
                ${groupTickets.map(ticket => `
                    <div class="ticket-number">
                        <span>✦</span>
                        <strong>#${escapeHtml(ticket.ticket_number)}</strong>
                    </div>
                `).join("")}
            </div>
        `;

        // Sorteio(s) em andamento
        const currentSections = activeGiveaways.length === 0
            ? `
                <section class="tickets-empty">
                    <span class="tickets-empty-symbol">✦</span>
                    <h2>Nenhum sorteio em andamento</h2>
                    <p>Fique de olho! Novos tesouros podem surgir em breve.</p>
                </section>
            `
            : activeGiveaways.map(giveaway => {
                const groupTickets = ticketsByGiveaway.get(giveaway.id) || [];

                return `
                    <section class="ticket-giveaway-card">
                        <div class="ticket-card-header">
                            <div>
                                <span class="ticket-eyebrow">SORTEIO EM ANDAMENTO</span>
                                <h2>${escapeHtml(giveaway.title)}</h2>
                            </div>

                            <span class="ticket-status ticket-status-active">ATIVO</span>
                        </div>

                        <div class="ticket-card-stats">
                            <div>
                                <span>Seus tickets</span>
                                <strong>${formatNumber(groupTickets.length)}</strong>
                            </div>
                            <div>
                                <span>Pontos investidos</span>
                                <strong>${formatNumber(pointsByGiveaway.get(giveaway.id) || 0)}</strong>
                            </div>
                            <div>
                                <span>Encerra em</span>
                                <strong>${escapeHtml(formatDate(giveaway.ends_at))}</strong>
                            </div>
                        </div>

                        ${groupTickets.length > 0
                            ? renderTicketNumbers(groupTickets)
                            : `<p class="ticket-card-empty">Você ainda não tem tickets neste sorteio.</p>`}

                        <a href="/giveaways" class="ticket-buy-more">
                            ✦ ${groupTickets.length > 0 ? "COMPRAR MAIS TICKETS" : "COMPRAR TICKETS"} ✦
                        </a>
                    </section>
                `;
            }).join("");

        // Sorteios anteriores
        const pastStatusLabels = {
            closed: ["ENCERRADO", "ticket-status-closed"],
            cancelled: ["CANCELADO", "ticket-status-other"],
            draft: ["EM BREVE", "ticket-status-other"]
        };

        const pastSections = pastGroups.length === 0
            ? `<p class="past-tickets-empty">Você ainda não participou de sorteios anteriores.</p>`
            : pastGroups.map(group => {
                const [statusLabel, statusClass] = pastStatusLabels[group.status] || ["—", "ticket-status-other"];

                return `
                    <details class="past-ticket-card">
                        <summary>
                            <div class="past-ticket-title">
                                <strong>${escapeHtml(group.title)}</strong>
                                <span>Encerrado em ${escapeHtml(formatDate(group.endsAt))}</span>
                            </div>

                            <div class="past-ticket-meta">
                                ${group.won ? `<span class="ticket-status ticket-status-won">🏆 VOCÊ VENCEU</span>` : ""}
                                <span class="ticket-status ${statusClass}">${statusLabel}</span>
                            </div>

                            <div class="past-ticket-numbers">
                                <div>
                                    <span>Tickets</span>
                                    <strong>${formatNumber(group.tickets.length)}</strong>
                                </div>
                                <div>
                                    <span>Pontos gastos</span>
                                    <strong>${formatNumber(group.points)}</strong>
                                </div>
                            </div>
                        </summary>

                        <div class="past-ticket-body">
                            ${renderTicketNumbers(group.tickets)}
                        </div>
                    </details>
                `;
            }).join("");

        return res.send(withPublicSidebar(req, `
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Meus Tickets - Weirdo's Treasure</title>
                <link rel="stylesheet" href="/css/home.css">

                <style>
                    .my-tickets-page {
                        width: min(100% - 40px, 1000px);
                        margin: 45px auto;
                    }

                    .my-tickets-header {
                        margin-bottom: 30px;
                        padding: 28px;
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border: 2px solid #8b683c;
                        border-radius: 10px;
                        box-shadow: 0 8px 25px rgba(0,0,0,.3);
                    }

                    .my-tickets-eyebrow,
                    .ticket-eyebrow {
                        color: #d6ad69;
                        font-size: 11px;
                        letter-spacing: 2px;
                        font-weight: bold;
                    }

                    .my-tickets-header h1 {
                        margin: 12px 0;
                        color: #e2bd76;
                        font-size: clamp(26px, 4vw, 36px);
                    }

                    .my-tickets-header p {
                        margin: 0;
                        color: #c8baa4;
                        line-height: 1.6;
                    }

                    .my-tickets-total {
                        display: inline-flex;
                        align-items: center;
                        gap: 10px;
                        margin-top: 22px;
                        padding: 12px 17px;
                        background: rgba(0,0,0,.25);
                        border: 1px solid #806039;
                        border-radius: 7px;
                        color: #e2bd76;
                    }

                    .my-tickets-total strong {
                        font-size: 23px;
                        color: #f0dfbd;
                    }

                    .ticket-giveaway-card {
                        margin-bottom: 22px;
                        padding: 25px;
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border: 1px solid #8b683c;
                        border-radius: 10px;
                        box-shadow: 0 6px 18px rgba(0,0,0,.3);
                    }

                    .ticket-card-header {
                        display: flex;
                        align-items: flex-start;
                        justify-content: space-between;
                        gap: 15px;
                        padding-bottom: 20px;
                        border-bottom: 1px solid rgba(198,157,92,.3);
                    }

                    .ticket-card-header h2 {
                        margin: 9px 0 0;
                        color: #e7c586;
                        font-size: 21px;
                        overflow-wrap: anywhere;
                    }

                    .ticket-status {
                        padding: 8px 12px;
                        border: 1px solid #806039;
                        border-radius: 5px;
                        font-size: 10px;
                        font-weight: bold;
                        letter-spacing: 1px;
                        white-space: nowrap;
                    }

                    .ticket-status-active {
                        color: #a8d69a;
                        border-color: #557b48;
                        background: rgba(72,117,56,.18);
                    }

                    .ticket-status-closed {
                        color: #d4b88b;
                        background: rgba(120,91,55,.2);
                    }

                    .ticket-status-other {
                        color: #c8baa4;
                    }

                    .ticket-card-summary {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 20px 0 35px;
    padding-bottom: 20px;
    border-bottom: 1px solid rgba(198,157,92,.3);
    color: #c8baa4;
}

                    .ticket-card-summary strong {
                        color: #e2bd76;
                        font-size: 23px;
                    }

                    .ticket-number-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(95px, 1fr));
                        gap: 12px;
                    }

                    .ticket-number {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        gap: 5px;
                        min-height: 65px;
                        padding: 10px;
                        box-sizing: border-box;
                        background: linear-gradient(145deg, #e2bd76, #a77a3d);
                        border: 1px solid #f0d49b;
                        border-radius: 7px;
                        box-shadow: inset 0 1px 3px rgba(255,255,255,.2),
                                    0 3px 8px rgba(0,0,0,.25);
                        color: #21170c;
                    }

                    .ticket-number span {
                        font-size: 12px;
                    }

                    .ticket-number strong {
                        font-size: 17px;
                    }

                    .tickets-empty {
                        padding: 45px 25px;
                        text-align: center;
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border: 1px dashed #8b683c;
                        border-radius: 10px;
                    }

                    .tickets-empty-symbol {
                        display: block;
                        margin-bottom: 15px;
                        color: #d6ad69;
                        font-size: 42px;
                    }

                    .tickets-empty h2 {
                        color: #e2bd76;
                    }

                    .tickets-empty p {
                        color: #c8baa4;
                        line-height: 1.6;
                    }

                    .my-tickets-navigation {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 12px;
                        margin-top: 28px;
                    }

                    .my-tickets-navigation a {
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        min-height: 44px;
                        padding: 12px 20px;
                        box-sizing: border-box;
                        background: linear-gradient(180deg, #e2bd76, #a77a3d);
                        border: 1px solid #f0d49b;
                        border-radius: 6px;
                        color: #21170c;
                        font-size: 13px;
                        font-weight: bold;
                        letter-spacing: .5px;
                        text-decoration: none;
                        transition: filter .2s, transform .2s;
                    }

                    .my-tickets-navigation a:hover {
                        filter: brightness(1.15);
                        transform: translateY(-2px);
                    }

                    .my-tickets-navigation .secondary-link {
                        background: linear-gradient(145deg, #30251b, #1d1712);
                        border-color: #806039;
                        color: #e2bd76;
                    }

                    .my-tickets-section-title {
                        margin: 0 0 16px;
                        color: #e2bd76;
                        font-size: 20px;
                        letter-spacing: .5px;
                    }

                    .my-tickets-section-past {
                        margin-top: 38px;
                    }

                    .ticket-card-stats {
                        display: grid;
                        grid-template-columns: repeat(3, minmax(0, 1fr));
                        gap: 10px;
                        margin: 20px 0 24px;
                    }

                    .ticket-card-stats div {
                        display: flex;
                        flex-direction: column;
                        gap: 6px;
                        padding: 12px 14px;
                        background: rgba(0,0,0,.22);
                        border: 1px solid #51402a;
                        border-radius: 7px;
                    }

                    .ticket-card-stats span,
                    .past-ticket-numbers span {
                        color: #a99578;
                        font-size: 10px;
                        font-weight: bold;
                        letter-spacing: 1px;
                        text-transform: uppercase;
                    }

                    .ticket-card-stats strong {
                        color: #e2bd76;
                        font-size: 20px;
                    }

                    .ticket-card-empty,
                    .past-tickets-empty {
                        margin: 0 0 10px;
                        color: #c8baa4;
                        font-style: italic;
                    }

                    .ticket-status-won {
                        color: #f0d49b;
                        border-color: #c99b53;
                        background: rgba(201,155,83,.18);
                    }

                    .past-ticket-card {
                        margin-bottom: 12px;
                        background: linear-gradient(145deg, #2a2018, #1d1712);
                        border: 1px solid #5e4529;
                        border-radius: 9px;
                    }

                    .past-ticket-card[open] {
                        border-color: #8b683c;
                    }

                    .past-ticket-card summary {
                        display: grid;
                        grid-template-columns: 1fr auto auto;
                        align-items: center;
                        gap: 16px;
                        padding: 16px 20px;
                        cursor: pointer;
                        list-style: none;
                    }

                    .past-ticket-card summary::-webkit-details-marker {
                        display: none;
                    }

                    .past-ticket-title {
                        display: flex;
                        flex-direction: column;
                        gap: 4px;
                        min-width: 0;
                    }

                    .past-ticket-title strong {
                        color: #e7c586;
                        font-size: 17px;
                        overflow-wrap: anywhere;
                    }

                    .past-ticket-title strong::before {
                        content: "▸ ";
                        color: #a99578;
                    }

                    .past-ticket-card[open] .past-ticket-title strong::before {
                        content: "▾ ";
                    }

                    .past-ticket-title span {
                        color: #a99578;
                        font-size: 12px;
                    }

                    .past-ticket-meta {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 6px;
                        justify-content: flex-end;
                    }

                    .past-ticket-numbers {
                        display: flex;
                        gap: 18px;
                    }

                    .past-ticket-numbers div {
                        display: flex;
                        flex-direction: column;
                        align-items: flex-end;
                        gap: 3px;
                    }

                    .past-ticket-numbers strong {
                        color: #e8dfcf;
                        font-size: 18px;
                    }

                    .past-ticket-body {
                        padding: 4px 20px 20px;
                        border-top: 1px solid rgba(198,157,92,.2);
                        padding-top: 16px;
                    }

                    .past-ticket-body .ticket-number {
                        background: linear-gradient(145deg, #8a734e, #5e4a2e);
                        border-color: #a48a5e;
                        color: #f0e4cc;
                    }

                    @media(max-width: 600px) {
                        .ticket-card-stats {
                            grid-template-columns: 1fr 1fr;
                        }

                        .ticket-card-stats div:last-child {
                            grid-column: 1 / -1;
                        }

                        .past-ticket-card summary {
                            grid-template-columns: 1fr;
                            gap: 10px;
                            padding: 14px 16px;
                        }

                        .past-ticket-meta {
                            justify-content: flex-start;
                        }

                        .past-ticket-numbers div {
                            align-items: flex-start;
                        }

                        .past-ticket-body {
                            padding: 14px 16px 16px;
                        }
                    }

                    @media(max-width: 600px) {
                        .my-tickets-page {
                            width: calc(100% - 24px);
                            margin: 25px auto;
                        }

                        .my-tickets-header,
                        .ticket-giveaway-card {
                            padding: 20px;
                        }

                        .ticket-card-header {
                            flex-direction: column;
                        }

                        .ticket-number-grid {
                            grid-template-columns: repeat(3, minmax(0, 1fr));
                            gap: 8px;
                        }

                        .my-tickets-navigation {
                            flex-direction: column;
                        }

                        .my-tickets-navigation a {
                            width: 100%;
                        }
                    }
                        .ticket-buy-more {
                        margin-top: 15px;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 44px;
    margin-bottom: 20px;
    padding: 10px 16px;
    box-sizing: border-box;
    background: linear-gradient(180deg, #e2bd76, #a77a3d);
    border: 1px solid #f0d49b;
    border-radius: 6px;
    color: #21170c;
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 1px;
    text-decoration: none;
    transition: filter .2s, transform .2s;
}

.ticket-buy-more:hover {
    filter: brightness(1.15);
    transform: translateY(-2px);
}

                </style>
            </head>

            <body>
                <main class="my-tickets-page">
                    <header class="my-tickets-header">
                        <span class="my-tickets-eyebrow">WEIRDO'S TREASURE</span>

                        <h1>Meus Tickets</h1>

                        <p>
                            Olá, ${escapeHtml(req.session.twitchUser.displayName)}!
                            Aqui estão os tickets que você conquistou em suas aventuras.
                        </p>
                    </header>

                    <h2 class="my-tickets-section-title">✦ Sorteio disponível</h2>
                    ${currentSections}

                    <h2 class="my-tickets-section-title my-tickets-section-past">✦ Sorteios anteriores</h2>
                    ${pastSections}

                    <nav class="my-tickets-navigation">
                        <a href="/dashboard" class="secondary-link">VOLTAR AO PAINEL</a>
                    </nav>
                </main>
            </body>
            </html>
        `, "/my-tickets"));

    } catch (error) {
        console.error("Erro ao carregar meus tickets:", error);
        return res.status(500).send("Não foi possível carregar seus tickets.");
    }
});

// Monta o estado da Arena (null quando o sorteio não existe)
async function computeArenaState(giveawayId) {
    {

        const { data: giveaway, error: giveawayError } = await supabase
            .from("giveaways")
            .select("id, title, description, status, current_round, draw_in_progress")
            .eq("id", giveawayId)
            .maybeSingle();

        if (giveawayError || !giveaway) {
            return null;
        }

        // Todos os tickets do sorteio (paginado)
        const tickets = [];

        for (let from = 0; from < 1000000; from += 1000) {
            const { data, error } = await supabase
                .from("tickets")
                .select("twitch_id, ticket_number")
                .eq("giveaway_id", giveawayId)
                .order("ticket_number", { ascending: true })
                .range(from, from + 999);

            if (error) throw error;

            tickets.push(...(data || []));

            if (!data || data.length < 1000) break;
        }

        const [settingsResult, drawsResult] = await Promise.all([
            supabase
                .from("system_settings")
                .select("subscriber_multiplier")
                .eq("id", 1)
                .maybeSingle(),
            supabase
                .from("giveaway_draws")
                .select("id, round_number, winner_twitch_id, winning_ticket_number, status, drawn_at, response_deadline_at, winner_responded_at")
                .eq("giveaway_id", giveawayId)
                .order("round_number", { ascending: true })
        ]);

        if (settingsResult.error) throw settingsResult.error;
        if (drawsResult.error) throw drawsResult.error;

        const draws = drawsResult.data || [];
        const currentDraw = draws.length > 0 ? draws[draws.length - 1] : null;

        const participantIds = [...new Set(tickets.map(ticket => ticket.twitch_id))];
        const userIds = [...new Set([...participantIds, ...draws.map(draw => draw.winner_twitch_id)])];

        let users = [];

        if (userIds.length > 0) {
            const { data: userRows, error: usersError } = await supabase
                .from("users")
                .select("twitch_id, twitch_login, display_name, profile_image_url")
                .in("twitch_id", userIds);

            if (usersError) throw usersError;

            users = userRows || [];
        }

        const userById = new Map(users.map(user => [user.twitch_id, user]));
        const participants = participantIds.map(id => userById.get(id) || { twitch_id: id, display_name: "Participante" });
        const nameOf = (user) => user?.display_name || user?.twitch_login || "Participante";

        // Tickets para a animação: exclui quem venceu rodadas anteriores (o vencedor atual continua)
        const previousWinnerIds = new Set(draws.slice(0, -1).map(draw => draw.winner_twitch_id));
        const animationTickets = tickets.filter(ticket => !previousWinnerIds.has(ticket.twitch_id));

        // Amostra fixa (sempre a mesma) para não pesar a consulta de 1 em 1 segundo
        const POOL_LIMIT = 400;
        const step = Math.max(1, animationTickets.length / POOL_LIMIT);
        const ticketPool = [];

        for (let i = 0; i < animationTickets.length && ticketPool.length < POOL_LIMIT; i += step) {
            const ticket = animationTickets[Math.floor(i)];
            const user = userById.get(ticket.twitch_id);

            ticketPool.push({
                ticket_number: ticket.ticket_number,
                twitch_id: ticket.twitch_id,
                display_name: nameOf(user),
                profile_image_url: user?.profile_image_url || ""
            });
        }

        const allWinnerIds = new Set(draws.map(draw => draw.winner_twitch_id));
        const eligibleParticipantsLeft = participantIds.filter(id => !allWinnerIds.has(id)).length;

        let messages = [];

        if (currentDraw) {
            const { data: chatMessages, error: messagesError } = await supabase
                .from("giveaway_chat_messages")
                .select("id, display_name, message, sent_at")
                .eq("draw_id", currentDraw.id)
                .order("sent_at", { ascending: true })
                .limit(100);

            if (messagesError) throw messagesError;

            messages = chatMessages || [];
        }

        const winnerUser = currentDraw ? userById.get(currentDraw.winner_twitch_id) : null;

        return {
            spinMs: ARENA_SPIN_MS,
            giveaway: {
                id: giveaway.id,
                title: giveaway.title,
                description: giveaway.description,
                status: giveaway.status
            },
            currentDraw,
            winner: winnerUser
                ? {
                    twitch_login: winnerUser.twitch_login,
                    display_name: winnerUser.display_name,
                    profile_image_url: winnerUser.profile_image_url
                }
                : null,
            draws: draws.map(draw => {
                const user = userById.get(draw.winner_twitch_id);

                return {
                    ...draw,
                    display_name: nameOf(user),
                    profile_image_url: user?.profile_image_url || ""
                };
            }),
            messages,
            totalTickets: tickets.length,
            totalParticipants: participantIds.length,
            participants,
            subscriberMultiplier: settingsResult.data?.subscriber_multiplier ?? 1,
            eligibleParticipantsLeft,
            ticketPool
        };
    }
}

// Cache de 1 segundo por sorteio: várias telas abertas geram uma única consulta
const ARENA_STATE_CACHE_MS = 1000;
const arenaStateCache = new Map();

function invalidateArenaState(giveawayId) {
    arenaStateCache.delete(giveawayId);
}

app.get("/arena/:id/state", arenaStateLimiter, async (req, res) => {
    const giveawayId = req.params.id;

    if (!/^[0-9a-f-]{36}$/i.test(giveawayId)) {
        return res.status(404).json({ error: "Sorteio não encontrado." });
    }

    try {
        let entry = arenaStateCache.get(giveawayId);

        if (!entry || Date.now() - entry.createdAt > ARENA_STATE_CACHE_MS) {
            entry = { createdAt: Date.now(), promise: computeArenaState(giveawayId) };
            arenaStateCache.set(giveawayId, entry);
            entry.promise.catch(() => arenaStateCache.delete(giveawayId));
        }

        const state = await entry.promise;

        if (!state) {
            return res.status(404).json({ error: "Sorteio não encontrado." });
        }

        res.set("Cache-Control", "no-store");
        return res.json({ ...state, serverTime: Date.now() });

    } catch (error) {
        console.error("Erro ao carregar dados da Arena:", error.message);

        return res.status(500).json({
            error: "Não foi possível carregar os dados da Arena."
        });
    }
});

// Remove do cache estados antigos
const arenaCacheCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [id, entry] of arenaStateCache) {
        if (now - entry.createdAt > 60 * 1000) arenaStateCache.delete(id);
    }
}, 60 * 1000);
if (arenaCacheCleanupTimer && arenaCacheCleanupTimer.unref) arenaCacheCleanupTimer.unref();

// Arena do Tesouro: janela usada no OBS (sem menu lateral).
// O botão de girar só aparece para o administrador logado.
app.get("/arena/:id", async (req, res) => {
    const giveawayId = req.params.id;

    const { data: giveaway, error } = await supabase
        .from("giveaways")
        .select("id, title")
        .eq("id", giveawayId)
        .maybeSingle();

    if (error || !giveaway) {
        return res.status(404).send("Sorteio não encontrado.");
    }

    const sessionUser = req.session && req.session.twitchUser;
    const isAdmin = Boolean(
        sessionUser &&
        process.env.ADMIN_TWITCH_ID &&
        sessionUser.id === process.env.ADMIN_TWITCH_ID
    );
    const csrfToken = isAdmin ? getCsrfToken(req) : "";

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Arena do Tesouro - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/arena.css">
        </head>

        <body
            data-giveaway-id="${escapeDashboardHtml(giveaway.id)}"
            data-admin="${isAdmin ? "1" : "0"}"
            data-csrf="${escapeDashboardHtml(csrfToken)}"
            data-spin-ms="${ARENA_SPIN_MS}"
        >
            <header class="arena-header">
                <h1>ARENA DO TESOURO</h1>
                <h2 id="giveawayTitle" class="arena-giveaway-title">${escapeDashboardHtml(giveaway.title)}</h2>
                <div id="giveawayMeta" class="arena-giveaway-meta"></div>
            </header>

            <main>
                <div class="arena-layout">
                    <!-- PARTICIPANTES -->
                    <section class="arena-box">
                        <h2>PARTICIPANTES</h2>
                        <div class="participant-total" id="arenaParticipantCount">0</div>
                        <div class="participant-total-label">USUÁRIOS PARTICIPANDO</div>
                        <div class="participant-tickets">
                            TICKETS
                            <strong id="arenaTicketCount">0</strong>
                        </div>
                    </section>

                    <!-- ABERTURA DO TESOURO -->
                    <section class="arena-box case-opening">
                        <h2>ABERTURA DO TESOURO</h2>

                        <div class="case-window" id="caseWindow">
                            <div class="case-pointer"></div>
                            <div class="case-track" id="treasureWheel"></div>
                            <div class="case-empty" id="caseEmpty" hidden>SEM TICKETS</div>
                        </div>

                        <div class="case-caption" id="wheelCaption">Carregando...</div>
                    </section>

                    <!-- CHAT DO VENCEDOR -->
                    <section class="arena-box winner-chat-panel">
                        <h2>CHAT DO VENCEDOR</h2>
                        <div id="countdown" class="chat-countdown"></div>
                        <div id="winnerChat"></div>
                    </section>
                </div>

                <!-- VENCEDORES DESTE SORTEIO -->
                <section class="arena-box winners-box">
                    <div class="winners-box-header">
                        <h2>🏆 VENCEDORES DESTE SORTEIO</h2>
                        ${isAdmin ? `
                            <div class="draw-controls">
                                <span class="draw-hint" id="drawHint"></span>
                                <button type="button" class="draw-button" id="drawButton" disabled>✦ INICIAR GIRO ✦</button>
                            </div>
                        ` : ""}
                    </div>
                    <div class="winners-list" id="winnersList"></div>
                </section>

                <section class="panel">
                    <h2>Informações do sorteio</h2>
                    <div class="info-row">
                        <div>Tickets: <strong id="totalTickets">0</strong></div>
                        <div>Participantes: <strong id="totalParticipants">0</strong></div>
                        <div>Multiplicador de inscritos: <strong><span id="subscriberMultiplier">1</span>x</strong></div>
                    </div>
                </section>

                <section class="panel">
                    <h2>Participantes do sorteio</h2>
                    <div id="participantsList">Carregando participantes...</div>
                </section>
            </main>

            <canvas id="fireworks" aria-hidden="true"></canvas>

            <div class="celebration" id="celebration" hidden>
                <div class="celebration-card">
                    <div class="celebration-eyebrow">🏆 TEMOS UM VENCEDOR! 🏆</div>
                    <span class="celebration-avatar" id="celebrationAvatar"></span>
                    <div class="celebration-name" id="celebrationName"></div>
                    <div class="celebration-ticket" id="celebrationTicket"></div>
                    <div class="celebration-note">Responda no chat da live para confirmar o prêmio!</div>
                </div>
            </div>

            <script src="/js/arena.js"></script>
        </body>
        </html>
    `);
});

async function connectTwitchChat(
    accessToken,
    broadcasterId,
    reconnectUrl = null
) {
    if (
        !reconnectUrl &&
        twitchEventSubSocket &&
        twitchEventSubSocket.readyState === WebSocket.OPEN
    ) {
        console.log("Conexão com o chat da Twitch já está ativa.");
        return;
    }

    const socket = new WebSocket(
        reconnectUrl || "wss://eventsub.wss.twitch.tv/ws"
    );

    twitchEventSubSocket = socket;
    twitchEventSubLastMessageAt = Date.now();

    socket.on("message", async (rawMessage) => {
        let message;

        // Qualquer mensagem (inclusive o "keepalive") prova que a conexão está viva
        if (twitchEventSubSocket === socket) {
            twitchEventSubLastMessageAt = Date.now();
        }

        try {
            message = JSON.parse(rawMessage.toString());
        } catch (error) {
            console.error("Mensagem inválida recebida da Twitch.");
            return;
        }

        const messageType = message.metadata?.message_type;

        // Conexão inicial ou reconexão concluída
        if (messageType === "session_welcome") {
            twitchEventSubSessionId =
                message.payload.session.id;

            const keepaliveSeconds = Number(message.payload.session.keepalive_timeout_seconds);

            if (Number.isFinite(keepaliveSeconds) && keepaliveSeconds > 0) {
                twitchEventSubKeepaliveMs = keepaliveSeconds * 1000;
            }

            console.log("Conectado ao EventSub da Twitch.");

            // Na reconexão, a Twitch transfere as inscrições automaticamente
            if (reconnectUrl) {
                twitchChatSubscribed = true;
                chatReconnectFailures = 0;
                console.log("Reconexão concluída. Inscrições preservadas.");
                return;
            }

            // Registrar a inscrição somente na conexão inicial
            try {
                const response = await fetch(
                    "https://api.twitch.tv/helix/eventsub/subscriptions",
                    {
                        method: "POST",
                        headers: {
                            "Client-Id": process.env.TWITCH_CLIENT_ID,
                            "Authorization": `Bearer ${accessToken}`,
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            type: "channel.chat.message",
                            version: "1",
                            condition: {
                                broadcaster_user_id: broadcasterId,
                                user_id: broadcasterId
                            },
                            transport: {
                                method: "websocket",
                                session_id: twitchEventSubSessionId
                            }
                        })
                    }
                );

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(JSON.stringify(result));
                }

                twitchChatSubscribed = true;
                chatReconnectFailures = 0;
                console.log("Inscrição no chat da Twitch realizada.");
            } catch (error) {
                console.error(
                    "Erro ao registrar o chat:",
                    error.message
                );

                socket.close();
            }
        }

        // Mensagens recebidas no chat
if (messageType === "notification") {
    if (
        message.payload.subscription?.type ===
        "channel.chat.message"
    ) {
        const chatMessage = message.payload.event;



        

// Verificar se quem escreveu é o vencedor de uma rodada
if (
    !chatMessage.chatter_user_id ||
    chatMessage.broadcaster_user_id !== broadcasterId
) {
    return;
}

const now = new Date().toISOString();

// =====================================================
// 1. PROCURAR UMA RODADA AGUARDANDO A RESPOSTA
// =====================================================

// Mensagens enviadas enquanto a Arena ainda está girando não confirmam o prêmio
const { data: pendingDraws, error: pendingError } = await supabase
    .from("giveaway_draws")
    .select("id, giveaway_id, round_number")
    .eq("winner_twitch_id", chatMessage.chatter_user_id)
    .eq("status", "awaiting_response")
    .gt("response_deadline_at", now)
    .lte("drawn_at", new Date(Date.now() - ARENA_SPIN_MS).toISOString());

if (pendingError) {
    console.error("Erro ao verificar vencedor:", pendingError.message);
    return;
}

if (pendingDraws && pendingDraws.length > 0) {

    const giveawayIds = [
        ...new Set(pendingDraws.map(draw => draw.giveaway_id))
    ];

    const { data: activeGiveaways, error: giveawayError } = await supabase
        .from("giveaways")
        .select("id, current_round, draw_in_progress")
        .in("id", giveawayIds)
        .eq("draw_in_progress", true);

    if (giveawayError) {
        console.error("Erro ao verificar sorteios:", giveawayError.message);
        return;
    }

    const validDraws = pendingDraws.filter(draw =>
        activeGiveaways?.some(giveaway =>
            giveaway.id === draw.giveaway_id &&
            giveaway.current_round === draw.round_number &&
            giveaway.draw_in_progress === true
        )
    );

    if (validDraws.length > 1) {
        console.error("Mais de uma rodada pendente encontrada para o vencedor.");
        return;
    }

    if (validDraws.length === 1) {

        const pendingDraw = validDraws[0];

        // Confirmar a primeira mensagem do vencedor
        const { data: confirmedDraw, error: confirmError } = await supabase
            .from("giveaway_draws")
            .update({
                status: "confirmed",
                winner_responded_at: now
            })
            .eq("id", pendingDraw.id)
            .eq("status", "awaiting_response")
            .gt("response_deadline_at", now)
            .select("id")
            .maybeSingle();

        if (confirmError) {
            console.error("Erro ao confirmar vencedor:", confirmError.message);
            return;
        }

        if (!confirmedDraw) {
            return;
        }

        // Salvar a primeira mensagem
        const { error: saveMessageError } = await supabase
            .from("giveaway_chat_messages")
            .insert({
                giveaway_id: pendingDraw.giveaway_id,
                draw_id: pendingDraw.id,
                twitch_id: chatMessage.chatter_user_id,
                display_name: chatMessage.chatter_user_name,
                message: chatMessage.message.text,
                sent_at: now
            });

        if (saveMessageError) {
            console.error(
                "Erro ao salvar mensagem do vencedor:",
                saveMessageError.message
            );
        }

        // Liberar a rodada após a confirmação
        const { data: releasedGiveaway, error: releaseError } = await supabase
            .from("giveaways")
            .update({
                draw_in_progress: false
            })
            .eq("id", pendingDraw.giveaway_id)
            .eq("current_round", pendingDraw.round_number)
            .eq("draw_in_progress", true)
            .select("id")
            .maybeSingle();

        if (releaseError || !releasedGiveaway) {
            console.error(
                "Vencedor confirmado, mas houve um erro ao liberar a rodada:",
                releaseError?.message || "Sorteio não encontrado."
            );
            return;
        }

        console.log(
            `VENCEDOR CONFIRMOU! Rodada ${pendingDraw.round_number}.`
        );

        return;
    }
}

// =====================================================
// 2. PROCURAR UMA RODADA JÁ CONFIRMADA
// =====================================================

const { data: confirmedDraws, error: confirmedError } = await supabase
    .from("giveaway_draws")
    .select("id, giveaway_id, round_number, winner_responded_at")
    .eq("winner_twitch_id", chatMessage.chatter_user_id)
    .eq("status", "confirmed")
    .order("winner_responded_at", { ascending: false });

if (confirmedError) {
    console.error("Erro ao buscar rodada confirmada:", confirmedError.message);
    return;
}


if (!confirmedDraws || confirmedDraws.length === 0) {
    return;
}

const confirmedGiveawayIds = [
    ...new Set(confirmedDraws.map(draw => draw.giveaway_id))
];

const { data: releasedGiveaways, error: releasedError } = await supabase
    .from("giveaways")
    .select("id, current_round, draw_in_progress")
    .in("id", confirmedGiveawayIds)
    .eq("draw_in_progress", false);

if (releasedError) {
    console.error("Erro ao verificar conversa:", releasedError.message);
    return;
}


// Só aceitar mensagens da rodada atual, já confirmada
const conversationDraws = confirmedDraws.filter(draw =>
    releasedGiveaways?.some(giveaway =>
        giveaway.id === draw.giveaway_id &&
        giveaway.current_round === draw.round_number &&
        giveaway.draw_in_progress === false
    )
);


if (conversationDraws.length === 0) {
    return;
}

// Já vem ordenado: a primeira é a rodada confirmada mais recente
const conversationDraw = conversationDraws[0];

// Salvar as mensagens seguintes do vencedor
const { error: nextMessageError } = await supabase
    .from("giveaway_chat_messages")
    .insert({
        giveaway_id: conversationDraw.giveaway_id,
        draw_id: conversationDraw.id,
        twitch_id: chatMessage.chatter_user_id,
        display_name: chatMessage.chatter_user_name,
        message: chatMessage.message.text,
        sent_at: now
    });

if (nextMessageError) {
    console.error(
        "Erro ao salvar mensagem seguinte:",
        nextMessageError.message
    );
} else {
    console.log("Mensagem adicional do vencedor salva.");
}


            }
        }

        // Reconexão solicitada pela Twitch
        if (messageType === "session_reconnect") {
            const reconnectUrl =
                message.payload.session.reconnect_url;

            console.log("A Twitch solicitou uma reconexão.");

            connectTwitchChat(
                accessToken,
                broadcasterId,
                reconnectUrl
            );
        }

        if (messageType === "revocation") {
            console.error(
                "A Twitch revogou a inscrição do EventSub:",
                message.payload.subscription?.status
            );

            // Sem inscrição a conexão fica "surda": derrubar para o vigia refazer
            twitchChatSubscribed = false;
            socket.terminate();
        }
    });

    socket.on("error", (error) => {
        console.error("Erro na conexão EventSub:", error.message);
    });

    socket.on("close", () => {
        console.log("Conexão com o EventSub encerrada.");

        if (twitchEventSubSocket === socket) {
            twitchEventSubSocket = null;
            twitchEventSubSessionId = null;
            twitchChatSubscribed = false;
        }
    });
}

// ===== Vigia do chat: reconecta sozinho se a conexão cair ou "morrer" em silêncio =====
let chatReconnectFailures = 0;
let chatReconnectNextAttemptAt = 0;
let chatWatchdogRunning = false;

async function checkTwitchChatConnection() {
    // Canal ainda não conectado pelo administrador (ou cópia de teste)
    if (TWITCH_CHAT_DISABLED || !twitchBroadcasterId || !twitchBroadcasterAccessToken || chatWatchdogRunning) {
        return;
    }

    chatWatchdogRunning = true;

    try {
        const socket = twitchEventSubSocket;
        const now = Date.now();
        const silentFor = now - twitchEventSubLastMessageAt;

        if (socket && socket.readyState === WebSocket.OPEN) {
            // A Twitch manda sinal a cada ~10s; sem sinal por muito mais que isso, a conexão morreu
            if (silentFor > twitchEventSubKeepaliveMs + 20000) {
                console.error("Chat da Twitch sem sinal. Derrubando a conexão para reconectar.");
                socket.terminate();
            }
            return;
        }

        if (socket && socket.readyState === WebSocket.CONNECTING) {
            if (silentFor > 30000) {
                console.error("Conexão com o chat da Twitch travada. Tentando de novo.");
                socket.terminate();
            }
            return;
        }

        if (now < chatReconnectNextAttemptAt) {
            return;
        }

        // Espera crescente entre tentativas: 15s, 30s, 60s... até 5 minutos
        chatReconnectFailures += 1;
        chatReconnectNextAttemptAt = now + Math.min(5 * 60 * 1000, 15000 * 2 ** (chatReconnectFailures - 1));

        console.log("Reconectando ao chat da Twitch...");

        const accessToken = await getValidTwitchBroadcasterAccessToken();
        twitchEventSubSocket = null;
        await connectTwitchChat(accessToken, twitchBroadcasterId);
    } catch (error) {
        console.error("Falha ao reconectar o chat da Twitch:", error.message);
    } finally {
        chatWatchdogRunning = false;
    }
}

// Situação do chat para a página de saúde
function getTwitchChatStatus() {
    if (!twitchBroadcasterId || !twitchBroadcasterAccessToken) {
        return "nao_conectado";
    }

    const alive =
        twitchEventSubSocket &&
        twitchEventSubSocket.readyState === WebSocket.OPEN &&
        twitchChatSubscribed &&
        Date.now() - twitchEventSubLastMessageAt <= twitchEventSubKeepaliveMs + 20000;

    return alive ? "conectado" : "reconectando";
}

setInterval(() => {
    checkTwitchChatConnection();
}, 15000);

async function expirePendingDraws() {
    const now = new Date().toISOString();

    const { data: expiredDraws, error } = await supabase
        .from("giveaway_draws")
        .update({
            status: "expired"
        })
        .eq("status", "awaiting_response")
        .lte("response_deadline_at", now)
        .select("id, giveaway_id, round_number, winner_twitch_id");

    if (error) {
        console.error("Erro ao expirar rodadas:", error.message);
        return;
    }

    for (const draw of expiredDraws || []) {
        await supabase
            .from("giveaways")
            .update({
                draw_in_progress: false
            })
            .eq("id", draw.giveaway_id)
            .eq("current_round", draw.round_number);

        await supabase
            .from("audit_logs")
            .insert({
                twitch_id: draw.winner_twitch_id,
                action: "giveaway_draw_expired",
                details: {
                    giveaway_id: draw.giveaway_id,
                    round_number: draw.round_number
                }
            });

        console.log(
            `Rodada ${draw.round_number} expirou.`
        );
    }
}

let giveawayScheduleRunning = false;

async function processGiveawaySchedule() {

    if (giveawayScheduleRunning) return;

    giveawayScheduleRunning = true;

    try {
        const now = new Date().toISOString();

        // 1. Fechar sorteios cujo prazo terminou
        // mesmo que ainda estejam como draft.
        const { data: expiredDrafts, error: draftError } = await supabase
            .from("giveaways")
            .update({ status: "closed" })
            .eq("status", "draft")
            .lte("ends_at", now)
            .select("id");

        if (draftError) throw draftError;

        // 2. Ativar sorteios dentro do período programado.
        const { data: activated, error: activateError } = await supabase
            .from("giveaways")
            .update({ status: "active" })
            .eq("status", "draft")
            .lte("starts_at", now)
            .gt("ends_at", now)
            .select("id");

        if (activateError) throw activateError;

        // 3. Fechar sorteios ativos cujo prazo terminou.
        const { data: closed, error: closeError } = await supabase
            .from("giveaways")
            .update({ status: "closed" })
            .eq("status", "active")
            .lte("ends_at", now)
            .select("id");

        if (closeError) throw closeError;

        if (expiredDrafts?.length || activated?.length || closed?.length) {
            console.log("Controle automático de sorteios:", {
                draftsFechados: expiredDrafts?.length || 0,
                ativados: activated?.length || 0,
                encerrados: closed?.length || 0
            });
        }
    } catch (error) {
        console.error("Erro no controle automático de sorteios:", error.message);
    } finally {
        giveawayScheduleRunning = false;
    }
}

// Agendamento fora da função
console.log("[AGENDA] Inicializando agendador...");

processGiveawaySchedule();

setInterval(() => {
    processGiveawaySchedule();
}, 15000);

// Verificar prazos de resposta a cada segundo
setInterval(() => {
    expirePendingDraws().catch(error => {
        console.error("Erro no controle de prazos:", error);
    });
}, 1000);

// Regras dos sorteios e política de privacidade (página pública)
app.get("/regras", async (req, res) => {
    let pointsPerTicket = null;
    let subscriberMultiplier = null;

    try {
        const { data } = await supabase
            .from("system_settings")
            .select("points_per_ticket, subscriber_multiplier")
            .eq("id", 1)
            .maybeSingle();

        pointsPerTicket = data?.points_per_ticket ?? null;
        subscriberMultiplier = data?.subscriber_multiplier ?? null;
    } catch (error) {
        console.error("Erro ao carregar configurações para as regras:", error.message);
    }

    const priceText = pointsPerTicket
        ? `<strong>${adminNumber(pointsPerTicket)} pontos</strong>`
        : "o valor mostrado na página de sorteios";

    const multiplierText = subscriberMultiplier && Number(subscriberMultiplier) > 1
        ? `Quem é <strong>inscrito (sub)</strong> do canal no momento do sorteio tem cada ticket valendo <strong>${adminNumber(subscriberMultiplier)}x</strong> chances.`
        : "Todos os tickets têm a mesma chance.";

    res.send(withPublicSidebar(req, `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Regras e privacidade - Weirdo's Treasure</title>
            <link rel="stylesheet" href="/css/home.css">
            <style>
                .rules-page {
                    width: min(100% - 40px, 860px);
                    margin: 45px auto 60px;
                    color: #e8dfcf;
                }

                .rules-page h1 {
                    margin: 0 0 8px;
                    color: #e2bd76;
                    font-size: clamp(27px, 4vw, 38px);
                }

                .rules-updated {
                    margin: 0 0 28px;
                    color: #a99578;
                    font-size: 13px;
                }

                .rules-card {
                    margin-bottom: 20px;
                    padding: 24px 26px;
                    background: linear-gradient(145deg, #30251b, #1d1712);
                    border: 1px solid #705332;
                    border-radius: 10px;
                }

                .rules-card h2 {
                    margin: 0 0 14px;
                    color: #e2bd76;
                    font-size: 20px;
                }

                .rules-card ul {
                    margin: 0;
                    padding-left: 20px;
                }

                .rules-card li,
                .rules-card p {
                    color: #c8baa4;
                    line-height: 1.7;
                }

                .rules-card li + li {
                    margin-top: 6px;
                }

                .rules-card strong {
                    color: #f0d49b;
                }

                .rules-card a {
                    color: #e2bd7b;
                }

                @media (max-width: 600px) {
                    .rules-page {
                        width: calc(100% - 24px);
                        margin: 25px auto 40px;
                    }

                    .rules-card {
                        padding: 18px;
                    }
                }
            </style>
        </head>
        <body>
            <main class="rules-page">
                <h1>Regras e privacidade</h1>
                <p class="rules-updated">Última atualização: 13/11/2026</p>

                <section class="rules-card">
                    <h2>✦ Como participar</h2>
                    <ul>
                        <li>Os pontos são os pontos do canal no StreamElements, acumulados assistindo à live de <strong>${escapeDashboardHtml(LIVE_CHANNEL_LOGIN)}</strong> na Twitch.</li>
                        <li>Entre no site com a sua conta da Twitch e troque os pontos por tickets. Cada ticket custa ${priceText}.</li>
                        <li>Cada ticket é uma chance no sorteio. Quanto mais tickets, maiores as chances.</li>
                        <li>${multiplierText}</li>
                        <li>Na hora do sorteio, você precisa estar seguindo o canal.</li>
                        <li>A compra de tickets fecha na data de encerramento de cada sorteio.</li>
                    </ul>
                </section>

                <section class="rules-card">
                    <h2>✦ Compras de tickets</h2>
                    <ul>
                        <li>Os pontos são descontados no momento da compra e os tickets aparecem em "Meus tickets".</li>
                        <li>Tickets comprados não podem ser trocados de volta por pontos.</li>
                        <li>Se uma compra falhar depois do desconto, ela é conferida manualmente: ou os tickets são emitidos, ou os pontos são devolvidos.</li>
                        <li>O limite é de 1.000 tickets por compra.</li>
                        <li>Tentativas de burlar o sistema (contas falsas, abuso de falhas) podem levar à desclassificação.</li>
                    </ul>
                </section>

                <section class="rules-card">
                    <h2>✦ O sorteio</h2>
                    <ul>
                        <li>O sorteio é feito ao vivo, de forma manual, depois que o período de compras termina.</li>
                        <li>O vencedor é escolhido pelo servidor com um gerador de números aleatórios seguro, antes da animação começar. A animação apenas mostra o resultado.</li>
                        <li>Cada pessoa pode ganhar no máximo uma vez por sorteio.</li>
                        <li>Depois que o nome aparecer na tela, o vencedor tem <strong>40 segundos</strong> para mandar uma mensagem no chat da live. Mensagens enviadas antes do nome aparecer não contam.</li>
                        <li>Se o vencedor não responder a tempo, um novo sorteio é feito entre os demais participantes.</li>
                    </ul>
                </section>

                <section class="rules-card">
                    <h2>✦ Privacidade: quais dados guardamos</h2>
                    <ul>
                        <li><strong>Da sua conta da Twitch:</strong> ID, nome de usuário, nome de exibição e foto de perfil. Não temos acesso à sua senha nem ao seu e-mail.</li>
                        <li><strong>Da sua participação:</strong> compras, pontos gastos, tickets, resultados dos sorteios e, se você for sorteado, as mensagens enviadas no chat durante a confirmação.</li>
                        <li><strong>Cookie:</strong> usamos apenas um cookie de sessão, necessário para manter você conectado.</li>
                    </ul>
                </section>

                <section class="rules-card">
                    <h2>✦ Privacidade: como os dados são usados</h2>
                    <ul>
                        <li>Os dados servem apenas para fazer os sorteios funcionarem. Não são vendidos nem compartilhados para publicidade.</li>
                        <li>Serviços usados: Twitch (login e chat), StreamElements (pontos do canal), Supabase (banco de dados) e Cloudflare (entrega do site).</li>
                        <li>O nome e a foto dos participantes e vencedores podem aparecer na live durante o sorteio.</li>
                        <li>Para pedir a remoção dos seus dados, fale com <strong>${escapeDashboardHtml(LIVE_CHANNEL_LOGIN)}</strong> pela Twitch.</li>
                    </ul>
                </section>

                <section class="rules-card">
                    <p>Este site não é afiliado à Twitch nem ao StreamElements.</p>
                </section>
            </main>
        </body>
        </html>
    `, "/regras"));
});

// Minigame diário (página /minigame e suas rotas)
registerMinigame(app, {
    supabase,
    withPublicSidebar,
    getCsrfToken,
    requireCsrf,
    createRateLimiter,
    getStreamElementsChannelId,
    addStreamElementsPoints
});

// Texto do comando !sorteio do chat (o StreamElements busca este endereço com ${customapi})
const CHAT_GIVEAWAY_CACHE_MS = 30 * 1000;
let chatGiveawayCache = { text: null, at: 0 };

function chatDateTime(value) {
    const date = new Date(value);
    const day = date.toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit" });
    const time = date.toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo", hour: "2-digit", minute: "2-digit" });
    return `${day} às ${time}`;
}

function chatTitle(value) {
    const clean = String(value || "Sorteio").replace(/\s+/g, " ").trim();
    return clean.length > 80 ? clean.slice(0, 77) + "..." : clean;
}

app.get("/chat/sorteio", async (req, res) => {
    res.type("text/plain; charset=utf-8");
    res.set("Cache-Control", "no-store");

    if (chatGiveawayCache.text && Date.now() - chatGiveawayCache.at < CHAT_GIVEAWAY_CACHE_MS) {
        return res.send(chatGiveawayCache.text);
    }

    try {
        const nowIso = new Date().toISOString();

        const [activeResult, upcomingResult] = await Promise.all([
            supabase
                .from("giveaways")
                .select("title, ends_at")
                .eq("status", "active")
                .order("ends_at", { ascending: true })
                .limit(3),
            supabase
                .from("giveaways")
                .select("title, starts_at")
                .eq("status", "draft")
                .gt("starts_at", nowIso)
                .order("starts_at", { ascending: true })
                .limit(1)
        ]);

        if (activeResult.error) throw activeResult.error;
        if (upcomingResult.error) throw upcomingResult.error;

        const active = activeResult.data || [];
        const upcoming = (upcomingResult.data || [])[0];
        let text;

        if (active.length === 1) {
            text = `🏆 Sorteio ativo: ${chatTitle(active[0].title)} — compras até ${chatDateTime(active[0].ends_at)}. Garanta seus tickets: weirdostreasure.com.br/giveaways`;
        } else if (active.length > 1) {
            const list = active.map(item => `${chatTitle(item.title)} (até ${chatDateTime(item.ends_at)})`).join(" • ");
            text = `🏆 Sorteios ativos: ${list}. Garanta seus tickets: weirdostreasure.com.br/giveaways`;
        } else if (upcoming) {
            text = `⏳ Nenhum sorteio aberto agora. Próximo: ${chatTitle(upcoming.title)}, começa em ${chatDateTime(upcoming.starts_at)}. weirdostreasure.com.br`;
        } else {
            text = "Nenhum sorteio ativo no momento. Fique de olho, novos tesouros vêm aí! weirdostreasure.com.br";
        }

        chatGiveawayCache = { text, at: Date.now() };
        return res.send(text);
    } catch (error) {
        console.error("Erro no texto do !sorteio:", error.message);
        return res.send("Confira os sorteios em weirdostreasure.com.br/giveaways");
    }
});

// Verificação simples usada pela hospedagem: só diz que o servidor está respondendo
app.get("/vivo", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.type("text/plain").send("ok");
});

// Saúde do site para monitores (ex.: UptimeRobot).
// Responde 200 quando banco e chat estão funcionando; 503 quando algo precisa de atenção.
app.get("/saude", async (req, res) => {
    let database = "ok";

    try {
        const { error } = await supabase
            .from("system_settings")
            .select("id", { head: true, count: "exact" })
            .eq("id", 1)
            .abortSignal(AbortSignal.timeout(5000));

        if (error) database = "erro";
    } catch (error) {
        database = "erro";
    }

    const chat = getTwitchChatStatus();
    const healthy = database === "ok" && chat === "conectado";

    res.set("Cache-Control", "no-store");

    return res.status(healthy ? 200 : 503).json({
        ok: healthy,
        banco: database,
        chat_twitch: chat,
        ligado_ha_minutos: Math.floor(process.uptime() / 60)
    });
});

// Página não encontrada
app.use((req, res) => {
    res.status(404).send("Página não encontrada.");
});

// Erros inesperados: registrar no log e nunca mostrar detalhes internos
app.use((error, req, res, next) => {
    console.error("Erro não tratado:", error?.message || error);

    if (res.headersSent) {
        return next(error);
    }

    const status = Number.isInteger(error?.status) && error.status >= 400 && error.status < 500
        ? error.status
        : 500;

    if (req.get("X-Requested-With") === "fetch") {
        return res.status(status).json({ ok: false, error: "Não foi possível concluir a solicitação." });
    }

    return res.status(status).send(status === 500 ? "Erro interno. Tente novamente em instantes." : "Solicitação inválida.");
});

// Uma falha inesperada (ex.: conexão de chat) não pode derrubar o servidor
process.on("unhandledRejection", (reason) => {
    console.error("Promessa rejeitada sem tratamento:", reason?.message || reason);
});

// HOST=127.0.0.1 em produção: o site só é acessível pelo túnel da Cloudflare
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, async () => {
    console.log(`Servidor iniciado em ${HOST}:${PORT}`);

    if (TWITCH_CHAT_DISABLED) {
        console.log("Cópia de teste: chat da Twitch desligado.");
        return;
    }

    await restoreTwitchBroadcasterAuthentication();
});
