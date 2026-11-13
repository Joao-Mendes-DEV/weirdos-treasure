// Peças de segurança do servidor: variáveis de ambiente, cabeçalhos,
// limite de requisições e armazenamento de sessões no Supabase.
const session = require("express-session");

// ---------- Variáveis de ambiente ----------
const REQUIRED_ENV = [
    "SESSION_SECRET",
    "SUPABASE_URL",
    "SUPABASE_SECRET_KEY",
    "TWITCH_CLIENT_ID",
    "TWITCH_CLIENT_SECRET",
    "TWITCH_REDIRECT_URI",
    "TWITCH_TOKEN_ENCRYPTION_KEY",
    "STREAMELEMENTS_JWT",
    "ADMIN_TWITCH_ID"
];

// Confere se tudo está definido (sem nunca mostrar os valores)
function validateEnvironment() {
    const problems = [];

    for (const name of REQUIRED_ENV) {
        if (!process.env[name] || !String(process.env[name]).trim()) {
            problems.push(`${name} não está definida`);
        }
    }

    if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) {
        problems.push("SESSION_SECRET precisa ter pelo menos 32 caracteres");
    }

    if (
        process.env.TWITCH_TOKEN_ENCRYPTION_KEY &&
        !/^[0-9a-fA-F]{64}$/.test(process.env.TWITCH_TOKEN_ENCRYPTION_KEY)
    ) {
        problems.push("TWITCH_TOKEN_ENCRYPTION_KEY precisa ter 64 caracteres hexadecimais");
    }

    if (problems.length > 0) {
        console.error("Configuração inválida:\n - " + problems.join("\n - "));

        if (process.env.NODE_ENV === "production") {
            process.exit(1);
        }
    }
}

// ---------- Cabeçalhos de segurança ----------
const CONTENT_SECURITY_POLICY = [
    "default-src 'self'",
    "img-src 'self' data: https:",
    "style-src 'self' 'unsafe-inline'",
    "script-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
    "font-src 'self' data:",
    "media-src 'self'",
    "form-action 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'"
].join("; ");

function securityHeaders(req, res, next) {
    res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");

    if (req.secure) {
        res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }

    next();
}

// ---------- Limite de requisições (memória, janela fixa) ----------
const rateLimitBuckets = new Set();

function createRateLimiter({ windowMs, max, keyFn, message, skip }) {
    const hits = new Map();
    rateLimitBuckets.add(hits);

    return function rateLimiter(req, res, next) {
        if (skip && skip(req)) return next();

        const key = keyFn ? keyFn(req) : req.ip;
        const now = Date.now();
        let entry = hits.get(key);

        if (!entry || now >= entry.resetAt) {
            entry = { count: 0, resetAt: now + windowMs };
            hits.set(key, entry);
        }

        entry.count += 1;

        if (entry.count > max) {
            const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
            res.setHeader("Retry-After", String(retryAfter));

            const text = message || "Muitas solicitações em pouco tempo. Aguarde um instante e tente novamente.";

            if (req.get("X-Requested-With") === "fetch" || req.path.endsWith("/state")) {
                return res.status(429).json({ ok: false, error: text });
            }

            return res.status(429).send(text);
        }

        next();
    };
}

// Limpa contadores vencidos para a memória não crescer
const rateLimitCleanupTimer = setInterval(() => {
    const now = Date.now();

    for (const hits of rateLimitBuckets) {
        for (const [key, entry] of hits) {
            if (now >= entry.resetAt) hits.delete(key);
        }
    }
}, 60 * 1000);
if (rateLimitCleanupTimer && rateLimitCleanupTimer.unref) rateLimitCleanupTimer.unref();

// ---------- Sessões guardadas no Supabase ----------
// Tabela public.sessions (sid, sess, expires_at). Enquanto a tabela não existir,
// usa a memória e avisa no log (útil só para desenvolvimento).
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 12 * 60 * 60 * 1000;

class SupabaseSessionStore extends session.Store {
    constructor(supabase) {
        super();
        this.supabase = supabase;
        this.memory = new session.MemoryStore();
        this.useMemory = false;
        this.lastTouch = new Map();

        this.ready = this.supabase
            .from("sessions")
            .select("sid")
            .limit(1)
            .then(({ error }) => {
                if (error) {
                    this.useMemory = true;
                    console.error(
                        "AVISO: tabela de sessões indisponível (" + error.message +
                        "). Usando memória — rode o script SQL antes de publicar."
                    );
                }
            });

        const cleanupTimer = setInterval(() => this.cleanup(), 60 * 60 * 1000);
        if (cleanupTimer && cleanupTimer.unref) cleanupTimer.unref();
    }

    expiresFor(sess) {
        const expires = sess?.cookie?.expires ? new Date(sess.cookie.expires) : null;
        return expires && !Number.isNaN(expires.getTime())
            ? expires
            : new Date(Date.now() + SESSION_TTL_MS);
    }

    get(sid, callback) {
        this.ready.then(async () => {
            if (this.useMemory) return this.memory.get(sid, callback);

            try {
                const { data, error } = await this.supabase
                    .from("sessions")
                    .select("sess, expires_at")
                    .eq("sid", sid)
                    .maybeSingle();

                if (error) return callback(error);
                if (!data || new Date(data.expires_at) <= new Date()) return callback(null, null);

                callback(null, data.sess);
            } catch (error) {
                callback(error);
            }
        });
    }

    set(sid, sess, callback = () => {}) {
        this.ready.then(async () => {
            if (this.useMemory) return this.memory.set(sid, sess, callback);

            try {
                const { error } = await this.supabase
                    .from("sessions")
                    .upsert({
                        sid,
                        sess,
                        expires_at: this.expiresFor(sess).toISOString()
                    }, { onConflict: "sid" });

                this.lastTouch.set(sid, Date.now());
                callback(error || null);
            } catch (error) {
                callback(error);
            }
        });
    }

    destroy(sid, callback = () => {}) {
        this.lastTouch.delete(sid);

        this.ready.then(async () => {
            if (this.useMemory) return this.memory.destroy(sid, callback);

            try {
                const { error } = await this.supabase.from("sessions").delete().eq("sid", sid);
                callback(error || null);
            } catch (error) {
                callback(error);
            }
        });
    }

    // Renova a validade no máximo a cada 12h por sessão (evita uma escrita por requisição)
    touch(sid, sess, callback = () => {}) {
        const last = this.lastTouch.get(sid) || 0;

        if (Date.now() - last < TOUCH_INTERVAL_MS) return callback(null);

        this.lastTouch.set(sid, Date.now());

        this.ready.then(async () => {
            if (this.useMemory) return this.memory.touch(sid, sess, callback);

            try {
                const { error } = await this.supabase
                    .from("sessions")
                    .update({ expires_at: this.expiresFor(sess).toISOString() })
                    .eq("sid", sid);

                callback(error || null);
            } catch (error) {
                callback(error);
            }
        });
    }

    async cleanup() {
        await this.ready;
        if (this.useMemory) return;

        const { error } = await this.supabase
            .from("sessions")
            .delete()
            .lt("expires_at", new Date().toISOString());

        if (error) console.error("Erro ao limpar sessões expiradas:", error.message);

        if (this.lastTouch.size > 50000) this.lastTouch.clear();
    }
}

module.exports = {
    validateEnvironment,
    securityHeaders,
    createRateLimiter,
    SupabaseSessionStore,
    SESSION_TTL_MS
};
