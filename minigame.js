// Minigame diário: adivinhe a palavra de 5 letras em até 6 tentativas.
// A palavra fica só no servidor; o navegador recebe apenas as cores de cada tentativa.
const crypto = require("crypto");
const { ANSWERS, VALID_GUESSES, normalizeWord } = require("./minigame-words");

// Uma partida por dia, no horário de Brasília (vira à meia-noite)
const GAME_TIMEZONE = "America/Sao_Paulo";
const GAME_TIMEZONE_OFFSET = "-03:00";
// Partida aberta há mais tempo que isso é encerrada sem pontos
const MAX_GAME_MS = 20 * 60 * 60 * 1000;
const MAX_ATTEMPTS = 6;
const POINTS_BY_ATTEMPT = [180, 150, 120, 90, 60, 30];
const CREDIT_MAX_ATTEMPTS = 5;
// Evita repetir palavras recentes para o mesmo usuário
const RECENT_WORDS_TO_AVOID = 60;

// Meia-noite (horário de Brasília) do dia seguinte ao da data informada
function nextDayStart(date) {
    const key = new Date(date).toLocaleDateString("en-CA", { timeZone: GAME_TIMEZONE });
    const next = new Date(`${key}T00:00:00Z`);
    next.setUTCDate(next.getUTCDate() + 1);
    return new Date(`${next.toISOString().slice(0, 10)}T00:00:00${GAME_TIMEZONE_OFFSET}`).getTime();
}

// Cores: g = verde (lugar certo), y = amarela (está na palavra, lugar errado), r = vermelha (não está)
function evaluateGuess(guess, word) {
    const result = Array(5).fill("r");
    const remaining = {};

    for (let i = 0; i < 5; i++) {
        if (guess[i] === word[i]) {
            result[i] = "g";
        } else {
            remaining[word[i]] = (remaining[word[i]] || 0) + 1;
        }
    }

    for (let i = 0; i < 5; i++) {
        if (result[i] === "g") continue;

        if (remaining[guess[i]] > 0) {
            result[i] = "y";
            remaining[guess[i]] -= 1;
        }
    }

    return result;
}

module.exports = function registerMinigame(app, deps) {
    const {
        supabase,
        withPublicSidebar,
        getCsrfToken,
        requireCsrf,
        createRateLimiter,
        getStreamElementsChannelId,
        addStreamElementsPoints
    } = deps;

    const minigameLimiter = createRateLimiter({
        windowMs: 60 * 1000,
        max: 40,
        keyFn: (req) => req.session?.twitchUser?.id || req.ip,
        message: "Muitas tentativas em pouco tempo. Aguarde um instante."
    });

    const wantsLogin = (req, res) => {
        if (!req.session?.twitchUser) {
            res.status(401).json({ ok: false, error: "Entre com a Twitch para jogar." });
            return true;
        }
        return false;
    };

    async function loadLastGame(twitchId) {
        const { data, error } = await supabase
            .from("daily_word_games")
            .select("id, word, status, attempts, guesses, points_awarded, credit_status, started_at, finished_at")
            .eq("twitch_id", twitchId)
            .order("started_at", { ascending: false })
            .limit(1)
            .maybeSingle();

        if (error) throw error;
        return data;
    }

    async function pickWord(twitchId) {
        const { data, error } = await supabase
            .from("daily_word_games")
            .select("word")
            .eq("twitch_id", twitchId)
            .order("started_at", { ascending: false })
            .limit(RECENT_WORDS_TO_AVOID);

        if (error) throw error;

        const recent = new Set((data || []).map(row => row.word));
        const options = ANSWERS.filter(word => !recent.has(word));
        const pool = options.length > 0 ? options : ANSWERS;

        return pool[crypto.randomInt(pool.length)];
    }

    // Sair da página com a partida aberta = perder a chance
    async function abandonPlayingGame(twitchId) {
        const { error } = await supabase
            .from("daily_word_games")
            .update({ status: "abandoned", finished_at: new Date().toISOString() })
            .eq("twitch_id", twitchId)
            .eq("status", "playing");

        if (error) throw error;
    }

    function buildState(game) {
        const now = Date.now();
        const startedAt = game ? new Date(game.started_at).getTime() : 0;
        const nextAvailable = game ? nextDayStart(startedAt) : 0;
        const finished = game && game.status !== "playing";

        return {
            ok: true,
            serverTime: now,
            pointsByAttempt: POINTS_BY_ATTEMPT,
            canPlay: !game || now >= nextAvailable,
            nextAvailableAt: game && now < nextAvailable ? new Date(nextAvailable).toISOString() : null,
            game: game ? {
                status: game.status,
                attempts: Array.isArray(game.guesses) ? game.guesses : [],
                pointsAwarded: game.points_awarded,
                creditStatus: game.credit_status,
                startedAt: game.started_at,
                // A palavra só é revelada depois que a partida acabou
                word: finished ? game.word.toUpperCase() : null
            } : null
        };
    }

    async function creditPoints(gameId, login, points, previousAttempts = 0) {
        try {
            const channelId = await getStreamElementsChannelId();
            await addStreamElementsPoints(channelId, login, points);

            await supabase
                .from("daily_word_games")
                .update({
                    credit_status: "credited",
                    credited_at: new Date().toISOString(),
                    credit_attempts: previousAttempts + 1
                })
                .eq("id", gameId);

            return "credited";
        } catch (error) {
            console.error("Minigame: falha ao creditar pontos:", error.message);

            await supabase
                .from("daily_word_games")
                .update({ credit_status: "failed", credit_attempts: previousAttempts + 1 })
                .eq("id", gameId);

            return "failed";
        }
    }

    // Tenta de novo os créditos que falharam (a cada 5 minutos, até 5 vezes)
    async function retryFailedCredits() {
        const { data, error } = await supabase
            .from("daily_word_games")
            .select("id, points_awarded, credit_attempts, users ( twitch_login )")
            .eq("credit_status", "failed")
            .lt("credit_attempts", CREDIT_MAX_ATTEMPTS)
            .limit(20);

        if (error) {
            console.error("Minigame: erro ao buscar créditos pendentes:", error.message);
            return;
        }

        for (const game of data || []) {
            const login = game.users?.twitch_login;
            if (!login || game.points_awarded <= 0) continue;
            await creditPoints(game.id, login, game.points_awarded, game.credit_attempts);
        }
    }

    const retryTimer = setInterval(() => {
        retryFailedCredits().catch(error => console.error("Minigame:", error.message));
    }, 5 * 60 * 1000);
    if (retryTimer && retryTimer.unref) retryTimer.unref();

    // ---------- Página ----------
    app.get("/minigame", async (req, res, next) => {
        try {
            const user = req.session?.twitchUser;

            if (user) {
                await abandonPlayingGame(user.id);
            }

            const pointsList = POINTS_BY_ATTEMPT
                .map((points, index) => `<li><strong>${index + 1}ª tentativa:</strong> ${points} pontos</li>`)
                .join("");

            res.send(withPublicSidebar(req, `
                <!DOCTYPE html>
                <html lang="pt-BR">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Minigame diário - Weirdo's Treasure</title>
                    <link rel="stylesheet" href="/css/home.css">
                    <link rel="stylesheet" href="/css/minigame.css">
                </head>
                <body data-logged-in="${user ? "1" : "0"}" data-csrf="${user ? getCsrfToken(req) : ""}">
                    <main class="mg-page">
                        <header class="mg-header">
                            <span class="mg-eyebrow">WEIRDO'S TREASURE</span>
                            <h1>Minigame diário</h1>
                            <p>Descubra a palavra secreta de 5 letras e ganhe pontos para trocar por tickets.</p>
                        </header>

                        <section class="mg-status" id="mgStatus">
                            ${user ? `
                                <div class="mg-timer" id="mgTimer">Carregando...</div>
                                <button type="button" class="mg-start" id="mgStart" disabled>✦ INICIAR ✦</button>
                            ` : `
                                <div class="mg-timer">Entre com a sua conta da Twitch para jogar.</div>
                                <a class="mg-start mg-login" href="/auth/twitch?returnTo=/minigame">Entrar com Twitch</a>
                            `}
                        </section>

                        <section class="mg-game" id="mgGame" hidden>
                            <div class="mg-board" id="mgBoard" aria-label="Tabuleiro"></div>
                            <div class="mg-message" id="mgMessage" role="status" aria-live="polite"></div>
                            <div class="mg-keyboard" id="mgKeyboard" aria-label="Teclado"></div>
                        </section>

                        <section class="mg-result" id="mgResult" hidden></section>

                        <section class="mg-rules">
                            <h2>✦ Como jogar</h2>
                            <ul>
                                <li>Clique em <strong>Iniciar</strong> e tente descobrir a palavra de <strong>5 letras</strong> em até <strong>6 tentativas</strong>.</li>
                                <li>Cada pessoa recebe uma palavra diferente. Acentos não contam (ex.: "avião" é AVIAO).</li>
                                <li>Só valem palavras que existem.</li>
                                <li>Depois de cada tentativa, as letras mudam de cor:</li>
                            </ul>
                            <div class="mg-legend">
                                <span><b class="mg-tile-mini is-g">A</b> letra certa no lugar certo</span>
                                <span><b class="mg-tile-mini is-y">B</b> letra existe, mas em outro lugar</span>
                                <span><b class="mg-tile-mini is-r">C</b> letra não existe na palavra</span>
                            </div>
                            <h3>Pontos</h3>
                            <ul class="mg-points">${pointsList}<li><strong>Não acertou:</strong> 0 pontos</li></ul>
                            <h3>Regras</h3>
                            <ul>
                                <li>Você pode jogar <strong>uma vez por dia</strong>. O dia vira à meia-noite (horário de Brasília).</li>
                                <li><strong>Se sair da página durante a partida, você perde a chance</strong> e só joga de novo no dia seguinte.</li>
                                <li>Os pontos caem no seu saldo do canal (StreamElements) e podem ser usados para comprar tickets.</li>
                            </ul>
                        </section>
                    </main>

                    <div class="mg-modal" id="mgLeaveModal" hidden>
                        <div class="mg-modal-card" role="dialog" aria-modal="true" aria-labelledby="mgLeaveTitle">
                            <h2 id="mgLeaveTitle">Sair da partida?</h2>
                            <p>Se você sair agora, <strong>perde a chance desta partida</strong> e só poderá jogar novamente amanhã.</p>
                            <div class="mg-modal-actions">
                                <button type="button" class="mg-start" id="mgStay">Continuar jogando</button>
                                <button type="button" class="mg-leave" id="mgLeave">Sair mesmo assim</button>
                            </div>
                        </div>
                    </div>

                    <script src="/js/minigame.js"></script>
                </body>
                </html>
            `, "/minigame"));
        } catch (error) {
            next(error);
        }
    });

    // ---------- API ----------
    app.get("/minigame/estado", async (req, res) => {
        if (wantsLogin(req, res)) return;

        try {
            const game = await loadLastGame(req.session.twitchUser.id);
            res.set("Cache-Control", "no-store");
            return res.json(buildState(game));
        } catch (error) {
            console.error("Minigame: erro ao carregar estado:", error.message);
            return res.status(500).json({ ok: false, error: "Não foi possível carregar o minigame." });
        }
    });

    app.post("/minigame/iniciar", minigameLimiter, requireCsrf, async (req, res) => {
        if (wantsLogin(req, res)) return;

        const twitchId = req.session.twitchUser.id;

        try {
            const word = await pickWord(twitchId);

            const { error } = await supabase.rpc("start_daily_word_game_today", {
                p_twitch_id: twitchId,
                p_word: word
            });

            if (error) {
                if (String(error.message).includes("COOLDOWN")) {
                    const game = await loadLastGame(twitchId);
                    return res.status(409).json({ ...buildState(game), ok: false, error: "Você já jogou hoje. Volte amanhã!" });
                }
                throw error;
            }

            const game = await loadLastGame(twitchId);
            return res.json(buildState(game));
        } catch (error) {
            console.error("Minigame: erro ao iniciar:", error.message);
            return res.status(500).json({ ok: false, error: "Não foi possível iniciar a partida." });
        }
    });

    app.post("/minigame/tentativa", minigameLimiter, requireCsrf, async (req, res) => {
        if (wantsLogin(req, res)) return;

        const user = req.session.twitchUser;
        const guess = normalizeWord(typeof req.body.palavra === "string" ? req.body.palavra : "");

        if (guess.length !== 5) {
            return res.status(400).json({ ok: false, error: "A palavra precisa ter 5 letras." });
        }

        if (!VALID_GUESSES.has(guess)) {
            // Registro para ampliar a lista de palavras aceitas
            console.log("Minigame: palavra fora da lista:", guess);
            return res.status(400).json({ ok: false, error: "Essa palavra não está na lista." });
        }

        try {
            const game = await loadLastGame(user.id);

            if (!game || game.status !== "playing") {
                return res.status(409).json({ ...buildState(game), ok: false, error: "Nenhuma partida em andamento." });
            }

            if (Date.now() - new Date(game.started_at).getTime() > MAX_GAME_MS) {
                await abandonPlayingGame(user.id);
                return res.status(409).json({ ...buildState(await loadLastGame(user.id)), ok: false, error: "O tempo desta partida acabou." });
            }

            const attempts = Array.isArray(game.guesses) ? game.guesses : [];

            if (attempts.some(attempt => attempt.guess === guess.toUpperCase())) {
                return res.status(400).json({ ok: false, error: "Você já tentou essa palavra." });
            }

            const result = evaluateGuess(guess, game.word);
            const newAttempts = [...attempts, { guess: guess.toUpperCase(), result }];
            const won = guess === game.word;
            const lost = !won && newAttempts.length >= MAX_ATTEMPTS;
            const points = won ? POINTS_BY_ATTEMPT[newAttempts.length - 1] : 0;

            const update = {
                guesses: newAttempts,
                attempts: newAttempts.length
            };

            if (won || lost) {
                update.status = won ? "won" : "lost";
                update.finished_at = new Date().toISOString();
                update.points_awarded = points;
                update.credit_status = points > 0 ? "pending" : "none";
            }

            // Só grava se ninguém mexeu na partida desde a leitura (evita tentativa dupla)
            const { data: updated, error: updateError } = await supabase
                .from("daily_word_games")
                .update(update)
                .eq("id", game.id)
                .eq("status", "playing")
                .eq("attempts", attempts.length)
                .select("id");

            if (updateError) throw updateError;

            if (!updated || updated.length === 0) {
                return res.status(409).json({ ok: false, error: "A partida mudou. Atualize a página." });
            }

            if (won && points > 0) {
                await creditPoints(game.id, user.login, points);
            }

            return res.json(buildState(await loadLastGame(user.id)));
        } catch (error) {
            console.error("Minigame: erro na tentativa:", error.message);
            return res.status(500).json({ ok: false, error: "Não foi possível registrar a tentativa." });
        }
    });
};

module.exports.evaluateGuess = evaluateGuess;
module.exports.POINTS_BY_ATTEMPT = POINTS_BY_ATTEMPT;
