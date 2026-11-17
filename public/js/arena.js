// Arena do Tesouro — giro estilo "abertura de caixa", vencedores e celebração.
// O vencedor é sempre o que o servidor já gravou no banco; a animação só encena até ele.
(function () {
    "use strict";

    const body = document.body;
    const GIVEAWAY_ID = body.dataset.giveawayId;
    const IS_ADMIN = body.dataset.admin === "1";
    const CSRF = body.dataset.csrf || "";
    const SPIN_MS = Number(body.dataset.spinMs) || 14000;
    const REVEAL_DELAY_MS = 350;
    const CELEBRATION_MS = 7000;
    const SOUND_ENABLED = new URLSearchParams(location.search).get("som") !== "0";
    // Sorteio pelo chat (!euquero): cada inscrição faz o papel de um ticket
    const IS_CHAT = body.dataset.kind === "chat";
    const ENTRY_LABEL = IS_CHAT ? "INSCRIÇÃO #" : "TICKET #";

    const $ = (id) => document.getElementById(id);
    const els = {
        title: $("giveawayTitle"),
        meta: $("giveawayMeta"),
        participantCount: $("arenaParticipantCount"),
        ticketCount: $("arenaTicketCount"),
        caseWindow: $("caseWindow"),
        track: $("treasureWheel"),
        caseEmpty: $("caseEmpty"),
        caption: $("wheelCaption"),
        countdown: $("countdown"),
        chat: $("winnerChat"),
        winnersList: $("winnersList"),
        drawButton: $("drawButton"),
        drawHint: $("drawHint"),
        totalTickets: $("totalTickets"),
        totalParticipants: $("totalParticipants"),
        multiplier: $("subscriberMultiplier"),
        participantsList: $("participantsList"),
        celebration: $("celebration"),
        celebrationAvatar: $("celebrationAvatar"),
        celebrationName: $("celebrationName"),
        celebrationTicket: $("celebrationTicket"),
        canvas: $("fireworks"),
        signupBanner: $("signupBanner"),
        signupTimer: $("signupTimer"),
        closeSignupButton: $("closeSignupButton")
    };

    let state = null;
    let clockOffset = 0;
    let bestRtt = Infinity;
    let requestInFlight = false;
    let drawError = "";
    let participantsSignature = "";
    let idleSignature = "";

    // Animação em andamento
    let spin = null;          // { drawId, motion, cards, winnerCard, ... }
    let animatedDrawId = null;
    let celebratedDrawId = null;

    const serverNow = () => Date.now() + clockOffset;

    // ---------- Aleatoriedade com semente (OBS e navegador mostram o mesmo giro) ----------
    function seedFrom(text) {
        let h = 1779033703 ^ text.length;
        for (let i = 0; i < text.length; i++) {
            h = Math.imul(h ^ text.charCodeAt(i), 3432918353);
            h = (h << 13) | (h >>> 19);
        }
        h = Math.imul(h ^ (h >>> 16), 2246822507);
        h = Math.imul(h ^ (h >>> 13), 3266489909);
        return (h ^= h >>> 16) >>> 0;
    }

    function mulberry32(seed) {
        let a = seed >>> 0;
        return function () {
            a = (a + 0x6D2B79F5) >>> 0;
            let t = a;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
    }

    // ---------- Som (opcional: ?som=0 desliga) ----------
    let audioCtx = null;

    function audio() {
        if (!SOUND_ENABLED) return null;
        try {
            if (!audioCtx) {
                const Ctx = window.AudioContext || window.webkitAudioContext;
                if (!Ctx) return null;
                audioCtx = new Ctx();
            }
            if (audioCtx.state === "suspended") audioCtx.resume();
            return audioCtx;
        } catch (error) {
            return null;
        }
    }

    function tone(freq, start, duration, type, volume) {
        const ctx = audio();
        if (!ctx) return;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = type;
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(volume, ctx.currentTime + start);
        gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + start + duration);
        osc.connect(gain).connect(ctx.destination);
        osc.start(ctx.currentTime + start);
        osc.stop(ctx.currentTime + start + duration + 0.02);
    }

    function playTick(slow) {
        tone(slow ? 1500 : 1900, 0, 0.035, "triangle", slow ? 0.09 : 0.05);
    }

    function playFanfare() {
        [523.25, 659.25, 783.99, 1046.5].forEach((freq, i) => tone(freq, i * 0.13, 0.35, "triangle", 0.12));
        tone(1046.5, 0.6, 0.9, "sine", 0.1);
        tone(1318.5, 0.6, 0.9, "sine", 0.06);
    }

    // ---------- Utilidades de DOM ----------
    function avatarElement(className, imageUrl, name) {
        if (imageUrl) {
            const img = document.createElement("img");
            img.className = className;
            img.src = imageUrl;
            img.alt = "";
            img.loading = "lazy";
            return img;
        }
        const span = document.createElement("span");
        span.className = className;
        span.textContent = String(name || "?").charAt(0).toUpperCase();
        return span;
    }

    function makeTicketCard(ticket) {
        const card = document.createElement("div");
        card.className = "ticket-card";

        const number = document.createElement("div");
        number.className = "ticket-card-number";
        number.textContent = "#" + ticket.ticket_number;

        const name = document.createElement("div");
        name.className = "ticket-card-name";
        name.textContent = ticket.display_name || "Participante";

        card.append(avatarElement("ticket-card-avatar", ticket.profile_image_url, ticket.display_name), number, name);
        return card;
    }

    function setCaption(text, mode) {
        els.caption.textContent = text;
        els.caption.classList.toggle("is-drama", mode === "drama");
        els.caption.classList.toggle("is-winner", mode === "winner");
    }

    function trackGeometry() {
        const first = els.track.firstElementChild;
        const cardWidth = first ? first.offsetWidth : 140;
        const gap = parseFloat(getComputedStyle(els.track).columnGap) || 8;
        return { cardWidth, gap, stride: cardWidth + gap };
    }

    // ---------- Plano do giro ----------
    // Variações de "drama" no final (sempre parando no ticket vencedor):
    //  crawl   – desacelera bem devagar até parar
    //  stays   – vai se arrastando até a borda e quase passa para o próximo, mas fica
    //  creeps  – parece que vai parar antes, e entra no vencedor por poucos pixels
    // O movimento é sempre só para frente: o ponteiro nunca passa do vencedor e volta,
    // para não parecer que o resultado foi trocado no fim.
    function buildPlan(draw, pool, winnerTicket) {
        const rng = mulberry32(seedFrom(String(draw.id)));
        const roll = rng();
        const variant = roll < 0.35 ? "crawl" : roll < 0.65 ? "stays" : "creeps";

        const count = 96;
        const winnerIndex = 66 + Math.floor(rng() * 8);
        const others = pool.filter((ticket) =>
            !(String(ticket.ticket_number) === String(winnerTicket.ticket_number) &&
              String(ticket.twitch_id) === String(winnerTicket.twitch_id)));
        const source = others.length > 0 ? others : [winnerTicket];

        const cards = [];
        for (let i = 0; i < count; i++) {
            if (i === winnerIndex) {
                cards.push(winnerTicket);
                continue;
            }
            let pick = source[Math.floor(rng() * source.length)];
            // Vizinhos do vencedor: de preferência outras pessoas, para o "quase" ter graça
            if (Math.abs(i - winnerIndex) === 1) {
                for (let tries = 0; tries < 12 && String(pick.twitch_id) === String(winnerTicket.twitch_id); tries++) {
                    pick = source[Math.floor(rng() * source.length)];
                }
            }
            // Evita o mesmo nome em sequência quando houver opção
            const previous = cards[i - 1];
            for (let tries = 0; tries < 4 && previous && source.length > 1 && String(pick.twitch_id) === String(previous.twitch_id); tries++) {
                pick = source[Math.floor(rng() * source.length)];
            }
            cards.push(pick);
        }

        return {
            variant,
            cards,
            winnerIndex,
            r: [rng(), rng(), rng(), rng()]
        };
    }

    // Movimento: fase principal (desaceleração contínua) + fase de drama, com a velocidade
    // contínua na emenda. Duração total fixa (SPIN_MS) para bater com o prazo do servidor.
    function buildMotion(plan, geometry) {
        const { cardWidth, stride } = geometry;
        const r = plan.r;
        const winnerStart = plan.winnerIndex * stride;
        const s0 = (2 + r[0] * 0.8) * stride;

        let T2;
        let p2;
        let d2;
        let finalOffset;

        if (plan.variant === "crawl") {
            T2 = 3300; p2 = 2; d2 = 1.45 * stride;
            finalOffset = (0.25 + r[1] * 0.5) * cardWidth;
        } else if (plan.variant === "stays") {
            T2 = 4300; p2 = 2; d2 = 1.15 * stride;
            finalOffset = (0.93 + r[1] * 0.045) * cardWidth;
        } else {
            T2 = 4600; p2 = 3; d2 = 1.35 * stride;
            finalOffset = 2 + r[1] * 3;
        }

        // Para sempre dentro do card vencedor, sem nunca encostar no próximo
        finalOffset = Math.min(finalOffset, cardWidth - 2);
        const finalPosition = winnerStart + finalOffset;
        const T1 = SPIN_MS - T2;
        const D1 = finalPosition - d2 - s0;
        const p1 = 3;
        const v0 = (p2 + 1) * d2 / T2;
        const vmax = Math.max(v0, (D1 / T1 - v0) * (p1 + 1) + v0);
        const mainCoef = (vmax - v0) * T1 / (p1 + 1);
        const junction = s0 + D1;
        const dramaCoef = v0 * T2 / (p2 + 1);

        function position(t) {
            if (t <= 0) return s0;
            if (t < T1) {
                const u = t / T1;
                return s0 + v0 * t + mainCoef * (1 - Math.pow(1 - u, p1 + 1));
            }
            if (t < T1 + T2) {
                const w = (t - T1) / T2;
                return Math.min(finalPosition, junction + dramaCoef * (1 - Math.pow(1 - w, p2 + 1)));
            }
            return finalPosition;
        }

        return { position, dramaStart: T1, stride };
    }

    // ---------- Giro ----------
    function winnerTicketFrom(data) {
        const draw = data.currentDraw;
        const winner = data.winner || {};
        return {
            ticket_number: draw.winning_ticket_number,
            twitch_id: draw.winner_twitch_id,
            display_name: winner.display_name || winner.twitch_login || "Vencedor",
            profile_image_url: winner.profile_image_url || ""
        };
    }

    function startSpin(data, elapsed) {
        const draw = data.currentDraw;
        const winnerTicket = winnerTicketFrom(data);
        const plan = buildPlan(draw, data.ticketPool || [], winnerTicket);

        els.track.replaceChildren();
        els.caseEmpty.hidden = true;
        const cardEls = plan.cards.map((ticket) => {
            const card = makeTicketCard(ticket);
            els.track.appendChild(card);
            return card;
        });

        const motion = buildMotion(plan, trackGeometry());

        spin = {
            drawId: draw.id,
            drawnAt: new Date(draw.drawn_at).getTime(),
            motion,
            winnerCard: cardEls[plan.winnerIndex],
            winnerTicket,
            lastIndex: -1,
            finished: false
        };

        setCaption(elapsed < motion.dramaStart ? (IS_CHAT ? "OS NOMES ESTÃO GIRANDO..." : "OS TICKETS ESTÃO GIRANDO...") : "SERÁ QUE...?", elapsed < motion.dramaStart ? "" : "drama");
        requestAnimationFrame(spinFrame);
    }

    function spinFrame() {
        if (!spin || spin.finished) return;

        const t = serverNow() - spin.drawnAt;
        const s = spin.motion.position(Math.min(t, SPIN_MS));
        const pointerX = els.caseWindow.clientWidth / 2;
        els.track.style.transform = "translateX(" + (pointerX - s).toFixed(2) + "px)";

        const index = Math.floor(s / spin.motion.stride);
        if (index !== spin.lastIndex) {
            if (spin.lastIndex !== -1) playTick(t > spin.motion.dramaStart);
            spin.lastIndex = index;
        }

        if (t >= spin.motion.dramaStart && !els.caption.classList.contains("is-drama") && t < SPIN_MS) {
            setCaption("SERÁ QUE...?", "drama");
        }

        if (t >= SPIN_MS + REVEAL_DELAY_MS) {
            finishSpin(t);
            return;
        }

        requestAnimationFrame(spinFrame);
    }

    function finishSpin(t) {
        spin.finished = true;
        spin.winnerCard.classList.add("is-winner");
        setCaption("🏆 " + ENTRY_LABEL + spin.winnerTicket.ticket_number + " — " + spin.winnerTicket.display_name, "winner");

        if (t - SPIN_MS < CELEBRATION_MS && celebratedDrawId !== spin.drawId) {
            celebratedDrawId = spin.drawId;
            celebrate(spin.winnerTicket);
        }

        if (state) render(state);
    }

    function showStaticWinner(data) {
        const winnerTicket = winnerTicketFrom(data);
        els.track.replaceChildren();
        els.caseEmpty.hidden = true;
        const card = makeTicketCard(winnerTicket);
        card.classList.add("is-winner");
        els.track.appendChild(card);
        const { cardWidth } = trackGeometry();
        els.track.style.transform = "translateX(" + (els.caseWindow.clientWidth / 2 - cardWidth / 2) + "px)";
        setCaption("🏆 " + ENTRY_LABEL + winnerTicket.ticket_number + " — " + winnerTicket.display_name, "winner");
        spin = { drawId: data.currentDraw.id, finished: true, winnerTicket };
    }

    function showIdleStrip(data) {
        const pool = data.ticketPool || [];
        const signature = pool.length + ":" + (pool[0] ? pool[0].ticket_number : "") + ":" + data.giveaway.status;
        if (signature === idleSignature && els.track.childElementCount > 0) return;
        idleSignature = signature;

        els.track.replaceChildren();
        if (pool.length === 0) {
            els.caseEmpty.hidden = false;
            setCaption(IS_CHAT ? "Ninguém se inscreveu." : "Nenhum ticket neste sorteio.", "");
            return;
        }

        els.caseEmpty.hidden = true;
        const rng = mulberry32(seedFrom(String(GIVEAWAY_ID)));
        for (let i = 0; i < 14; i++) {
            els.track.appendChild(makeTicketCard(pool[Math.floor(rng() * pool.length)]));
        }
        const { stride, cardWidth } = trackGeometry();
        els.track.style.transform = "translateX(" + (els.caseWindow.clientWidth / 2 - (6 * stride + cardWidth / 2)) + "px)";
        setCaption("Aguardando o giro...", "");
    }

    function handleDraw(data) {
        const draw = data.currentDraw;

        if (!draw) {
            spin = null;
            animatedDrawId = null;
            showIdleStrip(data);
            return;
        }

        if (animatedDrawId === draw.id) return;
        animatedDrawId = draw.id;
        idleSignature = "";

        const elapsed = serverNow() - new Date(draw.drawn_at).getTime();

        if (elapsed < SPIN_MS + REVEAL_DELAY_MS) {
            startSpin(data, Math.max(0, elapsed));
        } else {
            showStaticWinner(data);
            if (elapsed - SPIN_MS < CELEBRATION_MS && celebratedDrawId !== draw.id) {
                celebratedDrawId = draw.id;
                celebrate(winnerTicketFrom(data));
            }
        }
    }

    function isRevealed(draw) {
        if (!draw) return false;
        return serverNow() - new Date(draw.drawn_at).getTime() >= SPIN_MS + REVEAL_DELAY_MS;
    }

    // ---------- Celebração ----------
    let celebrationTimer = null;

    function celebrate(winnerTicket) {
        els.celebrationName.textContent = winnerTicket.display_name;
        els.celebrationTicket.textContent = ENTRY_LABEL + winnerTicket.ticket_number;
        const avatar = avatarElement("celebration-avatar", winnerTicket.profile_image_url, winnerTicket.display_name);
        avatar.id = "celebrationAvatar";
        els.celebrationAvatar.replaceWith(avatar);
        els.celebrationAvatar = avatar;

        els.celebration.hidden = false;
        requestAnimationFrame(() => els.celebration.classList.add("is-visible"));
        clearTimeout(celebrationTimer);
        celebrationTimer = setTimeout(() => {
            els.celebration.classList.remove("is-visible");
            setTimeout(() => { els.celebration.hidden = true; }, 500);
        }, 6200);

        playFanfare();
        launchFireworks(CELEBRATION_MS);
    }

    // Fogos em canvas, sem bibliotecas
    const COLORS = ["#f0c36b", "#ffe2a0", "#ff6b5a", "#7ee08a", "#6fb8ff", "#d68cff", "#ffffff"];
    let particles = [];
    let rockets = [];
    let fireworksUntil = 0;
    let fireworksRunning = false;
    let nextLaunch = 0;

    function resizeCanvas() {
        const ratio = window.devicePixelRatio || 1;
        els.canvas.width = window.innerWidth * ratio;
        els.canvas.height = window.innerHeight * ratio;
        els.canvas.getContext("2d").setTransform(ratio, 0, 0, ratio, 0, 0);
    }

    function launchRocket() {
        const w = window.innerWidth;
        const h = window.innerHeight;
        rockets.push({
            x: w * (0.12 + Math.random() * 0.76),
            y: h + 10,
            vx: (Math.random() - 0.5) * 2,
            vy: -(h * 0.016 + Math.random() * h * 0.006),
            color: COLORS[Math.floor(Math.random() * COLORS.length)]
        });
    }

    function explode(x, y, color) {
        const count = 70 + Math.floor(Math.random() * 40);
        const power = 3 + Math.random() * 3;
        for (let i = 0; i < count; i++) {
            const angle = (Math.PI * 2 * i) / count + Math.random() * 0.2;
            const speed = power * (0.4 + Math.random() * 0.8);
            particles.push({
                x, y,
                vx: Math.cos(angle) * speed,
                vy: Math.sin(angle) * speed,
                life: 1,
                decay: 0.011 + Math.random() * 0.012,
                color: Math.random() < 0.25 ? "#ffffff" : color,
                size: 1.6 + Math.random() * 1.8
            });
        }
        tone(90 + Math.random() * 60, 0, 0.25, "sawtooth", 0.035);
    }

    function confettiBurst() {
        const w = window.innerWidth;
        for (let i = 0; i < 160; i++) {
            particles.push({
                x: Math.random() * w,
                y: -20 - Math.random() * 200,
                vx: (Math.random() - 0.5) * 2.5,
                vy: 1.5 + Math.random() * 3,
                life: 1,
                decay: 0.004 + Math.random() * 0.004,
                color: COLORS[Math.floor(Math.random() * COLORS.length)],
                size: 3 + Math.random() * 3,
                confetti: true,
                spin: Math.random() * Math.PI
            });
        }
    }

    function launchFireworks(duration) {
        resizeCanvas();
        fireworksUntil = performance.now() + duration;
        nextLaunch = 0;
        confettiBurst();
        if (!fireworksRunning) {
            fireworksRunning = true;
            requestAnimationFrame(fireworksFrame);
        }
    }

    function fireworksFrame(now) {
        const ctx = els.canvas.getContext("2d");
        ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

        if (now < fireworksUntil && now >= nextLaunch) {
            launchRocket();
            if (Math.random() < 0.35) launchRocket();
            nextLaunch = now + 280 + Math.random() * 320;
        }

        rockets = rockets.filter((rocket) => {
            rocket.x += rocket.vx;
            rocket.y += rocket.vy;
            rocket.vy += 0.12;
            ctx.fillStyle = rocket.color;
            ctx.beginPath();
            ctx.arc(rocket.x, rocket.y, 2.4, 0, Math.PI * 2);
            ctx.fill();
            if (rocket.vy >= -0.5) {
                explode(rocket.x, rocket.y, rocket.color);
                return false;
            }
            return true;
        });

        particles = particles.filter((p) => {
            p.x += p.vx;
            p.y += p.vy;
            if (p.confetti) {
                p.vx *= 0.99;
                p.spin += 0.15;
            } else {
                p.vx *= 0.975;
                p.vy = p.vy * 0.975 + 0.06;
            }
            p.life -= p.decay;
            if (p.life <= 0) return false;

            ctx.globalAlpha = Math.max(0, p.life);
            ctx.fillStyle = p.color;
            if (p.confetti) {
                ctx.save();
                ctx.translate(p.x, p.y);
                ctx.rotate(p.spin);
                ctx.fillRect(-p.size / 2, -p.size, p.size, p.size * 2);
                ctx.restore();
            } else {
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fill();
            }
            ctx.globalAlpha = 1;
            return true;
        });

        if (now < fireworksUntil || rockets.length > 0 || particles.length > 0) {
            requestAnimationFrame(fireworksFrame);
        } else {
            fireworksRunning = false;
            ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
        }
    }

    window.addEventListener("resize", () => {
        if (fireworksRunning) resizeCanvas();
    });

    // ---------- Renderização ----------
    const STATUS_TEXT = {
        active: "SORTEIO EM ANDAMENTO",
        closed: "SORTEIO ENCERRADO",
        draft: "SORTEIO AGENDADO",
        cancelled: "SORTEIO CANCELADO"
    };

    function secondsLeft(draw) {
        return Math.max(0, Math.ceil((new Date(draw.response_deadline_at).getTime() - serverNow()) / 1000));
    }

    function renderParticipants(data) {
        const winnerIds = new Set((data.draws || []).filter(isRevealed).map((draw) => String(draw.winner_twitch_id)));
        const signature = (data.participants || []).map((p) => p.twitch_id + (p.profile_image_url ? "i" : "") + (winnerIds.has(String(p.twitch_id)) ? "*" : "")).join(",");
        if (signature === participantsSignature) return;
        participantsSignature = signature;

        els.participantsList.replaceChildren();
        if (!data.participants || data.participants.length === 0) {
            els.participantsList.textContent = IS_CHAT
                ? (data.giveaway.status === "active" ? "Ninguém se inscreveu ainda. Digite " + (data.chatCommand || "!euquero") + " no chat!" : "Ninguém se inscreveu.")
                : "Nenhum participante ainda.";
            return;
        }

        data.participants.forEach((participant) => {
            const name = participant.display_name || participant.twitch_login || "Participante";
            const item = document.createElement("div");
            item.className = "participant-item" + (winnerIds.has(String(participant.twitch_id)) ? " is-winner" : "");
            const label = document.createElement("span");
            label.className = "participant-name";
            label.textContent = (winnerIds.has(String(participant.twitch_id)) ? "🏆 " : "") + name;
            item.append(avatarElement("participant-avatar", participant.profile_image_url, name), label);
            if (IS_CHAT && participant.entry_number) {
                const number = document.createElement("span");
                number.className = "participant-number";
                number.textContent = "#" + participant.entry_number;
                item.append(number);
            }
            els.participantsList.appendChild(item);
        });
    }

    let winnersSignature = "";

    function renderWinners(data) {
        const draws = data.draws || [];
        const signature = draws.map((draw) =>
            draw.id + ":" + draw.status + ":" + isRevealed(draw) + ":" + (draw.status === "awaiting_response" ? secondsLeft(draw) : "")
        ).join("|");
        if (signature === winnersSignature && els.winnersList.childElementCount > 0) return;
        winnersSignature = signature;
        els.winnersList.replaceChildren();

        if (draws.length === 0) {
            const empty = document.createElement("p");
            empty.className = "winners-empty";
            empty.textContent = "Nenhum vencedor sorteado ainda.";
            els.winnersList.appendChild(empty);
            return;
        }

        draws.forEach((draw) => {
            const item = document.createElement("div");
            const text = document.createElement("div");
            text.className = "winner-item-text";
            const name = document.createElement("strong");
            const detail = document.createElement("span");
            const status = document.createElement("span");
            status.className = "winner-item-status";

            if (!isRevealed(draw)) {
                item.className = "winner-item is-hidden";
                name.textContent = "Girando...";
                detail.textContent = "Rodada " + draw.round_number;
                item.append(avatarElement("winner-item-avatar", "", "?"));
            } else {
                const displayName = draw.display_name || "Vencedor";
                name.textContent = displayName;
                detail.textContent = "Rodada " + draw.round_number + (IS_CHAT ? " · Inscrição #" : " · Ticket #") + draw.winning_ticket_number;

                if (draw.status === "confirmed") {
                    item.className = "winner-item is-confirmed";
                    status.textContent = "✔ CONFIRMADO";
                } else if (draw.status === "expired") {
                    item.className = "winner-item is-expired";
                    status.textContent = "✖ NÃO RESPONDEU";
                } else {
                    item.className = "winner-item is-awaiting";
                    status.textContent = "⏳ AGUARDANDO RESPOSTA · " + secondsLeft(draw) + "s";
                }
                item.append(avatarElement("winner-item-avatar", draw.profile_image_url, displayName));
            }

            text.append(name, detail);
            if (status.textContent) text.append(status);
            item.append(text);
            els.winnersList.appendChild(item);
        });
    }

    function renderChat(data) {
        const draw = data.currentDraw;
        const countdown = els.countdown;
        countdown.classList.remove("is-ok", "is-expired");
        els.chat.replaceChildren();

        const placeholder = (text) => {
            const p = document.createElement("div");
            p.className = "chat-placeholder";
            p.textContent = text;
            els.chat.appendChild(p);
        };

        if (!draw) {
            countdown.textContent = "";
            placeholder("Aguardando o vencedor...");
            return;
        }

        if (!isRevealed(draw)) {
            countdown.textContent = "";
            placeholder("Aguardando o resultado...");
            return;
        }

        if (draw.status === "awaiting_response") {
            countdown.textContent = "Tempo para responder: " + secondsLeft(draw) + "s";
        } else if (draw.status === "confirmed") {
            countdown.textContent = "✔ VENCEDOR CONFIRMOU!";
            countdown.classList.add("is-ok");
        } else if (draw.status === "expired") {
            countdown.textContent = "✖ TEMPO ESGOTADO";
            countdown.classList.add("is-expired");
        }

        if (!data.messages || data.messages.length === 0) {
            placeholder(draw.status === "expired" ? "O vencedor não respondeu a tempo." : "Aguardando a mensagem do vencedor...");
            return;
        }

        data.messages.forEach((item) => {
            const line = document.createElement("div");
            const name = document.createElement("strong");
            name.textContent = item.display_name + ": ";
            const message = document.createElement("span");
            message.textContent = item.message;
            line.append(name, message);
            els.chat.appendChild(line);
        });
        els.chat.scrollTop = els.chat.scrollHeight;
    }

    function renderControls(data) {
        if (!IS_ADMIN || !els.drawButton) return;

        const draw = data.currentDraw;
        const spinning = Boolean(draw) && !isRevealed(draw);
        const awaiting = Boolean(draw) && draw.status === "awaiting_response";

        let hint = "";
        let disabled = true;

        const allWinnersConfirmed = IS_CHAT && data.confirmedWinners >= data.giveaway.winnersCount;

        if (els.closeSignupButton) {
            els.closeSignupButton.hidden = data.giveaway.status !== "active";
            els.closeSignupButton.disabled = requestInFlight;
        }

        if (requestInFlight) {
            hint = "Aguarde...";
        } else if (IS_CHAT && data.giveaway.status === "active") {
            hint = "Aguarde o fim das inscrições para girar.";
        } else if (data.giveaway.status !== "closed") {
            hint = "Encerre o sorteio para poder girar.";
        } else if (spinning) {
            hint = "Girando...";
        } else if (awaiting) {
            hint = "Aguardando resposta do vencedor (" + secondsLeft(draw) + "s)";
        } else if (allWinnersConfirmed) {
            hint = "Todos os ganhadores confirmados!";
        } else if (data.eligibleParticipantsLeft === 0) {
            hint = "Todos os participantes já foram sorteados.";
        } else {
            disabled = false;
            hint = drawError || "";
        }

        els.drawButton.disabled = disabled;
        els.drawButton.textContent = (data.draws && data.draws.length > 0)
            ? (IS_CHAT && data.confirmedWinners > 0 && !allWinnersConfirmed ? "✦ PRÓXIMO GANHADOR ✦" : "✦ SORTEAR NOVAMENTE ✦")
            : "✦ INICIAR GIRO ✦";
        els.drawHint.textContent = hint;
        els.drawHint.classList.toggle("is-error", !disabled && Boolean(drawError));
    }

    const CHAT_STATUS_TEXT = {
        active: "INSCRIÇÕES ABERTAS",
        closed: "INSCRIÇÕES ENCERRADAS",
        cancelled: "SORTEIO CANCELADO"
    };

    function formatClock(ms) {
        const total = Math.max(0, Math.ceil(ms / 1000));
        const minutes = Math.floor(total / 60);
        const seconds = total % 60;
        return String(minutes).padStart(2, "0") + ":" + String(seconds).padStart(2, "0");
    }

    // Faixa "DIGITE !euquero" com o tempo restante (no lugar do giro enquanto as inscrições estão abertas)
    function renderSignup(data) {
        if (!IS_CHAT || !els.signupBanner) return;

        const open = data.giveaway.status === "active";
        els.signupBanner.hidden = !open;
        els.caseWindow.hidden = open;

        if (open) {
            const left = new Date(data.giveaway.endsAt).getTime() - serverNow();
            els.signupTimer.textContent = formatClock(left);
            els.signupTimer.classList.toggle("is-ending", left <= 10000);
            setCaption(left > 0 ? "Inscrições abertas" : "Encerrando inscrições...", "");
        }
    }

    function render(data) {
        els.title.textContent = data.giveaway.title;
        els.meta.textContent = (IS_CHAT ? CHAT_STATUS_TEXT : STATUS_TEXT)[data.giveaway.status] || "";
        els.meta.classList.toggle("is-active", data.giveaway.status === "active");

        els.participantCount.textContent = data.totalParticipants;
        els.ticketCount.textContent = IS_CHAT
            ? data.confirmedWinners + "/" + data.giveaway.winnersCount
            : data.totalTickets;
        if (els.totalTickets) els.totalTickets.textContent = data.totalTickets;
        if (els.totalParticipants) els.totalParticipants.textContent = data.totalParticipants;
        if (els.multiplier) els.multiplier.textContent = data.subscriberMultiplier;

        renderSignup(data);

        renderParticipants(data);
        renderWinners(data);
        renderChat(data);
        renderControls(data);
    }

    // ---------- Comunicação com o servidor ----------
    async function refresh() {
        try {
            const sentAt = Date.now();
            const response = await fetch("/arena/" + encodeURIComponent(GIVEAWAY_ID) + "/state", { cache: "no-store" });
            const receivedAt = Date.now();
            if (!response.ok) throw new Error("HTTP " + response.status);
            const data = await response.json();

            const rtt = receivedAt - sentAt;
            if (typeof data.serverTime === "number" && rtt <= bestRtt + 50) {
                bestRtt = Math.min(bestRtt, rtt);
                clockOffset = data.serverTime + rtt / 2 - receivedAt;
            }

            state = data;
            handleDraw(data);
            render(data);
        } catch (error) {
            console.error("Erro ao atualizar a Arena:", error);
        }
    }

    async function requestDraw() {
        if (requestInFlight) return;
        requestInFlight = true;
        drawError = "";
        audio(); // libera o som no navegador (precisa de um clique)
        if (state) renderControls(state);

        try {
            const response = await fetch("/admin/giveaways/" + encodeURIComponent(GIVEAWAY_ID) + "/draw", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "fetch"
                },
                body: "_csrf=" + encodeURIComponent(CSRF)
            });

            let result = {};
            try { result = await response.json(); } catch (error) { result = {}; }

            if (!response.ok || !result.ok) {
                drawError = result.error || "Não foi possível sortear. Tente novamente.";
            }
        } catch (error) {
            drawError = "Falha de conexão. Tente novamente.";
        } finally {
            requestInFlight = false;
            await refresh();
        }
    }

    async function requestCloseSignup() {
        if (requestInFlight) return;
        if (!window.confirm("Encerrar as inscrições agora?")) return;
        requestInFlight = true;
        drawError = "";

        try {
            const response = await fetch("/admin/sorteio-chat/" + encodeURIComponent(GIVEAWAY_ID) + "/encerrar", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "fetch"
                },
                body: "_csrf=" + encodeURIComponent(CSRF)
            });
            if (!response.ok) drawError = "Não foi possível encerrar as inscrições.";
        } catch (error) {
            drawError = "Falha de conexão. Tente novamente.";
        } finally {
            requestInFlight = false;
            await refresh();
        }
    }

    if (IS_ADMIN && els.drawButton) {
        els.drawButton.addEventListener("click", requestDraw);
    }

    if (IS_ADMIN && els.closeSignupButton) {
        els.closeSignupButton.addEventListener("click", requestCloseSignup);
    }

    refresh();
    setInterval(refresh, 1000);
    // Contadores mais suaves entre uma consulta e outra
    setInterval(() => { if (state) { renderWinners(state); renderControls(state); renderSignup(state); } }, 250);
})();
