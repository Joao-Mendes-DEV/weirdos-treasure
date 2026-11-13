// Minigame diário — interface. Quem confere as tentativas é o servidor.
(function () {
    "use strict";

    const body = document.body;
    if (body.dataset.loggedIn !== "1") return;

    const CSRF = body.dataset.csrf || "";
    const $ = (id) => document.getElementById(id);
    const els = {
        timer: $("mgTimer"),
        start: $("mgStart"),
        game: $("mgGame"),
        board: $("mgBoard"),
        message: $("mgMessage"),
        keyboard: $("mgKeyboard"),
        result: $("mgResult"),
        modal: $("mgLeaveModal"),
        stay: $("mgStay"),
        leave: $("mgLeave")
    };

    const KEY_ROWS = [
        ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "back"],
        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "enter"],
        ["z", "x", "c", "v", "b", "n", "m"]
    ];
    const STATUS_RANK = { r: 1, y: 2, g: 3 };

    let state = null;
    let clockOffset = 0;
    let current = ["", "", "", "", ""];
    let cursor = 0;
    const resetCurrent = () => { current = ["", "", "", "", ""]; cursor = 0; };
    let busy = false;
    let pendingHref = null;
    let leavingAllowed = false;
    let lastRenderedAttempts = 0;
    let refreshing = false;

    const isPlaying = () => Boolean(state && state.game && state.game.status === "playing");
    const serverNow = () => Date.now() + clockOffset;

    // ---------- Comunicação ----------
    async function api(path, payload) {
        const options = payload
            ? {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "fetch"
                },
                body: new URLSearchParams({ _csrf: CSRF, ...payload }).toString()
            }
            : { credentials: "same-origin", cache: "no-store" };

        const response = await fetch(path, options);
        let data = {};
        try { data = await response.json(); } catch (error) { data = {}; }
        if (typeof data.serverTime === "number") clockOffset = data.serverTime - Date.now();
        return { ok: response.ok && data.ok !== false, data };
    }

    // ---------- Tabuleiro ----------
    function buildBoard() {
        els.board.replaceChildren();
        for (let r = 0; r < 6; r++) {
            const row = document.createElement("div");
            row.className = "mg-row";
            for (let c = 0; c < 5; c++) {
                const tile = document.createElement("div");
                tile.className = "mg-tile";
                tile.addEventListener("click", () => selectTile(r, c));
                row.appendChild(tile);
            }
            els.board.appendChild(row);
        }
    }

    function buildKeyboard() {
        els.keyboard.replaceChildren();
        KEY_ROWS.forEach((keys) => {
            const row = document.createElement("div");
            row.className = "mg-key-row";
            keys.forEach((key) => {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "mg-key" + (key.length > 1 ? " is-wide" : "");
                button.dataset.key = key;
                button.textContent = key === "enter" ? "ENVIAR" : key === "back" ? "⌫" : key;
                button.setAttribute("aria-label", key === "enter" ? "Enviar" : key === "back" ? "Apagar" : key);
                button.addEventListener("click", () => handleKey(key));
                row.appendChild(button);
            });
            els.keyboard.appendChild(row);
        });
    }

    function renderBoard(animateLast) {
        const attempts = state && state.game ? state.game.attempts : [];
        const rows = els.board.children;

        for (let r = 0; r < 6; r++) {
            const tiles = rows[r].children;
            const attempt = attempts[r];

            for (let c = 0; c < 5; c++) {
                const tile = tiles[c];
                tile.className = "mg-tile";
                tile.style.animationDelay = "";

                if (attempt) {
                    tile.textContent = attempt.guess[c];
                    tile.classList.add("is-" + attempt.result[c]);
                    if (animateLast && r === attempts.length - 1) {
                        tile.classList.add("is-reveal");
                        tile.style.animationDelay = (c * 0.12) + "s";
                    }
                } else if (r === attempts.length && isPlaying()) {
                    tile.textContent = current[c] || "";
                    tile.classList.add("is-active");
                    if (current[c]) tile.classList.add("is-filled");
                    if (c === cursor) tile.classList.add("is-cursor");
                } else {
                    tile.textContent = "";
                }
            }
        }

        // Cores do teclado: vale a melhor informação de cada letra
        const best = {};
        attempts.forEach((attempt) => {
            for (let c = 0; c < 5; c++) {
                const letter = attempt.guess[c].toLowerCase();
                const status = attempt.result[c];
                if (!best[letter] || STATUS_RANK[status] > STATUS_RANK[best[letter]]) best[letter] = status;
            }
        });

        els.keyboard.querySelectorAll(".mg-key").forEach((key) => {
            key.classList.remove("is-g", "is-y", "is-r");
            if (best[key.dataset.key]) key.classList.add("is-" + best[key.dataset.key]);
        });
    }

    function shakeCurrentRow() {
        const attempts = state && state.game ? state.game.attempts.length : 0;
        const row = els.board.children[attempts];
        if (!row) return;
        row.classList.remove("is-shake");
        void row.offsetWidth;
        row.classList.add("is-shake");
    }

    function setMessage(text, isError) {
        els.message.textContent = text || "";
        els.message.classList.toggle("is-error", Boolean(isError));
    }

    // ---------- Estado na tela ----------
    function formatCountdown(ms) {
        const total = Math.max(0, Math.ceil(ms / 1000));
        const h = String(Math.floor(total / 3600)).padStart(2, "0");
        const m = String(Math.floor((total % 3600) / 60)).padStart(2, "0");
        const s = String(total % 60).padStart(2, "0");
        return h + ":" + m + ":" + s;
    }

    function renderTimer() {
        if (!state) return;

        els.timer.classList.remove("is-ready");

        if (isPlaying()) {
            els.timer.textContent = "Partida em andamento — boa sorte!";
            els.start.hidden = true;
            return;
        }

        els.start.hidden = false;

        if (state.nextAvailableAt) {
            const remaining = new Date(state.nextAvailableAt).getTime() - serverNow();

            if (remaining <= 0) {
                refresh();
                return;
            }

            els.timer.replaceChildren(
                document.createTextNode("Próxima partida em "),
                Object.assign(document.createElement("strong"), { textContent: formatCountdown(remaining) })
            );
            els.start.disabled = true;
            return;
        }

        els.timer.textContent = "Você pode jogar agora!";
        els.timer.classList.add("is-ready");
        els.start.disabled = busy;
    }

    function renderResult() {
        const game = state && state.game;
        const showResult = game && game.status !== "playing" && state.nextAvailableAt;

        els.result.hidden = !showResult;
        if (!showResult) return;

        els.result.replaceChildren();
        els.result.classList.toggle("is-lost", game.status !== "won");

        const title = document.createElement("h2");
        const lines = [];

        if (game.status === "won") {
            title.textContent = "🏆 Você acertou!";
            const points = document.createElement("p");
            points.className = "mg-points-won";
            points.textContent = "+" + game.pointsAwarded + " pontos";
            lines.push(points);

            const credit = document.createElement("p");
            credit.textContent = game.creditStatus === "credited"
                ? "Os pontos já estão no seu saldo do canal."
                : "Os pontos serão creditados no seu saldo em instantes.";
            lines.push(credit);
        } else if (game.status === "lost") {
            title.textContent = "Não foi desta vez!";
            const text = document.createElement("p");
            text.textContent = "A palavra era:";
            lines.push(text);
        } else {
            title.textContent = "Partida encerrada";
            const text = document.createElement("p");
            text.textContent = "Você saiu da página durante a partida e perdeu a chance desta rodada.";
            lines.push(text);
        }

        els.result.append(title, ...lines);

        if (game.word && game.status !== "abandoned") {
            const word = document.createElement("span");
            word.className = "mg-word";
            word.textContent = game.word;
            els.result.appendChild(word);
        }
    }

    function render(animateLast) {
        const game = state && state.game;
        const showBoard = isPlaying() || (game && game.status !== "abandoned" && state.nextAvailableAt && game.attempts.length > 0);

        els.game.hidden = !showBoard;
        if (showBoard) renderBoard(animateLast);

        renderTimer();
        renderResult();
    }

    async function refresh() {
        if (refreshing) return;
        refreshing = true;
        const { data } = await api("/minigame/estado").finally(() => { refreshing = false; });
        if (data && data.ok !== false && "canPlay" in data) {
            state = data;
            lastRenderedAttempts = state.game ? state.game.attempts.length : 0;
            render(false);
        } else {
            els.timer.textContent = (data && data.error) || "Não foi possível carregar o minigame.";
        }
    }

    // ---------- Ações ----------
    async function startGame() {
        if (busy) return;
        busy = true;
        els.start.disabled = true;
        setMessage("");

        const { ok, data } = await api("/minigame/iniciar", {});
        busy = false;

        if ("canPlay" in data) state = data;
        resetCurrent();
        lastRenderedAttempts = 0;
        render(false);

        if (!ok) {
            els.timer.textContent = data.error || "Não foi possível iniciar.";
        } else {
            setMessage("Digite uma palavra de 5 letras.");
        }
    }

    async function submitGuess() {
        if (busy || !isPlaying()) return;

        if (current.some(letter => !letter)) {
            setMessage("Preencha os 5 quadrados.", true);
            shakeCurrentRow();
            return;
        }

        busy = true;
        const { ok, data } = await api("/minigame/tentativa", { palavra: current.join("") });
        busy = false;

        if (!ok) {
            setMessage(data.error || "Não foi possível enviar.", true);
            if ("canPlay" in data) {
                state = data;
                resetCurrent();
                render(false);
            } else {
                shakeCurrentRow();
            }
            return;
        }

        state = data;
        resetCurrent();
        const grew = state.game && state.game.attempts.length > lastRenderedAttempts;
        lastRenderedAttempts = state.game ? state.game.attempts.length : 0;
        render(grew);

        if (isPlaying()) {
            const left = 6 - state.game.attempts.length;
            setMessage(left === 1 ? "Última chance!" : "Restam " + left + " tentativas.");
        } else {
            setMessage("");
        }
    }

    // Próximo quadrado vazio à direita (ou o primeiro vazio da linha)
    function nextCursor(from) {
        for (let i = from + 1; i < 5; i++) if (!current[i]) return i;
        for (let i = 0; i < 5; i++) if (!current[i]) return i;
        return Math.min(from + 1, 4);
    }

    function selectTile(row, column) {
        const attempts = state && state.game ? state.game.attempts.length : 0;
        if (!isPlaying() || busy || row !== attempts) return;
        cursor = column;
        renderBoard(false);
    }

    function handleKey(key) {
        if (!isPlaying() || busy) return;

        if (key === "enter") return submitGuess();

        if (key === "back") {
            // Apaga o quadrado selecionado; se já estiver vazio, volta um
            if (current[cursor]) {
                current[cursor] = "";
            } else if (cursor > 0) {
                cursor -= 1;
                current[cursor] = "";
            }
        } else if (key === "left") {
            cursor = Math.max(0, cursor - 1);
        } else if (key === "right") {
            cursor = Math.min(4, cursor + 1);
        } else if (/^[a-z]$/.test(key)) {
            current[cursor] = key;
            cursor = nextCursor(cursor);
        }

        setMessage("");
        renderBoard(false);
    }

    document.addEventListener("keydown", (event) => {
        if (event.ctrlKey || event.metaKey || event.altKey) return;
        if (!els.modal.hidden) return;

        const key = event.key;
        if (key === "Enter") { event.preventDefault(); handleKey("enter"); }
        else if (key === "Backspace" || key === "Delete") { event.preventDefault(); handleKey("back"); }
        else if (key === "ArrowLeft") { event.preventDefault(); handleKey("left"); }
        else if (key === "ArrowRight") { event.preventDefault(); handleKey("right"); }
        else {
            const letter = key.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
            if (/^[a-z]$/.test(letter)) handleKey(letter);
        }
    });

    // ---------- Aviso ao sair durante a partida ----------
    window.addEventListener("beforeunload", (event) => {
        if (isPlaying() && !leavingAllowed) {
            event.preventDefault();
            event.returnValue = "";
        }
    });

    document.addEventListener("click", (event) => {
        const link = event.target.closest("a[href]");
        if (!link || !isPlaying()) return;
        event.preventDefault();
        pendingHref = link.href;
        els.modal.hidden = false;
        els.stay.focus();
    });

    els.stay.addEventListener("click", () => {
        els.modal.hidden = true;
        pendingHref = null;
    });

    els.leave.addEventListener("click", () => {
        leavingAllowed = true;
        if (pendingHref) window.location.href = pendingHref;
    });

    els.start.addEventListener("click", startGame);

    buildBoard();
    buildKeyboard();
    refresh();
    setInterval(renderTimer, 1000);
})();
