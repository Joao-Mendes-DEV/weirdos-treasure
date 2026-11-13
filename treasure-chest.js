// Baú de tesouros em pixel art (arte original, estilo RPG 2D clássico).
// Uso: const svg = buildTreasureChestSvg();  -> string <svg>...</svg> para colocar no HTML.

const PALETTE = {
    K: "#1a0f08", w: "#5a3718", W: "#8a5a2b", L: "#b07a3c", d: "#3a2210",
    i: "#24150a", B: "#b8861b", b: "#e8c04a", G: "#f2c53d", g: "#9c6f14",
    Y: "#fff2a8", R: "#d63a3a", r: "#8f1f1f", E: "#3fbf6a", e: "#1f7a3e",
    S: "#4a8fe0", s: "#2a5a9a", z: "#000000"
};

function buildTreasureChestGrid() {
    const W = 32, H = 28;
    const grid = Array.from({ length: H }, () => Array(W).fill("."));
    const px = (x, y, c) => { if (x >= 0 && x < W && y >= 0 && y < H) grid[y][x] = c; };
    const rect = (x, y, w, h, c) => { for (let j = y; j < y + h; j++) for (let i = x; i < x + w; i++) px(i, j, c); };
    const box = (x, y, w, h, line, fill) => { rect(x, y, w, h, line); rect(x + 1, y + 1, w - 2, h - 2, fill); };

    // sombra no chão
    rect(5, 26, 22, 1, "z");
    rect(8, 27, 16, 1, "z");

    // tampa aberta (parte de trás)
    box(6, 1, 20, 10, "K", "w");
    for (const x of [11, 16, 21]) rect(x, 2, 1, 8, "d");
    rect(8, 2, 2, 8, "B"); rect(8, 2, 1, 8, "b");
    rect(22, 2, 2, 8, "B"); rect(22, 2, 1, 8, "b");
    rect(7, 2, 18, 1, "W");

    // interior do baú
    rect(4, 10, 24, 4, "i");

    // pilha de ouro
    const pile = [[5, 13, 6], [6, 11, 10], [7, 9, 14], [8, 7, 18], [9, 6, 20], [10, 5, 22], [11, 4, 24], [12, 4, 24]];
    for (const [y, x0, w] of pile) {
        rect(x0, y, w, 1, "G");
        px(x0, y, "g"); px(x0 + w - 1, y, "g");
    }
    rect(13, 5, 6, 1, "g");
    for (const [y, x0, w] of pile) {
        for (let x = x0 + 1; x < x0 + w - 1; x++) {
            if ((x * 7 + y * 13) % 11 === 0) px(x, y, "Y");
            else if ((x * 5 + y * 3) % 7 === 0) px(x, y, "g");
        }
    }

    // moedas em destaque
    for (const [x, y] of [[10, 7], [20, 8], [14, 6], [8, 10], [24, 10], [17, 11]]) {
        rect(x, y, 2, 1, "Y"); px(x, y + 1, "g");
    }

    // gemas
    rect(11, 8, 2, 2, "R"); px(11, 9, "r"); px(12, 9, "r");
    rect(19, 8, 2, 2, "E"); px(19, 9, "e"); px(20, 9, "e");
    rect(15, 9, 2, 2, "S"); px(15, 10, "s"); px(16, 10, "s");
    px(11, 8, "Y"); px(19, 8, "Y"); px(15, 9, "Y");

    // brilhos
    for (const [x, y] of [[3, 4], [28, 6], [24, 3]]) {
        px(x, y, "Y"); px(x - 1, y, "Y"); px(x + 1, y, "Y"); px(x, y - 1, "Y"); px(x, y + 1, "Y");
    }

    // frente do baú
    box(3, 13, 26, 13, "K", "W");
    rect(4, 14, 24, 2, "B"); rect(4, 14, 24, 1, "b");
    rect(4, 17, 24, 1, "L");
    rect(4, 20, 24, 1, "d");
    rect(4, 23, 24, 2, "w");
    rect(7, 16, 2, 9, "B"); rect(7, 16, 1, 9, "b");
    rect(23, 16, 2, 9, "B"); rect(23, 16, 1, 9, "b");

    // fechadura
    box(13, 16, 6, 7, "K", "G");
    rect(14, 17, 1, 5, "Y");
    rect(15, 18, 2, 2, "K"); px(15, 20, "K"); px(16, 20, "K");

    // rebites e pés
    for (const [x, y] of [[5, 15], [26, 15], [5, 24], [26, 24]]) px(x, y, "Y");
    rect(3, 25, 4, 1, "K"); rect(25, 25, 4, 1, "K");

    // moedas caídas
    px(1, 25, "G"); px(2, 25, "g"); px(1, 24, "Y");
    px(29, 25, "G"); px(30, 25, "Y"); px(30, 24, "g");

    return { grid, W, H };
}

function buildTreasureChestSvg(className = "treasure-chest") {
    const { grid, W, H } = buildTreasureChestGrid();
    let rects = "";

    grid.forEach((row, y) => {
        let x = 0;

        while (x < W) {
            const color = row[x];
            let length = 1;

            while (x + length < W && row[x + length] === color) length++;

            if (color !== ".") {
                const opacity = color === "z" ? ' fill-opacity="0.3"' : "";
                rects += `<rect x="${x}" y="${y}" width="${length}" height="1" fill="${PALETTE[color]}"${opacity}/>`;
            }

            x += length;
        }
    });

    return `<svg class="${className}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" shape-rendering="crispEdges" role="img" aria-label="Baú de tesouros">${rects}</svg>`;
}

module.exports = { buildTreasureChestSvg };
