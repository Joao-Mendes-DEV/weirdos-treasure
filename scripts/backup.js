// Backup do banco: salva cada tabela em JSON dentro de backups/AAAA-MM-DD_HHMM/
// Só lê o banco. Uso: npm run backup
// Mantém os 8 backups mais recentes e apaga os mais antigos.
require("dotenv").config({ quiet: true });

const fs = require("fs");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

// Sessões e tokens do canal ficam de fora (são temporários ou sensíveis)
const TABLES = [
    "users",
    "giveaways",
    "tickets",
    "transactions",
    "giveaway_draws",
    "draw_results",
    "giveaway_chat_messages",
    "audit_logs",
    "system_settings"
];

const KEEP_BACKUPS = 8;
const BACKUP_ROOT = path.join(__dirname, "..", "backups");

async function exportTable(supabase, table) {
    const rows = [];

    for (let from = 0; ; from += 1000) {
        const { data, error } = await supabase
            .from(table)
            .select("*")
            .order("id", { ascending: true })
            .range(from, from + 999);

        if (error) {
            throw new Error(`${table}: ${error.message}`);
        }

        rows.push(...(data || []));

        if (!data || data.length < 1000) break;
    }

    return rows;
}

async function main() {
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
        throw new Error("SUPABASE_URL e SUPABASE_SECRET_KEY precisam estar no .env");
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY);

    const stamp = new Date().toLocaleString("sv-SE", { timeZone: "America/Sao_Paulo" })
        .slice(0, 16)
        .replace(" ", "_")
        .replace(":", "");
    const folder = path.join(BACKUP_ROOT, stamp);

    fs.mkdirSync(folder, { recursive: true });

    for (const table of TABLES) {
        const rows = await exportTable(supabase, table);
        fs.writeFileSync(path.join(folder, `${table}.json`), JSON.stringify(rows, null, 2));
        console.log(`${table}: ${rows.length} linhas`);
    }

    // Apagar backups antigos
    const backups = fs.readdirSync(BACKUP_ROOT)
        .filter(name => fs.statSync(path.join(BACKUP_ROOT, name)).isDirectory())
        .sort();

    for (const old of backups.slice(0, Math.max(0, backups.length - KEEP_BACKUPS))) {
        fs.rmSync(path.join(BACKUP_ROOT, old), { recursive: true, force: true });
    }

    console.log(`Backup salvo em ${folder}`);
}

main().catch((error) => {
    console.error("Backup falhou:", error.message);
    process.exit(1);
});
