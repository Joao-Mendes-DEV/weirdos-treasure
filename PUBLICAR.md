# Como colocar o Weirdo's Treasure no ar

Servidor gratuito da **Oracle Cloud** + **Túnel da Cloudflare** com o seu domínio.
O site fica ligado 24h, com HTTPS, sem depender do seu PC e sem abrir portas no servidor.

> Faça as etapas na ordem. Se travar em qualquer uma, copie a mensagem de erro e me mande.

---

## Etapa 1 — Colocar o domínio na Cloudflare (grátis)

1. Crie uma conta em <https://dash.cloudflare.com/sign-up> (ou entre na sua).
2. Clique em **Add a domain / Adicionar domínio**, digite o seu domínio e escolha o plano **Free**.
3. A Cloudflare mostra **dois nameservers** (algo como `ana.ns.cloudflare.com`).
4. No site onde você comprou o domínio (ex.: Registro.br), troque os **servidores DNS** pelos dois da Cloudflare.
   - No Registro.br: *Domínio → Alterar servidores DNS*.
5. Espere a Cloudflare avisar que o domínio está **Active** (pode levar de minutos a algumas horas).
6. Em **SSL/TLS → Edge Certificates**, ligue **Always Use HTTPS**.

## Etapa 2 — Enviar o código para o GitHub (repositório privado)

1. No GitHub, crie um repositório **privado** chamado `weirdos-treasure` (sem README, sem .gitignore).
2. No seu PC, dentro da pasta do projeto:
   ```
   git init
   git add .
   git commit -m "Versão para publicação"
   git branch -M main
   git remote add origin https://github.com/SEU_USUARIO/weirdos-treasure.git
   git push -u origin main
   ```
3. Confira no GitHub que **não existe** arquivo `.env` no repositório (só o `.env.example`).

## Etapa 3 — Criar o servidor gratuito na Oracle Cloud

1. Cadastre-se em <https://www.oracle.com/cloud/free/>.
   - Pede cartão só para verificação; o plano **Always Free** não cobra.
   - **Região (Home Region)**: escolha **Brazil East (São Paulo)** ou **Brazil Southeast (Vinhedo)**. Não dá para trocar depois.
2. No painel: **Compute → Instances → Create instance**.
   - **Image**: Canonical **Ubuntu 24.04**.
   - **Shape**: *Ampere* → **VM.Standard.A1.Flex** com **1 OCPU e 6 GB** (aparece a etiqueta *Always Free-eligible*).
     - Se aparecer *Out of capacity*, tente outro *Availability domain* ou o shape **VM.Standard.E2.1.Micro** (também gratuito).
   - **SSH keys**: escolha *Generate a key pair* e **baixe a chave privada** (guarde bem esse arquivo).
3. Crie e anote o **Public IP address** da instância.

## Etapa 4 — Entrar no servidor e instalar o necessário

No PowerShell do seu PC (troque o caminho da chave e o IP):
```
ssh -i C:\caminho\da\chave.key ubuntu@IP_DO_SERVIDOR
```

Já dentro do servidor, rode:
```
sudo apt update && sudo apt upgrade -y
sudo apt install -y git unattended-upgrades

# Node.js 22 (versão estável de longo prazo)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node -v
```

## Etapa 5 — Baixar o código no servidor

1. Crie uma chave só de leitura para o servidor acessar o repositório privado:
   ```
   ssh-keygen -t ed25519 -C "servidor-weirdos" -f ~/.ssh/github -N ""
   cat ~/.ssh/github.pub
   ```
2. Copie o texto mostrado. No GitHub: repositório → **Settings → Deploy keys → Add deploy key**, cole e **não** marque *Allow write access*.
3. No servidor:
   ```
   printf "Host github.com\n  IdentityFile ~/.ssh/github\n" >> ~/.ssh/config
   git clone git@github.com:SEU_USUARIO/weirdos-treasure.git
   cd weirdos-treasure
   npm ci --omit=dev
   ```

## Etapa 6 — Criar o .env no servidor

```
cp .env.example .env
nano .env
```
- Preencha com os **mesmos valores** do `.env` do seu PC (copie e cole um por um).
- **Mude** `TWITCH_REDIRECT_URI` para `https://SEU_DOMINIO/auth/twitch/callback`.
- Deixe `NODE_ENV=production`, `PORT=3000` e `HOST=127.0.0.1`.
- **Importante:** `TWITCH_TOKEN_ENCRYPTION_KEY` tem que ser **igual** à de hoje, senão o canal conectado não funciona.
- Salve com `Ctrl+O`, `Enter`, `Ctrl+X`. Depois proteja o arquivo:
  ```
  chmod 600 .env
  ```

## Etapa 7 — Deixar o site ligado 24h

```
sudo cp deploy/weirdos-treasure.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now weirdos-treasure
journalctl -u weirdos-treasure -n 30
```
O log deve mostrar `Servidor iniciado em 127.0.0.1:3000` e **nenhuma** linha de "Configuração inválida".

> **Antes de seguir, desligue o servidor do seu PC.** Dois servidores ligados ao mesmo tempo conectam duas vezes no chat da Twitch.

## Etapa 8 — Túnel da Cloudflare (liga o domínio ao servidor)

No servidor:
```
# Instalar o cloudflared
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install -y cloudflared

# Autorizar (mostra um link: abra no navegador e escolha o seu domínio)
cloudflared tunnel login

# Criar o túnel e apontar o domínio para ele
cloudflared tunnel create weirdos-treasure
cloudflared tunnel route dns weirdos-treasure SEU_DOMINIO
cloudflared tunnel route dns weirdos-treasure www.SEU_DOMINIO
```
O comando `tunnel create` mostra um **ID** (ex.: `6ff42ae2-...`). Depois:
```
sudo mkdir -p /etc/cloudflared
sudo cp ~/.cloudflared/ID_DO_TUNEL.json /etc/cloudflared/
sudo cp deploy/cloudflared-config.yml /etc/cloudflared/config.yml
sudo nano /etc/cloudflared/config.yml     # troque TUNNEL_ID e SEU_DOMINIO
sudo cloudflared service install
sudo systemctl status cloudflared
```

## Etapa 9 — Atualizar a Twitch

1. Em <https://dev.twitch.tv/console/apps>, abra o seu aplicativo.
2. Em **OAuth Redirect URLs**, adicione `https://SEU_DOMINIO/auth/twitch/callback` e salve.
3. Pode remover o endereço antigo do `trycloudflare.com`.

## Etapa 10 — Testar

1. Abra `https://SEU_DOMINIO` e entre com a Twitch.
2. **Painel → Sorteios**: o cartão "Canal da Twitch" deve estar verde. Se não estiver, clique em **Conectar canal**.
3. Faça uma compra pequena e confira em "Meus tickets".
4. No OBS, troque o endereço da Arena para `https://SEU_DOMINIO/arena/ID_DO_SORTEIO`.

---

## Depois de publicado

**Atualizar o site** (quando eu mudar algo no código):
```
# no PC: git add . && git commit -m "descrição" && git push
# no servidor:
cd ~/weirdos-treasure && git pull && npm ci --omit=dev && sudo systemctl restart weirdos-treasure
```

**Ver o log do site:** `journalctl -u weirdos-treasure -f` (sair com `Ctrl+C`)

**Reiniciar:** `sudo systemctl restart weirdos-treasure`

**Aviso quando o site cair (grátis)**
1. Crie uma conta em <https://uptimerobot.com>.
2. **Add New Monitor** → tipo **HTTP(s)** → URL `https://SEU_DOMINIO/saude` → intervalo de 5 minutos.
3. Escolha como quer ser avisado (e-mail ou app no celular).

O endereço `/saude` responde "ok" quando o banco e o chat da Twitch estão funcionando. Se o chat cair, o site tenta se reconectar sozinho; o aviso só chega se o problema continuar.

**Backup do banco**
- No seu PC, a qualquer momento: `npm run backup` (salva em `backups/`, que nunca vai para o GitHub).
- Automático no servidor, toda segunda às 4h: rode `crontab -e` e adicione a linha
  ```
  0 4 * * 1 cd /home/ubuntu/weirdos-treasure && /usr/bin/npm run backup >> backups/backup.log 2>&1
  ```
- Ficam guardados os 8 backups mais recentes. De vez em quando, faça um backup no PC também (se o servidor sumir, os backups dele vão junto).

**Observações**
- O servidor instala atualizações de segurança do Ubuntu sozinho (`unattended-upgrades`).
- O plano grátis do Supabase pausa projetos parados por 7 dias; com o site ligado isso não acontece.
- Nenhuma porta precisa ser aberta na Oracle: o túnel sai do servidor para a Cloudflare.
