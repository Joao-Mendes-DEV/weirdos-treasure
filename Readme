# Como colocar o Weirdo's Treasure no ar (Fly.io)

O site roda no **Fly.io** (região São Paulo), ligado 24h, com HTTPS e o seu domínio da Cloudflare.
Custo aproximado: **~US$ 2/mês** (máquina `shared-cpu-1x` com 256 MB). Confira o valor atual em <https://fly.io/pricing>.

> Faça as etapas na ordem. Se travar em qualquer uma, copie a mensagem de erro e me mande.
> Os comandos são para o **PowerShell**, dentro da pasta do projeto.

---

## Etapa 1 — Instalar o Fly e criar a conta

1. Instale o programa do Fly (`flyctl`):
   ```
   iwr https://fly.io/install.ps1 -useb | iex
   ```
2. **Feche e abra o PowerShell de novo** e confira: `fly version`
3. Crie a conta (abre o navegador): `fly auth signup`
   - Se já tiver conta: `fly auth login`
4. No painel <https://fly.io/dashboard>, em **Billing**, cadastre o cartão.

## Etapa 2 — Criar o app

```
fly apps create weirdos-treasure
```
- Se disser que o nome já existe, escolha outro (ex.: `weirdos-treasure-joao`) e troque a linha `app = "..."` no arquivo `fly.toml` pelo nome novo.

## Etapa 3 — Enviar as variáveis secretas

Isto copia o seu `.env` para o cofre do Fly (o arquivo em si não é enviado):
```
Get-Content .env | fly secrets import --stage
```
Agora troque o endereço de retorno do login para o seu domínio (troque `SEU_DOMINIO`):
```
fly secrets set --stage TWITCH_REDIRECT_URI=https://SEU_DOMINIO/auth/twitch/callback
```
Confira os nomes (os valores ficam escondidos): `fly secrets list`

## Etapa 4 — Atualizar a Twitch

1. Em <https://dev.twitch.tv/console/apps>, abra o seu aplicativo.
2. Em **OAuth Redirect URLs**, adicione `https://SEU_DOMINIO/auth/twitch/callback` e salve.

## Etapa 5 — Publicar

> **Antes: desligue o servidor do seu PC** (e o túnel `trycloudflare`, se estiver aberto).
> Dois servidores ligados ao mesmo tempo conectam duas vezes no chat da Twitch.

```
fly deploy --ha=false
```
- O `--ha=false` garante **uma única máquina** (o site precisa rodar em uma cópia só).
- Leva alguns minutos na primeira vez. No fim, confira:
  ```
  fly status
  fly logs
  ```
  O `fly status` deve mostrar **1 máquina** `started`. O log deve mostrar `Servidor iniciado em 0.0.0.0:3000` e **nenhuma** linha de "Configuração inválida".
- Teste: abra `https://NOME_DO_APP.fly.dev/vivo` — deve aparecer `ok`.

## Etapa 6 — Ligar o seu domínio

1. Veja os endereços do app:
   ```
   fly ips list
   ```
   - Se não aparecer um IPv4, rode `fly ips allocate-v4 --shared` (grátis).
2. Na Cloudflare, em **DNS → Records**, crie (apague registros antigos `@`/`www` do tipo A, AAAA ou CNAME, se existirem):

   | Tipo | Nome  | Conteúdo            | Proxy status |
   |------|-------|---------------------|--------------|
   | A    | `@`   | IPv4 do `fly ips list` | **DNS only** (nuvem cinza) |
   | AAAA | `@`   | IPv6 do `fly ips list` | **DNS only** (nuvem cinza) |
   | A    | `www` | IPv4 do `fly ips list` | **DNS only** (nuvem cinza) |
   | AAAA | `www` | IPv6 do `fly ips list` | **DNS only** (nuvem cinza) |

   > A nuvem precisa ficar **cinza**: o próprio Fly emite o certificado HTTPS, e assim o site enxerga o IP real de cada visitante (usado nos limites contra abuso).
3. Peça os certificados HTTPS:
   ```
   fly certs add SEU_DOMINIO
   fly certs add www.SEU_DOMINIO
   ```
4. Espere ficar pronto (pode levar alguns minutos):
   ```
   fly certs show SEU_DOMINIO
   ```
   Quando aparecer **Status = Issued**, está pronto.

## Etapa 7 — Testar

1. Abra `https://SEU_DOMINIO` e entre com a Twitch.
2. **Painel → Sorteios**: o cartão "Canal da Twitch" deve estar verde (os tokens já estão no banco). Se não estiver, clique em **Conectar canal**.
3. Abra `https://SEU_DOMINIO/saude` — deve mostrar `"ok":true`.
4. Faça uma compra pequena e confira em "Meus tickets".
5. No OBS, troque o endereço da Arena para `https://SEU_DOMINIO/arena/ID_DO_SORTEIO`.

---

## Depois de publicado

**Atualizar o site** (quando eu mudar algo no código):
```
fly deploy
git add . ; git commit -m "descrição" ; git push
```

**Ver o log ao vivo:** `fly logs` (sair com `Ctrl+C`)

**Reiniciar:** `fly apps restart NOME_DO_APP`

**Trocar uma variável secreta:** `fly secrets set NOME=valor` (o site reinicia sozinho)

**Aviso quando o site cair (grátis)**
1. Crie uma conta em <https://uptimerobot.com>.
2. **Add New Monitor** → tipo **HTTP(s)** → URL `https://SEU_DOMINIO/saude` → intervalo de 5 minutos.
3. Escolha como quer ser avisado (e-mail ou app no celular).

O endereço `/saude` responde "ok" quando o banco e o chat da Twitch estão funcionando. Se o chat cair, o site tenta se reconectar sozinho; o aviso só chega se o problema continuar.

**Backup do banco** — no seu PC, uma vez por semana:
```
npm run backup
```
Salva em `backups/` (nunca vai para o GitHub). Ficam os 8 mais recentes.

**Observações**
- Acompanhe a fatura em <https://fly.io/dashboard> → Billing nos primeiros meses.
- Se o log mostrar falta de memória (`out of memory`), aumente: `fly scale memory 512` (custa um pouco mais).
- O plano grátis do Supabase pausa projetos parados por 7 dias; com o site ligado isso não acontece.
