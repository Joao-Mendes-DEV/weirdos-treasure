# Weirdo's Treasure: contexto e tarefas pendentes

## Sobre o projeto
- Site de sorteios da comunidade da Twitch **joao_weird** (RubinOT/Tibia).
- O usuário entra com a Twitch, gasta pontos do **StreamElements Loyalty** para comprar tickets, e o admin faz o sorteio.
- Depois do sorteio, o vencedor tem 10 segundos de revelação e 40 segundos para falar no chat da Twitch.
- A página **Arena** (`/arena/:id`) é uma janela usada no OBS. **Não coloque menu lateral nela.**

## Tecnologia
- Node/Express em um único arquivo `server.js`. O HTML das páginas é montado em template strings.
- Supabase (chave de serviço no `.env`), EventSub da Twitch por websocket para o chat, API do StreamElements.
- CSS em `public/css/home.css` (site) e `public/css/admin.css` (admin). Páginas públicas também têm `<style>` próprio dentro do `server.js`.
- A função `withPublicSidebar(req, html, activePath)` injeta o menu lateral nas páginas públicas.

## Regras para qualquer alteração
- Não mexer na lógica de compra de tickets e de pontos (CSRF, chave de idempotência, transações). Só a apresentação.
- Escapar todo texto vindo do banco ao montar HTML.
- Textos da interface em português do Brasil.
- Manter o visual: fonte Georgia, fundo marrom escuro e dourado
  (`#30251b`, `#211912`, `#705332`, `#d6a85c`, `#e2bd7b`, `#e8dfcf`), botões dourados com gradiente `#c99b53` → `#98703a`.
- Nunca ler nem mostrar o conteúdo do `.env`.
- Depois de cada tarefa: rodar o servidor, abrir no computador e no celular (largura 390px) e conferir.

## Já implementado (não refazer)
- Menu lateral nas páginas públicas e no admin (no celular vira barra no topo).
- Foto da Twitch ao lado do "Início" no menu do topo (celular); botão "Entrar com Twitch" quando deslogado.
- Home com o bloco de regras (acumular pontos assistindo à live, seguir o canal, estar online para responder no chat).
- Minha conta: saldo de pontos no cabeçalho, foto e usuário à direita, e o sorteio ativo com os tickets do usuário nele.
- Admin: gráficos diários (usuários, tickets, pontos) e `admin.css` no visual do site.
- Chat do vencedor registrando várias mensagens.

## Tarefas pendentes

### 1. Minha conta
Remover o card "Painel Administrativo" que aparece ao lado de "Meus Tickets". O link continua no menu lateral.

### 2. Página inicial (`/`)
a. Trocar o título "REGRAS DO SORTEIO" por **"COMO PARTICIPAR?"** e remover a seção dos 3 cards (`.how-it-works`).

b. No banner do sorteio ativo, trocar o bloco "WEIRDO'S TREASURE – UM TESOURO AGUARDA POR VOCÊ" por uma imagem 2D em pixel art de um **baú de tesouros**, no estilo de jogos 2D clássicos (lembrando o Tibia, mas com arte original, sem usar imagens do jogo). O arquivo `treasure-chest.js` já tem o gerador: `buildTreasureChestSvg()` devolve o SVG pronto. Usar a imagem com `image-rendering: pixelated`, largura em torno de 280px e uma sombra suave.

c. Logo abaixo do sorteio ativo, mostrar os **próximos sorteios agendados** (status `draft`, `starts_at` no futuro, até 3), com o mesmo banner, selo "PRÓXIMO SORTEIO" e um botão desabilitado "EM BREVE". Sem sorteio ativo: mostrar "Nenhum sorteio ativo no momento" e os próximos logo abaixo.

d. Faixa compacta (cerca de 60px) de **"AO VIVO"** quando a live estiver online: miniatura, título, jogo e espectadores. Ao clicar, abrir `https://www.twitch.tv/joao_weird` em nova aba. Se a live estiver offline, não mostrar nada. Usar a API Helix `GET /streams` com token de aplicativo (client credentials, usando `TWITCH_CLIENT_ID` e `TWITCH_CLIENT_SECRET` do `.env`), com cache de uns 60 segundos e timeout curto para não atrasar a página.

### 3. Página de sorteios (`/giveaways`)
Reformular para ficar mais intuitiva. Cada sorteio ativo em um cartão com:
- o baú, o título, a descrição e a data de encerramento;
- **quantos tickets o usuário já tem naquele sorteio**;
- **saldo de pontos do usuário** e preço do ticket;
- seletor de quantidade com botões − e +, atalhos (1, 5, 10 e "Máx"), total da compra e saldo após a compra;
- se o saldo não bastar: botão desabilitado e aviso "faltam X pontos".

Manter os campos do formulário (`_csrf`, `idempotency_key`, `quantity`) e a rota `POST /giveaways/:id/purchase`.

### 4. Compra sem saldo
Hoje as respostas de "Saldo insuficiente" na rota `POST /giveaways/:id/purchase` (dois pontos do código) são HTML cru. Usar a mesma página `sendPurchaseResult` da compra concluída, com uma variante de erro (ícone "!" avermelhado), mostrando: sorteio, quantidade, pontos necessários, saldo atual e quantos pontos faltam.
