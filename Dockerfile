# Imagem do site para o Fly.io
FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /app

# Instala só as dependências de produção (aproveita cache quando o código muda)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Código do site
COPY server.js security.js treasure-chest.js ./
COPY public ./public

# Roda sem privilégios de administrador
USER node

EXPOSE 3000
CMD ["node", "server.js"]
