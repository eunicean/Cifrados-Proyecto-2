# API Express (app.js). Contexto de build: raiz del repo.
FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY app.js ./
COPY src ./src

USER node
EXPOSE 3001
CMD ["node", "app.js"]
