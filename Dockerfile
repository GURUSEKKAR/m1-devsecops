FROM node:18-alpine
WORKDIR /app
COPY src/package*.json ./
RUN npm install --production
COPY src/ .
EXPOSE 8080
CMD ["node", "index.js"]
