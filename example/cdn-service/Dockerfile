FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
COPY views/ views/
COPY public/ public/
# Create the SVG logo (only asset not in source)
RUN printf '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="#0066cc"/><text x="50" y="55" text-anchor="middle" fill="white" font-size="20" font-weight="bold">OX</text></svg>\n' > public/logo.svg
EXPOSE 9000
CMD ["node", "server.js"]
