FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
# Create sample static assets
RUN mkdir -p public/protected && \
    printf '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="#0066cc"/><text x="50" y="55" text-anchor="middle" fill="white" font-size="20">OX</text></svg>\n' > public/logo.svg && \
    printf 'body { font-family: sans-serif; background: #f0f4f8; color: #333; }\n' > public/styles.css && \
    printf 'console.log("Oxigate example app loaded");\n' > public/app.js && \
    printf '<!DOCTYPE html><html><head><title>Oxigate</title><link rel="stylesheet" href="/static/styles.css"></head><body><h1>Welcome to Oxigate</h1><p>The gateway is running.</p><a href="/api/users">API users</a></body></html>\n' > public/index.html && \
    printf '<!DOCTYPE html><html><head><title>Dashboard</title><link rel="stylesheet" href="/static/styles.css"></head><body><h1>Dashboard</h1><p>This is a protected page.</p></body></html>\n' > public/protected/dashboard.html && \
    printf '<!DOCTYPE html><html><head><title>Profile</title><link rel="stylesheet" href="/static/styles.css"></head><body><h1>Profile</h1><p>Your profile page.</p></body></html>\n' > public/protected/profile.html
EXPOSE 9000
CMD ["node", "server.js"]
