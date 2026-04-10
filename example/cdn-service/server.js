import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname  = dirname(fileURLToPath(import.meta.url));
const app        = express();
const PORT       = 9000;
const PUBLIC_DIR = join(__dirname, 'public');
const ASSET_LIST = ['logo.svg', 'styles.css', 'app.js'];

// ── Request logger ────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(JSON.stringify({
    ts:     new Date().toISOString(),
    method: req.method,
    path:   req.path,
  }));
  next();
});

// ── Add X-Internal-Server to every response ───────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Internal-Server', 'cdn-service-v1');
  next();
});

// ── Directory listing at /static/ ────────────────────────────────────────────
app.get('/static/', (_req, res) => {
  res.json({ files: ASSET_LIST });
});

// ── Serve static files from ./public under /static/ ──────────────────────────
app.use('/static', express.static(PUBLIC_DIR, { index: false }));


// ── Protected pages (─ /protected/<page> → /protected/<page>.html) ────────────────────
// The gateway forwards /protected/dashboard as-is; we append .html and serve
// the corresponding file from the public/ directory.
app.get('/protected/*', (req, res, next) => {
  const htmlPath = join(PUBLIC_DIR, req.path + '.html');
  res.sendFile(htmlPath, (err) => {
    if (err) next(); // fall through to 404 if file not found
  });
});

// ── 404 fallback ─────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Start ─────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`CDN service listening on port ${PORT}`);
  console.log(`Serving static assets from ${PUBLIC_DIR}`);
});
