import express from 'express';

const app  = express();
const PORT = 8080;

app.use(express.json());

// ── Request logger ────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(JSON.stringify({
    ts:                   new Date().toISOString(),
    method:               req.method,
    path:                 req.path,
    'x-api-key':          req.headers['x-api-key']          ?? null,
    'x-id-token':         req.headers['x-id-token']         ?? null,
    'x-forwarded-prefix': req.headers['x-forwarded-prefix'] ?? null,
    authorization:        req.headers['authorization']       ?? null,
    cookie:               req.headers['cookie']              ?? null,
  }));
  next();
});

// ── Add X-Internal-Server to every response ───────────────────────────────────
// (Oxigate is configured to strip this header before forwarding to the client)
app.use((_req, res, next) => {
  res.setHeader('X-Internal-Server', 'backend-v1');
  next();
});

// ── Health check ─────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'backend', timestamp: new Date().toISOString() });
});

// ── Root (receives requests when strip_prefix removes /api) ──────────────────
app.get('/', (_req, res) => {
  res.json({ message: 'backend root', timestamp: new Date().toISOString() });
});

// ── Users ─────────────────────────────────────────────────────────────
app.get('/users', (_req, res) => {
  res.json([
    { id: 1, name: 'Alice Rossi', email: 'alice@example.com', role: 'admin' },
    { id: 2, name: 'Bob Verdi',   email: 'bob@example.com',   role: 'user'  },
  ]);
});

app.post('/users', (req, res) => {
  const body = req.body ?? {};
  res.status(201).json({
    ...body,
    id:         Math.floor(Math.random() * 9000) + 1000,
    created_at: new Date().toISOString(),
  });
});

// ── Items ─────────────────────────────────────────────────────────────
app.get('/items', (_req, res) => {
  res.json([
    { id: 'item-1', name: 'Widget Alpha', price: 9.99,  stock: 42 },
    { id: 'item-2', name: 'Gadget Beta',  price: 24.99, stock: 7  },
  ]);
});

app.put('/items/:id', (req, res) => {
  const body = req.body ?? {};
  res.json({
    id:         req.params.id,
    ...body,
    updated_at: new Date().toISOString(),
  });
});

app.delete('/items/:id', (req, res) => {
  res.json({ deleted: true, id: req.params.id });
});

// ── Start ─────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend listening on port ${PORT}`);
});
