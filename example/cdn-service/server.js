import express from 'express';
import { engine } from 'express-handlebars';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname  = dirname(fileURLToPath(import.meta.url));
const app        = express();
const PORT       = 9000;
const PUBLIC_DIR = join(__dirname, 'public');

// ── Handlebars engine ─────────────────────────────────────────────────────────
app.engine('hbs', engine({
  helpers: {
    slice: (str, start, end) => (str ?? '').slice(start, end),
  },
  extname:        '.hbs',
  defaultLayout:  'main',
  layoutsDir:     join(__dirname, 'views', 'layouts'),
  partialsDir:    join(__dirname, 'views', 'partials'),
}));
app.set('view engine', 'hbs');
app.set('views', join(__dirname, 'views'));

// ── Static assets ─────────────────────────────────────────────────────────────
app.use('/static', express.static(PUBLIC_DIR, { index: false }));

// ── Request logger ─────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(JSON.stringify({
    ts:            new Date().toISOString(),
    method:        req.method,
    path:          req.path,
    authorization: req.headers['authorization'] ? '[present]' : null,
    'x-id-token':  req.headers['x-id-token']    ? '[present]' : null,
  }));
  next();
});

// ── Add X-Internal-Server to every response ───────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Internal-Server', 'cdn-service-v1');
  next();
});

// ── Auth context helper ───────────────────────────────────────────────────────
// The gateway injects Authorization and X-Id-Token when a session exists.
// We expose a plain object to every Handlebars template.
function authContext(req) {
  const idToken   = req.headers['x-id-token']    ?? null;
  const accessTok = req.headers['authorization'] ?? null;  // "Bearer <token>"
  const loggedIn  = !!(idToken && accessTok);

  // Decode the ID-token payload (no signature verification — CDN is internal).
  let user = null;
  if (idToken) {
    try {
      const payload = idToken.split('.')[1];
      // Pad base64url to a multiple of 4 then decode.
      const json = Buffer.from(
        payload.replace(/-/g, '+').replace(/_/g, '/'),
        'base64',
      ).toString('utf8');
      const claims = JSON.parse(json);
      user = {
        name:    claims.name  ?? claims.preferred_username ?? claims.sub ?? 'User',
        email:   claims.email ?? null,
        subject: claims.sub   ?? null,
      };
    } catch {
      // Malformed token — treat as anonymous.
    }
  }

  return { loggedIn, user };
}

// ── Root ("/") ─────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.render('index', {
    title:       'Welcome to Oxigate',
    ...authContext(req),
  });
});

// ── Protected pages ("/protected/<page>") ─────────────────────────────────────
// The gateway routes /protected/* here with pass_through, so req.path is
// e.g. "/protected/dashboard". We map that to a Handlebars view.
const PROTECTED_VIEWS = {
  '/protected/dashboard': { view: 'protected/dashboard', title: 'Dashboard' },
  '/protected/profile':   { view: 'protected/profile',   title: 'Profile'   },
};

app.get('/protected/*', (req, res, next) => {
  // Normalise: remove trailing slash
  const key = req.path.replace(/\/$/, '');
  const entry = PROTECTED_VIEWS[key];

  if (!entry) {
    return next(); // fall through to 404
  }

  const auth = authContext(req);
  if (!auth.loggedIn) {
    // Redirect unauthenticated visitors to the gateway login route.
    return res.redirect(`/auth?redirect=${encodeURIComponent(req.path)}`);
  }

  res.render(entry.view, {
    title: entry.title,
    ...auth,
  });
});

// ── 404 ────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('404', {
    title:       'Page not found',
    requestPath: req.path,
    ...authContext(req),
  });
});

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`CDN service listening on port ${PORT}`);
});
