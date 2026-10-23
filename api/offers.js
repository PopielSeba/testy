import { createClient } from '@libsql/client';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

let client;
let tablePromise;

function database() {
  if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
    throw new Error('Database credentials are not configured');
  }
  if (!client) {
    client = createClient({
      url: process.env.TURSO_DATABASE_URL,
      authToken: process.env.TURSO_AUTH_TOKEN,
    });
  }
  return client;
}

async function ready() {
  if (!tablePromise) {
    tablePromise = database().execute(
      "CREATE TABLE IF NOT EXISTS offers (" +
      "id TEXT PRIMARY KEY, edit_hash TEXT NOT NULL, company TEXT NOT NULL, " +
      "contact TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', " +
      "payload TEXT NOT NULL, creator_hash TEXT, created_at TEXT NOT NULL, " +
      "updated_at TEXT NOT NULL, submitted_at TEXT)"
    ).catch((error) => {
      tablePromise = null;
      throw error;
    });
  }
  await tablePromise;
}

function sha(input) {
  return createHash('sha256').update(String(input)).digest('hex');
}

function equalSecret(input, configured) {
  if (!input || !configured) return false;
  const a = Buffer.from(sha(input), 'hex');
  const b = Buffer.from(sha(configured), 'hex');
  return timingSafeEqual(a, b);
}

function send(res, code, payload) {
  res.status(code).json(payload);
}

function validPayload(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
  if (data.version !== 3 || !Array.isArray(data.stages) || data.stages.length !== 4 ||
      !Array.isArray(data.rows) || data.rows.length > 400) return false;
  if (typeof data.company !== 'string' || data.company.trim().length < 2 ||
      data.company.length > 140 || typeof data.contact !== 'string' ||
      data.contact.trim().length < 3 || data.contact.length > 240) return false;
  for (const stage of data.stages) {
    if (!stage || typeof stage !== 'object' || Array.isArray(stage)) return false;
  }
  for (const row of data.rows) {
    if (!row || typeof row !== 'object' || !Number.isInteger(row.stage) ||
        row.stage < 0 || row.stage > 3 || typeof row.title !== 'string' ||
        row.title.length > 500) return false;
  }
  return JSON.stringify(data).length <= 350000;
}

function safeBody(req) {
  const len = Number(req.headers['content-length'] || 0);
  if (len > 360000) throw new Error('Oferta jest zbyt duża');
  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  if (!body || typeof body !== 'object') throw new Error('Nieprawidłowe dane');
  return body;
}

function requestIp(req) {
  const forwarded = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '';
  return String(Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',')[0].trim();
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Allow', 'GET, POST');
  if (!['GET', 'POST'].includes(req.method)) return send(res, 405, { error: 'Metoda niedozwolona' });

  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).host !== req.headers.host) {
        return send(res, 403, { error: 'Nieprawidłowe pochodzenie żądania' });
      }
    } catch {
      return send(res, 403, { error: 'Nieprawidłowe pochodzenie żądania' });
    }
  }

  try {
    await ready();
    const db = database();

    if (req.method === 'GET') {
      const id = typeof req.query.id === 'string' ? req.query.id : '';
      if (!id) {
        const adminKey = req.headers['x-admin-key'];
        if (!equalSecret(adminKey, process.env.OFFERS_ADMIN_KEY)) {
          return send(res, 401, { error: 'Brak dostępu do ofert' });
        }
        const result = await db.execute(
          'SELECT id, company, contact, status, payload, created_at, updated_at, submitted_at FROM offers ORDER BY created_at DESC LIMIT 300'
        );
        return send(res, 200, {
          offers: result.rows.map((r) => ({
            id: r.id, company: r.company, contact: r.contact, status: r.status,
            data: JSON.parse(r.payload), createdAt: r.created_at,
            updatedAt: r.updated_at, submittedAt: r.submitted_at,
          })),
        });
      }
      const editKey = req.headers['x-edit-key'];
      if (!/^[0-9a-f-]{36}$/.test(id) || typeof editKey !== 'string' ||
          !/^[A-Za-z0-9_-]{32}$/.test(editKey)) {
        return send(res, 401, { error: 'Nieprawidłowy kod dostępu' });
      }
      const result = await db.execute({
        sql: 'SELECT id, status, payload, updated_at FROM offers WHERE id = ? AND edit_hash = ?',
        args: [id, sha(editKey)],
      });
      if (!result.rows.length) return send(res, 404, { error: 'Nie znaleziono oferty lub kod jest błędny' });
      const row = result.rows[0];
      return send(res, 200, { id: row.id, status: row.status, data: JSON.parse(row.payload), updatedAt: row.updated_at });
    }

    let body;
    try { body = safeBody(req); } catch (error) {
      return send(res, 400, { error: error.message || 'Nieprawidłowe dane' });
    }
    const data = body.data;
    if (!validPayload(data)) {
      return send(res, 400, { error: 'Podaj nazwę firmy, kontakt i poprawne dane wyceny' });
    }
    const payload = JSON.stringify(data);
    const company = data.company.trim();
    const contact = data.contact.trim();
    const now = new Date().toISOString();
    const finalize = body.finalize === true;

    if (body.id || body.editKey) {
      if (typeof body.id !== 'string' || !/^[0-9a-f-]{36}$/.test(body.id) ||
          typeof body.editKey !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(body.editKey)) {
        return send(res, 400, { error: 'Nieprawidłowy kod dostępu' });
      }
      const result = await db.execute({
        sql: "UPDATE offers SET company = ?, contact = ?, payload = ?, updated_at = ?, status = ?, submitted_at = ? " +
             "WHERE id = ? AND edit_hash = ? AND status = 'draft'",
        args: [
          company, contact, payload, now, finalize ? 'submitted' : 'draft',
          finalize ? now : null, body.id, sha(body.editKey),
        ],
      });
      if (result.rowsAffected !== 1) {
        return send(res, 409, { error: 'Nie znaleziono roboczej oferty; mogła już zostać złożona' });
      }
      return send(res, 200, { id: body.id, editKey: body.editKey, status: finalize ? 'submitted' : 'draft', updatedAt: now });
    }

    // Basic per-address creation limit to reduce public form abuse.
    const ip = requestIp(req);
    const creatorHash = ip ? sha(ip + ':' + (process.env.OFFERS_ADMIN_KEY || '')) : null;
    if (creatorHash) {
      const recent = await db.execute({
        sql: "SELECT count(*) AS n FROM offers WHERE creator_hash = ? AND created_at > ?",
        args: [creatorHash, new Date(Date.now() - 3600000).toISOString()],
      });
      if (Number(recent.rows[0].n) >= 12) {
        return send(res, 429, { error: 'Za dużo nowych ofert. Spróbuj później.' });
      }
    }
    const id = randomUUID();
    const editKey = randomBytes(24).toString('base64url');
    await db.execute({
      sql: 'INSERT INTO offers (id, edit_hash, company, contact, status, payload, creator_hash, created_at, updated_at, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [id, sha(editKey), company, contact, finalize ? 'submitted' : 'draft',
        payload, creatorHash, now, now, finalize ? now : null],
    });
    return send(res, 201, { id, editKey, status: finalize ? 'submitted' : 'draft', updatedAt: now });
  } catch (error) {
    console.error('Offers API failure:', error?.message || 'unknown');
    return send(res, 503, { error: 'Zapisywanie jest chwilowo niedostępne. Dane lokalne nie zostały usunięte.' });
  }
}
