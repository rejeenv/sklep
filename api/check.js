// api/check.js
// Strona VIP wywołuje ten endpoint żeby sprawdzić czy sesja jest ważna
// Zwraca JSON z danymi użytkownika lub błąd 401

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  const cookie = req.headers.cookie || '';
  const match = cookie.match(/rejeen_session=([^;]+)/);

  if (!match) {
    return res.status(401).json({ ok: false, error: 'no_session' });
  }

  try {
    const [data, sig] = match[1].split('.');

    if (!data || !sig) {
      return res.status(401).json({ ok: false, error: 'invalid_cookie' });
    }

    // Weryfikuj podpis
    const secret = process.env.SESSION_SECRET || 'fallback_secret';
    const expectedSig = await signHmac(data, secret);

    if (sig !== expectedSig) {
      return res.status(401).json({ ok: false, error: 'invalid_signature' });
    }

    // Zdekoduj dane
    const session = JSON.parse(Buffer.from(data, 'base64').toString());

    // Sprawdź czy sesja nie wygasła
    if (Date.now() > session.expires) {
      return res.status(401).json({ ok: false, error: 'expired' });
    }

    return res.status(200).json({
      ok: true,
      username: session.username,
      avatar: session.avatar,
      id: session.id,
    });
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'parse_error' });
  }
}

async function signHmac(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Buffer.from(sig).toString('base64url');
}
