// api/callback.js
// Discord odsyła tu użytkownika po autoryzacji z kodem
// Wymieniamy kod na token, sprawdzamy rolę i ustawiamy cookie

export default async function handler(req, res) {
  const { code } = req.query;

  if (!code) {
    return res.redirect('/vip?error=no_code');
  }

  try {
    // 1. Wymień kod na access token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://rejeen.xyz/api/callback',
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) {
      return res.redirect('/vip?error=token_failed');
    }

    // 2. Pobierz dane członka serwera (wraz z rolami)
    const memberRes = await fetch(
      `https://discord.com/api/users/@me/guilds/${process.env.DISCORD_GUILD_ID}/member`,
      {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      }
    );

    if (!memberRes.ok) {
      // Nie jest na serwerze
      return res.redirect('/vip?error=not_member');
    }

    const member = await memberRes.json();

    // 3. Sprawdź czy ma rolę "comet"
    const hasRole = member.roles.includes(process.env.DISCORD_ROLE_ID);

    if (!hasRole) {
      return res.redirect('/vip?error=no_role');
    }

    // 4. Pobierz nazwę użytkownika
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userRes.json();

    // 5. Ustaw cookie z tokenem sesji (prosty base64 — wystarczy dla tego zastosowania)
    const sessionData = Buffer.from(
      JSON.stringify({
        username: user.username,
        avatar: user.avatar,
        id: user.id,
        verified: true,
        expires: Date.now() + 1000 * 60 * 60 * 24, // 24h
      })
    ).toString('base64');

    // Podpisz prosty HMAC żeby nikt nie sfałszował cookie
    const secret = process.env.SESSION_SECRET || 'fallback_secret';
    const hmac = await signHmac(sessionData, secret);
    const cookieValue = `${sessionData}.${hmac}`;

    res.setHeader(
      'Set-Cookie',
      `rejeen_session=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
    );

    return res.redirect('/vip');
  } catch (err) {
    console.error('OAuth error:', err);
    return res.redirect('/vip?error=server_error');
  }
}

// Prosty HMAC-SHA256 używając Web Crypto API
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
