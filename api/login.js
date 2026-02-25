// api/login.js
// Przekierowuje użytkownika na stronę autoryzacji Discorda

export default function handler(req, res) {
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: 'https://rejeen.xyz/api/callback',
    response_type: 'code',
    scope: 'identify guilds.members.read',
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
}
