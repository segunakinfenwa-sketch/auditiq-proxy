const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['POST', 'GET'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '10kb' }));

// ── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'AuditIQ API Proxy',
    version: '1.0.0'
  });
});

// ── DEBUG ENDPOINT (temporary) ───────────────────────────────────────────────
app.get('/debug', (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY || 'NOT SET';
  res.json({
    keySet: !!process.env.ANTHROPIC_API_KEY,
    keyLength: key.length,
    keyStart: key.substring(0, 12),
    keyEnd: key.substring(key.length - 4),
    hasLineBreak: key.includes('\n') || key.includes('\r'),
    hasSpaces: key.includes(' ')
  });
});

// ── PROXY ENDPOINT ────────────────────────────────────────────────────────────
app.post('/audit', async (req, res) => {
  const { systemPrompt, userMessage } = req.body;

  // Basic validation
  if (!systemPrompt || !userMessage) {
    return res.status(400).json({ error: 'Missing systemPrompt or userMessage' });
  }

  if (typeof systemPrompt !== 'string' || typeof userMessage !== 'string') {
    return res.status(400).json({ error: 'Invalid input types' });
  }

  if (userMessage.length > 500) {
    return res.status(400).json({ error: 'URL too long' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4000,
        system: systemPrompt,
        messages: [{ role: 'user', content: userMessage }]
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('Anthropic API error:', response.status, errText);
      // Return full error details for debugging
      return res.status(502).json({ 
        error: 'AI service error', 
        status: response.status,
        detail: errText,
        keyUsed: process.env.ANTHROPIC_API_KEY ? process.env.ANTHROPIC_API_KEY.substring(0,15) + '...' : 'NOT SET'
      });
    }

    const data = await response.json();
    return res.json(data);

  } catch (err) {
    console.error('Proxy error:', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`AuditIQ proxy running on port ${PORT}`);
});
