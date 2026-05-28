const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', methods: ['POST', 'GET'], allowedHeaders: ['Content-Type'] }));
app.use(express.json({ limit: '10kb' }));

// Clean API key — strip ALL whitespace and non-printable characters
function getCleanKey() {
  const raw = process.env.ANTHROPIC_API_KEY || '';
  return raw.replace(/[^\x20-\x7E]/g, '').trim();
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'AuditIQ API Proxy', version: '2.0.0' });
});

app.get('/debug', (req, res) => {
  const raw = process.env.ANTHROPIC_API_KEY || 'NOT SET';
  const clean = getCleanKey();
  res.json({
    keySet: !!process.env.ANTHROPIC_API_KEY,
    rawLength: raw.length,
    cleanLength: clean.length,
    keyStart: clean.substring(0, 15),
    keyEnd: clean.substring(clean.length - 4),
    hasLineBreak: raw.includes('\n') || raw.includes('\r'),
    hasSpaces: raw.includes(' '),
    rawVsClean: raw.length !== clean.length ? 'DIFFERENT - had bad chars' : 'SAME - clean'
  });
});

app.post('/audit', async (req, res) => {
  const { systemPrompt, userMessage } = req.body;

  if (!systemPrompt || !userMessage) {
    return res.status(400).json({ error: 'Missing systemPrompt or userMessage' });
  }

  const apiKey = getCleanKey();

  if (!apiKey || !apiKey.startsWith('sk-ant-')) {
    return res.status(500).json({ 
      error: 'API key not configured correctly',
      keyStart: apiKey.substring(0, 10)
    });
  }

  const payload = JSON.stringify({
    model: 'claude-3-5-haiku-20241022',
    max_tokens: 4000,
    system: systemPrompt,
    messages: [{ role: 'user', content: userMessage }]
  });

  try {
    const result = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        }
      };

      const request = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => resolve({ status: response.statusCode, body: data }));
      });

      request.on('error', reject);
      request.write(payload);
      request.end();
    });

    if (result.status !== 200) {
      console.error('Anthropic error:', result.status, result.body);
      return res.status(502).json({
        error: 'AI service error',
        status: result.status,
        detail: result.body
      });
    }

    return res.json(JSON.parse(result.body));

  } catch (err) {
    console.error('Proxy error:', err.message);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`AuditIQ proxy v2 running on port ${PORT}`);
});
