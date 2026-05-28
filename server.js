const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', methods: ['POST', 'GET'], allowedHeaders: ['Content-Type'] }));
app.use(express.json({ limit: '10kb' }));

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'AuditIQ API Proxy', version: '1.0.0' });
});

app.get('/debug', (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY || 'NOT SET';
  res.json({
    keySet: !!process.env.ANTHROPIC_API_KEY,
    keyLength: key.length,
    keyStart: key.substring(0, 15),
    keyEnd: key.substring(key.length - 4),
    hasLineBreak: key.includes('\n') || key.includes('\r'),
    hasSpaces: key.includes(' '),
    nodeVersion: process.version
  });
});

app.post('/audit', async (req, res) => {
  const { systemPrompt, userMessage } = req.body;

  if (!systemPrompt || !userMessage) {
    return res.status(400).json({ error: 'Missing systemPrompt or userMessage' });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'API key not configured' });
  }

  try {
    const https = require('https');
    
    const payload = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }]
    });

    const result = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'x-api-key': apiKey.trim(),
          'anthropic-version': '2023-06-01'
        }
      };

      const req = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          resolve({ status: response.statusCode, body: data });
        });
      });

      req.on('error', reject);
      req.write(payload);
      req.end();
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
  console.log(`AuditIQ proxy running on port ${PORT}`);
});
