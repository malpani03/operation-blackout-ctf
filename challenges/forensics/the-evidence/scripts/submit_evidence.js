const http = require('http');

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve(JSON.parse(body)));
    }).on('error', reject);
  });
}

function evaluate(wsUrl, expression) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    ws.addEventListener('open', () => ws.send(JSON.stringify({
      id: 1,
      method: 'Runtime.evaluate',
      params: { expression, awaitPromise: true, returnByValue: true },
    })));
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== 1) return;
      ws.close();
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result.result.value);
    });
    ws.addEventListener('error', reject);
  });
}

(async () => {
  const evidence = {
    handover: '7f742f77f5d76059453a4b3e0b99e37628258eba8216d17a125da4676cc4544a',
    source: '10.27.4.18',
    task: 'db06efd5a7549b9e',
    exported_utc: '2026-09-27T08:42:11Z',
    document_sha256: '4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de',
  };
  const targets = await getJson('http://127.0.0.1:9222/json/list');
  const page = targets.find((target) => target.type === 'page' && target.url.startsWith('https://ctf.roshancodes.com/'));
  if (!page) throw new Error('Authenticated CTF page target not found');
  const expression = `fetch('/evidence/verify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(${JSON.stringify(evidence)})
  }).then(async r => ({status:r.status, body:await r.text()}))`;
  const result = await evaluate(page.webSocketDebuggerUrl, expression);
  console.log('HTTP', result.status);
  console.log(result.body);
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
