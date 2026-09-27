'use strict';

const http = require('http');

function getJson(url) {
  return new Promise((resolve, reject) => http.get(url, (response) => {
    let body = '';
    response.on('data', (chunk) => { body += chunk; });
    response.on('end', () => resolve(JSON.parse(body)));
  }).on('error', reject));
}

function evaluate(wsUrl, expression) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(wsUrl);
    socket.addEventListener('open', () => socket.send(JSON.stringify({
      id: 1,
      method: 'Runtime.evaluate',
      params: { expression, awaitPromise: true, returnByValue: true },
    })));
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== 1) return;
      socket.close();
      if (message.error) reject(new Error(message.error.message));
      else if (message.result.exceptionDetails) reject(new Error(message.result.exceptionDetails.exception.description));
      else resolve(message.result.result.value);
    });
    socket.addEventListener('error', reject);
  });
}

(async () => {
  const targets = await getJson('http://127.0.0.1:9222/json/list');
  const page = targets.find((target) => target.type === 'page' && target.url.includes('/implant/'))
    || targets.find((target) => target.type === 'page' && target.url.includes('/app/'));
  if (!page) throw new Error('Authenticated challenge page not found');
  const payload = {
    handover: '4e01be292ac76974380fe751574304c936320bfb932b6af6b00d6337bcc5ce86',
    owner: 2419674196,
    generation: 3850136661,
    token: 'a648b8e3fbb05b5a70572e5cae51ec92',
  };
  const expression = `(async () => {
    const response = await fetch('/implant/auth', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(${JSON.stringify(payload)}),
    });
    return {status: response.status, body: await response.text()};
  })()`;
  const result = await evaluate(page.webSocketDebuggerUrl, expression);
  console.log(JSON.stringify(result, null, 2));
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
