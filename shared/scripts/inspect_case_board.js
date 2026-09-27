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
    const ws = new WebSocket(wsUrl);
    ws.addEventListener('open', () => ws.send(JSON.stringify({
      id: 1,
      method: 'Runtime.evaluate',
      params: { expression, returnByValue: true },
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
  const targets = await getJson('http://127.0.0.1:9222/json/list');
  const page = targets.find((target) => target.type === 'page' && target.url.includes('/app/'));
  if (!page) throw new Error('Case board page not found');
  const result = await evaluate(page.webSocketDebuggerUrl, `JSON.stringify({
    text: document.body.innerText,
    inputs: [...document.querySelectorAll('input')].map((x, i) => ({i, placeholder:x.placeholder, value:x.value})),
    buttons: [...document.querySelectorAll('button')].map((x, i) => ({i, text:x.innerText, disabled:x.disabled}))
  }, null, 2)`);
  console.log(result);
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
