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
    ws.addEventListener('open', () => ws.send(JSON.stringify({id: 1, method: 'Runtime.evaluate', params: {
      expression, awaitPromise: true, returnByValue: true,
    }})));
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== 1) return;
      ws.close();
      if (message.error) reject(new Error(message.error.message));
      else if (message.result.exceptionDetails) reject(new Error(message.result.exceptionDetails.exception.description));
      else resolve(message.result.result.value);
    });
    ws.addEventListener('error', reject);
  });
}

(async () => {
  const targets = await getJson('http://127.0.0.1:9222/json/list');
  const page = targets.find((target) => target.type === 'page' && target.url.includes('/app/'));
  if (!page) throw new Error('Case board page not found');
  const result = await evaluate(page.webSocketDebuggerUrl, `(async () => {
    const button = [...document.querySelectorAll('button')].find(x => x.innerText === 'Recover case handover');
    if (!button) throw new Error('Recover case handover button not found');
    button.click();
    await new Promise(resolve => setTimeout(resolve, 700));
    return document.body.innerText;
  })()`);
  console.log(result);
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
