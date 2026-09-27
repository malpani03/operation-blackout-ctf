const http = require('http');

const answers = {
  welcome: '49',
  badge: '1110100011110001',
  rota: 'CBAEFD',
  helpdesk: '30186',
  voicemail: '609637',
  printq: 'AEYIOAKN',
  vending: '140',
  legacy: '01110011',
  entropy: '760422',
  iris: '011000001000101011001111110000000000',
};

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
      else if (message.result.exceptionDetails) {
        reject(new Error(message.result.exceptionDetails.exception.description));
      } else resolve(message.result.result.value);
    });
    socket.addEventListener('error', reject);
  });
}

async function main() {
  const targets = await getJson('http://127.0.0.1:9222/json/list');
  const page = targets.find((target) => target.type === 'page' && target.url.includes('/app/'));
  if (!page) throw new Error('Authenticated case-board page not found on CDP port 9222');

  const expression = `(async () => {
    const answers = ${JSON.stringify(answers)};
    const results = {};
    for (const [slug, answer] of Object.entries(answers)) {
      const response = await fetch('/s/' + slug + '/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({answer}),
      });
      results[slug] = {status: response.status, body: await response.json()};
    }
    return results;
  })()`;

  const results = await evaluate(page.webSocketDebuggerUrl, expression);
  console.log(JSON.stringify(results, null, 2));
  if (Object.values(results).some((result) => result.status !== 200 || !result.body.ok)) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
