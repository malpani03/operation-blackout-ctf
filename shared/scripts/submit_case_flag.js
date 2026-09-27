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
      params: { expression, awaitPromise: true, returnByValue: true },
    })));
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
  const expression = `(async () => {
    const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
    const caseButton = [...document.querySelectorAll('button')]
      .find(x => x.innerText.includes('The Evidence'));
    if (!caseButton) throw new Error('The Evidence case button not found');
    caseButton.click();
    await pause(500);
    const input = [...document.querySelectorAll('input')]
      .find(x => /flag/i.test(x.placeholder || '') || /flag/i.test(x.getAttribute('aria-label') || ''));
    if (!input) throw new Error('Flag input not found');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'flag{evidence_23c52b9d18c24656}');
    input.dispatchEvent(new Event('input', {bubbles:true}));
    input.dispatchEvent(new Event('change', {bubbles:true}));
    await pause(100);
    const submit = [...document.querySelectorAll('button')]
      .find(x => /submit flag/i.test(x.innerText));
    if (!submit) throw new Error('Submit flag button not found');
    submit.click();
    await pause(1200);
    return {text: document.body.innerText};
  })()`;
  const result = await evaluate(page.webSocketDebuggerUrl, expression);
  console.log(JSON.stringify(result, null, 2));
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
