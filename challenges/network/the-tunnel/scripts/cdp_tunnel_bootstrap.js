const fs = require('fs');

async function main() {
  const targets = await (await fetch('http://127.0.0.1:9222/json/list')).json();
  const target = targets.find((entry) => entry.type === 'page' && entry.url.startsWith('https://ctf.roshancodes.com/app/'));
  if (!target) throw new Error('Authenticated investigation-console tab not found');

  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message.result);
  });

  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });

  const expression = `(async () => {
    const paths = ['/api/case/tunnel', '/api/handover/insider', '/api/fieldtoken', '/api/state'];
    const entries = await Promise.all(paths.map(async (path) => {
      const response = await fetch(path);
      return [path, { status: response.status, body: await response.json() }];
    }));
    return Object.fromEntries(entries);
  })()`;
  const result = await send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  socket.close();
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  fs.writeFileSync('assets/tunnel-bootstrap.json', JSON.stringify(result.result.value, null, 2));
  console.log('Saved assets/tunnel-bootstrap.json');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
