const fs = require('fs');

async function main() {
  const path = process.argv[2];
  const outputPath = process.argv[3];
  if (!path || !outputPath) throw new Error('Usage: node cdp_download.js URL_OR_PATH OUTPUT');

  const targets = await (await fetch('http://127.0.0.1:9222/json/list')).json();
  const target = targets.find((entry) => entry.type === 'page' && entry.url.startsWith('https://ctf.roshancodes.com/app/'));
  if (!target) throw new Error('Authenticated investigation-console tab not found');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  const response = new Promise((resolve, reject) => {
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== 1) return;
      if (message.error) reject(new Error(JSON.stringify(message.error)));
      else resolve(message.result);
    });
  });
  const expression = `(async () => {
    const response = await fetch(${JSON.stringify(path)});
    const bytes = new Uint8Array(await response.arrayBuffer());
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return { status: response.status, url: response.url, contentType: response.headers.get('content-type'), base64: btoa(binary) };
  })()`;
  socket.send(JSON.stringify({
    id: 1,
    method: 'Runtime.evaluate',
    params: { expression, awaitPromise: true, returnByValue: true },
  }));
  const result = await response;
  socket.close();
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  const value = result.result.value;
  if (value.status !== 200) throw new Error(`HTTP ${value.status} from ${value.url}`);
  const body = Buffer.from(value.base64, 'base64');
  fs.writeFileSync(outputPath, body);
  console.log(JSON.stringify({ outputPath, url: value.url, contentType: value.contentType, bytes: body.length }));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
