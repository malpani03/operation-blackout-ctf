const fs = require('fs');
const http = require('http');
const https = require('https');

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

function cdpCall(wsUrl, method, params = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    ws.addEventListener('open', () => ws.send(JSON.stringify({ id: 1, method, params })));
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== 1) return;
      ws.close();
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    });
    ws.addEventListener('error', reject);
  });
}

function download(cookie) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream('assets/bundle.zip', { flags: 'wx' });
    const request = https.get({
      hostname: 'ctf.roshancodes.com',
      path: '/evidence/bundle.zip',
      headers: { Cookie: `hx_player=${cookie}` },
    }, (response) => {
      if (response.statusCode !== 200) {
        output.close();
        fs.unlinkSync('assets/bundle.zip');
        reject(new Error(`Download failed with HTTP ${response.statusCode}`));
        return;
      }
      response.pipe(output);
      output.on('finish', () => output.close(resolve));
    });
    request.on('error', (error) => {
      output.close();
      if (fs.existsSync('assets/bundle.zip')) fs.unlinkSync('assets/bundle.zip');
      reject(error);
    });
  });
}

(async () => {
  const targets = await getJson('http://127.0.0.1:9222/json/list');
  const page = targets.find((target) => target.type === 'page' && target.url.startsWith('https://ctf.roshancodes.com/'));
  if (!page) throw new Error('Authenticated CTF page target not found');
  const result = await cdpCall(page.webSocketDebuggerUrl, 'Network.getAllCookies');
  const auth = result.cookies.find((cookie) => cookie.name === 'hx_player' && cookie.domain.endsWith('ctf.roshancodes.com'));
  if (!auth) throw new Error('CTF authentication cookie not found');
  await download(auth.value);
  console.log('bundle.zip downloaded through the authenticated browser session');
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
