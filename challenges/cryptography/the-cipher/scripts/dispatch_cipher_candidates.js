async (page) => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const candidates = JSON.parse(fs.readFileSync(path.resolve('analysis/cipher-record-aad-forgeries.json'), 'utf8'));
  const handover = 'be3f63da3765d3a093a77e6027271589cc5cc760d4d3ff657f440bed3a6177b9';
  const results = [];
  for (const candidate of candidates) {
    const response = await page.evaluate(async ({handover, candidate}) => {
      const request = await fetch('/cipher/dispatch', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          handover,
          nonce: candidate.nonce,
          ciphertext: candidate.ciphertext,
          tag: candidate.tag,
        }),
      });
      return {status: request.status, body: await request.text()};
    }, {handover, candidate});
    results.push({
      format: candidate.format,
      root: candidate.root,
      mapping: candidate.mapping,
      target_metadata: candidate.target_metadata,
      ...response,
    });
    if (!response.body.includes('"ok":false')) break;
  }
  return results;
}
