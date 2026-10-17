import { readFileSync } from 'node:fs';

export const tlsOptions = {
  key: readFileSync(new URL('./localhost-key.pem', import.meta.url)),
  cert: readFileSync(new URL('./localhost-cert.pem', import.meta.url)),
};
