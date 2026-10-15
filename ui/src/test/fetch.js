import { vi } from 'vitest';

// mockFetch stubs global fetch with a route table: keys are "METHOD /path"
// (path without the /api/v1 prefix, query string included when given) and
// values are { status, body } or a function (request) => { status, body } or
// a Promise of one. Unmatched requests fail the test loudly.
export function mockFetch(routes) {
  const calls = [];
  const fn = vi.fn(async (url, options = {}) => {
    const method = (options.method || 'GET').toUpperCase();
    const path = url.replace(/^\/api\/v1/, '');
    calls.push({ method, path, body: options.body });
    const key = `${method} ${path}`;
    const bare = `${method} ${path.split('?')[0]}`;
    const route = routes[key] ?? routes[bare];
    if (!route) throw new Error(`unexpected request: ${key}`);
    const res = await (typeof route === 'function' ? route({ method, path, body: options.body, signal: options.signal }) : route);
    const status = res.status ?? 200;
    const text = res.raw ?? (res.body === undefined ? '' : JSON.stringify(res.body));
    return new Response(status === 204 ? null : text, {
      status,
      headers: { 'Content-Type': res.raw ? 'text/html' : 'application/json' },
    });
  });
  vi.stubGlobal('fetch', fn);
  return { fn, calls };
}
