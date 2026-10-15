import { vi, afterEach } from 'vitest';

const restore = [];
afterEach(() => restore.splice(0).forEach((fn) => fn()));

// stubDownload replaces what download() needs from the browser: object URLs
// (jsdom has none), the anchor click, and the delayed revoke timer. Call it
// inside a test; everything is put back after it, so nothing leaks.
export function stubDownload() {
  const original = { create: URL.createObjectURL, revoke: URL.revokeObjectURL };
  restore.push(() => {
    URL.createObjectURL = original.create;
    URL.revokeObjectURL = original.revoke;
  });
  const created = vi.fn(() => 'blob:orbit');
  const revoked = vi.fn();
  URL.createObjectURL = created;
  URL.revokeObjectURL = revoked;

  // Run the 1 s revoke timer by hand instead of leaving it pending.
  const timers = [];
  const realSetTimeout = globalThis.setTimeout;
  vi.spyOn(globalThis, 'setTimeout').mockImplementation((fn, ms, ...args) => {
    if (ms === 1000) {
      timers.push(fn);
      return 0;
    }
    return realSetTimeout(fn, ms, ...args);
  });

  const names = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function () { names.push(this.download); });
  return { created, revoked, names, flushTimers: () => timers.splice(0).forEach((fn) => fn()) };
}
