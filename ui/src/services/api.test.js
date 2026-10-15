import { describe, it, expect, vi } from 'vitest';
import { request, ApiError, UNAUTHORIZED_EVENT, vulnerabilityApi, scanApi, attachmentName } from './api';
import { mockFetch } from '../test/fetch';
import { stubDownload } from '../test/download';

describe('request', () => {
  it('returns the envelope data', async () => {
    mockFetch({ 'GET /x': { body: { success: true, data: { a: 1 } } } });
    await expect(request('/x')).resolves.toEqual({ a: 1 });
  });

  it('returns null for 204', async () => {
    mockFetch({ 'DELETE /x': { status: 204 } });
    await expect(request('/x', { method: 'DELETE' })).resolves.toBeNull();
  });

  it('turns an API error into ApiError with the server message', async () => {
    mockFetch({ 'GET /x': { status: 400, body: { success: false, error: 'bad input' } } });
    const err = await request('/x').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(400);
    expect(err.message).toBe('bad input');
  });

  it('survives a non-JSON error page from a proxy', async () => {
    mockFetch({ 'GET /x': { status: 502, raw: '<html>Bad Gateway</html>' } });
    const err = await request('/x').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(502);
    expect(err.message).toMatch(/502/);
  });

  it('on 401 clears the token, announces it and throws', async () => {
    localStorage.setItem('orbit_token', 't');
    mockFetch({ 'GET /x': { status: 401, body: { success: false, error: 'expired' } } });
    const listener = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, listener);
    const err = await request('/x').catch((e) => e);
    window.removeEventListener(UNAUTHORIZED_EVENT, listener);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(401);
    expect(localStorage.getItem('orbit_token')).toBeNull();
    expect(listener).toHaveBeenCalledOnce();
  });

  it('on 401 keeps a token that replaced the one the request was sent with', async () => {
    localStorage.setItem('orbit_token', 'old');
    let respond;
    const { fn } = mockFetch({ 'GET /x': () => new Promise((r) => { respond = r; }) });
    const listener = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, listener);
    const pending = request('/x').catch((e) => e);
    await vi.waitFor(() => expect(respond).toBeDefined());
    localStorage.setItem('orbit_token', 'new'); // e.g. logged in again in another tab
    respond({ status: 401, body: { success: false, error: 'expired' } });
    const err = await pending;
    window.removeEventListener(UNAUTHORIZED_EVENT, listener);
    expect(fn.mock.calls[0][1].headers.Authorization).toBe('Bearer old');
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(401);
    expect(localStorage.getItem('orbit_token')).toBe('new');
    expect(listener).not.toHaveBeenCalled();
  });

  it('sends the bearer token', async () => {
    localStorage.setItem('orbit_token', 'abc');
    const { fn } = mockFetch({ 'GET /x': { body: { data: 1 } } });
    await request('/x');
    expect(fn.mock.calls[0][1].headers.Authorization).toBe('Bearer abc');
  });
});

describe('vulnerabilityApi.list', () => {
  it('sends the exploit filters and the sort', async () => {
    const { calls } = mockFetch({ 'GET /vulnerabilities': { body: { success: true, data: { data: [] } } } });
    await vulnerabilityApi.list({ page: 2, kev: true, min_epss: '0.1', sort: 'epss' });
    expect(calls[0].path).toBe('/vulnerabilities?page=2&per_page=25&kev=true&min_epss=0.1&sort=epss');
  });

  it('leaves the defaults out of the URL', async () => {
    const { calls } = mockFetch({ 'GET /vulnerabilities': { body: { success: true, data: { data: [] } } } });
    await vulnerabilityApi.list({ kev: false, sort: 'severity' });
    expect(calls[0].path).toBe('/vulnerabilities?page=1&per_page=25');
  });
});

describe('download', () => {
  it('saves the file under the server name, sending the token', async () => {
    localStorage.setItem('orbit_token', 'abc');
    const { created, revoked, names, flushTimers } = stubDownload();
    const { fn } = mockFetch({
      'GET /scans/s1/sbom': { body: { bomFormat: 'CycloneDX' }, headers: { 'Content-Disposition': 'attachment; filename=web-s1.cdx.json' } },
    });
    await scanApi.downloadSbom('s1', 'cyclonedx');
    expect(fn.mock.calls[0][0]).toBe('/api/v1/scans/s1/sbom?format=cyclonedx');
    expect(fn.mock.calls[0][1].headers.Authorization).toBe('Bearer abc');
    expect(created).toHaveBeenCalledOnce();
    expect(names).toEqual(['web-s1.cdx.json']);
    flushTimers();
    expect(revoked).toHaveBeenCalledWith('blob:orbit');
  });

  it('falls back to its own name without Content-Disposition', async () => {
    const { names } = stubDownload();
    mockFetch({ 'GET /scans/abcdef123456/sbom': { body: {} } });
    await scanApi.downloadSbom('abcdef123456', 'spdx');
    expect(names).toEqual(['orbit-abcdef12.spdx.json']);
  });

  it('throws the server error and saves nothing', async () => {
    const { names } = stubDownload();
    mockFetch({ 'GET /scans/s1/sbom': { status: 409, body: { success: false, error: 'scan is not completed' } } });
    const err = await scanApi.downloadSbom('s1', 'cyclonedx').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(err.message).toBe('scan is not completed');
    expect(names).toEqual([]);
  });

  it('on 401 clears the token', async () => {
    localStorage.setItem('orbit_token', 't');
    stubDownload();
    mockFetch({ 'GET /scans/s1/sbom': { status: 401, body: { error: 'expired' } } });
    await scanApi.downloadSbom('s1', 'spdx').catch(() => {});
    expect(localStorage.getItem('orbit_token')).toBeNull();
  });
});

describe('attachmentName', () => {
  it('reads quoted and bare file names', () => {
    expect(attachmentName('attachment; filename="a b.json"')).toBe('a b.json');
    expect(attachmentName('attachment; filename=x.cdx.json')).toBe('x.cdx.json');
    expect(attachmentName(null)).toBeNull();
  });
});
