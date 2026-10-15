import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useScanTracker } from './useScanTracker';
import { mockFetch } from '../test/fetch';

function wrapper({ children }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe('useScanTracker', () => {
  it('tracks a scan until it completes', async () => {
    let polls = 0;
    let releasePost;
    const postGate = new Promise((resolve) => {
      releasePost = resolve;
    });
    const { calls } = mockFetch({
      'POST /repositories/r1/scan': async () => {
        await postGate;
        return { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } };
      },
      'GET /scans/s1': () => {
        polls++;
        return { body: { data: { id: 's1', status: polls < 2 ? 'running' : 'completed' } } };
      },
    });
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanTracker({ onFinished, pollInterval: 10 }), { wrapper });

    let started;
    await act(async () => {
      started = result.current.start('r1');
    });
    // The trigger is still in flight: spinner is on, nothing is polled yet.
    expect(result.current.isScanning('r1')).toBe(true);
    expect(calls.some((c) => c.path.startsWith('/scans/'))).toBe(false);

    await act(async () => {
      releasePost();
      await started;
    });
    expect(result.current.isScanning('r1')).toBe(true);
    await waitFor(() => expect(onFinished).toHaveBeenCalledWith('r1', expect.objectContaining({ status: 'completed' })));
    await waitFor(() => expect(result.current.isScanning('r1')).toBe(false));
    expect(onFinished).toHaveBeenCalledTimes(1);
    expect(polls).toBeGreaterThanOrEqual(2);
  });

  it('stops tracking when the trigger fails', async () => {
    mockFetch({ 'POST /repositories/r1/scan': { status: 404, body: { error: 'repository not found' } } });
    const { result } = renderHook(() => useScanTracker({ onFinished: vi.fn(), pollInterval: 10 }), { wrapper });
    await act(async () => {
      await expect(result.current.start('r1')).rejects.toThrow('repository not found');
    });
    expect(result.current.isScanning('r1')).toBe(false);
  });

  it('reports a failed scan as finished', async () => {
    mockFetch({
      'POST /repositories/r1/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
      'GET /scans/s1': { body: { data: { id: 's1', status: 'failed' } } },
    });
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanTracker({ onFinished, pollInterval: 10 }), { wrapper });
    await act(() => result.current.start('r1'));
    await waitFor(() => expect(onFinished).toHaveBeenCalledWith('r1', expect.objectContaining({ status: 'failed' })));
    await waitFor(() => expect(result.current.isScanning('r1')).toBe(false));
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it('keeps polling after a server error', async () => {
    let polls = 0;
    mockFetch({
      'POST /repositories/r1/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
      'GET /scans/s1': () => {
        polls++;
        if (polls === 1) return { status: 500, body: { error: 'boom' } };
        return { body: { data: { id: 's1', status: 'completed' } } };
      },
    });
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanTracker({ onFinished, pollInterval: 10 }), { wrapper });
    await act(() => result.current.start('r1'));
    await waitFor(() => expect(onFinished).toHaveBeenCalledWith('r1', expect.objectContaining({ status: 'completed' })));
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it('stops tracking and reports null when a poll returns 404', async () => {
    mockFetch({
      'POST /repositories/r1/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
      'GET /scans/s1': { status: 404, body: { error: 'scan not found' } },
    });
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanTracker({ onFinished, pollInterval: 10 }), { wrapper });
    await act(() => result.current.start('r1'));
    await waitFor(() => expect(onFinished).toHaveBeenCalledWith('r1', null));
    await waitFor(() => expect(result.current.isScanning('r1')).toBe(false));
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it('tracks several in-flight triggers without duplicate-query warnings', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const gates = {};
    const gate = (id) => new Promise((resolve) => { gates[id] = resolve; });
    const g1 = gate('r1');
    const g2 = gate('r2');
    let polls2 = 0;
    mockFetch({
      'POST /repositories/r1/scan': async () => {
        await g1;
        return { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } };
      },
      'POST /repositories/r2/scan': async () => {
        await g2;
        return { status: 202, body: { data: { scan_id: 's2', status: 'pending', queued: true } } };
      },
      'GET /scans/s1': { body: { data: { id: 's1', status: 'completed' } } },
      'GET /scans/s2': () => {
        polls2++;
        return { body: { data: { id: 's2', status: polls2 < 4 ? 'running' : 'completed' } } };
      },
    });
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanTracker({ onFinished, pollInterval: 10 }), { wrapper });

    let p1;
    let p2;
    await act(async () => {
      p1 = result.current.start('r1');
      p2 = result.current.start('r2');
    });
    expect(result.current.scanningCount).toBe(2);

    await act(async () => {
      gates.r1();
      gates.r2();
      await Promise.all([p1, p2]);
    });
    await waitFor(() => expect(onFinished).toHaveBeenCalledWith('r1', expect.objectContaining({ status: 'completed' })));
    expect(result.current.isScanning('r2')).toBe(true);
    await waitFor(() => expect(onFinished).toHaveBeenCalledWith('r2', expect.objectContaining({ status: 'completed' })));
    await waitFor(() => expect(result.current.scanningCount).toBe(0));
    expect(polls2).toBeGreaterThanOrEqual(4);
    expect(warn).not.toHaveBeenCalled();
  });
});
