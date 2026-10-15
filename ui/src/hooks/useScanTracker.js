import { useCallback, useState } from 'react';
import { useQueries } from '@tanstack/react-query';
import { ApiError, repositoryApi, scanApi } from '../services/api';

const ACTIVE = new Set(['pending', 'running']);

// useScanTracker triggers scans and polls each one until it finishes, so the
// UI shows "scanning" for exactly as long as the scan really runs.
//
// onFinished(repoId, scan | null) is called once per tracked scan: with the
// finished scan, or with null when polling gave up (a 4xx such as 404).
// Server errors (5xx) and network errors keep the scan tracked and are retried
// on the next poll.
export function useScanTracker({ onFinished, pollInterval = 2000 } = {}) {
  const [tracked, setTracked] = useState({}); // repoId -> scanId ('' while the trigger is in flight)

  const untrack = useCallback((repoId) => {
    setTracked((prev) => Object.fromEntries(Object.entries(prev).filter(([id]) => id !== repoId)));
  }, []);

  // Finishing is handled inside the poll itself (an async callback), so no
  // effect has to mirror query results into state. Entries whose trigger is
  // still in flight have no scan to poll yet and are left out.
  useQueries({
    queries: Object.entries(tracked)
      .filter(([, scanId]) => scanId !== '')
      .map(([repoId, scanId]) => ({
        queryKey: ['scan', scanId],
        refetchInterval: pollInterval,
        gcTime: 0,
        queryFn: async () => {
          let scan;
          try {
            scan = await scanApi.getById(scanId);
          } catch (err) {
            if (err instanceof ApiError && err.status < 500) {
              untrack(repoId);
              onFinished?.(repoId, null);
            }
            throw err;
          }
          if (!ACTIVE.has(scan.status)) {
            untrack(repoId);
            onFinished?.(repoId, scan);
          }
          return scan;
        },
      })),
  });

  const start = useCallback(async (repoId) => {
    setTracked((prev) => ({ ...prev, [repoId]: prev[repoId] ?? '' }));
    try {
      const res = await repositoryApi.triggerScan(repoId);
      setTracked((prev) => ({ ...prev, [repoId]: res.scan_id }));
    } catch (err) {
      // Only drop a pending trigger; a failed re-trigger must not untrack a running scan.
      setTracked((prev) => (prev[repoId] === '' ? Object.fromEntries(Object.entries(prev).filter(([id]) => id !== repoId)) : prev));
      throw err;
    }
  }, []);

  const isScanning = useCallback((repoId) => Object.hasOwn(tracked, repoId), [tracked]);
  return { start, isScanning, scanningCount: Object.keys(tracked).length };
}
