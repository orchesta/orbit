import { describe, it, expect } from 'vitest';
import { queryClient } from './queryClient';
import { ApiError } from './services/api';

const retry = queryClient.getDefaultOptions().queries.retry;

describe('production query retry predicate', () => {
  it('retries a 5xx ApiError once', () => {
    const err = new ApiError(503, 'boom');
    expect(retry(0, err)).toBe(true);
    expect(retry(1, err)).toBe(false);
  });

  it('retries a network error once', () => {
    const err = new TypeError('Failed to fetch');
    expect(retry(0, err)).toBe(true);
    expect(retry(1, err)).toBe(false);
  });

  it.each([400, 401, 403, 404, 409, 422])('never retries a %i ApiError', (status) => {
    expect(retry(0, new ApiError(status, 'nope'))).toBe(false);
  });
});
