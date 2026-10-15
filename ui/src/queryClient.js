import { QueryClient } from '@tanstack/react-query';
import { ApiError } from './services/api';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Client errors (4xx) will not fix themselves; retry only transient ones once.
      retry: (count, error) => !(error instanceof ApiError && error.status < 500) && count < 1,
      refetchOnWindowFocus: false,
    },
  },
});
