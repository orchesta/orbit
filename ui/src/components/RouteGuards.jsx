import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/auth';
import Spinner from './Spinner';
import ErrorState from './ErrorState';

const FULL_SCREEN = 'flex h-screen w-full items-center justify-center bg-slate-950';

// AuthUnavailable is shown instead of a redirect when auth state could not be
// loaded, so an outage never looks like being logged out.
function AuthUnavailable({ error, onRetry }) {
  return (
    <div className={FULL_SCREEN}>
      <div className="w-full max-w-md px-4">
        <ErrorState title="Orbit is unavailable" error={error} onRetry={onRetry} />
      </div>
    </div>
  );
}

export function ProtectedRoute({ children }) {
  const { user, loading, setupRequired, authError, retryAuth } = useAuth();

  if (loading) {
    return <Spinner className={FULL_SCREEN} />;
  }

  if (authError) {
    return <AuthUnavailable error={authError} onRetry={retryAuth} />;
  }

  if (setupRequired) {
    return <Navigate to="/setup" replace />;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

export function AuthRoute({ children }) {
  const { user, loading, setupRequired, authError, retryAuth } = useAuth();

  if (loading) {
    return <Spinner className={FULL_SCREEN} />;
  }

  if (authError) {
    return <AuthUnavailable error={authError} onRetry={retryAuth} />;
  }

  if (setupRequired) {
    return <Navigate to="/setup" replace />;
  }

  if (user) {
    return <Navigate to="/" replace />;
  }

  return children;
}

export function SetupRoute({ children }) {
  const { loading, setupRequired, user, authError, retryAuth } = useAuth();

  if (loading) {
    return <Spinner className={FULL_SCREEN} />;
  }

  if (authError) {
    return <AuthUnavailable error={authError} onRetry={retryAuth} />;
  }

  if (!setupRequired && user) {
    return <Navigate to="/" replace />;
  }

  if (!setupRequired) {
    return <Navigate to="/login" replace />;
  }

  return children;
}
