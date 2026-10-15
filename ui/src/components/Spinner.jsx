export default function Spinner({ className = 'flex h-64 items-center justify-center' }) {
  return (
    <div className={className} role="status" aria-label="Loading">
      <div className="h-8 w-8 animate-spin rounded-full border-4 border-blue-600 border-t-transparent"></div>
    </div>
  );
}
