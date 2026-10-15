import { useState } from 'react';

// ConfirmDialog is a modal confirmation. onConfirm may be async; the confirm
// button is disabled and backdrop clicks are ignored while it runs. The dialog
// closes through onCancel once onConfirm succeeds; if it fails, the error is
// alerted and the dialog stays open so the action can be retried.
export default function ConfirmDialog({ title, message, confirmLabel = 'Delete', variant = 'danger', onConfirm, onCancel }) {
  const [busy, setBusy] = useState(false);
  const danger = variant === 'danger';

  async function handleConfirm() {
    setBusy(true);
    try {
      await onConfirm();
      onCancel();
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-gray-900/50 p-4" role="dialog" aria-label={title} onClick={busy ? undefined : onCancel}>
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-start gap-4">
            <div className={`flex-shrink-0 h-10 w-10 rounded-full flex items-center justify-center ${danger ? 'bg-red-100' : 'bg-blue-100'}`}>
              <svg className={`w-5 h-5 ${danger ? 'text-red-600' : 'text-blue-600'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.268 16c-.77 1.333.192 3 1.732 3z" /></svg>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
              <p className="text-sm text-gray-500 mt-1">{message}</p>
            </div>
          </div>
        </div>
        <div className="px-6 py-4 bg-gray-50 flex justify-end gap-3 border-t border-gray-200">
          <button
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 ${danger ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'}`}
            disabled={busy}
            onClick={handleConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
