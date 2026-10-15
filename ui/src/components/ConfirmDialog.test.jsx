import { describe, it, expect, vi, afterEach } from 'vitest';
import { useState } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ConfirmDialog from './ConfirmDialog';

// Harness closes the dialog through onCancel, as Repositories does.
function Harness({ onConfirm }) {
  const [open, setOpen] = useState(true);
  return open
    ? <ConfirmDialog title="Delete Repository" message="Sure?" onConfirm={onConfirm} onCancel={() => setOpen(false)} />
    : <p>closed</p>;
}

describe('ConfirmDialog', () => {
  afterEach(() => vi.restoreAllMocks());

  it('stays open with the error alerted when onConfirm rejects, so the action can be retried', async () => {
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    const onConfirm = vi.fn().mockRejectedValue(new Error('delete failed'));
    render(<Harness onConfirm={onConfirm} />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(alert).toHaveBeenCalledWith('Error: delete failed'));
    expect(screen.getByRole('dialog', { name: 'Delete Repository' })).toBeInTheDocument();

    const confirm = screen.getByRole('button', { name: 'Delete' });
    await waitFor(() => expect(confirm).toBeEnabled());
    await userEvent.click(confirm);
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(2));
  });

  it('closes once onConfirm resolves', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(<Harness onConfirm={onConfirm} />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('closed')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('ignores backdrop clicks while onConfirm runs', async () => {
    let finish;
    const onConfirm = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
    render(<Harness onConfirm={onConfirm} />);

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await userEvent.click(screen.getByRole('dialog'));
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    finish();
    expect(await screen.findByText('closed')).toBeInTheDocument();
  });

  it('closes on a backdrop click when idle', async () => {
    render(<Harness onConfirm={vi.fn()} />);
    await userEvent.click(screen.getByRole('dialog'));
    expect(screen.getByText('closed')).toBeInTheDocument();
  });
});
