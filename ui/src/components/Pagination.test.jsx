import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Pagination from './Pagination';

const pageButtons = () => screen.getAllByRole('button', { name: /^Page \d+$/ }).map((b) => Number(b.textContent));
const setup = (props) => render(<Pagination total={500} label="repos" onChange={() => {}} {...props} />);

describe('Pagination', () => {
  it('renders nothing for a single page', () => {
    const { container } = setup({ page: 1, totalPages: 1 });
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when there are no pages', () => {
    const { container } = setup({ page: 1, totalPages: 0 });
    expect(container).toBeEmptyDOMElement();
  });

  it('shows every page when there are at most 7', () => {
    setup({ page: 3, totalPages: 5 });
    expect(pageButtons()).toEqual([1, 2, 3, 4, 5]);
  });

  it.each([
    [1, [1, 2, 3, 4, 5, 6, 7]],
    [4, [1, 2, 3, 4, 5, 6, 7]],
    [5, [2, 3, 4, 5, 6, 7, 8]],
    [10, [7, 8, 9, 10, 11, 12, 13]],
    [17, [14, 15, 16, 17, 18, 19, 20]],
    [20, [14, 15, 16, 17, 18, 19, 20]],
  ])('windows 7 buttons around page %i of 20', (page, expected) => {
    setup({ page, totalPages: 20 });
    expect(pageButtons()).toEqual(expected);
  });

  it('disables Prev on the first page and Next on the last', () => {
    const first = setup({ page: 1, totalPages: 4 });
    expect(screen.getByRole('button', { name: /Prev/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Next/ })).toBeEnabled();
    first.unmount();
    setup({ page: 4, totalPages: 4 });
    expect(screen.getByRole('button', { name: /Prev/ })).toBeEnabled();
    expect(screen.getByRole('button', { name: /Next/ })).toBeDisabled();
  });

  it('reports the clicked page through onChange', async () => {
    const onChange = vi.fn();
    setup({ page: 2, totalPages: 4, onChange });
    await userEvent.click(screen.getByRole('button', { name: /Next/ }));
    await userEvent.click(screen.getByRole('button', { name: /Prev/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Page 4' }));
    expect(onChange.mock.calls.map((c) => c[0])).toEqual([3, 1, 4]);
  });
});
