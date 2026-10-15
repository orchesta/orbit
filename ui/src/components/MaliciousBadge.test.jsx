import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import MaliciousBadge from './MaliciousBadge';

describe('MaliciousBadge', () => {
  it('names the finding malicious and explains it on hover', () => {
    render(<MaliciousBadge />);
    expect(screen.getByText('Malicious')).toHaveAttribute('title', expect.stringContaining('OpenSSF Malicious Packages'));
  });
});
