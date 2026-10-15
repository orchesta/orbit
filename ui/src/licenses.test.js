import { describe, it, expect } from 'vitest';
import { licenseBreakdown } from './licenses';

describe('licenseBreakdown', () => {
  it('counts licenses, most common first, unknown last', () => {
    expect(licenseBreakdown([
      { license: 'MIT' }, { license: 'BSD-3-Clause' }, { license: '' }, { license: 'MIT' }, {}, { license: 'Apache-2.0' },
    ])).toEqual([
      { license: 'MIT', count: 2 },
      { license: 'Apache-2.0', count: 1 },
      { license: 'BSD-3-Clause', count: 1 },
      { license: null, count: 2 },
    ]);
  });

  it('is empty for no dependencies', () => {
    expect(licenseBreakdown([])).toEqual([]);
  });
});
