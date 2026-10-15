import { providerLabel } from '../providers';

const GITHUB = "M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z";
const GITLAB = "M23.955 13.587l-1.342-4.135-2.664-8.189a.455.455 0 00-.867 0L16.418 9.45H7.582L4.918 1.263a.455.455 0 00-.867 0L1.387 9.452.045 13.587a.924.924 0 00.331 1.023L12 23.054l11.624-8.443a.92.92 0 00.331-1.024";

// ProviderIcon draws the provider's mark. The Azure DevOps one is a generic
// cloud-and-branch glyph, not a brand logo.
export default function ProviderIcon({ provider, className = 'w-5 h-5', decorative = false }) {
  const label = providerLabel(provider);
  // Next to a text label the icon is decoration, not a second name.
  const a11y = decorative ? { 'aria-hidden': true } : { role: 'img', 'aria-label': label };
  if (provider === 'azuredevops') {
    return (
      <svg data-provider={provider} {...a11y} className={`${className} text-blue-600`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
        <path d="M7 18a4 4 0 01-.6-7.96A5.5 5.5 0 0117 9.5a4 4 0 01.5 8.5" />
        <circle cx="9" cy="16.5" r="1.3" />
        <circle cx="15" cy="16.5" r="1.3" />
        <path d="M9 15.2V12m6 3.2c0-1.6-1.5-2-3-2.2" />
      </svg>
    );
  }
  if (provider === 'gitlab') {
    return (
      <svg data-provider={provider} {...a11y} className={`${className} text-orange-500`} viewBox="0 0 24 24" fill="currentColor"><path d={GITLAB} /></svg>
    );
  }
  return (
    <svg data-provider={provider} {...a11y} className={`${className} text-gray-800`} viewBox="0 0 24 24" fill="currentColor"><path d={GITHUB} /></svg>
  );
}
