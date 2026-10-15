// MaliciousBadge marks a finding from the OpenSSF Malicious Packages data:
// the package version itself is malicious, not merely vulnerable.
export default function MaliciousBadge() {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-700 text-white"
      title="Known malicious package (OpenSSF Malicious Packages). Remove it and treat machines that installed it as compromised."
    >
      Malicious
    </span>
  );
}
