// Provider metadata shared by the pages. Add a provider here, not in a ternary.
export const PROVIDERS = [
  { id: 'github', label: 'GitHub', needsConnection: false },
  { id: 'gitlab', label: 'GitLab', needsConnection: false },
  { id: 'azuredevops', label: 'Azure DevOps', needsConnection: true },
];

export const providerById = (id) => PROVIDERS.find((p) => p.id === id);

// providerLabel is the display name; an unknown id is shown as it came.
export const providerLabel = (id) => providerById(id)?.label ?? id ?? '';

export const needsConnection = (id) => !!providerById(id)?.needsConnection;

export const TOKEN_PLACEHOLDERS = {
  github: 'ghp_xxxxxxxxxxxxxxxxxxxx',
  gitlab: 'glpat-xxxxxxxxxxxxxxxxxxxx',
  azuredevops: 'Personal access token with Code (Read) scope',
};
