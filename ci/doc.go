// Package ci holds tests for the CI templates (action.yml, gitlab and
// azure-pipelines). The templates' shell scripts are run with fake docker,
// orbit and wget commands that record their arguments.
package ci
