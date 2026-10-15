package git

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// layout creates a clone-like tree in root whose symlinks point at files
// and directories outside it.
func layout(t *testing.T) (root string) {
	t.Helper()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), "db_password=hunter2\n")
	mustWrite(t, filepath.Join(outside, "dir", "package.json"), "{}")

	root = t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies":{}}`)
	mustWrite(t, filepath.Join(root, "sub", "go.mod"), "module x\n")
	mustWrite(t, filepath.Join(root, ".git", "config"), "")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "requirements.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "dir"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkFilesSkipsSymlinksAndGitDir(t *testing.T) {
	files, err := NewLocalGit().WalkFiles(layout(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"package.json", filepath.Join("sub", "go.mod")}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("WalkFiles = %q, want %q", files, want)
	}
}

func TestReadFileStaysInsideRoot(t *testing.T) {
	root := layout(t)
	g := NewLocalGit()

	got, err := g.ReadFile(root, "package.json")
	if err != nil || string(got) != `{"dependencies":{}}` {
		t.Fatalf("ReadFile(package.json) = %q, %v", got, err)
	}
	for _, rel := range []string{"requirements.txt", filepath.Join("linked", "package.json"), filepath.Join("..", "secret.txt")} {
		if _, err := g.ReadFile(root, rel); err == nil {
			t.Fatalf("ReadFile(%q) must fail", rel)
		}
	}
}

func TestReadFileRejectsOversizedManifest(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	mustWrite(t, path, "")
	if err := os.Truncate(path, MaxManifestBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalGit().ReadFile(root, "package.json"); err == nil {
		t.Fatal("manifests over MaxManifestBytes must be refused")
	}
}

func TestReadFileLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package-lock.json")
	mustWrite(t, path, "")
	size := int64(MaxManifestBytes + 1)
	if err := os.Truncate(path, size); err != nil {
		t.Fatal(err)
	}
	g := NewLocalGit()
	if _, err := g.ReadFile(root, "package-lock.json"); err == nil {
		t.Fatal("ReadFile must refuse files over MaxManifestBytes")
	}
	if got, err := g.ReadFileLimit(root, "package-lock.json", MaxLockfileBytes); err != nil || int64(len(got)) != size {
		t.Fatalf("ReadFileLimit(MaxLockfileBytes) = %d bytes, %v", len(got), err)
	}
	if _, err := g.ReadFileLimit(root, "package-lock.json", size-1); err == nil {
		t.Fatal("ReadFileLimit must refuse files over its limit")
	}
}

func TestWalkFilesSkipsDependencyAndBuildDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module x\n")
	mustWrite(t, filepath.Join(root, "src", "package.json"), "{}")
	// Real source layouts that must still be scanned.
	keep := []string{"obj/project.assets.json", "packages/foo/package.json", "web/dist/package.json", "svc/target/pom.xml", "bin/package.json", "build/package.json"}
	for _, p := range keep {
		mustWrite(t, filepath.Join(root, filepath.FromSlash(p)), "x")
	}
	for _, p := range []string{
		"node_modules/x/package.json",
		"a/node_modules/y/package.json",
		"vendor/modules.txt",
		".yarn/cache/package.json",
		"a/.pnpm-store/v3/package.json",
		"testdata/requirements.txt",
		"pkg/testdata/nested/go.mod",
	} {
		mustWrite(t, filepath.Join(root, filepath.FromSlash(p)), "x")
	}
	files, err := NewLocalGit().WalkFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"go.mod", filepath.Join("src", "package.json")}
	for _, p := range keep {
		want = append(want, filepath.FromSlash(p))
	}
	sort.Strings(want)
	sort.Strings(files)
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("WalkFiles = %q, want %q", files, want)
	}
}

func TestSkipDirsIsExtensible(t *testing.T) {
	old := SkipDirs
	t.Cleanup(func() { SkipDirs = old })
	SkipDirs = append(append([]string{}, old...), "custom")

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "custom", "package.json"), "{}")
	mustWrite(t, filepath.Join(root, "package.json"), "{}")
	files, err := NewLocalGit().WalkFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"package.json"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("WalkFiles = %q, want %q", files, want)
	}
}

// A root that is itself named testdata is still walked; only nested
// testdata directories are skipped.
func TestWalkFilesWalksTestdataRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "testdata")
	mustWrite(t, filepath.Join(root, "requirements.txt"), "x")
	mustWrite(t, filepath.Join(root, "sub", "go.mod"), "x")
	mustWrite(t, filepath.Join(root, "sub", "testdata", "go.mod"), "x")
	files, err := NewLocalGit().WalkFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	want := []string{"requirements.txt", filepath.Join("sub", "go.mod")}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("WalkFiles = %q, want %q", files, want)
	}
}
