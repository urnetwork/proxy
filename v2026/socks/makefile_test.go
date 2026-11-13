package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Many MIPS routers have no FPU, and a hardfloat binary dies there with an
// illegal instruction (https://go.dev/wiki/GoMips). The 32-bit arches read
// GOMIPS; mips64 and mips64le read GOMIPS64 and ignore GOMIPS. These tests
// build a minimal program with the exact environment of each MIPS recipe line
// in the Makefile and check the float mode the toolchain recorded.

var mipsFloatVars = map[string]string{
	"mips":     "GOMIPS",
	"mipsle":   "GOMIPS",
	"mips64":   "GOMIPS64",
	"mips64le": "GOMIPS64",
}

// makeBuildEnvs returns the `env` assignments of each `go build` recipe line in
// the Makefile's build target, keyed by GOARCH, as make would run them.
func makeBuildEnvs(t *testing.T) map[string][]string {
	t.Helper()

	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make required")
	}
	cmd := exec.Command(makePath, "-n", "build")
	cmd.Env = append(os.Environ(), "MAKEFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("make -n build: %v", err)
	}

	envs := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "env" || !strings.Contains(line, " go build ") {
			continue
		}
		var assignments []string
		goarch := ""
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				break
			}
			assignments = append(assignments, field)
			if key == "GOARCH" {
				goarch = value
			}
		}
		if goarch == "" {
			t.Fatalf("recipe line has no GOARCH: %s", line)
		}
		envs[goarch] = assignments
	}
	return envs
}

// recordedBuildSetting reads one `build` setting from `go version -m`.
func recordedBuildSetting(t *testing.T, binary string, key string) string {
	t.Helper()

	out, err := exec.Command("go", "version", "-m", binary).Output()
	if err != nil {
		t.Fatalf("go version -m %s: %v", binary, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "build" {
			if k, v, ok := strings.Cut(fields[1], "="); ok && k == key {
				return v
			}
		}
	}
	return ""
}

func TestMakefileBuildsMipsSoftFloat(t *testing.T) {
	envs := makeBuildEnvs(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module mipsfloattest\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Only the Makefile's assignments may select the target and float mode.
	var baseEnv []string
	for _, kv := range os.Environ() {
		switch key, _, _ := strings.Cut(kv, "="); key {
		case "GOOS", "GOARCH", "GOMIPS", "GOMIPS64", "GOFLAGS", "GOWORK", "CGO_ENABLED":
		default:
			baseEnv = append(baseEnv, kv)
		}
	}
	baseEnv = append(baseEnv, "GOWORK=off")

	for goarch, floatVar := range mipsFloatVars {
		assignments, ok := envs[goarch]
		if !ok {
			t.Errorf("Makefile has no %s build", goarch)
			continue
		}
		binary := filepath.Join(dir, goarch)
		cmd := exec.Command("go", "build", "-o", binary, ".")
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, baseEnv...), assignments...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s build with %v: %v\n%s", goarch, assignments, err, out)
		}
		if mode := recordedBuildSetting(t, binary, floatVar); mode != "softfloat" {
			t.Errorf("%s binary records %s=%q, want softfloat (Makefile env %v)", goarch, floatVar, mode, assignments)
		}
	}
}
