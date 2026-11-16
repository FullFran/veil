package domain_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// hostsPrefix is the import path prefix of every host adapter package.
const hostsPrefix = "github.com/FullFran/veil/internal/hosts"

// listedPackage is the subset of `go list -json` output this test reads.
type listedPackage struct {
	ImportPath string
	Error      *struct{ Err string }
	DepsErrors []struct{ Err string }
}

// TestDomainImportsNoHostAdapter keeps internal/domain host-agnostic: no
// package it depends on, directly or transitively, and including its tests,
// may be a host adapter under internal/hosts.
func TestDomainImportsNoHostAdapter(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	cmd := exec.Command(goBin, "list", "-e", "-deps", "-test", "-json", "../../internal/domain/...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, stderr.String())
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	listed := 0
	for {
		var pkg listedPackage
		if err := dec.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		listed++
		if pkg.Error != nil {
			t.Errorf("go list error in %s: %s", pkg.ImportPath, pkg.Error.Err)
		}
		for _, depErr := range pkg.DepsErrors {
			t.Errorf("go list dependency error in %s: %s", pkg.ImportPath, depErr.Err)
		}
		if pkg.ImportPath == hostsPrefix || strings.HasPrefix(pkg.ImportPath, hostsPrefix+"/") {
			t.Errorf("internal/domain depends on host adapter package %s", pkg.ImportPath)
		}
	}
	if listed == 0 {
		t.Fatal("go list returned no packages")
	}
}
