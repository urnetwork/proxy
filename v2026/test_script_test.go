// Pins the local suite's output-filter status and binary-text contracts.
package proxy

import (
	"os"
	"strings"
	"testing"
)

// The live test pipeline snapshots both zsh statuses before selecting the
// downstream failure ahead of a secondary upstream SIGPIPE.
func TestTestScriptPreservesPipelineFailures(t *testing.T) {
	contentBytes, err := os.ReadFile("test.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(contentBytes)
	for _, signature := range []string{
		"| grep --binary-files=text --line-buffered",
		`pipeline_status=("${pipestatus[@]}")`,
		`test_pipeline_status "${pipeline_status[1]}" "${pipeline_status[2]}" || exit $?`,
	} {
		if count := strings.Count(content, signature); count != 1 {
			t.Errorf("%q count = %d; want 1", signature, count)
		}
	}
}

// The top-level runner enters and verifies the workspace-wide gate before its
// package discovery can build or execute test code.
func TestTestScriptAcquiresNetworkSuiteGate(t *testing.T) {
	contentBytes, err := os.ReadFile("test.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(contentBytes)
	gateIndex := strings.Index(content, `exec "$network_test_gate" run-all run-all-proxy`)
	verifyIndex := strings.Index(content, `"$network_test_gate" --verify-held run-all`)
	discoveryIndex := strings.Index(content, "for d in `find .")
	if gateIndex < 0 || verifyIndex < 0 || discoveryIndex < 0 {
		t.Fatalf("gate/discovery locations = %d/%d/%d; want all present", gateIndex, verifyIndex, discoveryIndex)
	}
	if gateIndex >= discoveryIndex || verifyIndex >= discoveryIndex {
		t.Fatal("proxy package discovery precedes network-suite gate ownership")
	}
}
