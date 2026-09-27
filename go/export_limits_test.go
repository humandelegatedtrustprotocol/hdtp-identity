package pactidentity

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The export's bounds are written three times: contract/contract.json's ExportLimits, the core's
// constants (held to the contract by crates/pact-identity/tests/limits.rs), and these. This holds
// the Go port's to the contract, so the contract a host reads is the port it runs.
func TestTheContractsExportLimitsAreThePortsConstants(t *testing.T) {
	raw, err := os.ReadFile("../contract/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Defs struct {
			ExportLimits struct {
				Const map[string]int `json:"const"`
			} `json:"ExportLimits"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	port := map[string]int{
		"manifest": ExportManifestMax, "contacts_csv": ExportContactsMax, "contacts_rows": ExportContactsRowMax, "threads_csv": ExportThreadsMax,
		"messages_line": ExportLineMax, "media_file": ExportMediaMax, "body": ExportBodyMax, "name_characters": ExportNameMax, "attachments": ExportAttachmentsMax,
	}
	if !reflect.DeepEqual(contract.Defs.ExportLimits.Const, port) {
		t.Fatalf("contract/contract.json's ExportLimits %v and the Go port's constants %v", contract.Defs.ExportLimits.Const, port)
	}
}
