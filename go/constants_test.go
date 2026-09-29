package pactidentity

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

// The constants the two ports each write down, held to the one copy contract/contract.json carries
// ($defs Windows, Kdf, KdfArgs, KdfDefault and LimitsIdle). crates/pact-identity/tests/constants.rs
// and vault.rs's tests hold the core's to the same file. (The export's bounds are held by
// export_limits_test.go; the canonical number table by review_test.go.)
func contractDefs(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("../contract/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	return contract.Defs
}

func TestTheContractsWindowsAreThePortsConstants(t *testing.T) {
	var windows struct {
		Const map[string]int64 `json:"const"`
	}
	if err := json.Unmarshal(contractDefs(t)["Windows"], &windows); err != nil {
		t.Fatal(err)
	}
	port := map[string]int64{
		"skew_s": SkewSeconds, "max_lifetime_s": MaxLifetimeSeconds,
		"tombstone_s": int64(Tombstone.Seconds()), "claim_window_s": int64(ClaimWindow.Seconds()),
		"max_leaf_days": MaxLeafDays, "signing_max_ahead_s": int64(SigningMaxAhead.Seconds()),
	}
	if !reflect.DeepEqual(windows.Const, port) {
		t.Fatalf("contract/contract.json's Windows %v and the Go port's constants %v", windows.Const, port)
	}
}

func TestTheContractsIdleWindowIsThePorts(t *testing.T) {
	var idle struct {
		Const int64 `json:"const"`
	}
	if err := json.Unmarshal(contractDefs(t)["LimitsIdle"], &idle); err != nil {
		t.Fatal(err)
	}
	if idle.Const != LimitsIdleMS {
		t.Fatalf("contract/contract.json's LimitsIdle %d and LimitsIdleMS %d", idle.Const, LimitsIdleMS)
	}
}

// Each bound read from the contract, and one past it refused through the boundary, which costs
// nothing because the range is checked before Argon2id is asked for anything. The accepted side of
// the memory ceiling is 2 GiB, which no test allocates; the equality is what holds it.
func TestTheContractsKDFBoundsAndDefaultAreThePorts(t *testing.T) {
	defs := contractDefs(t)
	type bound struct {
		Minimum uint64 `json:"minimum"`
		Maximum uint64 `json:"maximum"`
	}
	port := map[string]bound{"m_kib": {uint64(minMKiB), uint64(maxMKiB)}, "t": {1, uint64(maxT)}, "p": {1, uint64(maxP)}}
	for _, schema := range []string{"Kdf", "KdfArgs"} {
		var s struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(defs[schema], &s); err != nil {
			t.Fatal(err)
		}
		for member, want := range port {
			var got bound
			if err := json.Unmarshal(s.Properties[member], &got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("contract/contract.json's %s.%s is %v, and the Go port's bounds are %v", schema, member, got, want)
			}
		}
	}
	var def struct {
		Const KDF `json:"const"`
	}
	if err := json.Unmarshal(defs["KdfDefault"], &def); err != nil {
		t.Fatal(err)
	}
	if def.Const != DefaultKDF {
		t.Errorf("contract/contract.json's KdfDefault %+v and DefaultKDF %+v", def.Const, DefaultKDF)
	}
	for _, c := range []struct {
		member string
		value  uint64
	}{
		{"m_kib", uint64(maxMKiB) + 1}, {"m_kib", uint64(minMKiB) - 1},
		{"t", uint64(maxT) + 1}, {"t", 0}, {"p", uint64(maxP) + 1}, {"p", 0},
	} {
		kdf := map[string]any{"name": "argon2id", "m_kib": DefaultKDF.MKiB, "t": DefaultKDF.T, "p": DefaultKDF.P}
		kdf[c.member] = c.value
		args := fmt.Sprintf(`{"passphrase":"x","plaintext":{"v":2},"kdf":%s}`, mustJSON(kdf))
		if out := string(Call("vault_seal", json.RawMessage(args))); out != `{"error":"vault","why":"kdf parameters out of range"}` {
			t.Errorf("vault_seal with %s %d: %s", c.member, c.value, out)
		}
	}
}
