package signatures

import "testing"

func TestLoadAndExplainEmbeddedSignatures(t *testing.T) {
	rules, allow, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 || len(allow) == 0 {
		t.Fatalf("expected finding and allowlist rules, got rules=%d allow=%d", len(rules), len(allow))
	}
	if SignatureVersion() == "" {
		t.Fatalf("signature version is empty")
	}
	rule, ok, err := Explain("PRM001")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || rule.ID != "PRM001" || rule.Rationale == "" || rule.Remediation == "" {
		t.Fatalf("explain did not return PRM001 metadata: %#v ok=%v", rule, ok)
	}
	if _, ok, err := Explain("NOPE"); err != nil || ok {
		t.Fatalf("unknown rule explain = ok=%v err=%v", ok, err)
	}
}

func TestActiveRulesOmitDeprecatedRules(t *testing.T) {
	active, err := ActiveRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) == 0 {
		t.Fatalf("no active rules loaded")
	}
	for _, rule := range active {
		if rule.Status != "active" {
			t.Fatalf("non-active rule returned: %#v", rule)
		}
	}
}
