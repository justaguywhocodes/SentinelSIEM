package correlate

import (
	"testing"
)

// --- Exact match tests ---

func TestExactMatcher_StringMatch(t *testing.T) {
	fn := buildExactMatcher("malicious")
	if !fn("malicious") {
		t.Error("expected exact match")
	}
	if !fn("Malicious") {
		t.Error("expected case-insensitive match")
	}
	if !fn("MALICIOUS") {
		t.Error("expected case-insensitive match (all caps)")
	}
	if fn("benign") {
		t.Error("should not match different string")
	}
}

func TestExactMatcher_IntMatch(t *testing.T) {
	fn := buildExactMatcher(42)
	if !fn(42) {
		t.Error("expected int match")
	}
	if !fn("42") {
		t.Error("expected string-of-int match")
	}
	if fn(43) {
		t.Error("should not match different int")
	}
}

func TestExactMatcher_NilValue(t *testing.T) {
	fn := buildExactMatcher(nil)
	if !fn(nil) {
		t.Error("nil rule value should match nil event value")
	}
	if fn("something") {
		t.Error("nil rule value should not match non-nil event value")
	}
}

func TestExactMatcher_NilEventValue(t *testing.T) {
	fn := buildExactMatcher("value")
	if fn(nil) {
		t.Error("non-nil rule value should not match nil event value")
	}
}

func TestExactMatcher_BoolMatch(t *testing.T) {
	fn := buildExactMatcher(true)
	if !fn(true) {
		t.Error("expected bool match")
	}
	if !fn("true") {
		t.Error("expected string-of-bool match")
	}
	if fn(false) {
		t.Error("should not match false")
	}
}

// --- Contains modifier tests ---

func TestContainsMatcher_Basic(t *testing.T) {
	fn := buildContainsMatcher("remote")
	if !fn("remote_thread") {
		t.Error("expected contains match")
	}
	if !fn("Remote_Thread") {
		t.Error("expected case-insensitive contains match")
	}
	if fn("local_process") {
		t.Error("should not match non-containing string")
	}
}

func TestContainsMatcher_NilValue(t *testing.T) {
	fn := buildContainsMatcher("test")
	if fn(nil) {
		t.Error("should not match nil value")
	}
}

func TestContainsMatcher_EmptyRuleValue(t *testing.T) {
	fn := buildContainsMatcher("")
	if !fn("anything") {
		t.Error("empty substring is contained in everything")
	}
}

// --- Startswith modifier tests ---

func TestStartswithMatcher(t *testing.T) {
	fn := buildStartswithMatcher("scan_")
	if !fn("scan_result") {
		t.Error("expected startswith match")
	}
	if !fn("Scan_Result") {
		t.Error("expected case-insensitive startswith")
	}
	if fn("noscan_result") {
		t.Error("should not match different prefix")
	}
}

// --- Endswith modifier tests ---

func TestEndswithMatcher(t *testing.T) {
	fn := buildEndswithMatcher(".exe")
	if !fn("malware.exe") {
		t.Error("expected endswith match")
	}
	if !fn("MALWARE.EXE") {
		t.Error("expected case-insensitive endswith")
	}
	if fn("malware.dll") {
		t.Error("should not match different suffix")
	}
}

// --- Regex modifier tests ---

func TestRegexMatcher_Basic(t *testing.T) {
	fn, err := buildRegexMatcher(`^scan_.*result$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("scan_any_result") {
		t.Error("expected regex match")
	}
	if fn("noscan_result") {
		t.Error("should not match different pattern")
	}
}

func TestRegexMatcher_InvalidPattern(t *testing.T) {
	_, err := buildRegexMatcher(`[invalid`)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestRegexMatcher_NilValue(t *testing.T) {
	fn, err := buildRegexMatcher(`test`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn(nil) {
		t.Error("should not match nil")
	}
}

// --- CIDR modifier tests ---

func TestCIDRMatcher_IPv4(t *testing.T) {
	fn, err := buildCIDRMatcher("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be in 10.0.0.0/8")
	}
	if fn("192.168.1.1") {
		t.Error("expected 192.168.1.1 to not be in 10.0.0.0/8")
	}
}

func TestCIDRMatcher_Specific(t *testing.T) {
	fn, err := buildCIDRMatcher("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("192.168.1.100") {
		t.Error("expected match within /24")
	}
	if fn("192.168.2.1") {
		t.Error("expected no match outside /24")
	}
}

func TestCIDRMatcher_InvalidCIDR(t *testing.T) {
	_, err := buildCIDRMatcher("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestCIDRMatcher_InvalidIP(t *testing.T) {
	fn, err := buildCIDRMatcher("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("not-an-ip") {
		t.Error("should not match invalid IP")
	}
}

func TestCIDRMatcher_NilValue(t *testing.T) {
	fn, err := buildCIDRMatcher("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn(nil) {
		t.Error("should not match nil")
	}
}

// --- base64 encoding tests ---

func TestBase64EncodeValues(t *testing.T) {
	values := []interface{}{"hello", "world", 42}
	encoded := base64EncodeValues(values)
	if encoded[0] != "aGVsbG8=" {
		t.Errorf("expected aGVsbG8=, got %v", encoded[0])
	}
	if encoded[1] != "d29ybGQ=" {
		t.Errorf("expected d29ybGQ=, got %v", encoded[1])
	}
	// Non-string values should be preserved.
	if encoded[2] != 42 {
		t.Errorf("expected 42, got %v", encoded[2])
	}
}

// --- buildModifierChain tests ---

func TestModifierChain_NoModifiers_OR(t *testing.T) {
	fn, err := buildModifierChain(nil, []interface{}{"alpha", "beta"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alpha") {
		t.Error("expected OR: alpha should match")
	}
	if !fn("beta") {
		t.Error("expected OR: beta should match")
	}
	if fn("gamma") {
		t.Error("expected OR: gamma should not match")
	}
}

func TestModifierChain_ContainsAll(t *testing.T) {
	fn, err := buildModifierChain([]string{"contains", "all"}, []interface{}{"foo", "bar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("foobar") {
		t.Error("expected AND: foobar contains both foo and bar")
	}
	if !fn("barfoo") {
		t.Error("expected AND: barfoo contains both foo and bar")
	}
	if fn("foo") {
		t.Error("expected AND: foo only contains foo, not bar")
	}
}

func TestModifierChain_Base64Contains(t *testing.T) {
	// base64("hello") = "aGVsbG8="
	fn, err := buildModifierChain([]string{"base64", "contains"}, []interface{}{"hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("xxxaGVsbG8=yyy") {
		t.Error("expected base64+contains to match")
	}
	if fn("hello") {
		t.Error("should not match plain hello (not base64)")
	}
}

func TestModifierChain_NoValues(t *testing.T) {
	fn, err := buildModifierChain(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No values → matches anything (field-exists check).
	if !fn("anything") {
		t.Error("expected no-values to match anything")
	}
}

func TestModifierChain_UnknownModifier(t *testing.T) {
	// Unknown modifiers should be silently ignored.
	fn, err := buildModifierChain([]string{"future_modifier"}, []interface{}{"value"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("value") {
		t.Error("expected plain match with unknown modifier ignored")
	}
}

func TestModifierChain_InvalidRegex(t *testing.T) {
	_, err := buildModifierChain([]string{"re"}, []interface{}{"[invalid"})
	if err == nil {
		t.Error("expected error for invalid regex in chain")
	}
}

func TestModifierChain_InvalidCIDR(t *testing.T) {
	_, err := buildModifierChain([]string{"cidr"}, []interface{}{"not-cidr"})
	if err == nil {
		t.Error("expected error for invalid CIDR in chain")
	}
}

// --- matchAnySliceElement tests ---

func TestMatchAnySliceElement_StringSlice(t *testing.T) {
	fn := buildExactMatcher("network")
	if !matchAnySliceElement([]string{"network", "process"}, fn) {
		t.Error("expected match in string slice")
	}
	if matchAnySliceElement([]string{"process", "file"}, fn) {
		t.Error("expected no match in string slice")
	}
}

func TestMatchAnySliceElement_InterfaceSlice(t *testing.T) {
	fn := buildExactMatcher("alert")
	vals := []interface{}{"alert", "info"}
	if !matchAnySliceElement(vals, fn) {
		t.Error("expected match in interface slice")
	}
}

func TestMatchAnySliceElement_ScalarValue(t *testing.T) {
	fn := buildExactMatcher("test")
	if !matchAnySliceElement("test", fn) {
		t.Error("expected match for scalar")
	}
	if matchAnySliceElement("other", fn) {
		t.Error("expected no match for scalar")
	}
}

// --- Adversarial modifier tests ---

func TestContainsMatcher_SpecialChars(t *testing.T) {
	fn := buildContainsMatcher("c:\\windows\\")
	if !fn("c:\\windows\\system32") {
		t.Error("expected match with backslash")
	}
}

func TestExactMatcher_EmptyString(t *testing.T) {
	fn := buildExactMatcher("")
	if !fn("") {
		t.Error("empty should match empty")
	}
	if fn("notempty") {
		t.Error("empty should not match non-empty")
	}
}

func TestRegexMatcher_DotStar(t *testing.T) {
	fn, err := buildRegexMatcher(`.*`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("anything") {
		t.Error("expected .* to match anything")
	}
	if !fn("") {
		t.Error("expected .* to match empty string")
	}
}

func TestCIDRMatcher_IPv6(t *testing.T) {
	fn, err := buildCIDRMatcher("::1/128")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("::1") {
		t.Error("expected ::1 to match ::1/128")
	}
	if fn("::2") {
		t.Error("expected ::2 to not match ::1/128")
	}
}

func TestModifierChain_AllWithSingleValue(t *testing.T) {
	// "all" with a single value should behave the same as without "all".
	fn, err := buildModifierChain([]string{"contains", "all"}, []interface{}{"test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("testing") {
		t.Error("expected match with all+single value")
	}
	if fn("nope") {
		t.Error("expected no match")
	}
}
