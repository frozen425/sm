package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestToKebabCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"DATABASE_URL", "database-url"},
		{"db_password", "db-password"},
		{"API KEY", "api-key"},
		{"simple", "simple"},
	}

	for _, test := range tests {
		actual := toKebabCase(test.input)
		if actual != test.expected {
			t.Errorf("toKebabCase(%q) = %q; want %q", test.input, actual, test.expected)
		}
	}
}

func TestGenerateCandidates(t *testing.T) {
	// Test candidate generation with service name set
	candidatesWithSvc := generateCandidates("DATABASE_URL", "dev", "auth")
	expectedWithSvc := []string{
		"auth-database-url-dev",
		"auth-DATABASE_URL-dev",
		"auth-database-url-DEV",
		"auth-DATABASE_URL-DEV",
		"dev-auth-database-url",
		"dev-auth-DATABASE_URL",
		"DEV-auth-database-url",
		"DEV-auth-DATABASE_URL",
		"auth-database-url",
		"auth-DATABASE_URL",
		"AUTH-DATABASE_URL",
		"dev-database-url",
		"dev-DATABASE_URL",
		"DEV-database-url",
		"DEV-DATABASE_URL",
		"database-url-dev",
		"DATABASE_URL-dev",
		"database-url-DEV",
		"DATABASE_URL-DEV",
		"database-url",
		"DATABASE_URL",
	}
	if !reflect.DeepEqual(candidatesWithSvc, expectedWithSvc) {
		t.Errorf("generateCandidates(DATABASE_URL, dev, auth) failed.\nGot: %v\nWant: %v", candidatesWithSvc, expectedWithSvc)
	}

	// Test candidate generation without service name
	candidatesNoSvc := generateCandidates("DATABASE_URL", "prod", "")
	expectedNoSvc := []string{
		"prod-database-url",
		"prod-DATABASE_URL",
		"PROD-database-url",
		"PROD-DATABASE_URL",
		"database-url-prod",
		"DATABASE_URL-prod",
		"database-url-PROD",
		"DATABASE_URL-PROD",
		"database-url",
		"DATABASE_URL",
	}
	if !reflect.DeepEqual(candidatesNoSvc, expectedNoSvc) {
		t.Errorf("generateCandidates(DATABASE_URL, prod, \"\") failed.\nGot: %v\nWant: %v", candidatesNoSvc, expectedNoSvc)
	}
}

func TestSanitizeReason(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sm env injection", "sm env injection"},
		{"sm-env-injection", "smenvinjection"}, // Should remove hyphens to prevent base64
		{"sm env injection for auth!", "sm env injection for auth"},
		{"  spaces   trim  ", "spaces   trim"},
		{"", "sm env injection"}, // fallback
		{"!@#$%^&*", "sm env injection"}, // fallback
	}

	for _, test := range tests {
		actual := sanitizeReason(test.input)
		if actual != test.expected {
			t.Errorf("sanitizeReason(%q) = %q; want %q", test.input, actual, test.expected)
		}
	}
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		uri            string
		defaultProject string
		wantProject    string
		wantSecret     string
		wantVersion    string
		wantErr        bool
	}{
		{"sm://", "my-project", "my-project", "", "latest", false},
		{"sm://auto", "my-project", "my-project", "", "latest", false},
		{"sm://db-secret", "my-project", "my-project", "db-secret", "latest", false},
		{"sm://db-secret/2", "my-project", "my-project", "db-secret", "2", false},
		{"sm://db-secret/latest", "my-project", "my-project", "db-secret", "latest", false},
		{"sm://other-project/db-secret", "my-project", "other-project", "db-secret", "latest", false},
		{"sm://other-project/db-secret/3", "my-project", "other-project", "db-secret", "3", false},
		{"sm://projects/other-project/secrets/db-secret", "my-project", "other-project", "db-secret", "latest", false},
		{"sm://projects/other-project/secrets/db-secret/versions/4", "my-project", "other-project", "db-secret", "4", false},
	}

	for _, test := range tests {
		proj, sec, ver, err := ParseURI(test.uri, test.defaultProject)
		if (err != nil) != test.wantErr {
			t.Errorf("ParseURI(%q) error state = %v, expected error state = %v", test.uri, err != nil, test.wantErr)
			continue
		}
		if !test.wantErr {
			if proj != test.wantProject || sec != test.wantSecret || ver != test.wantVersion {
				t.Errorf("ParseURI(%q):\nGot: proj=%q, sec=%q, ver=%q\nWant: proj=%q, sec=%q, ver=%q",
					test.uri, proj, sec, ver, test.wantProject, test.wantSecret, test.wantVersion)
			}
		}
	}
}

func TestMergeEnviron(t *testing.T) {
	base := []string{"PATH=/bin", "DEBUG=false", "PORT=80"}
	overrides := map[string]string{
		"DEBUG": "true",
		"TOKEN": "secret-value",
	}

	merged := mergeEnviron(base, overrides)
	expectedMap := map[string]string{
		"PATH":  "/bin",
		"DEBUG": "true",
		"PORT":  "80",
		"TOKEN": "secret-value",
	}

	// Reconstruct map from merged environment slices
	actualMap := make(map[string]string)
	for _, e := range merged {
		split := strings.SplitN(e, "=", 2)
		if len(split) == 2 {
			actualMap[split[0]] = split[1]
		}
	}

	if !reflect.DeepEqual(actualMap, expectedMap) {
		t.Errorf("mergeEnviron failed.\nGot: %v\nWant: %v", actualMap, expectedMap)
	}
}

func TestExtractDestination(t *testing.T) {
	tests := []struct {
		uri         string
		expectedDst string
		expectedURI string
	}{
		{"sm://", "", "sm://"},
		{"sm://auto", "", "sm://auto"},
		{"sm://my-secret", "", "sm://my-secret"},
		{"sm://my-secret?destination=/tmp/file.txt", "/tmp/file.txt", "sm://my-secret"},
		{"sm://project/my-secret?destination=file.txt", "file.txt", "sm://project/my-secret"},
		{"sm://project/my-secret/1?destination=/tmp/out", "/tmp/out", "sm://project/my-secret/1"},
		{"sm://projects/p/secrets/s/versions/1?destination=/var/run/secret", "/var/run/secret", "sm://projects/p/secrets/s/versions/1"},
	}

	for _, test := range tests {
		dst, uri := extractDestination(test.uri)
		if dst != test.expectedDst || uri != test.expectedURI {
			t.Errorf("extractDestination(%q) = (%q, %q); want (%q, %q)",
				test.uri, dst, uri, test.expectedDst, test.expectedURI)
		}
	}
}

func FuzzParseURI(f *testing.F) {
	seeds := []string{
		"sm://",
		"sm://auto",
		"sm://db-secret",
		"sm://db-secret/2",
		"sm://other-project/db-secret",
		"sm://projects/other-project/secrets/db-secret/versions/4",
	}
	for _, seed := range seeds {
		f.Add(seed, "default-proj")
	}
	f.Fuzz(func(t *testing.T, uri string, defaultProject string) {
		_, _, _, _ = ParseURI(uri, defaultProject)
	})
}

func FuzzSanitizeReason(f *testing.F) {
	seeds := []string{
		"sm env injection",
		"sm-env-injection",
		"spaces   trim",
		"!@#$%^&*",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, reason string) {
		_ = sanitizeReason(reason)
	})
}

func FuzzExtractDestination(f *testing.F) {
	seeds := []string{
		"sm://",
		"sm://my-secret?destination=/tmp/file.txt",
		"sm://projects/p/secrets/s/versions/1?destination=/var/run/secret",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		_, _ = extractDestination(uri)
	})
}
