package utils_test

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"tinyauth/internal/utils"
)

func TestGetUpperDomain(t *testing.T) {
	url := "https://sub1.sub2.domain.com:8080"
	expected := "sub2.domain.com"
	result, err := utils.GetUpperDomain(url)
	if err != nil {
		t.Fatalf("Error getting root url: %v", err)
	}
	if expected != result {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestGetUpperDomainNoSubdomain(t *testing.T) {
	url := "https://domain.com"
	expected := "domain.com"
	result, err := utils.GetUpperDomain(url)
	if err != nil {
		t.Fatalf("Error getting root url: %v", err)
	}
	if expected != result {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestReadFile(t *testing.T) {
	err := os.WriteFile("/tmp/test.txt", []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}
	data, err := utils.ReadFile("/tmp/test.txt")
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}
	if data != "test" {
		t.Fatalf("Expected test, got %v", data)
	}
	os.Remove("/tmp/test.txt")
}

func TestGetSecret(t *testing.T) {
	file := "/tmp/test.txt"
	expected := "test"
	os.WriteFile(file, []byte(fmt.Sprintf("\n\n    %s   \n", expected)), 0644)
	result := utils.GetSecret("", file)
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
	result = utils.GetSecret(expected, "")
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
	os.Remove(file)
}

func TestParseSecretFile(t *testing.T) {
	content := "\n\n    \nsecret\n    \n"
	expected := "secret"
	result := utils.ParseSecretFile(content)
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestCheckFilter(t *testing.T) {
	if !utils.CheckFilter("user1,user2", "user1") {
		t.Fatalf("Expected true")
	}
	if !utils.CheckFilter("/^user[0-9]+$/", "user1") {
		t.Fatalf("Expected true")
	}
	if !utils.CheckFilter("", "user1") {
		t.Fatalf("Expected true")
	}
	if utils.CheckFilter("user1,user2", "user3") {
		t.Fatalf("Expected false")
	}
}

func TestSanitizeHeader(t *testing.T) {
	if utils.SanitizeHeader("X-Header=value") != "X-Header=value" {
		t.Fatalf("Expected same header")
	}
	if utils.SanitizeHeader("X-Header=val\nue") != "X-Header=value" {
		t.Fatalf("Expected sanitized header")
	}
}

func TestParseHeaders(t *testing.T) {
	headers := []string{"X-Hea\x00der1=value1", "X-Header2=value\n2"}
	expected := map[string]string{"X-Header1": "value1", "X-Header2": "value2"}
	result := utils.ParseHeaders(headers)
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestFilterIP(t *testing.T) {
	ip := "10.10.10.10"
	ok, err := utils.FilterIP("10.10.10.0/24", ip)
	if err != nil || !ok {
		t.Fatalf("Expected match")
	}
	ok, err = utils.FilterIP("10.10.15.0/24", ip)
	if err != nil || ok {
		t.Fatalf("Expected no match")
	}
}

func TestDeriveKey(t *testing.T) {
	result, err := utils.DeriveKey("master", "info")
	if err != nil {
		t.Fatalf("Error deriving key: %v", err)
	}
	if result == "" {
		t.Fatalf("Expected non empty key")
	}
}

func TestCoalesceToString(t *testing.T) {
	if utils.CoalesceToString("test") != "test" {
		t.Fatalf("Expected same string")
	}
	if utils.CoalesceToString([]any{any("a"), any("b")}) != "a,b" {
		t.Fatalf("Expected joined string")
	}
	if utils.CoalesceToString(123) != "" {
		t.Fatalf("Expected empty string")
	}
}
