package postgresdb

import (
	"strings"
	"testing"
)

func TestUriHostAndDB(t *testing.T) {
	tests := []struct {
		name       string
		uri        string
		wantHost   string
		wantDBName string
		wantErr    string
	}{
		{
			name:       "basic URI",
			uri:        "postgres://user:pass@localhost:5432/mydb?sslmode=disable",
			wantHost:   "localhost",
			wantDBName: "mydb",
		},
		{
			name:       "postgresql scheme",
			uri:        "postgresql://alice@db.example.com/analytics",
			wantHost:   "db.example.com",
			wantDBName: "analytics",
		},
		{
			name:       "IPv6 host",
			uri:        "postgres://u:p@[::1]:5432/testdb?sslmode=disable",
			wantHost:   "::1",
			wantDBName: "testdb",
		},
		{
			name:    "missing scheme",
			uri:     "localhost:5432/mydb",
			wantErr: "unsupported connection URI scheme",
		},
		{
			name:    "missing database",
			uri:     "postgres://user:pass@localhost:5432/",
			wantErr: "missing a database name",
		},
		{
			name:    "missing host",
			uri:     "postgres:///mydb",
			wantErr: "missing a host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, dbname, err := uriHostAndDB(tt.uri)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.wantHost || dbname != tt.wantDBName {
				t.Fatalf("got host=%q db=%q, want host=%q db=%q", host, dbname, tt.wantHost, tt.wantDBName)
			}
		})
	}
}

func TestIsConnectionURI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"postgres://user:pass@host/db", true},
		{"postgresql://user:pass@host/db", true},
		{"  Postgres://user:pass@host/db", true},
		{"host=localhost dbname=mydb", false},
		{"", false},
		{"http://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsConnectionURI(tt.input); got != tt.want {
				t.Fatalf("IsConnectionURI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
