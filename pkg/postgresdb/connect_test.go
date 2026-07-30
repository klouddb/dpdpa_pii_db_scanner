package postgresdb

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestBuildConnectionString(t *testing.T) {
	base := Postgres{
		Host:     "localhost",
		Port:     "5432",
		User:     "postgres",
		Password: "password",
		DBName:   "testdb",
	}

	tests := []struct {
		name string
		edit func(*Postgres)
		want string
	}{
		{
			name: "TLS required by default",
			want: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=require",
		},
		{
			name: "TLS explicitly disabled for local development",
			edit: func(conf *Postgres) {
				conf.SSLmode = "disable"
			},
			want: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=disable",
		},
		{
			name: "full certificate verification",
			edit: func(conf *Postgres) {
				conf.SSLmode = "verify-full"
				conf.SSLcert = "/path/to/client.crt"
				conf.SSLkey = "/path/to/client.key"
				conf.SSLrootcert = "/path/to/root.crt"
			},
			want: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=verify-full sslcert=/path/to/client.crt sslkey=/path/to/client.key sslrootcert=/path/to/root.crt",
		},
		{
			name: "empty optional certificate values are omitted",
			edit: func(conf *Postgres) {
				conf.SSLmode = "verify-ca"
				conf.SSLrootcert = "/path/to/root.crt"
			},
			want: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=verify-ca sslrootcert=/path/to/root.crt",
		},
		{
			name: "empty password is omitted",
			edit: func(conf *Postgres) {
				conf.Password = ""
			},
			want: "host=localhost port=5432 user=postgres dbname=testdb sslmode=require",
		},
		{
			name: "spaces quotes backslashes and equals are escaped",
			edit: func(conf *Postgres) {
				conf.User = "app user"
				conf.Password = `pa ss'w\ord=1`
				conf.DBName = "db=name"
			},
			want: `host=localhost port=5432 user='app user' password='pa ss\'w\\ord=1' dbname='db=name' sslmode=require`,
		},
		{
			name: "IPv6 host and custom port",
			edit: func(conf *Postgres) {
				conf.Host = "::1"
				conf.Port = "5433"
			},
			want: "host=::1 port=5433 user=postgres password=password dbname=testdb sslmode=require",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := base
			if tt.edit != nil {
				tt.edit(&conf)
			}

			got := BuildConnectionString(conf)
			if got != tt.want {
				t.Fatalf("BuildConnectionString() = %q, want %q", got, tt.want)
			}

			db, err := ConnectDatabaseUsingConnectionString(got, false)
			if err != nil {
				t.Fatalf("parse generated connection string: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatalf("close database handle: %v", err)
			}
		})
	}
}

func TestValidateSSLMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{name: "default", mode: ""},
		{name: "disable", mode: "disable"},
		{name: "allow", mode: "allow"},
		{name: "prefer", mode: "prefer"},
		{name: "require", mode: "require"},
		{name: "verify CA", mode: "verify-ca"},
		{name: "verify full", mode: "verify-full"},
		{name: "invalid", mode: "enabled", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSLMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSSLMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestConnectionErrorsDoNotLogPasswords(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		secret     string
	}{
		{
			name:       "invalid SSL mode",
			connection: "host=localhost password=supersecret sslmode=not-a-mode",
			secret:     "supersecret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			previousLogger := log.Logger
			log.Logger = zerolog.New(&output)
			t.Cleanup(func() {
				log.Logger = previousLogger
			})

			db, err := ConnectDatabaseUsingConnectionString(tt.connection, true)
			if db != nil {
				_ = db.Close()
			}
			if err == nil {
				t.Fatal("expected invalid connection string to return an error")
			}
			if strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("connection error exposed password %q", tt.secret)
			}
			if strings.Contains(output.String(), tt.secret) {
				t.Fatalf("connection error log exposed password %q", tt.secret)
			}
		})
	}
}
