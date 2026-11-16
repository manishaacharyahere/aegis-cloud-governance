package database

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manishaacharyahere/aegis-cloud-governance/migrations"
)

func TestLoadMigrationsOrdersAndChecksums(t *testing.T) {
	fsys := fstest.MapFS{
		"0002_second.sql": {Data: []byte("SELECT 2;")},
		"0001_first.sql":  {Data: []byte("SELECT 1;")},
		"embed.go":        {Data: []byte("package migrations")},
	}
	got, err := LoadMigrations(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Version != 1 || got[1].Version != 2 || got[0].Name != "first" {
		t.Fatalf("unexpected order: %+v", got)
	}
	if len(got[0].Checksum) != 64 || got[0].Checksum == got[1].Checksum {
		t.Errorf("bad checksums: %q %q", got[0].Checksum, got[1].Checksum)
	}
}

func TestLoadMigrationsRejectsInvalidSets(t *testing.T) {
	tests := map[string]struct {
		fs   fstest.MapFS
		want string
	}{
		"bad name":  {fstest.MapFS{"1_x.sql": {}}, "invalid migration file name"},
		"uppercase": {fstest.MapFS{"0001_Init.sql": {}}, "invalid migration file name"},
		"zero":      {fstest.MapFS{"0000_x.sql": {}}, "start at 0001"},
		"gap":       {fstest.MapFS{"0001_a.sql": {}, "0003_c.sql": {}}, "contiguous"},
		"duplicate": {fstest.MapFS{"0001_a.sql": {}, "0001_b.sql": {}}, "duplicate"},
		"stray":     {fstest.MapFS{"0001_a.sql": {}, "notes.txt": {}}, "invalid migration file name"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := LoadMigrations(tt.fs)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	got, err := LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no embedded migrations")
	}
}
