// Package migrations embeds the ordered SQL schema migrations.
//
// Files are named NNNN_description.sql. Applied migrations must never be
// edited: the migrator stores a checksum and refuses to run if it changes.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
