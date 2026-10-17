package web

import "embed"

// Files contains the browser UI bundled into the server binary.
//
//go:embed index.html css js
var Files embed.FS
