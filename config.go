package main

import "encoding/base64"

// TODO: use envvars instead. 12 factor yay
var dataKey, _ = base64.StdEncoding.DecodeString("2AP/N4ajPY3rsjpaIagjjA+JHjDbIw+hI+uI32jnrP4=")
