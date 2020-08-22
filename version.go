package main

import "fmt"

const version = "0.2.1"

var revision = ""

func FmtVersion() string {
	if revision == "" {
		return version
	}
	return fmt.Sprintf("%s, build %s", version, revision)
}
