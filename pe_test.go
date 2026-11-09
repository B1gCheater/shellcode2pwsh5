package main

import "testing"

func TestWindowsCommandLine(t *testing.T) {
	args := []string{"--path", `C:\Program Files\`, "", `a"b`, `a\"b`, "--path"}
	want := `"--path" "C:\Program Files\\" "" "a\"b" "a\\\"b" "--path"`
	if got := windowsCommandLine(args); got != want {
		t.Errorf("command line = %q, want %q", got, want)
	}
}
