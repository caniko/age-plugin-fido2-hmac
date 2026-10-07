package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/olastor/age-plugin-fido2-hmac/pkg/plugin"
)

func TestSessionCommandHelper(t *testing.T) {
	if os.Getenv("FIDO_SESSION_COMMAND_HELPER") != "1" {
		return
	}
	if os.Getenv(plugin.SessionSocketEnv) == "" || os.Getenv(plugin.SessionCapabilityEnv) == "" {
		os.Exit(3)
	}
	if os.Args[len(os.Args)-1] == "failure" {
		os.Exit(7)
	}
	os.Exit(0)
}

func TestRunCleansSessionOnEveryCommandExit(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "start-failure"} {
		t.Run(outcome, func(t *testing.T) {
			// A short directory also lets this exercise a real socket on macOS.
			directory, err := os.MkdirTemp("", "fido-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			t.Setenv("XDG_RUNTIME_DIR", directory)
			t.Setenv("FIDO_SESSION_COMMAND_HELPER", "1")
			args := []string{os.Args[0], "-test.run=^TestSessionCommandHelper$", "--", outcome}
			want := 0
			switch outcome {
			case "failure":
				want = 7
			case "start-failure":
				args = []string{filepath.Join(directory, "missing-command")}
				want = 1
			}
			if got := run(args); got != want {
				t.Fatalf("command exit status = %d, want %d", got, want)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("command left session files or directories: %v", entries)
			}
		})
	}
}
