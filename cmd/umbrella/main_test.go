package main

import (
	"strings"
	"testing"
)

func TestPlanValidate(t *testing.T) {
	steps, err := plan("validate", "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("got %d validation steps, want 2", len(steps))
	}
	if !strings.Contains(strings.Join(steps[0].args, " "), "env-guard.mjs") {
		t.Fatalf("first step is not env-guard: %#v", steps[0])
	}
	if !strings.Contains(strings.Join(steps[1].args, " "), "c4-validate.mjs") {
		t.Fatalf("second step is not C4 validation: %#v", steps[1])
	}
}

func TestPlanFullAddsSmokeOnlyWithBaseURL(t *testing.T) {
	without, err := plan("full", "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	with, err := plan("full", "/repo", "https://staging.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(without) != 5 {
		t.Fatalf("got %d steps without endpoint, want 5", len(without))
	}
	if len(with) != 6 {
		t.Fatalf("got %d steps with endpoint, want 6", len(with))
	}
	if got := with[len(with)-1].args[len(with[len(with)-1].args)-1]; got != "https://staging.example.test" {
		t.Fatalf("smoke URL = %q", got)
	}
}

func TestPlanRejectsUnknownCommand(t *testing.T) {
	if _, err := plan("deploy-prod", "/repo", ""); err == nil {
		t.Fatal("expected unknown command error")
	}
}
