package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type step struct {
	name string
	dir  string
	args []string
}

func main() {
	rootFlag := flag.String("root", ".", "repository root")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: umbrella [--root DIR] <validate|test|smoke|full>\n\n")
		fmt.Fprintln(flag.CommandLine.Output(), "Commands:")
		fmt.Fprintln(flag.CommandLine.Output(), "  validate  Run environment-template and C4 model/diagram validation")
		fmt.Fprintln(flag.CommandLine.Output(), "  test      Run umbrella-tooling and application regression tests")
		fmt.Fprintln(flag.CommandLine.Output(), "  smoke     Probe CFS_BASE_URL (defaults to http://127.0.0.1:5080)")
		fmt.Fprintln(flag.CommandLine.Output(), "  full      Run validate and test; also smoke when CFS_BASE_URL is set")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		fatal(fmt.Errorf("%s is not a repository root (go.mod not found)", root))
	}
	steps, err := plan(flag.Arg(0), root, os.Getenv("CFS_BASE_URL"))
	if err != nil {
		fatal(err)
	}
	for _, s := range steps {
		fmt.Printf("\n==> %s\n", s.name)
		cmd := exec.Command(s.args[0], s.args[1:]...)
		cmd.Dir = s.dir
		cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
		cmd.Env = os.Environ()
		if err := cmd.Run(); err != nil {
			fatal(fmt.Errorf("%s failed: %w", s.name, err))
		}
	}
	fmt.Printf("\numbrella: %s workflow passed (%d steps)\n", flag.Arg(0), len(steps))
}

func plan(command, root, baseURL string) ([]step, error) {
	node := func(name, dir string, args ...string) step {
		return step{name: name, dir: filepath.Join(root, dir), args: append([]string{"node"}, args...)}
	}
	validate := []step{
		node("environment template lint", ".", "tools/env-guard.mjs", "--file", "deploy/systemd/cfs.env.example", "--example"),
		node("C4 model and diagram validation", ".", "tools/c4-validate.mjs"),
	}
	tests := []step{
		node("umbrella tooling tests", ".", "--test", "tools/test/tooling.test.mjs"),
		node("application syntax check", "mvc", "--check", "server.mjs"),
		node("application regression tests", "mvc", "--test"),
	}
	switch command {
	case "validate":
		return validate, nil
	case "test":
		return tests, nil
	case "smoke":
		args := []string{"tools/smoke-probe.mjs"}
		if strings.TrimSpace(baseURL) != "" {
			args = append(args, baseURL)
		}
		return []step{node("HTTP endpoint smoke probe", ".", args...)}, nil
	case "full":
		all := append(append([]step{}, validate...), tests...)
		if strings.TrimSpace(baseURL) != "" {
			args := []string{"tools/smoke-probe.mjs", baseURL}
			all = append(all, node("HTTP endpoint smoke probe", ".", args...))
		}
		return all, nil
	default:
		return nil, fmt.Errorf("unknown command %q (expected validate, test, smoke, or full)", command)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "umbrella:", err)
	os.Exit(1)
}
