//go:build unix

// pig-rex stands in for pig when pigpen-subagents starts a child (PIG_SUBAGENT_PIG_BINARY): in a Rex terminal the child
// runs as an interactive pig in a split beside the parent's pane, and its answer comes back on standard output as the
// hidden print-mode child's would. Anywhere else, and for any other invocation, it is pig.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	envFlag = "--pig-rex-env"
	taskMax = 100 << 10 // the task travels as an argument
)

var poll = 500 * time.Millisecond

// rexCLI runs the rex CLI and returns its standard output; a failure carries its standard error.
var rexCLI = func(bin string, args ...string) ([]byte, error) {
	out, err := exec.Command(bin, args...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		err = errors.New(strings.TrimSpace(string(ee.Stderr)))
	}
	return out, err
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "pig-rex:", err)
		return 1
	}
	// In the pane: take the parent's environment from the file, keep the pane's own REX_ variables, become pig.
	if len(args) >= 3 && args[0] == envFlag {
		b, err := os.ReadFile(args[1])
		if err != nil {
			return fail(err)
		}
		_ = os.Remove(args[1])
		return fail(syscall.Exec(args[2], args[2:], paneEnv(strings.Split(string(b), "\x00"), os.Environ())))
	}
	pig := os.Getenv("PIG_REX_PIG")
	if pig == "" {
		var err error
		if pig, err = exec.LookPath("pig"); err != nil {
			return fail(err)
		}
	}
	r := rex{bin: "rex", session: os.Getenv("REX_SESSION"), parent: os.Getenv("REX_BLOCK")}
	if d := os.Getenv("REX_BIN_DIR"); d != "" {
		r.bin = filepath.Join(d, "rex") // the CLI of the server this terminal runs in
	}
	if r.session == "" || r.parent == "" || len(args) == 0 || args[0] != "--print" {
		return fail(syscall.Exec(pig, append([]string{pig}, args...), os.Environ()))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	task, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fail(err)
	}
	self, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	cwd, _ := os.Getwd()
	res, err := r.run(ctx, []string{self, envFlag}, pig, args, string(task), cwd, os.Environ(), os.Getenv("PIG_AGENT_ROLE"))
	var np noPane
	if errors.As(err, &np) {
		fmt.Fprintf(os.Stderr, "pig-rex: %s; the child runs without a pane\n", np)
		cmd := exec.CommandContext(ctx, pig, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(task), os.Stdout, os.Stderr
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return fail(err)
		}
		return 0
	}
	if err != nil {
		return fail(err)
	}
	fmt.Print(res.stdout)
	if res.stderr != "" {
		fmt.Fprintln(os.Stderr, res.stderr)
	}
	return res.exit
}

// paneEnv is the child's environment: the parent's, with the REX_ variables Rex gave the pane in place of the parent's.
func paneEnv(parent, pane []string) []string {
	var out []string
	for _, kv := range parent {
		if kv != "" && !strings.HasPrefix(kv, "REX_") {
			out = append(out, kv)
		}
	}
	for _, kv := range pane {
		if strings.HasPrefix(kv, "REX_") {
			out = append(out, kv)
		}
	}
	return out
}

type rex struct{ bin, session, parent string }

type result struct {
	stdout, stderr string
	exit           int
}

// noPane is why no pane was opened; the child has not started and can run hidden.
type noPane string

func (e noPane) Error() string { return string(e) }

// call is one block method of Rex's terminal: its JSON result decoded into result.
func (r rex) call(method, block string, result any) error {
	args, _ := json.Marshal(map[string]string{"block_id": block})
	out, err := rexCLI(r.bin, "api", "call", "-s", r.session, "com.superlogical.terminal."+method, string(args))
	if err != nil {
		return err
	}
	return json.Unmarshal(out, result)
}

// state is a block's state: whether its program ended and with which code, else the status PiG reported (OSC 7501).
func (r rex) state(block string) (st string, finished bool, exit int, err error) {
	var proc struct {
		LastExit *struct {
			ExitCode int `json:"exit_code"`
		} `json:"last_exit"`
	}
	if err := r.call("process", block, &proc); err != nil {
		return "", false, 0, err
	}
	if proc.LastExit != nil {
		return "", true, proc.LastExit.ExitCode, nil
	}
	var status struct {
		Records []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"records"`
	}
	if err := r.call("program_status", block, &status); err != nil {
		return "", false, 0, err
	}
	for _, rec := range status.Records {
		if rec.ID == "" { // the root record: PiG reports no other
			st = rec.State
		}
	}
	return st, false, 0, nil
}

// run runs the child in a pane and waits for the end of its first turn. launcher is the command that gives the child
// its environment (this program and envFlag). A noPane error means nothing started; after the split, a failure is the
// child's and it never runs twice.
func (r rex) run(ctx context.Context, launcher []string, pig string, args []string, task, cwd string, env []string, agent string) (result, error) {
	if len(task) > taskMax {
		return result{}, noPane("the task is over 100 KiB")
	}
	if _, _, _, err := r.state(r.parent); err != nil {
		return result{}, noPane(fmt.Sprintf("Rex is not reachable (%v)", err))
	}
	// shortcut: the child's session is not kept; put it in the parent's session directory when someone wants to resume one.
	dir, err := os.MkdirTemp("", "pig-rex-")
	if err != nil {
		return result{}, err
	}
	defer os.RemoveAll(dir)
	// The environment travels in a file only this user can read, so it is neither on a command line nor a login shell's.
	envFile := filepath.Join(dir, "env")
	if err := os.WriteFile(envFile, []byte(strings.Join(env, "\x00")), 0o600); err != nil {
		return result{}, err
	}

	id := uuidV4()
	argv := append([]string{"split", "-s", r.session, "-b", r.parent, "--focus=false", "--shell=none", "--keep-open",
		"--cwd", cwd, "--label", paneName(agent, randHex(3)), "--json", "--"}, launcher...)
	argv = append(append(argv, envFile, pig), paneArgs(args, dir, id, task)...)
	out, err := rexCLI(r.bin, argv...)
	if err != nil {
		return result{}, fmt.Errorf("rex: %w", err)
	}
	var started struct {
		BlockIDs []string `json:"block_ids"`
	}
	if json.Unmarshal(out, &started) != nil || len(started.BlockIDs) == 0 || started.BlockIDs[0] == "" {
		return result{}, errors.New("rex started the child without a block; the child is unknown")
	}
	block := started.BlockIDs[0]
	defer func() { _, _ = rexCLI(r.bin, "block", "close", "-s", r.session, block) }() // ends the child too

	// Rex counts no turns: the first turn has ended at done or error, or at idle once the child was seen working.
	turned := false
	for {
		st, finished, exit, err := r.state(block)
		if err != nil {
			return result{exit: 1, stderr: fmt.Sprintf("Rex stopped answering while the child ran in %s: %v", block, err)}, nil
		}
		if finished || st == "done" || st == "error" || st == "idle" && turned {
			res, ok := sessionAnswer(dir, id)
			switch {
			case ok:
			case finished:
				screen, _ := rexCLI(r.bin, "capture", "-s", r.session, "-b", block, "--trim")
				lines := strings.Split(strings.TrimSpace(string(screen)), "\n")
				res = result{exit: exit, stderr: strings.Join(lines[max(0, len(lines)-40):], "\n")}
				if res.exit == 0 {
					res.exit = 1 // it ended cleanly without answering (/quit): not a success
				}
			default:
				res = result{exit: 1, stderr: "no answer in the child's session file"}
			}
			return res, nil
		}
		turned = turned || st == "working" || st == "blocked"
		select {
		case <-ctx.Done():
			return result{exit: 130, stderr: "cancelled"}, nil
		case <-time.After(poll):
		}
	}
}

// The helpers below come from pigpen-subagents' Herdr Desktop pane runner (panes.go), see CREDITS.md.

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func uuidV4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// paneArgs turns a print-mode child's argv into an interactive one: the leading --print goes, the session is pinned so
// its transcript can be found, and the prompt follows "--".
func paneArgs(args []string, sessionDir, sessionID, prompt string) []string {
	if len(args) > 0 && args[0] == "--print" {
		args = args[1:]
	}
	out := append([]string{}, args...)
	return append(out, "--session-dir", sessionDir, "--session-id", sessionID, "--", prompt)
}

// paneName is a label of at most 32 characters ending in "-"+suffix.
func paneName(agent, suffix string) string {
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(agent))
	if name == "" {
		name = "agent"
	}
	if max := 32 - 1 - len(suffix); len(name) > max {
		name = name[:max]
	}
	return name + "-" + suffix
}

// sessionAnswer reads the child's final answer from its transcript, mirroring PiG print mode: the last message
// decides. It reports false when there is no transcript or it ends mid-turn (not an assistant message, or stopReason toolUse).
func sessionAnswer(dir, id string) (result, bool) {
	files, _ := filepath.Glob(filepath.Join(dir, "*_"+id+".jsonl"))
	if len(files) == 0 {
		return result{}, false
	}
	f, err := os.Open(files[len(files)-1])
	if err != nil {
		return result{}, false
	}
	defer f.Close()
	type message struct {
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason   string `json:"stopReason"`
		ErrorMessage string `json:"errorMessage"`
	}
	var last *message
	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadBytes('\n')
		var l struct {
			Type    string  `json:"type"`
			Message message `json:"message"`
		}
		if json.Unmarshal(line, &l) == nil && l.Type == "message" {
			m := l.Message
			last = &m
		}
		if err != nil {
			break
		}
	}
	// the answer exists only when the transcript ends with a finished assistant message, not mid-turn
	if last == nil || last.Role != "assistant" || last.StopReason == "toolUse" {
		return result{}, false
	}
	if last.StopReason == "error" || last.StopReason == "aborted" {
		msg := last.ErrorMessage
		if msg == "" {
			msg = "Request " + last.StopReason
		}
		return result{exit: 1, stderr: msg}, true
	}
	var res result
	for _, c := range last.Content {
		if c.Type == "text" {
			res.stdout += c.Text + "\n"
		}
	}
	if last.StopReason == "length" {
		res.exit = 1
		res.stderr = "Response was truncated: the model reached its output token limit."
	}
	return res, true
}
