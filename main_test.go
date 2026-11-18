//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func eq(t *testing.T, got, want any, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %#v, want %#v", what, got, want)
	}
}

func assistant(content, stop string) string {
	return `{"type":"message","message":{"role":"assistant","content":[` + content + `],"stopReason":"` + stop + `"}}` + "\n"
}

func text(s string) string { return `{"type":"text","text":` + strconv.Quote(s) + `}` }

// rig is a scripted rex CLI with a stand-in child that writes `answer` as its session transcript. Each script entry is
// one poll of the child: a status ("working", "" for none yet), "exit/<code>" for an ended program, or "fail".
type rig struct {
	mu      sync.Mutex
	rex     rex
	calls   [][]string
	envFile string
	env     string
	envMode os.FileMode
	fail    map[string]bool // a command ("split", "parent") that fails
	noBlock bool
}

func (r *rig) count(cmd string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c[0] == cmd {
			n++
		}
	}
	return n
}

func (r *rig) run(ctx context.Context) (result, error) {
	return r.rex.run(ctx, []string{"/bin/pig-rex", envFlag}, "/bin/pig", []string{"--print", "--no-extensions"}, "Task: t", "/w",
		[]string{"PIG_SUBAGENT=1", "REX_BLOCK=block:p"}, "scout")
}

func newRig(t *testing.T, script []string, answer string) *rig {
	t.Helper()
	oldPoll, oldCLI := poll, rexCLI
	poll = time.Millisecond
	t.Cleanup(func() { poll, rexCLI = oldPoll, oldCLI })
	r := &rig{fail: map[string]bool{}, rex: rex{bin: "/rex/bin/rex", session: "session:s", parent: "block:p"}}
	step := 0
	rexCLI = func(bin string, args ...string) ([]byte, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		eq(t, bin, "/rex/bin/rex", "binary")
		r.calls = append(r.calls, args)
		switch args[0] {
		case "split":
			if r.fail["split"] {
				return nil, errors.New("no such session")
			}
			r.envFile = args[slices.Index(args, envFlag)+1]
			env, _ := os.ReadFile(r.envFile)
			st, _ := os.Stat(r.envFile)
			r.env, r.envMode = string(env), st.Mode().Perm()
			dir, id := args[slices.Index(args, "--session-dir")+1], args[slices.Index(args, "--session-id")+1]
			if answer != "" {
				os.WriteFile(filepath.Join(dir, "1_"+id+".jsonl"), []byte(assistant(text(answer), "stop")), 0o600)
			}
			if r.noBlock {
				return []byte(`{"block_ids":[]}`), nil
			}
			return []byte(`{"anchor_id":"block:p","block_ids":["block:c"],"split_ids":["split:x"],"revision":3}`), nil
		case "api":
			eq(t, args[:4], []string{"api", "call", "-s", "session:s"}, "api call")
			method, block := strings.TrimPrefix(args[4], "com.superlogical.terminal."), args[5]
			if block == `{"block_id":"block:p"}` {
				if r.fail["parent"] {
					return nil, errors.New("connection refused")
				}
				return []byte(`{"last_exit":null,"records":[{"state":"working","app":"pig"}]}`), nil
			}
			eq(t, block, `{"block_id":"block:c"}`, "the child's block")
			s := script[min(step, len(script)-1)]
			if method == "program_status" {
				step++
				if s == "" {
					return []byte(`{"records":[]}`), nil
				}
				return []byte(`{"records":[{"state":"` + s + `","app":"pig"},{"id":"build/test","state":"error"}]}`), nil
			}
			if s == "fail" {
				return nil, errors.New("server gone")
			}
			if code, ok := strings.CutPrefix(s, "exit/"); ok {
				return []byte(`{"last_exit":{"exit_code":` + code + `,"error":"exit status"}}`), nil
			}
			return []byte(`{"last_exit":null,"foreground":{"name":"pig"}}`), nil
		case "capture":
			return []byte(strings.Repeat("line\n", 50) + "fatal: x\n\n"), nil
		}
		return nil, nil
	}
	return r
}

var closeChild = []string{"block", "close", "-s", "session:s", "block:c"}

func TestRun(t *testing.T) {
	r := newRig(t, []string{"", "idle", "working", "blocked", "working", "done"}, "answer")
	res, err := r.run(context.Background())
	eq(t, err, nil, "error")
	eq(t, res, result{stdout: "answer\n"}, "result")

	split := r.calls[slices.IndexFunc(r.calls, func(c []string) bool { return c[0] == "split" })]
	i := slices.Index(split, "--")
	flags, argv := split[:i], split[i+1:]
	eq(t, flags[:10], []string{"split", "-s", "session:s", "-b", "block:p", "--focus=false", "--shell=none", "--keep-open", "--cwd", "/w"}, "flags")
	if !regexp.MustCompile(`^scout-[0-9a-f]{6}$`).MatchString(flags[slices.Index(flags, "--label")+1]) {
		t.Fatalf("label in %v", flags)
	}
	eq(t, slices.Contains(flags, "--json"), true, "--json")
	eq(t, argv[:2], []string{"/bin/pig-rex", envFlag}, "the launcher")
	eq(t, argv[3:5], []string{"/bin/pig", "--no-extensions"}, "pig, without --print")
	eq(t, argv[len(argv)-2:], []string{"--", "Task: t"}, "prompt")
	eq(t, r.env, "PIG_SUBAGENT=1\x00REX_BLOCK=block:p", "the environment file")
	eq(t, r.envMode, os.FileMode(0o600), "only the user reads it")
	for _, a := range split {
		eq(t, strings.Contains(a, "PIG_SUBAGENT"), false, "no environment on the command line")
	}
	eq(t, r.calls[len(r.calls)-1], closeChild, "cleanup")
	eq(t, r.count("block"), 1, "one close")
	eq(t, r.count("capture"), 0, "an answered child's screen is not read")
	if _, err := os.Stat(filepath.Dir(r.envFile)); !os.IsNotExist(err) {
		t.Fatalf("%s still exists", filepath.Dir(r.envFile))
	}
}

func TestRunTurnEnd(t *testing.T) {
	r := newRig(t, []string{"idle", "idle", "working", "idle", "working"}, "answer")
	_, err := r.run(context.Background())
	eq(t, err, nil, "error")
	eq(t, r.count("api"), 2+2*4, "idle ends the turn only after the child was seen working")

	r = newRig(t, []string{"blocked", "idle", "working"}, "answer")
	r.run(context.Background())
	eq(t, r.count("api"), 2+2*2, "blocked counts as working")

	r = newRig(t, []string{"error", "working"}, "")
	res, _ := r.run(context.Background())
	eq(t, r.count("api"), 2+2, "error ends it")
	eq(t, res, result{exit: 1, stderr: "no answer in the child's session file"}, "no answer")
	eq(t, r.count("capture"), 0, "a live child's screen is not read")
}

func TestRunExit(t *testing.T) {
	r := newRig(t, []string{"working", "exit/3"}, "")
	res, err := r.run(context.Background())
	eq(t, err, nil, "error")
	eq(t, res.exit, 3, "exit")
	eq(t, strings.HasSuffix(res.stderr, "line\nfatal: x"), true, "the screen's end")
	eq(t, strings.Count(res.stderr, "\n"), 39, "40 lines")
	eq(t, r.count("api"), 2+2+1, "an ended program's status is not read")
	eq(t, r.count("block"), 1, "the kept-open block is closed")

	r = newRig(t, []string{"exit/0"}, "")
	res, _ = r.run(context.Background())
	eq(t, res.exit, 1, "a clean exit without an answer is a failure")

	r = newRig(t, []string{"exit/0"}, "answer")
	res, _ = r.run(context.Background())
	eq(t, res, result{stdout: "answer\n"}, "an answer before the exit counts")
}

func TestRunLostServer(t *testing.T) {
	r := newRig(t, []string{"working", "fail"}, "answer")
	res, err := r.run(context.Background())
	eq(t, err, nil, "error")
	eq(t, res, result{exit: 1, stderr: "Rex stopped answering while the child ran in block:c: server gone"}, "result")
	eq(t, r.count("block"), 1, "the close is still tried")
}

func TestRunSplitFails(t *testing.T) {
	r := newRig(t, []string{"done"}, "answer")
	r.fail["split"] = true
	_, err := r.run(context.Background())
	var np noPane
	eq(t, err != nil && !errors.As(err, &np) && strings.Contains(err.Error(), "rex: no such session"), true, "an error, not a fallback")
	eq(t, r.count("block"), 0, "nothing to close")

	r = newRig(t, []string{"done"}, "answer")
	r.noBlock = true
	_, err = r.run(context.Background())
	eq(t, err != nil && !errors.As(err, &np) && strings.Contains(err.Error(), "without a block"), true, "no block: an error")
	eq(t, r.count("block"), 0, "nothing to close")
}

func TestRunCancel(t *testing.T) {
	r := newRig(t, []string{"working"}, "")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for r.count("api") < 4 { // the parent, then the first poll
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	res, err := r.run(ctx)
	eq(t, err, nil, "error")
	eq(t, res.exit, 130, "cancelled")
	eq(t, r.calls[len(r.calls)-1], closeChild, "the pane is closed")
}

func TestRunNoPane(t *testing.T) {
	var np noPane
	r := newRig(t, []string{"done"}, "answer")
	r.fail["parent"] = true
	_, err := r.run(context.Background())
	eq(t, errors.As(err, &np), true, "unreachable: no pane")
	eq(t, string(np), "Rex is not reachable (connection refused)", "why")
	eq(t, len(r.calls), 1, "only the parent's process was asked")

	r = newRig(t, []string{"done"}, "answer")
	_, err = r.rex.run(context.Background(), nil, "/bin/pig", nil, strings.Repeat("x", taskMax+1), "/w", nil, "scout")
	eq(t, errors.As(err, &np), true, "task size: no pane")
	eq(t, len(r.calls), 0, "no calls")
}

func TestPaneEnv(t *testing.T) {
	eq(t, paneEnv([]string{"A=1", "REX_BLOCK=block:p", "REX_SESSION=s", "B=x=y\nz", ""}, []string{"A=pane", "REX_BLOCK=block:c", "REX_SESSION=s"}),
		[]string{"A=1", "B=x=y\nz", "REX_BLOCK=block:c", "REX_SESSION=s"}, "the parent's environment with the pane's REX_")
}

func TestPaneArgsAndName(t *testing.T) {
	eq(t, paneArgs([]string{"--print", "--model", "p/m", "--print-x"}, "/d", "id", "Task: t"),
		[]string{"--model", "p/m", "--print-x", "--session-dir", "/d", "--session-id", "id", "--", "Task: t"}, "args")
	eq(t, paneName("My.Agent/X", "ab12"), "my.agent-x-ab12", "sanitized")
	eq(t, paneName(strings.Repeat("a", 40), "ab12"), strings.Repeat("a", 27)+"-ab12", "32 characters")
	eq(t, paneName("", "ab12"), "agent-ab12", "empty")
}

func TestSessionAnswer(t *testing.T) {
	answer := func(transcript string) (result, bool) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "1_id.jsonl"), []byte(`{"type":"session","id":"id"}`+"\n"+transcript), 0o600)
		return sessionAnswer(dir, "id")
	}
	toolUse := assistant(`{"type":"toolCall","name":"x"}`, "toolUse")
	big := `{"type":"message","message":{"role":"toolResult","content":[` + text(strings.Repeat("x", 2<<20)) + `]}}` + "\n"

	r, ok := answer(toolUse + big + assistant(`{"type":"thinking","thinking":"z"},`+text("a")+","+text("b"), "stop"))
	eq(t, []any{r, ok}, []any{result{stdout: "a\nb\n"}, true}, "the last message's text")
	r, _ = answer(`{"type":"message","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"boom"}}` + "\n")
	eq(t, r, result{exit: 1, stderr: "boom"}, "error")
	r, _ = answer(assistant("", "aborted"))
	eq(t, r, result{exit: 1, stderr: "Request aborted"}, "aborted")
	r, _ = answer(assistant(text("part"), "length"))
	eq(t, r, result{stdout: "part\n", exit: 1, stderr: "Response was truncated: the model reached its output token limit."}, "length")
	_, ok = answer(toolUse)
	eq(t, ok, false, "mid-turn: toolUse")
	_, ok = answer(toolUse + big)
	eq(t, ok, false, "mid-turn: a tool result")
	_, ok = answer("")
	eq(t, ok, false, "no assistant message")
	_, ok = sessionAnswer(t.TempDir(), "id")
	eq(t, ok, false, "no file")
}
