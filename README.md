# pig-rex

Shows [PiG](https://github.com/MichaelKinsy/PiG) subagents in their own [Rex](https://www.superlogical.com/rex) panes. A child of [pigpen-subagents](https://github.com/MichaelKinsy/pigpen/tree/main/components/subagents) normally runs hidden. With pig-rex it starts as an interactive `pig` in a split to the right of yours, and the pane closes when its answer is back.

PiG needs nothing else in Rex: it reports its status to Rex itself (OSC 7501), and `rex skill setup` installs the Rex skill where PiG finds it.

## Install

```sh
go install github.com/balcsida/pig-rex@latest
```

Then tell pigpen-subagents to start its children through it, wherever your `pig` gets its environment (a shell profile or a launcher script):

```sh
export PIG_SUBAGENT_PIG_BINARY="$(go env GOPATH)/bin/pig-rex"
```

It applies to PiG sessions started after that. macOS and Linux only.

## How it works

pig-rex is not an extension. pigpen-subagents starts every child with the program `PIG_SUBAGENT_PIG_BINARY` names, and pig-rex stands in for `pig` there:

- Outside a Rex terminal (`REX_SESSION` and `REX_BLOCK` are not set), or when it is not called as a print-mode child (`--print` first), it runs `pig` with the same arguments. Setting the variable everywhere costs nothing.
- In Rex it opens a split beside your pane (`rex split`, focus unchanged, labelled with the agent's name) and runs `pig` there without `--print`, with the task as its prompt.
- It waits until the child's first turn ends, prints the child's last assistant message, as the hidden child would, and closes the pane. Rex counts no turns, so the turn has ended when the child reports `done` or `error`, or `idle` after it was seen working.
- A child that stops on a dialog waits for you in its pane. Rex marks its tab as blocked.
- Escape in the parent ends the child and closes its pane.
- When Rex cannot be reached, or the task is over 100 KiB (it travels as an argument), the child runs hidden with a note on stderr.

The child's environment is the parent's, without the parent pane's `REX_` variables (Rex sets the child's own). It travels in a file only you can read, which pig-rex reads and removes in the pane before it becomes `pig`, so it is not on a command line. The task is an argument of the child's command line, visible in process listings.

`pig` is the first `pig` on `PATH`; `PIG_REX_PIG` names another one. Rex is driven through its CLI: the `rex` in `REX_BIN_DIR`, else the one on `PATH`.

## Limits

- The child's session is not kept. It lives in a temporary directory that is removed with the pane.
- A pig-rex that is killed outright (`SIGKILL`) leaves its pane open.
- Nothing tells the parent session that a child is blocked. Look at the pane.

Checked with PiG 0.7.0, pigpen-subagents 0.2.0 and Rex 0.1.0-preview.21 on macOS.

## Development

```sh
go test -race ./...
```

The tests run against a scripted `rex`. See [CREDITS.md](CREDITS.md) for the code that comes from pigpen-subagents.
