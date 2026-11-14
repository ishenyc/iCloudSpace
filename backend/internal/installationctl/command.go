package installationctl

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
)

func Run(ctx context.Context, args []string, output, diagnostics io.Writer) int {
	if len(args) == 0 {
		return failure(diagnostics, ErrInput, Result{})
	}
	flags := flag.NewFlagSet("installation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var spec, process, enabled, revision, key string
	switch args[0] {
	case "initialize":
		flags.StringVar(&spec, "spec-file", "", "")
	case "inspect", "upgrade", "query-upgrade":
		flags.StringVar(&process, "process-file", "", "")
	case "set-writes", "set-weak-recipient-evidence":
		flags.StringVar(&process, "process-file", "", "")
		flags.StringVar(&enabled, "enabled", "", "")
		flags.StringVar(&revision, "expected-revision", "", "")
		flags.StringVar(&key, "operation-key", "", "")
	case "query-write-change", "query-weak-recipient-change":
		flags.StringVar(&process, "process-file", "", "")
		flags.StringVar(&key, "operation-key", "", "")
	default:
		return failure(diagnostics, ErrInput, Result{})
	}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			return failure(diagnostics, ErrInput, Result{})
		}
		name, _, inline := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if flags.Lookup(name) == nil || seen[name] {
			return failure(diagnostics, ErrInput, Result{})
		}
		seen[name] = true
		if !inline {
			i++
			if i >= len(args) {
				return failure(diagnostics, ErrInput, Result{})
			}
		}
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return failure(diagnostics, ErrInput, Result{})
	}
	var result Result
	var err error
	switch args[0] {
	case "initialize":
		result, err = Initialize(ctx, spec)
	case "inspect":
		result, err = Inspect(ctx, process)
	case "upgrade":
		result, err = Upgrade(ctx, process)
	case "query-upgrade":
		result, err = QueryUpgrade(ctx, process)
	case "set-writes":
		if enabled != "true" && enabled != "false" {
			return failure(diagnostics, ErrInput, Result{})
		}
		result, err = SetWrites(ctx, process, enabled == "true", revision, key)
	case "query-write-change":
		result, err = QueryWriteChange(ctx, process, key)
	case "set-weak-recipient-evidence":
		if enabled != "true" && enabled != "false" {
			return failure(diagnostics, ErrInput, Result{})
		}
		result, err = SetWeakRecipientEvidence(ctx, process, enabled == "true", revision, key)
	case "query-weak-recipient-change":
		result, err = QueryWeakRecipientChange(ctx, process, key)
	}
	if err != nil {
		return failure(diagnostics, err, result)
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return failure(diagnostics, ErrPrivate, result)
	}
	return 0
}
func failure(writer io.Writer, err error, result Result) int {
	code, exit := "operation_failed", 1
	switch {
	case errors.Is(err, ErrInput):
		code = "invalid_command"
		exit = 2
	case errors.Is(err, ErrPrivate):
		code = "private_reference_rejected"
	case errors.Is(err, ErrBinding):
		code = "installation_binding_rejected"
	case errors.Is(err, ErrResources):
		code = "actual_resources_rejected"
	case errors.Is(err, ErrState):
		code = "installation_state_rejected"
	case errors.Is(err, ErrRunning):
		code = "installation_running"
	case errors.Is(err, ErrAmbient):
		code = "ambient_configuration_rejected"
	case errors.Is(err, ErrPassword):
		code = "password_policy_rejected"
	case errors.Is(err, ErrConflict):
		code = "operation_conflict"
	case errors.Is(err, ErrNotFound):
		code = "original_operation_not_recorded"
		exit = 4
	case errors.Is(err, ErrUnknown):
		code = "commit_unknown"
		exit = 3
	}
	_ = json.NewEncoder(writer).Encode(struct {
		Code   string `json:"code"`
		Result Result `json:"result"`
	}{code, result})
	return exit
}
