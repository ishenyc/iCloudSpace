package operatorctl

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"time"
)

// Run emits controlled JSON only. Flag package diagnostics never receive user
// supplied arguments or private file/DSN/password parsing causes.
func Run(ctx context.Context, args []string, output, diagnostics io.Writer) int {
	if len(args) == 0 {
		return failure(diagnostics, ErrInput, nil)
	}
	flags := flag.NewFlagSet("operator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var process, keyFile, password, operator string
	switch args[0] {
	case "key-generate":
		flags.StringVar(&keyFile, "file", "", "")
	case "inspect":
		flags.StringVar(&process, "process-file", "", "")
	case "operator-recover":
		flags.StringVar(&process, "process-file", "", "")
		flags.StringVar(&password, "password-file", "", "")
		flags.StringVar(&operator, "operator-id", "", "")
	default:
		return failure(diagnostics, ErrInput, nil)
	}
	seen := map[string]bool{}
	for index := 1; index < len(args); index++ {
		raw := args[index]
		if !strings.HasPrefix(raw, "-") {
			return failure(diagnostics, ErrInput, nil)
		}
		name, _, inline := strings.Cut(strings.TrimLeft(raw, "-"), "=")
		if flags.Lookup(name) == nil || seen[name] {
			return failure(diagnostics, ErrInput, nil)
		}
		seen[name] = true
		if !inline {
			index++
			if index >= len(args) {
				return failure(diagnostics, ErrInput, nil)
			}
		}
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return failure(diagnostics, ErrInput, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	switch args[0] {
	case "key-generate":
		if err := GenerateKey(keyFile); err != nil {
			return failure(diagnostics, err, nil)
		}
		if json.NewEncoder(output).Encode(struct {
			Outcome string `json:"outcome"`
		}{"created"}) != nil {
			return failure(diagnostics, ErrPrivateFile, nil)
		}
	case "inspect":
		result, err := Inspect(ctx, process)
		if err != nil {
			return failure(diagnostics, err, nil)
		}
		if json.NewEncoder(output).Encode(result) != nil {
			return failure(diagnostics, ErrPrivateFile, nil)
		}
	case "operator-recover":
		result, err := Recover(ctx, process, operator, password)
		if err != nil {
			return failure(diagnostics, err, &result)
		}
		if json.NewEncoder(output).Encode(result) != nil {
			return failure(diagnostics, ErrPrivateFile, &result)
		}
	}
	return 0
}
func failure(writer io.Writer, err error, recovery *Recovery) int {
	if recovery != nil && recovery.OperationID == "" {
		recovery = nil
	}
	code, exit := "operation_failed", 1
	switch {
	case errors.Is(err, ErrInput):
		code = "invalid_command"
		exit = 2
	case errors.Is(err, ErrPrivateFile):
		code = "private_file_unavailable"
	case errors.Is(err, ErrBinding):
		code = "installation_binding_rejected"
	case errors.Is(err, ErrRunning):
		code = "installation_running"
	case errors.Is(err, ErrReadOnly):
		code = "installation_read_only"
	case errors.Is(err, ErrPassword):
		code = "password_policy_rejected"
	case errors.Is(err, ErrOperator):
		code = "operator_unavailable"
	case errors.Is(err, ErrAmbient):
		code = "ambient_database_configuration_rejected"
	case errors.Is(err, ErrUnknown):
		code = "recovery_commit_unknown"
		exit = 3
	}
	_ = json.NewEncoder(writer).Encode(struct {
		Code     string    `json:"code"`
		Recovery *Recovery `json:"recovery,omitempty"`
	}{code, recovery})
	return exit
}
