// Package cli implements the NetTrace command line interface.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"nettrace/internal/config"
	"nettrace/internal/model"
	"nettrace/internal/storage"
)

// Run executes the CLI and returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage(os.Stdout)
		return 2
	}
	cmd := strings.ToLower(args[0])
	rest := args[1:]
	switch cmd {
	case "monitor":
		return runMonitor(rest)
	case "history":
		return runHistory(rest)
	case "export":
		return runExport(rest)
	case "status":
		return runStatus(rest)
	case "version", "--version", "-version":
		fmt.Printf("%s %s (%s/%s)\n", model.AppName, model.Version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "--help", "-h", "-help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "nettrace: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%s %s - per-process network monitor for Windows

Usage:
  nettrace monitor --exe "C:\path\program.exe" [flags]
  nettrace monitor --name "program.exe" [flags]
  nettrace history [filters] [flags]
  nettrace export --format csv|json [filters] [flags]
  nettrace status [flags]
  nettrace version

Commands:
  monitor   Capture network, DNS and process events for one executable.
  history   Show stored sessions, processes, connections and DNS queries.
  export    Export the stored history as CSV or JSON.
  status    Check the database and the availability of each event source.

Common flags:
  --db PATH        SQLite database (default: %%LOCALAPPDATA%%\NetTrace\nettrace.db)
  --config PATH    Configuration file (default: %%LOCALAPPDATA%%\NetTrace\config.json)

Run "nettrace <command> --help" for the flags of a command.

Kernel ETW providers require an elevated console (Run as administrator).
Without elevation NetTrace falls back to sampled IP Helper/Toolhelp data and
reports the limitation in the database and on the console.

`, model.AppName, model.Version)
}

type commonFlags struct {
	db     string
	config string
}

func addCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.db, "db", "", "SQLite database path")
	fs.StringVar(&c.config, "config", "", "configuration file path")
}

func (c *commonFlags) load() (*config.Config, error) {
	cfg, err := config.Load(c.config)
	if err != nil {
		return nil, err
	}
	if c.db != "" {
		cfg.DBPath = c.db
	}
	return cfg, nil
}

func openStore(cfg *config.Config) (*storage.Store, error) {
	return storage.Open(cfg.DBPath)
}

func failf(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "nettrace: "+format+"\n", args...)
	return 1
}

func parseFlags(fs *flag.FlagSet, args []string, usageFn func()) error {
	fs.Usage = usageFn
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return err
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}
