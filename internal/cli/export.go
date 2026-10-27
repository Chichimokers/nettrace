package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"nettrace/internal/exporter"
	"nettrace/internal/history"
)

func runExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	var (
		common  commonFlags
		filters filterFlags
		format  string
		out     string
		what    []string
	)
	addCommon(fs, &common)
	addFilterFlags(fs, &filters, 0)
	fs.StringVar(&format, "format", "csv", "output format: csv or json")
	fs.StringVar(&out, "out", "", "output file (CSV with --what all uses it as a base name)")
	fs.Func("what", "what to export: all, sessions, processes, connections, dns (repeatable)", func(s string) error {
		what = append(what, s)
		return nil
	})
	if err := parseFlags(fs, args, func() { exportUsage(fs) }); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	cfg, err := common.load()
	if err != nil {
		return failf("configuration: %v", err)
	}
	filter, err := filters.build()
	if err != nil {
		return failf("%v", err)
	}
	if _, err := exporter.NormalizeWhat(what); err != nil {
		return failf("%v", err)
	}
	store, err := openStore(cfg)
	if err != nil {
		return failf("database: %v", err)
	}
	defer store.Close()

	res, err := history.Query(context.Background(), store.DB(), filter)
	if err != nil {
		return failf("history: %v", err)
	}
	paths, err := exporter.Write(res, exporter.Options{
		Format: format,
		What:   what,
		Out:    out,
		Now:    time.Now(),
	})
	if err != nil {
		return failf("export: %v", err)
	}
	fmt.Printf("Exported %d session(s), %d process(es), %d connection event(s), %d DNS record(s)\n",
		len(res.Sessions), len(res.Processes), len(res.Connections), len(res.DNS))
	fmt.Printf("Filters: %s\n", filters.describe())
	for _, p := range paths {
		fmt.Printf("Wrote: %s\n", p)
	}
	return 0
}

func exportUsage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), `Usage:
  nettrace export --format csv  [filters] [--out FILE] [--what TYPE]
  nettrace export --format json [filters] [--out FILE] [--what TYPE]

Exports stored history. Timestamps are UTC RFC3339 values.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintf(fs.Output(), `
Notes:
  --what all exports every table. For CSV that produces one file per table and
  --out is used as the base name: <base>.sessions.csv, <base>.processes.csv,
  <base>.connections.csv and <base>.dns.csv.

Examples:
  nettrace export --format csv --out connections.csv --what connections
  nettrace export --format json --out session-3.json --session 3
  nettrace export --format csv --exe "SC2_x64.exe" --proto tcp --port 443
`)
}
