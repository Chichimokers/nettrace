package storage

import (
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	"nettrace/internal/model"
)

const (
	writerQueueSize = 8192
	writerBatchSize = 128
	writerFlush     = 200 * time.Millisecond
)

// Writer consumes records from a buffered channel and writes them in small
// transactions. Enqueue never blocks: if the queue is full the record is
// dropped and counted, which keeps the ETW callbacks responsive.
type Writer struct {
	store *Store
	ch    chan any

	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	stopping atomic.Bool
	written  atomic.Uint64
	dropped  atomic.Uint64
	failed   atomic.Uint64

	errMu   sync.Mutex
	lastErr string
}

// NewWriter creates a writer for the store.
func (s *Store) NewWriter() *Writer {
	return &Writer{
		store:  s,
		ch:     make(chan any, writerQueueSize),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start launches the background writer goroutine.
func (w *Writer) Start() {
	go w.loop()
}

// Enqueue queues a *model.ConnectionEvent, *model.DNSQuery, *model.ProcessEnd
// or model.SourceStatus. It returns false when the record could not be queued.
func (w *Writer) Enqueue(rec any) bool {
	select {
	case w.ch <- rec:
		return true
	default:
		if w.stopping.Load() {
			return false
		}
		w.dropped.Add(1)
		return false
	}
}

// Stop drains the queue, flushes the pending batch and waits for the writer to
// finish. It is safe to call more than once.
func (w *Writer) Stop() {
	w.stopOnce.Do(func() {
		w.stopping.Store(true)
		close(w.stopCh)
		<-w.done
	})
}

// Stats returns counters and the last write error.
func (w *Writer) Stats() (written, dropped, failed uint64, lastErr string) {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.written.Load(), w.dropped.Load(), w.failed.Load(), w.lastErr
}

func (w *Writer) loop() {
	defer close(w.done)
	ticker := time.NewTicker(writerFlush)
	defer ticker.Stop()

	batch := make([]any, 0, writerBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.flush(batch)
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-w.ch:
			batch = append(batch, rec)
			if len(batch) >= writerBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stopCh:
			// Drain everything already queued, then commit and exit.
			for {
				select {
				case rec := <-w.ch:
					batch = append(batch, rec)
					if len(batch) >= writerBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (w *Writer) flush(batch []any) {
	tx, err := w.store.db.Begin()
	if err != nil {
		w.recordError(err)
		// Retry records one by one outside a transaction.
		for _, rec := range batch {
			if err := w.store.applyRecord(rec); err != nil {
				w.failed.Add(1)
				w.recordError(err)
			} else {
				w.written.Add(1)
			}
		}
		return
	}
	for _, rec := range batch {
		if err := applyRecordTx(tx, rec); err != nil {
			w.failed.Add(1)
			w.recordError(err)
			continue
		}
		w.written.Add(1)
	}
	if err := tx.Commit(); err != nil {
		w.recordError(err)
		// The transaction may have been rolled back entirely; retry each record
		// individually because the upserts are idempotent.
		for _, rec := range batch {
			if err := w.store.applyRecord(rec); err != nil {
				w.failed.Add(1)
				w.recordError(err)
			}
		}
	}
}

func applyRecordTx(tx *sql.Tx, rec any) error {
	switch r := rec.(type) {
	case *model.ConnectionEvent:
		if r.DedupKey == "" {
			r.ComputeDedupKey()
		}
		return execUpsert(tx, connectionUpsertSQL,
			r.SessionID, r.ProcessInstanceID, int64(r.PID), r.ExeName, r.Proto, r.IPVersion,
			r.LocalAddr, int64(r.LocalPort), r.RemoteAddr, int64(r.RemotePort),
			r.State, r.EventType, utcString(r.FirstSeenUTC), utcString(r.LastSeenUTC),
			int64(r.BytesSent), int64(r.BytesRecv), r.Source, r.Detail, r.DedupKey)
	case *model.DNSQuery:
		if r.DedupKey == "" {
			r.ComputeDedupKey()
		}
		return execUpsert(tx, dnsUpsertSQL,
			r.SessionID, r.ProcessInstanceID, int64(r.PID), r.ExeName,
			r.QueryName, int64(r.QueryType), r.QueryTypeName, int64(r.Status), r.StatusText,
			joinAnswers(r.Answers), boolInt(r.Attributed), r.Attribution,
			utcString(r.FirstSeenUTC), utcString(r.LastSeenUTC), r.Source, r.Raw, r.DedupKey)
	case *model.ProcessEnd:
		var exit any
		if r.ExitCode != nil {
			exit = int64(*r.ExitCode)
		}
		_, err := tx.Exec(`UPDATE process_instances
			SET ended_utc=?, exit_code=COALESCE(?, exit_code)
			WHERE id=?`, utcString(r.EndedUTC), exit, r.InstanceID)
		return err
	case model.SourceStatus:
		return setSourceStatusTx(tx, r)
	case *model.SourceStatus:
		return setSourceStatusTx(tx, *r)
	default:
		return nil
	}
}

func setSourceStatusTx(tx *sql.Tx, st model.SourceStatus) error {
	_, err := tx.Exec(`INSERT INTO source_status(session_id, source, state, detail, updated_utc)
		VALUES(?,?,?,?,?)
		ON CONFLICT(session_id, source) DO UPDATE SET
			state=excluded.state, detail=excluded.detail, updated_utc=excluded.updated_utc`,
		st.SessionID, st.Source, st.State, st.Detail, utcString(st.UpdatedUTC))
	return err
}

func (s *Store) applyRecord(rec any) error {
	switch r := rec.(type) {
	case *model.ConnectionEvent:
		return s.UpsertConnection(r)
	case *model.DNSQuery:
		return s.UpsertDNS(r)
	case *model.ProcessEnd:
		return s.EndProcess(*r)
	case model.SourceStatus:
		return s.SetSourceStatus(r)
	case *model.SourceStatus:
		return s.SetSourceStatus(*r)
	default:
		return nil
	}
}

func execUpsert(tx *sql.Tx, query string, args ...any) error {
	_, err := tx.Exec(query, args...)
	return err
}

func (w *Writer) recordError(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	w.lastErr = err.Error()
	w.errMu.Unlock()
}
