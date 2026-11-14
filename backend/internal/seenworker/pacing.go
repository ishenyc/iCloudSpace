package seenworker

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errAdmissionUnavailable = errors.New("seenworker: source admission budget elapsed")

type sourceFinished struct {
	source int64
	err    error
}
type sourceWork struct {
	id    int64
	quota int
}

// runSources has one supervisor, at most four workers and one bounded queue.
// Discovery advances through source PK windows, independently of an earlier
// source's backlog or gate. Per-source membership covers queued and active
// work, so a source never occupies two workers in this service.
func (s *Service) runSources(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	workers := s.slots.Capacity() + 1
	if workers > 4 {
		workers = 4
	}
	if workers < 2 {
		workers = 2
	}
	queue := make(chan sourceWork, s.options.BatchSize)
	finished := make(chan sourceFinished, workers)
	var joined sync.WaitGroup
	defer func() { cancel(); joined.Wait() }()
	for range workers {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case source := <-queue:
					err := s.sourceTurn(ctx, source)
					select {
					case finished <- sourceFinished{source.id, err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	active := map[int64]bool{}
	var cursor int64
	dispatch := func() error {
		ids, err := s.sourceWindow(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}
		quota := s.options.BatchSize
		if len(ids) > 0 {
			quota /= len(ids)
		}
		if quota < 1 {
			quota = 1
		}
		for _, id := range ids {
			if active[id] {
				cursor = id
				continue
			}
			select {
			case queue <- sourceWork{id, quota}:
				active[id] = true
				cursor = id
			default:
				return nil
			}
		}
		return nil
	}
	if err := dispatch(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case completed := <-finished:
			delete(active, completed.source)
			if completed.err != nil {
				return completed.err
			}
		case <-ticker.C:
			if err := dispatch(); err != nil {
				return err
			}
		}
	}
}

func (s *Service) sourceWindow(ctx context.Context, after int64) ([]int64, error) {
	query, cancel := context.WithTimeout(ctx, s.discoveryBudget)
	defer cancel()
	read := func(after int64) ([]int64, error) {
		rows, err := s.db.QueryContext(query, `SELECT id FROM space.mail_sources WHERE id>$1 ORDER BY id LIMIT $2`, after, s.options.BatchSize)
		if err != nil {
			return nil, storage(query)
		}
		defer rows.Close()
		var ids []int64
		for rows.Next() {
			var id int64
			if rows.Scan(&id) != nil || id < 1 {
				return nil, ErrInvalid
			}
			ids = append(ids, id)
		}
		if rows.Err() != nil {
			return nil, storage(query)
		}
		return ids, nil
	}
	ids, err := read(after)
	if err == nil && len(ids) == 0 && after > 0 {
		return read(0)
	}
	return ids, err
}

func (s *Service) sourceDue(ctx context.Context, source int64, limit int) ([]job, error) {
	query, cancel := context.WithTimeout(ctx, s.discoveryBudget)
	defer cancel()
	rows, err := s.db.QueryContext(query, `SELECT `+jobColumns+` FROM space.seen_jobs WHERE source_id=$1 AND next_attempt_at<=$2 ORDER BY next_attempt_at,source_generation,mailbox_name,uid_validity,remote_uid LIMIT $3`, source, s.options.Clock(), limit)
	if err != nil {
		return nil, storage(query)
	}
	defer rows.Close()
	var jobs []job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, storage(query)
		}
		if !validIdentity(j.Identity) || j.SourceID != source {
			return nil, ErrInvalid
		}
		jobs = append(jobs, j)
	}
	if rows.Err() != nil {
		return nil, storage(query)
	}
	return jobs, nil
}

func (s *Service) sourceTurn(parent context.Context, source sourceWork) error {
	ctx, cancel := context.WithTimeout(parent, s.sourceBudget)
	defer cancel()
	jobs, err := s.sourceDue(ctx, source.id, source.quota)
	if err != nil {
		if parent.Err() != nil {
			return parent.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
	var result Result
	for _, j := range jobs {
		if ctx.Err() != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			return nil
		}
		if err = s.process(ctx, j, &result); err != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			if errors.Is(err, errAdmissionUnavailable) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}
	}
	return nil
}
