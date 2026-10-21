package piiscanner

import (
	"context"
	"fmt"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/redisdb"
	"github.com/redis/go-redis/v9"
)

const redisColumnSampleSize = 100

// RedisAdapter treats the whole selected Redis DB as a single "table" —
// Redis has no concept of separate tables, just one flat keyspace per DB index.
type RedisAdapter struct {
	cfg redisdb.Redis
	db  *redis.Client
}

func NewRedisAdapter(cfg redisdb.Redis) *RedisAdapter {
	return &RedisAdapter{cfg: cfg}
}

func (a *RedisAdapter) Connect(ctx context.Context) error {
	db, err := redisdb.Open(ctx, a.cfg)
	if err != nil {
		return err
	}
	a.db = db
	return nil
}

func (a *RedisAdapter) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Close()
}

func (a *RedisAdapter) Schema() string {
	return ""
}

func (a *RedisAdapter) ListTables(ctx context.Context) ([]TableRef, error) {
	return []TableRef{{Schema: "", Name: fmt.Sprintf("db%d", a.cfg.DB)}}, nil
}

func (a *RedisAdapter) RowCount(ctx context.Context, table TableRef) (int, error) {
	count, err := a.db.DBSize(ctx).Result()
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

// DetectRowCursor always returns false — Redis keys have no reliable
// creation order (RANDOMKEY/SCAN give no ordering guarantee), so
// row-level incremental scanning isn't possible here.
func (a *RedisAdapter) DetectRowCursor(ctx context.Context, table TableRef) (RowCursor, bool, error) {
	return RowCursor{}, false, nil
}

// ListColumns returns a best-effort sample of key names — purely so the
// column-name detector (e.g. a key literally containing "email") gets a
// chance to run, and so MetaScan has something to report. It is NOT used
// to filter which keys StreamValues actually scans — see StreamValues.
func (a *RedisAdapter) ListColumns(ctx context.Context, table TableRef) ([]string, error) {
	seen := make(map[string]bool)
	columns := []string{}

	for i := 0; i < redisColumnSampleSize; i++ {
		key, err := a.db.RandomKey(ctx).Result()
		if err == redis.Nil {
			break
		} else if err != nil {
			return nil, err
		}
		if !seen[key] {
			seen[key] = true
			columns = append(columns, key)
		}
	}

	return columns, nil
}

func (a *RedisAdapter) StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error {
	if opts.Mode == SampleMode_Limited {
		return a.streamSampledKeys(ctx, opts.Size, onRowScanned, cb)
	}
	return a.streamAllKeys(ctx, onRowScanned, cb)
}

// streamSampledKeys approach: ask Redis for one random
// key at a time, repeated `size` times. RANDOMKEY can return the same key
// more than once, so repeats are skipped rather than double-processed.
// Note: this does `size` separate round trips to Redis
func (a *RedisAdapter) streamSampledKeys(ctx context.Context, size int, onRowScanned func(), cb RowCallback) error {
	seen := make(map[string]bool)

	for i := 0; i < size; i++ {
		key, err := a.db.RandomKey(ctx).Result()
		if err == redis.Nil {
			break
		} else if err != nil {
			return err
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		if err := a.pushKey(ctx, key, onRowScanned, cb); err != nil {
			return err
		}
	}

	return nil
}

// streamAllKeys walks every key using SCAN, which — unlike the KEYS
// command — doesn't block the whole Redis server while it works.
func (a *RedisAdapter) streamAllKeys(ctx context.Context, onRowScanned func(), cb RowCallback) error {
	iter := a.db.Scan(ctx, 0, "", 0).Iterator()
	for iter.Next(ctx) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := a.pushKey(ctx, iter.Val(), onRowScanned, cb); err != nil {
			return err
		}
	}
	return iter.Err()
}

// pushKey reads one key's value(s), branching on Redis type, and reports
// every value found — same per-type handling uses.
func (a *RedisAdapter) pushKey(ctx context.Context, key string, onRowScanned func(), cb RowCallback) error {
	if onRowScanned != nil {
		onRowScanned()
	}

	keyType, err := a.db.Type(ctx, key).Result()
	if err != nil {
		return err
	}

	switch keyType {
	case "string":
		val, err := a.db.Get(ctx, key).Result()
		if err != nil {
			return err
		}
		return cb(key, val)

	case "list":
		vals, err := a.db.LRange(ctx, key, 0, 1000).Result()
		if err != nil {
			return err
		}
		if listLen, lerr := a.db.LLen(ctx, key).Result(); lerr == nil && listLen > 1001 {
			fmt.Printf("> [redis] key %q has %d list entries — only scanning the first 1000\n", key, listLen)
		}
		for _, v := range vals {
			if err := cb(key, v); err != nil {
				return err
			}
		}

	case "set":
		iter := a.db.SScan(ctx, key, 0, "", 0).Iterator()
		for iter.Next(ctx) {
			if err := cb(key, iter.Val()); err != nil {
				return err
			}
		}
		return iter.Err()

	case "hash":
		iter := a.db.HScan(ctx, key, 0, "", 0).Iterator()
		for iter.Next(ctx) {
			if err := cb(key, iter.Val()); err != nil {
				return err
			}
		}
		return iter.Err()

	case "zset":
		iter := a.db.ZScan(ctx, key, 0, "", 0).Iterator()
		for iter.Next(ctx) {
			if err := cb(key, iter.Val()); err != nil {
				return err
			}
		}
		return iter.Err()
	}

	return nil
}
