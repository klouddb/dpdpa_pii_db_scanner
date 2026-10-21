package redisdb

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	Host      string
	Port      string
	Username  string
	Password  string
	DB        int
	PingCheck bool
}

func Open(ctx context.Context, conf Redis) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", conf.Host, conf.Port),
		Username: conf.Username,
		Password: conf.Password,
		DB:       conf.DB,
	})

	if conf.PingCheck {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if _, err := client.Ping(ctx).Result(); err != nil {
			client.Close()
			return nil, fmt.Errorf("connect to Redis host=%q port=%q db=%d: %w", conf.Host, conf.Port, conf.DB, err)
		}
	}

	return client, nil
}
