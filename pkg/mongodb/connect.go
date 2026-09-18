package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Mongo struct {
	URI    string // full connection string, e.g. mongodb://user:pass@host:port
	DBName string
}

func Open(ctx context.Context, conf Mongo) (*mongo.Database, error) {
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(connectCtx, options.Client().ApplyURI(conf.URI))
	if err != nil {
		return nil, fmt.Errorf("connect to MongoDB database=%q: %w", conf.DBName, err)
	}

	pingCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("connect to MongoDB database=%q: %w", conf.DBName, err)
	}

	return client.Database(conf.DBName), nil
}
