package piiscanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const mongoColumnSampleSize = 100

type MongoAdapter struct {
	cfg mongodb.Mongo
	db  *mongo.Database
}

func NewMongoAdapter(cfg mongodb.Mongo) *MongoAdapter {
	return &MongoAdapter{cfg: cfg}
}

func (a *MongoAdapter) Connect(ctx context.Context) error {
	db, err := mongodb.Open(ctx, a.cfg)
	if err != nil {
		return err
	}
	a.db = db
	return nil
}

func (a *MongoAdapter) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Client().Disconnect(context.Background())
}

func (a *MongoAdapter) Schema() string {
	return ""
}

func (a *MongoAdapter) ListTables(ctx context.Context) ([]TableRef, error) {
	names, err := a.db.ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}

	tables := make([]TableRef, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, "system.") {
			continue
		}
		tables = append(tables, TableRef{Schema: "", Name: name})
	}
	return tables, nil
}

func (a *MongoAdapter) RowCount(ctx context.Context, table TableRef) (int, error) {
	count, err := a.db.Collection(table.Name).EstimatedDocumentCount(ctx)
	if err == nil {
		return int(count), nil
	}

	// EstimatedDocumentCount doesn't work on views — fall back to an
	// exact count, which does.
	exact, cErr := a.db.Collection(table.Name).CountDocuments(ctx, bson.D{})
	if cErr != nil {
		return 0, err // return the original error, more informative for a real failure
	}
	return int(exact), nil
}

// DetectRowCursor uses _id as the watermark — Mongo generates it
// server-side, it's indexed by default, and it's non-decreasing over time,
// so it needs none of the catalog introspection the SQL adapters do.
func (a *MongoAdapter) DetectRowCursor(ctx context.Context, table TableRef) (RowCursor, bool, error) {
	collection := a.db.Collection(table.Name)

	findOpts := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
	var doc bson.M
	err := collection.FindOne(ctx, bson.D{}, findOpts).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		// Empty collection — still a valid cursor, just with a zero
		// baseline so any future insert counts as "new."
		return RowCursor{Column: "_id", Kind: CursorKind_ObjectID, Value: "000000000000000000000000"}, true, nil
	}
	if err != nil {
		return RowCursor{}, false, fmt.Errorf("error reading max _id for %s: %v", table.DisplayName(), err)
	}

	id, ok := doc["_id"].(primitive.ObjectID)
	if !ok {
		// Collection uses a non-ObjectID _id (string, custom key, etc.) —
		// not usable as a monotonic cursor.
		return RowCursor{}, false, nil
	}

	return RowCursor{Column: "_id", Kind: CursorKind_ObjectID, Value: id.Hex()}, true, nil
}

// ListColumns has no schema to read, so it samples a handful of documents
// and returns the union of every field name it observes (nested fields
// flattened with dot notation, e.g. "address.city").
func (a *MongoAdapter) ListColumns(ctx context.Context, table TableRef) ([]string, error) {
	cur, err := a.db.Collection(table.Name).Aggregate(ctx, mongo.Pipeline{
		{{Key: "$sample", Value: bson.D{{Key: "size", Value: mongoColumnSampleSize}}}},
	})

	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	seen := make(map[string]bool)
	order := []string{}

	for cur.Next(ctx) {
		var doc bson.D
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		for _, field := range flattenFieldNames(doc, "") {
			if !seen[field] {
				seen[field] = true
				order = append(order, field)
			}
		}
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}

	return order, nil
}

func flattenFieldNames(doc bson.D, prefix string) []string {
	names := []string{}
	for _, elem := range doc {
		key := elem.Key
		if prefix != "" {
			key = prefix + "." + elem.Key
		}
		if nested, ok := elem.Value.(bson.D); ok {
			names = append(names, flattenFieldNames(nested, key)...)
		} else {
			names = append(names, key)
		}
	}
	return names
}

func (a *MongoAdapter) StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error {
	collection := a.db.Collection(table.Name)

	var cur *mongo.Cursor
	var err error
	switch {
	case opts.Mode == SampleMode_Limited:
		// RowCursor is never set alongside SampleMode_Limited — the
		// incremental "new rows only" pass only ever runs at DeepScan.
		cur, err = collection.Aggregate(ctx, mongo.Pipeline{
			{{Key: "$sample", Value: bson.D{{Key: "size", Value: opts.Size}}}},
		})
	case opts.RowCursor != nil:
		lastID, idErr := primitive.ObjectIDFromHex(opts.RowCursor.Value)
		if idErr != nil {
			return fmt.Errorf("invalid row cursor value %q: %v", opts.RowCursor.Value, idErr)
		}
		cur, err = collection.Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$gt", Value: lastID}}}})
	default:
		cur, err = collection.Find(ctx, bson.D{})
	}
	if err != nil {
		return err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if onRowScanned != nil {
			onRowScanned()
		}

		var doc bson.D
		if err := cur.Decode(&doc); err != nil {
			return err
		}

		for field, value := range flattenFieldValues(doc, "") {
			if value == "" || IgnoreColumn(field) {
				continue
			}
			if err := cb(field, value); err != nil {
				return err
			}
		}
	}

	return cur.Err()
}

// flattenFieldValues turns one Mongo document into flat "field -> value"
// pairs. String arrays are joined with ", " into a single value per field,
func flattenFieldValues(doc bson.D, prefix string) map[string]string {
	out := make(map[string]string)
	for _, elem := range doc {
		key := elem.Key
		if prefix != "" {
			key = prefix + "." + elem.Key
		}

		switch v := elem.Value.(type) {
		case string:
			out[key] = v
		case bson.D:
			for k, val := range flattenFieldValues(v, key) {
				out[k] = val
			}
		case bson.A:
			values := []string{}
			for _, item := range v {
				if s, ok := item.(string); ok {
					values = append(values, s)
				}
			}
			if len(values) > 0 {
				out[key] = strings.Join(values, ", ")
			}
		}
	}
	return out
}
