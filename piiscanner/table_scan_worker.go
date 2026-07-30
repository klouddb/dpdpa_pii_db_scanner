package piiscanner

import (
	"context"
	"fmt"
	"sync"
)

type ScanInput struct {
	Tablename  string
	ColumnName string
	Value      string
}

type ScanOutput struct {
	Type string
	ScanInput
	Detector string
	Labels   []PiiLabelWithWeight
}

type TableScanWorker struct {
	inputChan  chan ScanInput
	outputChan chan ScanOutput

	detectors      []Detector
	columnDetector Detector

	// cache column context results — same column name always gives same result
	columnContextCache   map[string]ColumnContext
	columnContextCacheMu sync.RWMutex
}

func NewTableScanWorker(inputChan chan ScanInput, outputChan chan ScanOutput, detectors []Detector) *TableScanWorker {
	return &TableScanWorker{
		inputChan:          inputChan,
		outputChan:         outputChan,
		detectors:          detectors,
		columnContextCache: make(map[string]ColumnContext),
	}
}

// WithColumnDetector sets the column detector used to determine hasColumnContext.
// If not set, hasColumnContext is always false.
func (t *TableScanWorker) WithColumnDetector(d Detector) *TableScanWorker {
	t.columnDetector = d
	return t
}

// getColumnContext checks if the column name matches any column detector pattern.
// Results are cached so the regex only runs once per unique column name.
func (t *TableScanWorker) getColumnContext(ctx context.Context, column string) ColumnContext {
	columnContext := make(ColumnContext)

	if t.columnDetector == nil {
		return columnContext
	}

	t.columnContextCacheMu.RLock()
	if cached, ok := t.columnContextCache[column]; ok {
		t.columnContextCacheMu.RUnlock()
		return cached
	}
	t.columnContextCacheMu.RUnlock()

	labels, err := t.columnDetector.Detect(ctx, column, nil)
	if err != nil {
		return columnContext
	}

	for _, label := range labels {
		columnContext[label.PIILabel] = true
	}

	t.columnContextCacheMu.Lock()
	t.columnContextCache[column] = columnContext
	t.columnContextCacheMu.Unlock()

	return columnContext
}

func (t *TableScanWorker) Start(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	for data := range t.inputChan {
		if data.Value == "" || data.Value == "<nil>" {
			continue
		}

		// Determine column context once per column name using column detector
		// Determine all PII labels associated with this column name.
		columnContext := t.getColumnContext(ctx, data.ColumnName)

		for _, detector := range t.detectors {
			labels, err := detector.Detect(ctx, data.Value, columnContext)
			if err != nil {
				return fmt.Errorf("error detecting pii data: from %s (%v)", detector.Name(), err)
			}
			t.outputChan <- ScanOutput{
				Type:      "value",
				ScanInput: data,
				Detector:  detector.Name(),
				Labels:    labels,
			}
		}
	}

	return nil
}
