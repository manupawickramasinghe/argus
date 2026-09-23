package sinks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func BenchmarkWriteBatch(b *testing.B) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		b.Fatal(err)
	}

	if err := db.AutoMigrate(&models.AuditLog{}); err != nil {
		b.Fatal(err)
	}

	sink := NewPostgresSink(db)
	ctx := context.Background()

	// Number of unique actors
	numActors := 100
	var logs []models.AuditLog
	for i := 0; i < numActors; i++ {
		logs = append(logs, models.AuditLog{
			Action:    "CREATE",
			ActorID:   fmt.Sprintf("actor-%d", i),
			Timestamp: time.Now().UTC(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clone logs so we don't modify the originals in a way that breaks subsequent runs
		batch := make([]models.AuditLog, len(logs))
		copy(batch, logs)
		err := sink.WriteBatch(ctx, batch)
		if err != nil {
			b.Fatal(err)
		}
	}
}
