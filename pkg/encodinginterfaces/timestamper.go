package encodinginterfaces

import "time"

type Timestamper interface {
	Format(when time.Time) string
	Parse(when string) (time.Time, error)
	Now() time.Time
}
