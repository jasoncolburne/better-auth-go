package encoding

import "time"

// RFC3339 format with millisecond precision (3 digits)
const ConsistentMilli = `2006-01-02T15:04:05.000Z07:00`

type Rfc3339 struct{}

func NewRfc3339() *Rfc3339 {
	return &Rfc3339{}
}

func (*Rfc3339) Format(when time.Time) string {
	return when.Format(ConsistentMilli)
}

func (*Rfc3339) Parse(when string) (time.Time, error) {
	return time.Parse(ConsistentMilli, when)
}

func (*Rfc3339) Now() time.Time {
	return time.Now().UTC()
}
