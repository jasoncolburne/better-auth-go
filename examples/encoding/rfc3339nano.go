package encoding

import "time"

type Rfc3339Nano struct{}

func NewRfc3339Nano() *Rfc3339Nano {
	return &Rfc3339Nano{}
}

func (*Rfc3339Nano) Format(when time.Time) string {
	return when.Format(time.RFC3339Nano)
}

func (*Rfc3339Nano) Parse(when string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, when)
}

func (*Rfc3339Nano) Now() time.Time {
	return time.Now().UTC()
}
