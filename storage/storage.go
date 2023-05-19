package storage

import "time"

type Store interface {
	UploadCheckData(checkID, kind string, startedAt time.Time, content []byte) (string, error)
}
