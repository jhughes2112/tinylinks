package linkdb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type DB struct {
	dir string
	mu  sync.Mutex
}

func New(dir string) *DB {
	os.MkdirAll(dir, 0755)
	return &DB{dir: dir}
}

func (db *DB) path(sub string) string {
	return filepath.Join(db.dir, sub+".json")
}

func (db *DB) Get(sub string) ([]string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	data, err := os.ReadFile(db.path(sub))
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var links []string
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, err
	}
	return links, nil
}

func (db *DB) save(sub string, links []string) error {
	data, err := json.Marshal(links)
	if err != nil {
		return err
	}
	return os.WriteFile(db.path(sub), data, 0600)
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func remove(list []string, item string) []string {
	res := make([]string, 0, len(list))
	for _, v := range list {
		if v != item {
			res = append(res, v)
		}
	}
	return res
}

func (db *DB) AddLink(a, b string) error {
	linksA, err := db.Get(a)
	if err != nil {
		return err
	}
	if !contains(linksA, b) {
		linksA = append(linksA, b)
		if err := db.save(a, linksA); err != nil {
			return err
		}
	}
	linksB, err := db.Get(b)
	if err != nil {
		return err
	}
	if !contains(linksB, a) {
		linksB = append(linksB, a)
		if err := db.save(b, linksB); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) RemoveLink(a, b string) error {
	linksA, err := db.Get(a)
	if err != nil {
		return err
	}
	if contains(linksA, b) {
		if err := db.save(a, remove(linksA, b)); err != nil {
			return err
		}
	}
	linksB, err := db.Get(b)
	if err != nil {
		return err
	}
	if contains(linksB, a) {
		if err := db.save(b, remove(linksB, a)); err != nil {
			return err
		}
	}
	return nil
}
