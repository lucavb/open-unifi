//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type dataDirLock struct{ file *os.File }

func acquireDataDirLock(dir string) (*dataDirLock, error) {
	path := filepath.Join(dir, ".openunifi.lock")
	// O_NOFOLLOW: a local actor with write access to the data directory must
	// not be able to swap the lock file for a symlink and make the process
	// flock an unrelated file. The file is never written, only flocked, so
	// failing closed on a symlink is the correct outcome.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open data directory lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("data directory %s is already in use: %w", dir, err)
	}
	return &dataDirLock{file: f}, nil
}

func (l *dataDirLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	if cerr := l.file.Close(); err == nil {
		err = cerr
	}
	return err
}
