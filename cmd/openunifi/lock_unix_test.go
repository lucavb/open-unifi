//go:build darwin || linux

package main

import "testing"

func TestDataDirLockContentionAndRelease(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireDataDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	if second, err := acquireDataDirLock(dir); err == nil {
		_ = second.Close()
		t.Fatal("second lock acquisition succeeded while first lock was held")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireDataDirLock(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}
