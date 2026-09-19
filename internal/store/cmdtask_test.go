package store

// Stored-task queue tests (§6.3 cmd passthrough): row shape, the one-slot
// overwrite queue, the detached read, and the tolerance of odd-shaped
// stored rows. The replay's byte shape and the engine's ranking are pinned
// in internal/server/adoption and internal/server (cmdtask tests there).

import (
	"reflect"
	"testing"
)

// TestArmCmdTaskRowShape pins the stored row: exactly the two §6.3-pinned
// fields, cmd stored verbatim and mac in the record's canonical identity
// (§6.3's example row is {"cmd":"restart","mac":…} — the `type` field's
// value is unrecovered and deliberately not invented).
func TestArmCmdTaskRowShape(t *testing.T) {
	d := Device{MAC: "f09fc2848f2a", State: StatePending}
	ArmCmdTask(&d, "restart")
	row, ok := d.Extra[CmdTaskKey].(JSONMap)
	if !ok {
		t.Fatalf("armed row not a JSONMap: %+v", d.Extra[CmdTaskKey])
	}
	want := JSONMap{"cmd": "restart", "mac": "f09fc2848f2a"}
	if !reflect.DeepEqual(map[string]any(row), map[string]any(want)) {
		t.Fatalf("row = %+v, want %+v", row, want)
	}
}

// TestArmCmdTaskOverwrites: at most one armed task — a second arming
// replaces the row wholesale, and the replacement is what the next replay
// carries.
func TestArmCmdTaskOverwrites(t *testing.T) {
	d := Device{MAC: "f09fc2848f2a"}
	ArmCmdTask(&d, "restart")
	ArmCmdTask(&d, "spectrum-scan")
	if got := CmdTaskCmd(d); got != "spectrum-scan" {
		t.Fatalf("second arming did not replace the task: cmd = %q", got)
	}
	row := ArmedCmdTask(d)
	if row == nil || len(row) != 2 {
		t.Fatalf("queue holds more than one row: %+v", row)
	}
}

// TestArmedCmdTaskDetached: the returned row is a detached copy — mutating
// it (or its nested values) never aliases the stored record, and a
// re-read returns the stored values.
func TestArmedCmdTaskDetached(t *testing.T) {
	d := Device{MAC: "f09fc2848f2a"}
	ArmCmdTask(&d, "restart")
	row := ArmedCmdTask(d)
	row["cmd"] = "tampered"
	delete(row, "mac")
	if got := CmdTaskCmd(d); got != "restart" {
		t.Fatalf("caller mutation reached the record: cmd = %q", got)
	}
	if again := ArmedCmdTask(d); again["mac"] != "f09fc2848f2a" {
		t.Fatalf("caller mutation reached the record: %+v", again)
	}
}

// TestArmedCmdTaskUnarmedShapes: absent row, nil Extra, odd-shaped values
// and a row without a non-empty cmd all read as unarmed — a malformed
// stored row must never arm a malformed replay.
func TestArmedCmdTaskUnarmedShapes(t *testing.T) {
	cases := []struct {
		name string
		dev  Device
	}{
		{"no extra", Device{MAC: "f09fc2848f2a"}},
		{"no row", Device{MAC: "f09fc2848f2a", Extra: JSONMap{"other": 1.0}}},
		{"scalar row", Device{MAC: "f09fc2848f2a", Extra: JSONMap{CmdTaskKey: "garbage"}}},
		{"slice row", Device{MAC: "f09fc2848f2a", Extra: JSONMap{CmdTaskKey: []any{"restart"}}}},
		{"empty cmd", Device{MAC: "f09fc2848f2a", Extra: JSONMap{CmdTaskKey: JSONMap{"cmd": "", "mac": "f09fc2848f2a"}}}},
		{"non-string cmd", Device{MAC: "f09fc2848f2a", Extra: JSONMap{CmdTaskKey: JSONMap{"cmd": 3.0, "mac": "f09fc2848f2a"}}}},
	}
	for _, tc := range cases {
		if row := ArmedCmdTask(tc.dev); row != nil {
			t.Fatalf("%s: row = %+v, want nil", tc.name, row)
		}
		if got := CmdTaskCmd(tc.dev); got != "" {
			t.Fatalf("%s: cmd = %q, want \"\"", tc.name, got)
		}
	}
}

// TestArmedCmdTaskNilMapArm: arming onto a record with nil Extra
// materializes the map (UpdateExisting seeds Device{MAC: …} with nil
// Extra; the arm must not panic on it).
func TestArmedCmdTaskNilMapArm(t *testing.T) {
	d := Device{MAC: "a040a0aabbcc"}
	ArmCmdTask(&d, "restart")
	if d.Extra == nil {
		t.Fatal("arm did not materialize Extra")
	}
	if got := CmdTaskCmd(d); got != "restart" {
		t.Fatalf("armed cmd = %q, want restart", got)
	}
}
