// Per-device stored-task queue (docs/PROTOCOL-mgmt.md §6.3 cmd task
// passthrough): a cmd string an admin enqueues for a device is stored on
// the device record and replayed VERBATIM as that device's next inform
// response — `new Object("cmd")` + `object.mergeFrom((X)task)`, the task's
// Mongo fields becoming response keys verbatim. Storage is
// Extra[CmdTaskKey], an ADMIN-OWNED row (CONTEXT.md trust policy): only
// the admin API writes it (internal/app EnqueueDeviceCmd), record
// absorption preserves it verbatim against device-supplied bodies
// (the adminOwnedKeys registry — a device can neither write nor
// introduce the key), and the adoption engine consumes it one-shot on the
// next decoded inform.
//
// §6.3 cites the stored rows as `Task._type=scheduled` rows like
// {"cmd":"restart","mac":…,"type":…}. The `type` field's VALUE is not
// recovered anywhere in the decompile, so it is NOT invented here: the
// stored row carries exactly the two fields whose shape and meaning §6.3
// pins — cmd and mac (the device's canonical 12-hex identity, the
// store's single normalizer). Pinning the real row's full field set is a
// live-proof obligation recorded with the lane.
package store

// CmdTaskKey is the Extra key of the armed stored-task row. The classic
// controller keeps queued tasks in a separate Mongo collection (not a
// device-record field), so — like FlagSetdefaultArmed's arming key — this
// is open-unifi's own name for the row this store queues; the REPLAYED
// payload keys inside the row are the jar-verbatim §6.3 names.
const CmdTaskKey = "cmd_task"

// ArmCmdTask arms the per-device stored task: at most ONE armed task per
// device, and a second arming REPLACES the armed task wholesale (§6.3 is
// silent on enqueue overwrite-vs-reject — chosen: overwrite, the simplest
// queue that keeps "at most one" true without an error path the admin UI
// would have to race). The stored row is the task document §6.3's
// mergeFrom replays: {"cmd": cmd, "mac": <canonical>} — values stored
// EXACTLY as given (verbatim replay), so cmd-string validation lives at
// the admin API boundary, not here.
func ArmCmdTask(d *Device, cmd string) {
	if d.Extra == nil {
		d.Extra = JSONMap{}
	}
	d.Extra[CmdTaskKey] = JSONMap{"cmd": cmd, "mac": d.MAC}
}

// ArmedCmdTask returns the armed task row (nil when none): a DETACHED deep
// copy, replayed verbatim by the adoption engine's §6.3 hook. An absent or
// odd-shaped row (or one whose cmd is not a non-empty string — e.g. a
// hand-corrupted devices.json) reads as unarmed, so a malformed row can
// never emit a malformed replay: never fail a fire over stored noise.
func ArmedCmdTask(d Device) JSONMap {
	var row map[string]any
	switch t := d.Extra[CmdTaskKey].(type) {
	case JSONMap:
		row = t
	case map[string]any:
		row = t
	default:
		return nil
	}
	if cmd, _ := row["cmd"].(string); cmd == "" {
		return nil
	}
	out := make(JSONMap, len(row))
	for k, v := range row {
		out[k] = cloneValue(v)
	}
	return out
}

// CmdTaskCmd returns the armed task's cmd string ("" when unarmed) — the
// admin-view projection of the queue: which cmd the device's next inform
// will replay.
func CmdTaskCmd(d Device) string {
	row := ArmedCmdTask(d)
	if row == nil {
		return ""
	}
	cmd, _ := row["cmd"].(string)
	return cmd
}
