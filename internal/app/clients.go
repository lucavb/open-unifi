package app

// Site-wide client views: the live per-AP session rows folded into one
// entry per client, and the opt-in persisted client event log
// (internal/clientevents) behind /api/v1/events and the per-client AP
// history.

import (
	"context"
	"sort"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/clientevents"
	"github.com/lucavb/open-unifi/internal/store"
)

// SetClientHistory attaches the persisted client event log. nil (the
// default) means client history is off. Call it once at startup, before
// the admin API serves.
func (a *App) SetClientHistory(h *clientevents.FileSink) { a.history = h }

// ListClients folds every device's session rows into one entry per client.
// A connected row beats a disconnected one; among equals the freshest
// last_seen wins, so a roaming client shows the AP it is on now even while
// the old AP still lists a stale row. Connected clients come first, then
// MAC order.
func (a *App) ListClients(_ context.Context) []adminapi.SiteClientView {
	devs, err := a.st.List()
	if err != nil {
		a.lg.Warn("list clients: device store", "err", err)
		return []adminapi.SiteClientView{}
	}
	type pick struct {
		s     store.ClientSession
		ap    string
		apNam string
	}
	best := map[string]pick{}
	for _, d := range devs {
		for _, s := range store.ClientSessions(d) {
			cur, ok := best[s.MAC]
			if ok {
				if cur.s.Connected != s.Connected {
					if cur.s.Connected {
						continue
					}
				} else if cur.s.LastSeen >= s.LastSeen {
					continue
				}
			}
			best[s.MAC] = pick{s: s, ap: store.ColonMAC(d.MAC), apNam: d.Name}
		}
	}
	out := make([]adminapi.SiteClientView, 0, len(best))
	for mac, p := range best {
		out = append(out, adminapi.SiteClientView{
			MAC: store.ColonMAC(mac), Hostname: p.s.Hostname, IP: p.s.IP, Connected: p.s.Connected,
			AP: p.ap, APName: p.apNam, SSID: p.s.ESSID, Radio: p.s.Radio, Channel: p.s.Channel,
			Since: p.s.Since, LastSeen: p.s.LastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connected != out[j].Connected {
			return out[i].Connected
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

// ListEvents returns the persisted client event log, newest first; with
// client history off it is Enabled=false and empty.
func (a *App) ListEvents(_ context.Context, q adminapi.EventsQuery) adminapi.EventsView {
	if a.history == nil {
		return adminapi.EventsView{Events: []adminapi.EventView{}}
	}
	evs := a.history.Query(clientevents.Filter{
		Client: q.Client, AP: q.AP, Key: q.Key, Since: q.Since, Until: q.Until, Limit: q.Limit,
	})
	out := make([]adminapi.EventView, 0, len(evs))
	for _, e := range evs {
		out = append(out, eventView(e))
	}
	return adminapi.EventsView{Enabled: true, Events: out}
}

// GetClientHistory returns the client's AP assignment intervals folded from
// the event log; with client history off it is Enabled=false and empty.
func (a *App) GetClientHistory(_ context.Context, mac string) adminapi.ClientHistoryView {
	view := adminapi.ClientHistoryView{Client: mac, Intervals: []adminapi.AssignmentView{}}
	if a.history == nil {
		return view
	}
	view.Enabled = true
	for _, iv := range a.history.History(mac) {
		view.Intervals = append(view.Intervals, adminapi.AssignmentView{
			AP: iv.AP, APName: iv.APName, SSID: iv.SSID, Channel: iv.Channel, From: iv.From, To: iv.To,
		})
	}
	return view
}

func eventView(e clientevents.Event) adminapi.EventView {
	return adminapi.EventView{
		Key: e.Key, Time: e.Time, Datetime: e.Datetime, Client: e.Client, Hostname: e.Hostname, IP: e.IP,
		AP: e.AP, APName: e.APName, APFrom: e.APFrom, APFromName: e.APFromName, APTo: e.APTo, APToName: e.APToName,
		SSID: e.SSID, Radio: e.Radio, RadioFrom: e.RadioFrom, RadioTo: e.RadioTo,
		Channel: e.Channel, ChannelFrom: e.ChannelFrom, ChannelTo: e.ChannelTo,
		Duration: e.Duration, Bytes: e.Bytes, Msg: e.Msg,
	}
}
