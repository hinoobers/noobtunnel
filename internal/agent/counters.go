package agent

import (
	"context"
	"sort"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

// netfilterSnapshot reads the packet counters of this host's firewall.
//
// The diff is what matters: when a packet disappears between two interfaces, the
// only thing that says which rule consumed it is a counter that moved - and
// asking an operator to run iptables before and after a failing connection is
// exactly the step that never happens.
func (a *Agent) netfilterSnapshot(ctx context.Context) []string {
	host := a.host()
	tool, err := host.LookPath("iptables-save")
	if err != nil {
		return nil
	}
	out, err := host.Run(ctx, tool, "-c")
	if err != nil {
		return nil
	}
	var entries []string
	table := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
		case strings.HasPrefix(line, "["):
			end := strings.Index(line, "]")
			if end < 0 {
				continue
			}
			header := strings.Trim(line[1:end], "[]")
			packets, _, _ := strings.Cut(header, ":")
			rule := strings.TrimSpace(line[end+1:])
			if packets == "" || rule == "" {
				continue
			}
			entries = append(entries, packets+" "+table+" "+rule)
		}
	}
	sort.Strings(entries)
	return entries
}

// sendCounters answers the control node's counter request.
func (a *Agent) sendCounters(cmd proto.Command, writer *connWriter) {
	result := proto.CounterResult{
		T:     proto.TCounters,
		Seq:   cmd.Seq,
		Rules: a.netfilterSnapshot(context.Background()),
	}
	if err := writer.send(result); err != nil {
		a.log.Warn("could not send firewall counters", "error", err)
	}
}
