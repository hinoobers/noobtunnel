package control

import (
    "testing"
    "time"

    "github.com/noobtunnel/noobtunnel/internal/proxy"
)

func TestRequestFacetCountsRespectOtherFilters(t *testing.T) {
    log := newRequestLog()
    at := time.Now()
    log.record(proxy.RequestEvent{Time: at, Host: "portfolio.example", Country: "EE", Allowed: true})
    log.record(proxy.RequestEvent{Time: at.Add(time.Second), Host: "portfolio.example", Country: "FI", Allowed: true})
    log.record(proxy.RequestEvent{Time: at.Add(2 * time.Second), Host: "other.example", Country: "EE", Allowed: true})
    log.record(proxy.RequestEvent{Time: at.Add(3 * time.Second), Host: "other.example", Country: "EE", Allowed: true})

    query := requestQuery{filters: map[string][]string{"host": {"portfolio.example"}}, allowedResourceIDs: map[uint32]bool{0: true}}
    values, more, err := log.requestFacet("country", "", 20, query)
    if err != nil || more || len(values) != 2 {
        t.Fatalf("unexpected country choices: %+v, more=%v, err=%v", values, more, err)
    }
    for _, value := range values {
        if value.Count != 1 {
            t.Fatalf("country count includes another host: %+v", values)
        }
    }
}
