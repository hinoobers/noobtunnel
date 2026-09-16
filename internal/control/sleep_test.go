package control_test

import "time"

// sleepBriefly gives reconciliation loops a chance to run in tests.
func sleepBriefly() { time.Sleep(250 * time.Millisecond) }
