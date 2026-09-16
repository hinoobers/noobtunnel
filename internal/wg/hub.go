package wg

// NewHubDevice builds the simulated control node device for --demo mode.
func (n *FakeNetwork) NewHubDevice() *FakeBackend {
	return &FakeBackend{Network: n, Label: "hub"}
}
