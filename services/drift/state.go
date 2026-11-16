package drift

import "github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"

// FromNormalized converts an inventory resource to a drift state.
// Relationships are deliberately excluded: topology changes are reported by
// the inventory change report; drift concerns a resource's own attributes.
func FromNormalized(n inventory.NormalizedResource) State {
	return State{ResourceID: n.ResourceID, Type: n.ResourceType, Region: n.Region, Environment: n.Environment,
		Owner: n.Owner, Tags: n.Tags, Configuration: n.Configuration}
}
