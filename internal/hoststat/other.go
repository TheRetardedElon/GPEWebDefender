//go:build !linux && !darwin && !freebsd && !windows

package hoststat

func platformFill(_ *Snapshot) {}
