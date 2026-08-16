//go:build windows

package hoststat

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = modkernel32.NewProc("GetTickCount64")
	procGetDiskFreeSpaceExW  = modkernel32.NewProc("GetDiskFreeSpaceExW")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func platformFill(s *Snapshot) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r != 0 {
		s.MemTotal = ms.TotalPhys
		s.MemAvail = ms.AvailPhys
		if ms.TotalPhys > ms.AvailPhys {
			s.MemUsed = ms.TotalPhys - ms.AvailPhys
		}
		s.MemPct = int(ms.MemoryLoad)
		if ms.TotalPageFile > ms.TotalPhys {
			s.SwapTotal = ms.TotalPageFile - ms.TotalPhys
			availPage := uint64(0)
			if ms.AvailPageFile > ms.AvailPhys {
				availPage = ms.AvailPageFile - ms.AvailPhys
			}
			if s.SwapTotal > availPage {
				s.SwapUsed = s.SwapTotal - availPage
			}
			if s.SwapTotal > 0 {
				s.SwapPct = int((s.SwapUsed * 100) / s.SwapTotal)
			}
		}
	}
	if ticks, _, _ := procGetTickCount64.Call(); ticks != 0 {
		s.UptimeSec = int64(ticks / 1000)
	}
	if d, ok := winDisk(`C:\`); ok {
		s.Disks = append(s.Disks, d)
	}
}

func winDisk(path string) (Disk, bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return Disk{}, false
	}
	var free, total, totalFree uint64
	r, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&free)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 || total == 0 {
		return Disk{}, false
	}
	used := total - free
	return Disk{Path: path, Total: total, Used: used, Free: free, Pct: int((used * 100) / total)}, true
}
