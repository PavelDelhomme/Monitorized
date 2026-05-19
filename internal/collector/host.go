package collector

import (
	"context"
	"time"

	"github.com/pactivisme/monitorized/internal/storage"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

type Host struct {
	store *storage.Store
}

func NewHost(store *storage.Store) *Host { return &Host{store: store} }

func (h *Host) Collect(ctx context.Context) error {
	cpuPct, _ := cpu.PercentWithContext(ctx, 0, false)
	vm, _ := mem.VirtualMemoryWithContext(ctx)
	du, _ := disk.UsageWithContext(ctx, "/")
	ld, _ := load.AvgWithContext(ctx)
	io, _ := net.IOCountersWithContext(ctx, false)

	var rx, tx uint64
	for _, n := range io {
		rx += n.BytesRecv
		tx += n.BytesSent
	}

	m := storage.HostMetric{
		TS:         time.Now().Unix(),
		CPUPercent: first(cpuPct, 0),
		MemUsed:    vm.Used,
		MemTotal:   vm.Total,
		DiskUsed:   du.Used,
		DiskTotal:  du.Total,
		Load1:      ld.Load1,
		Load5:      ld.Load5,
		Load15:     ld.Load15,
		NetRx:      rx,
		NetTx:      tx,
	}
	return h.store.InsertHost(ctx, m)
}

func first(s []float64, def float64) float64 {
	if len(s) > 0 {
		return s[0]
	}
	return def
}
