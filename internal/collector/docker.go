package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pactivisme/monitorized/internal/storage"
)

type Docker struct {
	client *http.Client
	base   string
	store  *storage.Store
}

func NewDocker(dockerHost string, store *storage.Store) (*Docker, error) {
	socket := "/var/run/docker.sock"
	if strings.HasPrefix(dockerHost, "unix://") {
		socket = strings.TrimPrefix(dockerHost, "unix://")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Docker{
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second},
		base:   "http://localhost",
		store:  store,
	}, nil
}

func (d *Docker) Close() error { return nil }

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

func (d *Docker) Collect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/containers/json?all=1", nil)
	if err != nil {
		return err
	}
	res, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("docker api: %s", string(b))
	}
	var list []dockerContainer
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		return err
	}
	ts := time.Now().Unix()
	for _, c := range list {
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = trimSlash(c.Names[0])
		}
		cpu, memUsed, memLimit := d.stats(ctx, c.ID)
		snap := storage.ContainerSnapshot{
			TS: ts, ID: c.ID[:12], Name: name, Image: c.Image,
			State: c.State, CPUPercent: cpu, MemUsage: memUsed, MemLimit: memLimit,
		}
		if err := d.store.InsertContainer(ctx, snap); err != nil {
			return err
		}
	}
	return nil
}

func (d *Docker) stats(ctx context.Context, id string) (cpu float64, memUsed, memLimit uint64) {
	url := fmt.Sprintf("%s/containers/%s/stats?stream=false", d.base, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, 0
	}
	res, err := d.client.Do(req)
	if err != nil {
		return 0, 0, 0
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, 0, 0
	}
	var raw struct {
		CPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemUsage uint64 `json:"system_cpu_usage"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemUsage uint64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage uint64 `json:"usage"`
			Limit uint64 `json:"limit"`
		} `json:"memory_stats"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0, 0, 0
	}
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemUsage - raw.PreCPUStats.SystemUsage)
	if sysDelta > 0 && cpuDelta > 0 {
		cpu = (cpuDelta / sysDelta) * 100
	}
	return cpu, raw.MemoryStats.Usage, raw.MemoryStats.Limit
}

func trimSlash(s string) string {
	if len(s) > 0 && s[0] == '/' {
		return s[1:]
	}
	return s
}
