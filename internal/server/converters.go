package server

import (
pb "github.com/runixo/agent/api/proto"
"github.com/runixo/agent/internal/collector"
"github.com/runixo/agent/internal/executor"
)

func convertSystemInfo(info *collector.SystemInfo) *pb.SystemInfo {
if info == nil {
return nil
}
result := &pb.SystemInfo{
Hostname:        info.Hostname,
Os:              info.Os,
Platform:        info.Platform,
PlatformVersion: info.PlatformVersion,
KernelVersion:   info.KernelVersion,
Arch:            info.Arch,
Uptime:          info.Uptime,
BootTime:        info.BootTime,
}
if info.Cpu != nil {
result.Cpu = &pb.CpuInfo{
Model:        info.Cpu.Model,
Cores:        info.Cpu.Cores,
Threads:      info.Cpu.Threads,
Frequency:    info.Cpu.Frequency,
UsagePerCore: info.Cpu.UsagePerCore,
}
}
if info.Memory != nil {
result.Memory = &pb.MemoryInfo{
Total:       info.Memory.Total,
Available:   info.Memory.Available,
Used:        info.Memory.Used,
UsedPercent: info.Memory.UsedPercent,
SwapTotal:   info.Memory.SwapTotal,
SwapUsed:    info.Memory.SwapUsed,
}
}
for _, d := range info.Disks {
result.Disks = append(result.Disks, &pb.DiskInfo{
Device:      d.Device,
Mountpoint:  d.Mountpoint,
Fstype:      d.Fstype,
Total:       d.Total,
Used:        d.Used,
Free:        d.Free,
UsedPercent: d.UsedPercent,
})
}
for _, n := range info.Networks {
result.Networks = append(result.Networks, &pb.NetworkInfo{
Name:      n.Name,
Addresses: n.Addresses,
Mac:       n.Mac,
BytesSent: n.BytesSent,
BytesRecv: n.BytesRecv,
})
}
return result
}

func convertMetrics(m *collector.Metrics) *pb.Metrics {
if m == nil {
return nil
}
result := &pb.Metrics{
CpuUsage:    m.CpuUsage,
MemoryUsage: m.MemoryUsage,
Load_1:      m.Load1,
Load_5:      m.Load5,
Load_15:     m.Load15,
}
for _, d := range m.DiskMetrics {
result.DiskMetrics = append(result.DiskMetrics, &pb.DiskMetric{
Device:     d.Device,
ReadBytes:  d.ReadBytes,
WriteBytes: d.WriteBytes,
ReadCount:  d.ReadCount,
WriteCount: d.WriteCount,
})
}
for _, n := range m.NetworkMetrics {
result.NetworkMetrics = append(result.NetworkMetrics, &pb.NetworkMetric{
Interface:   n.Interface,
BytesSent:   n.BytesSent,
BytesRecv:   n.BytesRecv,
PacketsSent: n.PacketsSent,
PacketsRecv: n.PacketsRecv,
})
}
return result
}

func convertFileInfo(f *executor.FileInfo) *pb.FileInfo {
if f == nil {
return nil
}
return &pb.FileInfo{
Name:    f.Name,
Path:    f.Path,
Size:    f.Size,
Mode:    f.Mode,
ModTime: f.ModTime,
IsDir:   f.IsDir,
Owner:   f.Owner,
Group:   f.Group,
}
}

func convertFileInfoList(files []*executor.FileInfo) []*pb.FileInfo {
var result []*pb.FileInfo
for _, f := range files {
result = append(result, convertFileInfo(f))
}
return result
}

func convertServiceList(services []*executor.ServiceInfo) []*pb.ServiceInfo {
var result []*pb.ServiceInfo
for _, s := range services {
result = append(result, &pb.ServiceInfo{
Name:        s.Name,
Status:      s.Status,
Description: s.Description,
Enabled:     s.Enabled,
Pid:         s.Pid,
Uptime:      s.Uptime,
})
}
return result
}

func convertProcessList(processes []*collector.ProcessInfo) []*pb.ProcessInfo {
var result []*pb.ProcessInfo
for _, p := range processes {
result = append(result, &pb.ProcessInfo{
Pid:           p.Pid,
Ppid:          p.Ppid,
Name:          p.Name,
User:          p.User,
Status:        p.Status,
CpuPercent:    p.CpuPercent,
MemoryPercent: p.MemoryPercent,
MemoryRss:     p.MemoryRss,
CreateTime:    p.CreateTime,
Cmdline:       p.Cmdline,
})
}
return result
}
