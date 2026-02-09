package collector

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Collector 系统信息采集器
type Collector struct {
	mu sync.Mutex
	// 上次采集的网络数据，用于计算速率
	lastNetworkStats map[string]*NetworkStat
	lastNetworkTime  time.Time
	// 上次采集的磁盘数据
	lastDiskStats map[string]*DiskStat
	lastDiskTime  time.Time
	// 上次采集的 CPU 数据（用于计算使用率）
	lastCpuStats *CpuStat
	lastCpuTime  time.Time
	// 缓存的指标结果（减少重复采集）
	cachedMetrics    *Metrics
	cachedMetricsAt  time.Time
	cacheValidFor    time.Duration
}

// 对象池：复用 Metrics 和切片，减少 GC 压力
var (
	metricsPool = sync.Pool{
		New: func() interface{} { return &Metrics{} },
	}
	diskMetricPool = sync.Pool{
		New: func() interface{} { return make([]*DiskMetric, 0, 16) },
	}
	netMetricPool = sync.Pool{
		New: func() interface{} { return make([]*NetworkMetric, 0, 8) },
	}
)

// CpuStat CPU 统计（来自 /proc/stat）
type CpuStat struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	Iowait  uint64
	Irq     uint64
	Softirq uint64
	Steal   uint64
}

// NetworkStat 网络统计
type NetworkStat struct {
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
}

// DiskStat 磁盘统计
type DiskStat struct {
	ReadBytes  uint64
	WriteBytes uint64
	ReadCount  uint64
	WriteCount uint64
}

// New 创建采集器
func New() *Collector {
	c := &Collector{
		lastNetworkStats: make(map[string]*NetworkStat),
		lastDiskStats:    make(map[string]*DiskStat),
		cacheValidFor:    800 * time.Millisecond, // 800ms 内的重复请求直接返回缓存
	}
	// 预热 CPU 采集
	cpu.Percent(time.Millisecond*100, false)
	// 初始化 CPU 基准数据
	c.lastCpuStats = c.readCpuStats()
	c.lastCpuTime = time.Now()
	// 初始化网络和磁盘基准数据
	c.initBaselineStats()
	return c
}

// readCpuStats 从 /proc/stat 读取 CPU 统计
func (c *Collector) readCpuStats() *CpuStat {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				stat := &CpuStat{}
				stat.User, _ = strconv.ParseUint(fields[1], 10, 64)
				stat.Nice, _ = strconv.ParseUint(fields[2], 10, 64)
				stat.System, _ = strconv.ParseUint(fields[3], 10, 64)
				stat.Idle, _ = strconv.ParseUint(fields[4], 10, 64)
				stat.Iowait, _ = strconv.ParseUint(fields[5], 10, 64)
				stat.Irq, _ = strconv.ParseUint(fields[6], 10, 64)
				stat.Softirq, _ = strconv.ParseUint(fields[7], 10, 64)
				if len(fields) >= 9 {
					stat.Steal, _ = strconv.ParseUint(fields[8], 10, 64)
				}
				return stat
			}
		}
	}
	return nil
}

// calculateCpuUsage 计算 CPU 使用率
func (c *Collector) calculateCpuUsage() float64 {
	current := c.readCpuStats()
	if current == nil || c.lastCpuStats == nil {
		// 回退到 gopsutil
		cpuPercent, err := cpu.Percent(time.Second, false)
		if err == nil && len(cpuPercent) > 0 {
			return cpuPercent[0]
		}
		return 0
	}

	// 计算差值
	prevTotal := c.lastCpuStats.User + c.lastCpuStats.Nice + c.lastCpuStats.System +
		c.lastCpuStats.Idle + c.lastCpuStats.Iowait + c.lastCpuStats.Irq +
		c.lastCpuStats.Softirq + c.lastCpuStats.Steal
	currTotal := current.User + current.Nice + current.System +
		current.Idle + current.Iowait + current.Irq +
		current.Softirq + current.Steal

	prevIdle := c.lastCpuStats.Idle + c.lastCpuStats.Iowait
	currIdle := current.Idle + current.Iowait

	totalDiff := currTotal - prevTotal
	idleDiff := currIdle - prevIdle

	// 更新上次数据
	c.lastCpuStats = current
	c.lastCpuTime = time.Now()

	if totalDiff == 0 {
		return 0
	}

	usage := float64(totalDiff-idleDiff) / float64(totalDiff) * 100
	return usage
}

// initBaselineStats 初始化基准统计数据
func (c *Collector) initBaselineStats() {
	// 网络基准
	netIO, err := net.IOCounters(true)
	if err == nil {
		for _, io := range netIO {
			c.lastNetworkStats[io.Name] = &NetworkStat{
				BytesSent:   io.BytesSent,
				BytesRecv:   io.BytesRecv,
				PacketsSent: io.PacketsSent,
				PacketsRecv: io.PacketsRecv,
			}
		}
		c.lastNetworkTime = time.Now()
	}

	// 磁盘基准
	diskIO, err := disk.IOCounters()
	if err == nil {
		for name, io := range diskIO {
			c.lastDiskStats[name] = &DiskStat{
				ReadBytes:  io.ReadBytes,
				WriteBytes: io.WriteBytes,
				ReadCount:  io.ReadCount,
				WriteCount: io.WriteCount,
			}
		}
		c.lastDiskTime = time.Now()
	}
}

// SystemInfo 系统信息
type SystemInfo struct {
	Hostname        string
	Os              string
	Platform        string
	PlatformVersion string
	KernelVersion   string
	Arch            string
	Uptime          int64
	BootTime        int64
	Cpu             *CpuInfo
	Memory          *MemoryInfo
	Disks           []*DiskInfo
	Networks        []*NetworkInfo
	Gpus            []*GpuInfo
}

// CpuInfo CPU信息
type CpuInfo struct {
	Model        string
	Cores        int32
	Threads      int32
	Frequency    float64
	UsagePerCore []float64
	Usage        float64 // 总体使用率
}

// MemoryInfo 内存信息
type MemoryInfo struct {
	Total       uint64
	Available   uint64
	Used        uint64
	UsedPercent float64
	SwapTotal   uint64
	SwapUsed    uint64
}

// DiskInfo 磁盘信息
type DiskInfo struct {
	Device      string
	Mountpoint  string
	Fstype      string
	Total       uint64
	Used        uint64
	Free        uint64
	UsedPercent float64
}

// NetworkInfo 网络信息
type NetworkInfo struct {
	Name      string
	Addresses []string
	Mac       string
	BytesSent uint64
	BytesRecv uint64
}

// GpuInfo GPU信息
type GpuInfo struct {
	Name          string
	DriverVersion string
	MemoryTotal   uint64
	MemoryUsed    uint64
	Temperature   float64
	Utilization   float64
}

// Metrics 监控指标
type Metrics struct {
	CpuUsage       float64
	MemoryUsage    float64
	DiskMetrics    []*DiskMetric
	NetworkMetrics []*NetworkMetric
	Load1          float64
	Load5          float64
	Load15         float64
}

// DiskMetric 磁盘指标（速率，字节/秒）
type DiskMetric struct {
	Device     string
	ReadBytes  uint64 // 读取速率 bytes/s
	WriteBytes uint64 // 写入速率 bytes/s
	ReadCount  uint64
	WriteCount uint64
}

// NetworkMetric 网络指标（速率，字节/秒）
type NetworkMetric struct {
	Interface   string
	BytesSent   uint64 // 发送速率 bytes/s
	BytesRecv   uint64 // 接收速率 bytes/s
	PacketsSent uint64
	PacketsRecv uint64
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	Pid           int32
	Ppid          int32
	Name          string
	User          string
	Status        string
	CpuPercent    float64
	MemoryPercent float64
	MemoryRss     uint64
	CreateTime    int64
	Cmdline       string
}

// GetSystemInfo 获取系统信息
func (c *Collector) GetSystemInfo() (*SystemInfo, error) {
	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	info := &SystemInfo{
		Hostname:        hostInfo.Hostname,
		Os:              hostInfo.OS,
		Platform:        hostInfo.Platform,
		PlatformVersion: hostInfo.PlatformVersion,
		KernelVersion:   hostInfo.KernelVersion,
		Arch:            runtime.GOARCH,
		Uptime:          int64(hostInfo.Uptime),
		BootTime:        int64(hostInfo.BootTime),
	}

	// CPU 信息
	cpuInfo, err := c.getCpuInfo()
	if err == nil {
		info.Cpu = cpuInfo
	}

	// 内存信息
	memInfo, err := c.getMemoryInfo()
	if err == nil {
		info.Memory = memInfo
	}

	// 磁盘信息
	diskInfo, err := c.getDiskInfo()
	if err == nil {
		info.Disks = diskInfo
	}

	// 网络信息
	netInfo, err := c.getNetworkInfo()
	if err == nil {
		info.Networks = netInfo
	}

	return info, nil
}

func (c *Collector) getCpuInfo() (*CpuInfo, error) {
	cpuInfos, err := cpu.Info()
	if err != nil {
		return nil, err
	}

	info := &CpuInfo{
		Cores:   int32(runtime.NumCPU()),
		Threads: int32(runtime.NumCPU()),
	}

	if len(cpuInfos) > 0 {
		info.Model = cpuInfos[0].ModelName
		info.Frequency = cpuInfos[0].Mhz
	}

	// CPU 使用率 - 使用短间隔获取更准确的值
	percentages, err := cpu.Percent(time.Millisecond*200, true)
	if err == nil {
		info.UsagePerCore = percentages
		// 计算总体使用率
		var total float64
		for _, p := range percentages {
			total += p
		}
		if len(percentages) > 0 {
			info.Usage = total / float64(len(percentages))
		}
	}

	return info, nil
}

func (c *Collector) getMemoryInfo() (*MemoryInfo, error) {
	vmem, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	swap, _ := mem.SwapMemory()

	info := &MemoryInfo{
		Total:       vmem.Total,
		Available:   vmem.Available,
		Used:        vmem.Used,
		UsedPercent: vmem.UsedPercent,
	}

	if swap != nil {
		info.SwapTotal = swap.Total
		info.SwapUsed = swap.Used
	}

	return info, nil
}

func (c *Collector) getDiskInfo() ([]*DiskInfo, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}

	var disks []*DiskInfo
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}

		disks = append(disks, &DiskInfo{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			Fstype:      p.Fstype,
			Total:       usage.Total,
			Used:        usage.Used,
			Free:        usage.Free,
			UsedPercent: usage.UsedPercent,
		})
	}

	return disks, nil
}

func (c *Collector) getNetworkInfo() ([]*NetworkInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	counters, _ := net.IOCounters(true)
	counterMap := make(map[string]net.IOCountersStat)
	for _, counter := range counters {
		counterMap[counter.Name] = counter
	}

	var networks []*NetworkInfo
	for _, iface := range interfaces {
		var addrs []string
		for _, addr := range iface.Addrs {
			addrs = append(addrs, addr.Addr)
		}

		netInfo := &NetworkInfo{
			Name:      iface.Name,
			Addresses: addrs,
			Mac:       iface.HardwareAddr,
		}

		if counter, ok := counterMap[iface.Name]; ok {
			netInfo.BytesSent = counter.BytesSent
			netInfo.BytesRecv = counter.BytesRecv
		}

		networks = append(networks, netInfo)
	}

	return networks, nil
}

// GetMetrics 获取监控指标（返回速率而非累计值）
func (c *Collector) GetMetrics() (*Metrics, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 缓存命中：短时间内多个客户端请求同一数据，直接返回
	if c.cachedMetrics != nil && time.Since(c.cachedMetricsAt) < c.cacheValidFor {
		return c.cachedMetrics, nil
	}

	now := time.Now()
	metrics := metricsPool.Get().(*Metrics)
	metrics.DiskMetrics = metrics.DiskMetrics[:0]
	metrics.NetworkMetrics = metrics.NetworkMetrics[:0]

	// CPU 使用率 - 使用 /proc/stat 差值计算，避免 gopsutil 的阻塞式采样
	metrics.CpuUsage = c.calculateCpuUsage()

	// 内存使用率
	vmem, err := mem.VirtualMemory()
	if err == nil {
		metrics.MemoryUsage = vmem.UsedPercent
	}

	// 负载
	loadAvg, err := load.Avg()
	if err == nil {
		metrics.Load1 = loadAvg.Load1
		metrics.Load5 = loadAvg.Load5
		metrics.Load15 = loadAvg.Load15
	}

	// 磁盘 IO（计算速率）
	diskIO, err := disk.IOCounters()
	if err == nil {
		elapsed := now.Sub(c.lastDiskTime).Seconds()
		if elapsed > 0 {
			for name, io := range diskIO {
				dm := &DiskMetric{Device: name}
				if last, ok := c.lastDiskStats[name]; ok {
					dm.ReadBytes = uint64(float64(io.ReadBytes-last.ReadBytes) / elapsed)
					dm.WriteBytes = uint64(float64(io.WriteBytes-last.WriteBytes) / elapsed)
					dm.ReadCount = uint64(float64(io.ReadCount-last.ReadCount) / elapsed)
					dm.WriteCount = uint64(float64(io.WriteCount-last.WriteCount) / elapsed)
				}
				metrics.DiskMetrics = append(metrics.DiskMetrics, dm)
				c.lastDiskStats[name] = &DiskStat{
					ReadBytes: io.ReadBytes, WriteBytes: io.WriteBytes,
					ReadCount: io.ReadCount, WriteCount: io.WriteCount,
				}
			}
		}
		c.lastDiskTime = now
	}

	// 网络 IO（计算速率）
	netIO, err := net.IOCounters(true)
	if err == nil {
		elapsed := now.Sub(c.lastNetworkTime).Seconds()
		if elapsed > 0 {
			for _, io := range netIO {
				nm := &NetworkMetric{Interface: io.Name}
				if last, ok := c.lastNetworkStats[io.Name]; ok {
					nm.BytesSent = uint64(float64(io.BytesSent-last.BytesSent) / elapsed)
					nm.BytesRecv = uint64(float64(io.BytesRecv-last.BytesRecv) / elapsed)
					nm.PacketsSent = uint64(float64(io.PacketsSent-last.PacketsSent) / elapsed)
					nm.PacketsRecv = uint64(float64(io.PacketsRecv-last.PacketsRecv) / elapsed)
				}
				metrics.NetworkMetrics = append(metrics.NetworkMetrics, nm)
				c.lastNetworkStats[io.Name] = &NetworkStat{
					BytesSent: io.BytesSent, BytesRecv: io.BytesRecv,
					PacketsSent: io.PacketsSent, PacketsRecv: io.PacketsRecv,
				}
			}
		}
		c.lastNetworkTime = now
	}

	// 更新缓存
	c.cachedMetrics = metrics
	c.cachedMetricsAt = now

	return metrics, nil
}

// ListProcesses 列出进程
func (c *Collector) ListProcesses() ([]*ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var processes []*ProcessInfo
	for _, p := range procs {
		name, _ := p.Name()
		user, _ := p.Username()
		status, _ := p.Status()
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()
		memInfo, _ := p.MemoryInfo()
		createTime, _ := p.CreateTime()
		cmdline, _ := p.Cmdline()
		ppid, _ := p.Ppid()

		procInfo := &ProcessInfo{
			Pid:           p.Pid,
			Ppid:          ppid,
			Name:          name,
			User:          user,
			CpuPercent:    cpuPercent,
			MemoryPercent: float64(memPercent),
			CreateTime:    createTime,
			Cmdline:       cmdline,
		}

		if len(status) > 0 {
			procInfo.Status = status[0]
		}

		if memInfo != nil {
			procInfo.MemoryRss = memInfo.RSS
		}

		processes = append(processes, procInfo)
	}

	return processes, nil
}
