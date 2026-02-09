package collector

import (
	"testing"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
}

func TestGetSystemInfo(t *testing.T) {
	c := New()
	info, err := c.GetSystemInfo()
	if err != nil {
		t.Fatalf("GetSystemInfo() error: %v", err)
	}

	if info == nil {
		t.Fatal("GetSystemInfo() returned nil")
	}

	// 验证基本字段
	if info.Hostname == "" {
		t.Error("Hostname is empty")
	}

	if info.Os == "" {
		t.Error("Os is empty")
	}

	if info.Arch == "" {
		t.Error("Arch is empty")
	}

	// 验证 CPU 信息
	if info.Cpu == nil {
		t.Error("Cpu info is nil")
	} else {
		if info.Cpu.Cores <= 0 {
			t.Error("Cpu cores should be > 0")
		}
	}

	// 验证内存信息
	if info.Memory == nil {
		t.Error("Memory info is nil")
	} else {
		if info.Memory.Total == 0 {
			t.Error("Memory total should be > 0")
		}
	}
}

func TestGetMetrics(t *testing.T) {
	c := New()
	metrics, err := c.GetMetrics()
	if err != nil {
		t.Fatalf("GetMetrics() error: %v", err)
	}

	if metrics == nil {
		t.Fatal("GetMetrics() returned nil")
	}

	// CPU 使用率应该在 0-100 之间
	if metrics.CpuUsage < 0 || metrics.CpuUsage > 100 {
		t.Errorf("CpuUsage out of range: %f", metrics.CpuUsage)
	}

	// 内存使用率应该在 0-100 之间
	if metrics.MemoryUsage < 0 || metrics.MemoryUsage > 100 {
		t.Errorf("MemoryUsage out of range: %f", metrics.MemoryUsage)
	}
}

func TestListProcesses(t *testing.T) {
	c := New()
	processes, err := c.ListProcesses()
	if err != nil {
		t.Fatalf("ListProcesses() error: %v", err)
	}

	if processes == nil {
		t.Fatal("ListProcesses() returned nil")
	}

	// 应该至少有一个进程
	if len(processes) == 0 {
		t.Error("No processes found")
	}

	// 验证进程信息
	// 注意：在 Windows 上，某些系统进程（如内核进程）可能无法获取名称
	// 这是正常的权限限制行为
	validProcessCount := 0
	for _, p := range processes {
		// PID 0 是系统空闲进程，在某些情况下可能无法正常访问
		if p.Pid < 0 {
			t.Errorf("Invalid negative PID: %d", p.Pid)
		}
		// 只统计有名称的进程
		if p.Name != "" && p.Pid > 0 {
			validProcessCount++
		}
	}

	// 至少应该有一些可访问的进程
	if validProcessCount == 0 {
		t.Error("No accessible processes found with valid names")
	}

	t.Logf("Found %d total processes, %d with valid names", len(processes), validProcessCount)
}
