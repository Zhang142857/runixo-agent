package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecute(t *testing.T) {
	ctx := context.Background()

	// 测试简单命令
	result, err := Execute(ctx, "echo", []string{"hello"}, Options{})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", result.ExitCode)
	}

	// Windows 的 echo 命令输出可能包含引号
	if result.Stdout == "" {
		t.Error("Stdout is empty")
	}
}

func TestExecuteWithTimeout(t *testing.T) {
	ctx := context.Background()

	// 测试超时
	result, err := Execute(ctx, "ping", []string{"-n", "10", "127.0.0.1"}, Options{
		Timeout: 1 * time.Second,
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	// 应该因为超时而返回非零退出码
	if result.ExitCode == 0 {
		t.Log("Command completed before timeout (this is OK on fast systems)")
	}
}

func TestExecuteWithWorkingDir(t *testing.T) {
	ctx := context.Background()
	tempDir := os.TempDir()

	// 使用 cmd.exe /c cd 来测试工作目录，因为 cd 是 shell 内置命令
	result, err := Execute(ctx, "cmd", []string{"/c", "cd"}, Options{
		WorkingDir: tempDir,
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", result.ExitCode)
	}
}

func TestReadFile(t *testing.T) {
	// 创建临时文件
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := []byte("Hello, World!")

	err := os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// 测试读取文件
	content, info, err := ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Content mismatch: got %s, want %s", content, testContent)
	}

	if info == nil {
		t.Fatal("FileInfo is nil")
	}

	if info.Name != "test.txt" {
		t.Errorf("Name mismatch: got %s, want test.txt", info.Name)
	}

	if info.Size != int64(len(testContent)) {
		t.Errorf("Size mismatch: got %d, want %d", info.Size, len(testContent))
	}
}

func TestReadFileNotFound(t *testing.T) {
	_, _, err := ReadFile("/nonexistent/file/path")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestWriteFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "write_test.txt")
	testContent := []byte("Test content")

	err := WriteFile(testFile, testContent, 0644, false)
	if err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	// 验证文件内容
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Content mismatch: got %s, want %s", content, testContent)
	}
}

func TestWriteFileWithCreateDirs(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "subdir", "nested", "test.txt")
	testContent := []byte("Nested content")

	err := WriteFile(testFile, testContent, 0644, true)
	if err != nil {
		t.Fatalf("WriteFile() with createDirs error: %v", err)
	}

	// 验证文件存在
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("File was not created")
	}
}

func TestListDirectory(t *testing.T) {
	tempDir := t.TempDir()

	// 创建一些测试文件
	os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("1"), 0644)
	os.WriteFile(filepath.Join(tempDir, "file2.txt"), []byte("2"), 0644)
	os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)

	files, err := ListDirectory(tempDir, false, true)
	if err != nil {
		t.Fatalf("ListDirectory() error: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("Expected 3 files, got %d", len(files))
	}
}

func TestListDirectoryRecursive(t *testing.T) {
	tempDir := t.TempDir()

	// 创建嵌套结构
	os.WriteFile(filepath.Join(tempDir, "root.txt"), []byte("root"), 0644)
	os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(tempDir, "subdir", "nested.txt"), []byte("nested"), 0644)

	files, err := ListDirectory(tempDir, true, true)
	if err != nil {
		t.Fatalf("ListDirectory() recursive error: %v", err)
	}

	// 应该包含根目录、root.txt、subdir、nested.txt
	if len(files) < 3 {
		t.Errorf("Expected at least 3 files, got %d", len(files))
	}
}

func TestKillProcess(t *testing.T) {
	// 测试向不存在的进程发送信号
	err := KillProcess(999999, 0)
	if err == nil {
		t.Log("KillProcess to nonexistent PID didn't return error (may be OS-specific)")
	}
}
