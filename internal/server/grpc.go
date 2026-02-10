package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	pb "github.com/runixo/agent/api/proto"
	"github.com/runixo/agent/internal/collector"
	"github.com/runixo/agent/internal/emergency"
	"github.com/runixo/agent/internal/executor"
	"github.com/runixo/agent/internal/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// 全局路径验证器
var pathValidator = security.NewPathValidator(security.DefaultSecurityConfig())

// AgentServer 实现 AgentServiceServer
type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	version      string
	collector    *collector.Collector
	token        string
	emergencyMgr *emergency.Manager
}

// NewAgentServer 创建新的 AgentServer
func NewAgentServer(version string, token string) *AgentServer {
	return &AgentServer{
		version:      version,
		collector:    collector.New(),
		token:        token,
		emergencyMgr: emergency.New(),
	}
}

// Authenticate 认证
func (s *AgentServer) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	// 使用常量时间比较防止时序攻击
	if s.token != "" && subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.token)) != 1 {
		return &pb.AuthResponse{
			Success: false,
			Message: "认证令牌无效",
		}, nil
	}
	return &pb.AuthResponse{
		Success:      true,
		Message:      "认证成功",
		AgentVersion: s.version,
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

// GetSystemInfo 获取系统信息
func (s *AgentServer) GetSystemInfo(ctx context.Context, req *pb.Empty) (*pb.SystemInfo, error) {
	info, err := s.collector.GetSystemInfo()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "获取系统信息失败: %v", err)
	}
	return convertSystemInfo(info), nil
}

// GetMetrics 获取实时监控指标流
func (s *AgentServer) GetMetrics(req *pb.MetricsRequest, stream pb.AgentService_GetMetricsServer) error {
	interval := time.Duration(req.IntervalSeconds) * time.Second
	if interval < time.Second {
		interval = 2 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			metrics, err := s.collector.GetMetrics()
			if err != nil {
				log.Error().Err(err).Msg("采集指标失败")
				continue
			}
			pbMetrics := convertMetrics(metrics)
			pbMetrics.Timestamp = time.Now().Unix()
			// 调试日志
			log.Debug().
				Float64("cpu_usage", pbMetrics.CpuUsage).
				Float64("memory_usage", pbMetrics.MemoryUsage).
				Int("network_metrics_count", len(pbMetrics.NetworkMetrics)).
				Msg("发送指标数据")
			if err := stream.Send(pbMetrics); err != nil {
				return err
			}
		}
	}
}

// ExecuteCommand 执行命令
func (s *AgentServer) ExecuteCommand(ctx context.Context, req *pb.CommandRequest) (*pb.CommandResponse, error) {
	// 拦截紧急避险特殊命令
	if resp := s.handleEmergencyCommand(req.Command, req.Args); resp != nil {
		return resp, nil
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	result, err := executor.Execute(ctx, req.Command, req.Args, executor.Options{
		WorkingDir: req.WorkingDir,
		Env:        req.Env,
		Timeout:    timeout,
		Sudo:       req.Sudo,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "执行命令失败: %v", err)
	}

	return &pb.CommandResponse{
		ExitCode:   int32(result.ExitCode),
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		DurationMs: result.DurationMs,
	}, nil
}

// ExecuteShell 交互式 Shell（已禁用）
// 安全修复：交互式 Shell 允许执行任意命令，完全绕过命令白名单
// 替代方案：使用 SSH 连接服务器，或使用 ExecuteCommand
func (s *AgentServer) ExecuteShell(stream pb.AgentService_ExecuteShellServer) error {
	return status.Error(codes.Unimplemented,
		"交互式 Shell 已禁用。请使用 SSH 连接服务器，或使用命令执行功能。")
}

// ReadFile 读取文件
func (s *AgentServer) ReadFile(ctx context.Context, req *pb.FileRequest) (*pb.FileContent, error) {
	content, info, err := executor.ReadFile(req.Path)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "读取文件失败: %v", err)
	}

	// 限制 gRPC 消息大小
	const maxGrpcMessageSize = 50 * 1024 * 1024 // 50MB
	if len(content) > maxGrpcMessageSize {
		return nil, status.Errorf(codes.ResourceExhausted, "文件过大，请使用流式下载")
	}

	return &pb.FileContent{
		Content: content,
		Info:    convertFileInfo(info),
	}, nil
}

// WriteFile 写入文件
func (s *AgentServer) WriteFile(ctx context.Context, req *pb.WriteFileRequest) (*pb.ActionResponse, error) {
	if err := executor.WriteFile(req.Path, req.Content, req.Mode, req.CreateDirs); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ActionResponse{Success: true, Message: "文件已保存"}, nil
}

// ListDirectory 列出目录
func (s *AgentServer) ListDirectory(ctx context.Context, req *pb.DirRequest) (*pb.DirContent, error) {
	files, err := executor.ListDirectory(req.Path, req.Recursive, req.ShowHidden)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "列出目录失败: %v", err)
	}
	return &pb.DirContent{
		Path:  req.Path,
		Files: convertFileInfoList(files),
	}, nil
}

// DeleteFile 删除文件（带安全检查）
func (s *AgentServer) DeleteFile(ctx context.Context, req *pb.FileRequest) (*pb.ActionResponse, error) {
	cleanPath, err := security.SanitizePath(req.Path)
	if err != nil {
		return &pb.ActionResponse{Success: false, Error: "路径安全检查失败: " + err.Error()}, nil
	}

	if err := pathValidator.ValidatePathForWrite(cleanPath); err != nil {
		return &pb.ActionResponse{Success: false, Error: "删除路径被拒绝: " + err.Error()}, nil
	}

	realPath, err := filepath.EvalSymlinks(cleanPath)
	if err == nil && realPath != cleanPath {
		if err := pathValidator.ValidatePathForWrite(realPath); err != nil {
			return &pb.ActionResponse{Success: false, Error: "符号链接目标路径被拒绝: " + err.Error()}, nil
		}
	}

	forbiddenPaths := []string{"/", "/bin", "/sbin", "/usr", "/etc", "/var", "/boot", "/root", "/home"}
	for _, forbidden := range forbiddenPaths {
		if cleanPath == forbidden {
			return &pb.ActionResponse{Success: false, Error: "禁止删除系统关键目录"}, nil
		}
	}

	if err := os.RemoveAll(cleanPath); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ActionResponse{Success: true, Message: "文件已删除"}, nil
}

// TailLog 日志流
func (s *AgentServer) TailLog(req *pb.LogRequest, stream pb.AgentService_TailLogServer) error {
	lineChan, err := executor.TailFile(stream.Context(), req.Path, int(req.Lines), req.Follow)
	if err != nil {
		return status.Errorf(codes.Internal, "读取日志失败: %v", err)
	}

	for line := range lineChan {
		if err := stream.Send(&pb.LogLine{
			Content:   line,
			Timestamp: time.Now().Unix(),
		}); err != nil {
			return err
		}
	}
	return nil
}

// ListServices 列出服务
func (s *AgentServer) ListServices(ctx context.Context, req *pb.ServiceFilter) (*pb.ServiceList, error) {
	services, err := executor.ListServices(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "列出服务失败: %v", err)
	}
	return &pb.ServiceList{Services: convertServiceList(services)}, nil
}

// ServiceAction 服务操作
func (s *AgentServer) ServiceAction(ctx context.Context, req *pb.ServiceActionRequest) (*pb.ActionResponse, error) {
	var action string
	switch req.Action {
	case pb.ServiceAction_SERVICE_START:
		action = "start"
	case pb.ServiceAction_SERVICE_STOP:
		action = "stop"
	case pb.ServiceAction_SERVICE_RESTART:
		action = "restart"
	case pb.ServiceAction_SERVICE_ENABLE:
		action = "enable"
	case pb.ServiceAction_SERVICE_DISABLE:
		action = "disable"
	default:
		return nil, status.Error(codes.InvalidArgument, "未知操作")
	}

	if err := executor.ServiceAction(ctx, req.Name, action); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ActionResponse{Success: true, Message: "操作成功"}, nil
}

// ListProcesses 列出进程
func (s *AgentServer) ListProcesses(ctx context.Context, req *pb.ProcessFilter) (*pb.ProcessList, error) {
	processes, err := s.collector.ListProcesses()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "列出进程失败: %v", err)
	}
	return &pb.ProcessList{Processes: convertProcessList(processes)}, nil
}

// KillProcess 终止进程
func (s *AgentServer) KillProcess(ctx context.Context, req *pb.KillProcessRequest) (*pb.ActionResponse, error) {
	if err := executor.KillProcess(int(req.Pid), int(req.Signal)); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ActionResponse{Success: true, Message: "进程已终止"}, nil
}

// UploadFile 流式文件上传
func (s *AgentServer) UploadFile(stream pb.AgentService_UploadFileServer) error {
	const maxUploadSize int64 = 1024 * 1024 * 1024 // 1GB 上传大小限制

	var (
		file       *os.File
		filePath   string
		totalSize  int64
		bytesRecv  int64
		isTarGz    bool
		extractTo  string
		createDirs bool
	)

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			// 上传完成
			if file != nil {
				file.Close()

				// 如果是 tar.gz，需要解压
				if isTarGz && extractTo != "" {
					log.Info().Str("file", filePath).Str("extract_to", extractTo).Msg("解压文件")

					// 创建解压目录
					if err := os.MkdirAll(extractTo, 0755); err != nil {
						os.Remove(filePath)
						return status.Errorf(codes.Internal, "创建解压目录失败: %v", err)
					}

					// Zip-slip 防护：解压前验证 tar.gz 内容
					if err := validateTarGzBeforeExtract(filePath, extractTo); err != nil {
						os.Remove(filePath)
						return status.Errorf(codes.InvalidArgument, "解压安全检查失败: %v", err)
					}

					// 解压
					cmd := exec.Command("tar", "--no-same-owner", "-xzf", filePath, "-C", extractTo)
					if output, err := cmd.CombinedOutput(); err != nil {
						os.Remove(filePath)
						return status.Errorf(codes.Internal, "解压失败: %v, output: %s", err, string(output))
					}

					// 二次验证：解压后检查
					if err := validateExtractedFiles(extractTo); err != nil {
						os.RemoveAll(extractTo)
						os.Remove(filePath)
						return status.Errorf(codes.InvalidArgument, "解压安全检查失败: %v", err)
					}

					// 删除临时 tar.gz 文件
					os.Remove(filePath)

					return stream.SendAndClose(&pb.UploadResponse{
						Success:      true,
						Message:      "文件夹上传并解压成功",
						BytesWritten: bytesRecv,
						Path:         extractTo,
					})
				}

				return stream.SendAndClose(&pb.UploadResponse{
					Success:      true,
					Message:      "文件上传成功",
					BytesWritten: bytesRecv,
					Path:         filePath,
				})
			}
			return stream.SendAndClose(&pb.UploadResponse{
				Success: false,
				Error:   "未收到任何数据",
			})
		}
		if err != nil {
			if file != nil {
				file.Close()
				os.Remove(filePath)
			}
			return err
		}

		switch data := chunk.Data.(type) {
		case *pb.FileChunk_Start:
			// 开始上传
			start := data.Start
			filePath = start.Path
			totalSize = start.TotalSize
			isTarGz = start.IsTarGz
			extractTo = start.ExtractTo
			createDirs = start.CreateDirs

			log.Info().
				Str("path", filePath).
				Int64("size", totalSize).
				Bool("is_tar_gz", isTarGz).
				Str("extract_to", extractTo).
				Msg("开始接收文件")

			// 大小限制检查
			if totalSize > maxUploadSize {
				return status.Errorf(codes.InvalidArgument, "文件过大，超过 1GB 限制 (size: %d)", totalSize)
			}

			// 安全检查
			cleanPath, err := security.SanitizePath(filePath)
			if err != nil {
				return status.Errorf(codes.InvalidArgument, "路径安全检查失败: %v", err)
			}
			filePath = cleanPath

			if err := pathValidator.ValidatePathForWrite(filePath); err != nil {
				return status.Errorf(codes.PermissionDenied, "写入路径被拒绝: %v", err)
			}

			// 安全检查：验证 extractTo 路径
			if isTarGz && extractTo != "" {
				cleanExtractTo, err := security.SanitizePath(extractTo)
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "解压路径安全检查失败: %v", err)
				}
				extractTo = cleanExtractTo

				if err := pathValidator.ValidatePathForWrite(extractTo); err != nil {
					return status.Errorf(codes.PermissionDenied, "解压路径被拒绝: %v", err)
				}
			}

			// 创建父目录
			if createDirs {
				dir := filepath.Dir(filePath)
				if err := os.MkdirAll(dir, 0755); err != nil {
					return status.Errorf(codes.Internal, "创建目录失败: %v", err)
				}
			}

			// 创建文件
			file, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(start.Mode))
			if err != nil {
				return status.Errorf(codes.Internal, "创建文件失败: %v", err)
			}

		case *pb.FileChunk_Chunk:
			// 写入数据块
			if file == nil {
				return status.Error(codes.FailedPrecondition, "未收到开始消息")
			}

			n, err := file.Write(data.Chunk)
			if err != nil {
				file.Close()
				os.Remove(filePath)
				return status.Errorf(codes.Internal, "写入文件失败: %v", err)
			}
			bytesRecv += int64(n)

			// 运行时大小检查（防止 totalSize 被伪造）
			if bytesRecv > maxUploadSize {
				file.Close()
				os.Remove(filePath)
				return status.Errorf(codes.ResourceExhausted, "上传数据超过 1GB 限制")
			}

			// 每 10MB 记录一次进度
			if bytesRecv%(10*1024*1024) < int64(len(data.Chunk)) {
				log.Debug().
					Int64("received", bytesRecv).
					Int64("total", totalSize).
					Float64("percent", float64(bytesRecv)/float64(totalSize)*100).
					Msg("上传进度")
			}

		case *pb.FileChunk_End:
			// 上传结束（可选的校验）
			log.Info().Int64("bytes", bytesRecv).Msg("文件接收完成")
		}
	}
}

// DownloadFile 流式文件下载
func (s *AgentServer) DownloadFile(req *pb.FileRequest, stream pb.AgentService_DownloadFileServer) error {
	// 安全检查
	cleanPath, err := security.SanitizePath(req.Path)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "路径安全检查失败: %v", err)
	}

	// 安全检查：验证路径访问权限
	if err := pathValidator.ValidatePath(cleanPath); err != nil {
		return status.Errorf(codes.PermissionDenied, "路径访问被拒绝: %v", err)
	}

	// 打开文件
	file, err := os.Open(cleanPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "打开文件失败: %v", err)
	}
	defer file.Close()

	// 获取文件信息
	info, err := file.Stat()
	if err != nil {
		return status.Errorf(codes.Internal, "获取文件信息失败: %v", err)
	}

	if info.IsDir() {
		return status.Error(codes.InvalidArgument, "不能下载目录，请先打包")
	}

	// 发送开始消息
	if err := stream.Send(&pb.FileChunk{
		Data: &pb.FileChunk_Start{
			Start: &pb.FileUploadStart{
				Path:      cleanPath,
				TotalSize: info.Size(),
				Mode:      int64(info.Mode()),
			},
		},
	}); err != nil {
		return err
	}

	// 分块发送文件内容
	buf := make([]byte, 64*1024) // 64KB chunks
	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "读取文件失败: %v", err)
		}

		if err := stream.Send(&pb.FileChunk{
			Data: &pb.FileChunk_Chunk{
				Chunk: buf[:n],
			},
		}); err != nil {
			return err
		}
	}

	// 发送结束消息
	return stream.Send(&pb.FileChunk{
		Data: &pb.FileChunk_End{
			End: &pb.FileUploadEnd{},
		},
	})
}

// SearchDockerHub 搜索 Docker Hub 镜像（服务端代理）
func (s *AgentServer) SearchDockerHub(ctx context.Context, req *pb.DockerSearchRequest) (*pb.DockerSearchResponse, error) {
	if req.Query == "" {
		return &pb.DockerSearchResponse{
			Success: false,
			Error:   "搜索关键词不能为空",
		}, nil
	}

	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 25
	}

	page := req.Page
	if page <= 0 {
		page = 1
	}

	// 构建 Docker Hub API URL（对查询参数进行 URL 编码）
	apiURL := fmt.Sprintf("https://hub.docker.com/v2/search/repositories/?query=%s&page_size=%d&page=%d",
		url.QueryEscape(req.Query), pageSize, page)

	log.Info().Str("url", apiURL).Str("query", req.Query).Msg("搜索 Docker Hub")

	// 发起 HTTP 请求
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("Docker Hub 搜索请求失败")
		return &pb.DockerSearchResponse{
			Success: false,
			Error:   "搜索请求失败: " + err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &pb.DockerSearchResponse{
			Success: false,
			Error:   fmt.Sprintf("Docker Hub 返回错误状态码: %d", resp.StatusCode),
		}, nil
	}

	// 解析响应
	var result struct {
		Count   int `json:"count"`
		Results []struct {
			RepoName         string `json:"repo_name"`
			ShortDescription string `json:"short_description"`
			StarCount        int64  `json:"star_count"`
			IsOfficial       bool   `json:"is_official"`
			IsAutomated      bool   `json:"is_automated"`
			PullCount        int64  `json:"pull_count"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Error().Err(err).Msg("解析 Docker Hub 响应失败")
		return &pb.DockerSearchResponse{
			Success: false,
			Error:   "解析响应失败: " + err.Error(),
		}, nil
	}

	// 转换结果
	images := make([]*pb.DockerImage, 0, len(result.Results))
	for _, r := range result.Results {
		images = append(images, &pb.DockerImage{
			Name:        r.RepoName,
			Description: r.ShortDescription,
			StarCount:   r.StarCount,
			IsOfficial:  r.IsOfficial,
			IsAutomated: r.IsAutomated,
			PullCount:   r.PullCount,
		})
	}

	log.Info().Int("count", len(images)).Msg("Docker Hub 搜索完成")

	return &pb.DockerSearchResponse{
		Success:    true,
		Results:    images,
		TotalCount: int32(result.Count),
	}, nil
}

// isBlockedURL 检查 URL 是否指向内网/元数据等禁止访问的地址
func isBlockedURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("无效的 URL: %v", err)
	}

	// 只允许 http/https
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("不允许的协议: %s", u.Scheme)
	}

	host := u.Hostname()

	// 先检查是否直接是 IP 字面量
	if ip := net.ParseIP(host); ip != nil {
		if err := checkBlockedIP(ip); err != nil {
			return err
		}
		return nil
	}

	// 解析域名
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("无法解析域名: %s", host)
	}

	for _, ip := range ips {
		if err := checkBlockedIP(ip); err != nil {
			return err
		}
	}

	return nil
}

// checkBlockedIP 检查单个 IP 是否在禁止列表中
func checkBlockedIP(ip net.IP) error {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("禁止访问内网地址: %s", ip)
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return fmt.Errorf("禁止访问云元数据服务")
	}
	return nil
}

// ProxyHttpRequest 代理 HTTP 请求
func (s *AgentServer) ProxyHttpRequest(ctx context.Context, req *pb.HttpProxyRequest) (*pb.HttpProxyResponse, error) {
	if req.Url == "" {
		return &pb.HttpProxyResponse{
			Success: false,
			Error:   "URL 不能为空",
		}, nil
	}

	// 安全检查：禁止访问内网/元数据地址
	if err := isBlockedURL(req.Url); err != nil {
		return &pb.HttpProxyResponse{
			Success: false,
			Error:   "URL 安全检查失败: " + err.Error(),
		}, nil
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	log.Info().Str("url", req.Url).Str("method", method).Msg("代理 HTTP 请求")

	// 创建请求
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.Url, bodyReader)
	if err != nil {
		return &pb.HttpProxyResponse{
			Success: false,
			Error:   "创建请求失败: " + err.Error(),
		}, nil
	}

	// 设置请求头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// 发起请求（禁用自动重定向，防止 302 绕过 SSRF 检查）
	// DNS 重绑定防护：自定义 Transport 在连接时再次验证 IP
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if ip := net.ParseIP(host); ip == nil {
					ips, err := net.LookupIP(host)
					if err != nil {
						return nil, fmt.Errorf("DNS 解析失败: %v", err)
					}
					for _, ip := range ips {
						if err := checkBlockedIP(ip); err != nil {
							return nil, fmt.Errorf("DNS 重绑定检测: %v", err)
						}
					}
				} else {
					if err := checkBlockedIP(ip); err != nil {
						return nil, err
					}
				}
				return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return &pb.HttpProxyResponse{
			Success: false,
			Error:   "请求失败: " + err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	// 读取响应体（限制大小防止 DoS）
	const maxProxyResponseSize = 10 * 1024 * 1024 // 10MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseSize))
	if err != nil {
		return &pb.HttpProxyResponse{
			Success: false,
			Error:   "读取响应失败: " + err.Error(),
		}, nil
	}

	// 转换响应头
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &pb.HttpProxyResponse{
		Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode: int32(resp.StatusCode),
		StatusText: resp.Status,
		Headers:    headers,
		Body:       body,
	}, nil
}

// handleEmergencyCommand 处理紧急避险特殊命令，返回 nil 表示不是特殊命令
func (s *AgentServer) handleEmergencyCommand(command string, args []string) *pb.CommandResponse {
	switch command {
	case "__emergency:enable":
		cpuThresh := 95.0
		memThresh := 95.0
		if len(args) >= 2 {
			if v, err := fmt.Sscanf(args[0], "%f", &cpuThresh); v == 0 || err != nil {
				cpuThresh = 95.0
			}
			if v, err := fmt.Sscanf(args[1], "%f", &memThresh); v == 0 || err != nil {
				memThresh = 95.0
			}
		}
		s.emergencyMgr.SetConfig(emergency.Config{CPUThreshold: cpuThresh, MemThreshold: memThresh})
		s.emergencyMgr.Enable()
		return &pb.CommandResponse{ExitCode: 0, Stdout: `{"success":true,"message":"紧急避险已启用"}`}

	case "__emergency:disable":
		s.emergencyMgr.Disable()
		return &pb.CommandResponse{ExitCode: 0, Stdout: `{"success":true,"message":"紧急避险已禁用"}`}

	case "__emergency:status":
		enabled, consecutive, history := s.emergencyMgr.GetStatus()
		// 使用 json.Marshal 防止 JSON 注入
		type historyEntry struct {
			PID       int32   `json:"pid"`
			Name      string  `json:"name"`
			Reason    string  `json:"reason"`
			CPU       float64 `json:"cpu"`
			Memory    float64 `json:"memory"`
			IsDocker  bool    `json:"is_docker"`
			Timestamp int64   `json:"timestamp"`
		}
		type statusResp struct {
			Enabled         bool           `json:"enabled"`
			ConsecutiveHigh int            `json:"consecutive_high"`
			SamplesRequired int            `json:"samples_required"`
			KillHistory     []historyEntry `json:"kill_history"`
		}
		resp := statusResp{
			Enabled:         enabled,
			ConsecutiveHigh: consecutive,
			SamplesRequired: emergency.SamplesRequired,
			KillHistory:     make([]historyEntry, 0, len(history)),
		}
		for _, h := range history {
			resp.KillHistory = append(resp.KillHistory, historyEntry{
				PID: int32(h.PID), Name: h.Name, Reason: h.Reason,
				CPU: h.CPU, Memory: h.Memory, IsDocker: h.IsDocker,
				Timestamp: h.Timestamp.Unix(),
			})
		}
		stdout, _ := json.Marshal(resp)
		return &pb.CommandResponse{ExitCode: 0, Stdout: string(stdout)}

	default:
		return nil
	}
}

// DownloadCertificate 下载 TLS 证书
// TODO: 需要重新生成 proto 文件以包含 CertificateResponse
/*
func (s *AgentServer) DownloadCertificate(ctx context.Context, req *pb.Empty) (*pb.CertificateResponse, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "/var/lib/runixo/tls/cert.pem"
	}

	certData, err := os.ReadFile(certFile)
	if err != nil {
		log.Error().Err(err).Str("file", certFile).Msg("读取证书文件失败")
		return nil, status.Errorf(codes.NotFound, "证书文件不存在: %v", err)
	}

	// 计算证书 SHA256 指纹
	fingerprint := ""
	block, _ := pem.Decode(certData)
	if block != nil {
		hash := sha256.Sum256(block.Bytes)
		fingerprint = fmt.Sprintf("%x", hash)
	}

	return &pb.CertificateResponse{
		Certificate: string(certData),
		Fingerprint: fingerprint,
	}, nil
}
*/

// validateExtractedFiles 验证解压后的文件都在目标目录内（防止 zip-slip）
func validateExtractedFiles(extractTo string) error {
	absExtractTo, err := filepath.Abs(extractTo)
	if err != nil {
		return fmt.Errorf("无法解析目标目录: %v", err)
	}
	return filepath.Walk(absExtractTo, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		realPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil
		}
		if !strings.HasPrefix(realPath, absExtractTo) {
			return fmt.Errorf("检测到路径遍历: %s 指向 %s", path, realPath)
		}
		return nil
	})
}

// validateTarGzBeforeExtract 在解压前验证 tar.gz 文件内容（Zip-Slip 防护）
func validateTarGzBeforeExtract(tarGzPath, extractTo string) error {
	absExtractTo, err := filepath.Abs(extractTo)
	if err != nil {
		return fmt.Errorf("无法解析目标目录: %v", err)
	}

	file, err := os.Open(tarGzPath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("gzip 解析失败: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar 失败: %v", err)
		}

		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") {
			return fmt.Errorf("检测到路径遍历: %s", header.Name)
		}

		targetPath := filepath.Join(absExtractTo, cleanName)
		if !strings.HasPrefix(targetPath, absExtractTo+string(filepath.Separator)) && targetPath != absExtractTo {
			return fmt.Errorf("检测到路径遍历: %s -> %s", header.Name, targetPath)
		}

		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			linkTarget := filepath.Clean(header.Linkname)
			if filepath.IsAbs(linkTarget) {
				return fmt.Errorf("检测到绝对路径符号链接: %s -> %s", header.Name, linkTarget)
			}
			resolvedLink := filepath.Join(filepath.Dir(targetPath), linkTarget)
			if !strings.HasPrefix(resolvedLink, absExtractTo+string(filepath.Separator)) && resolvedLink != absExtractTo {
				return fmt.Errorf("检测到符号链接路径遍历: %s -> %s", header.Name, linkTarget)
			}
		}
	}
	return nil
}
