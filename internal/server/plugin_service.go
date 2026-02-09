package server

import (
	"context"
	"encoding/json"

	pb "github.com/runixo/agent/api/proto"
	"github.com/runixo/agent/internal/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PluginServer 实现 PluginServiceServer
type PluginServer struct {
	pb.UnimplementedPluginServiceServer
	manager *plugin.Manager
}

// NewPluginServer 创建插件服务
func NewPluginServer(manager *plugin.Manager) *PluginServer {
	return &PluginServer{
		manager: manager,
	}
}

// ListPlugins 列出已安装的插件
func (s *PluginServer) ListPlugins(ctx context.Context, req *pb.Empty) (*pb.PluginList, error) {
	plugins := s.manager.ListPlugins()

	pbPlugins := make([]*pb.PluginInfo, 0, len(plugins))
	for _, p := range plugins {
		pbPlugins = append(pbPlugins, convertPluginInfo(p))
	}

	return &pb.PluginList{Plugins: pbPlugins}, nil
}

// InstallPlugin 安装插件
func (s *PluginServer) InstallPlugin(ctx context.Context, req *pb.InstallPluginRequest) (*pb.ActionResponse, error) {
	if req.PluginId == "" {
		return &pb.ActionResponse{Success: false, Error: "插件 ID 不能为空"}, nil
	}

	source := req.Source
	if source == "" {
		source = "official"
	}

	if err := s.manager.InstallPlugin(req.PluginId, source, req.Url, req.Data); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "插件安装成功"}, nil
}

// UninstallPlugin 卸载插件
func (s *PluginServer) UninstallPlugin(ctx context.Context, req *pb.PluginRequest) (*pb.ActionResponse, error) {
	if req.PluginId == "" {
		return &pb.ActionResponse{Success: false, Error: "插件 ID 不能为空"}, nil
	}

	if err := s.manager.UninstallPlugin(req.PluginId); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "插件已卸载"}, nil
}

// EnablePlugin 启用插件
func (s *PluginServer) EnablePlugin(ctx context.Context, req *pb.PluginRequest) (*pb.ActionResponse, error) {
	if req.PluginId == "" {
		return &pb.ActionResponse{Success: false, Error: "插件 ID 不能为空"}, nil
	}

	if err := s.manager.EnablePlugin(req.PluginId); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "插件已启用"}, nil
}

// DisablePlugin 禁用插件
func (s *PluginServer) DisablePlugin(ctx context.Context, req *pb.PluginRequest) (*pb.ActionResponse, error) {
	if req.PluginId == "" {
		return &pb.ActionResponse{Success: false, Error: "插件 ID 不能为空"}, nil
	}

	if err := s.manager.DisablePlugin(req.PluginId); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "插件已禁用"}, nil
}

// GetPluginConfig 获取插件配置
func (s *PluginServer) GetPluginConfig(ctx context.Context, req *pb.PluginRequest) (*pb.PluginConfig, error) {
	if req.PluginId == "" {
		return nil, status.Error(codes.InvalidArgument, "插件 ID 不能为空")
	}

	config, err := s.manager.GetPluginConfig(req.PluginId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "获取配置失败: %v", err)
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "序列化配置失败: %v", err)
	}

	return &pb.PluginConfig{
		PluginId:   req.PluginId,
		ConfigJson: string(configJSON),
	}, nil
}

// SetPluginConfig 设置插件配置
func (s *PluginServer) SetPluginConfig(ctx context.Context, req *pb.SetPluginConfigRequest) (*pb.ActionResponse, error) {
	if req.PluginId == "" {
		return &pb.ActionResponse{Success: false, Error: "插件 ID 不能为空"}, nil
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(req.ConfigJson), &config); err != nil {
		return &pb.ActionResponse{Success: false, Error: "解析配置失败: " + err.Error()}, nil
	}

	if err := s.manager.SetPluginConfig(req.PluginId, config); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "配置已保存"}, nil
}

// GetPluginStatus 获取插件状态
func (s *PluginServer) GetPluginStatus(ctx context.Context, req *pb.PluginRequest) (*pb.PluginStatus, error) {
	if req.PluginId == "" {
		return nil, status.Error(codes.InvalidArgument, "插件 ID 不能为空")
	}

	pluginStatus, err := s.manager.GetPluginStatus(req.PluginId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "获取状态失败: %v", err)
	}

	return &pb.PluginStatus{
		PluginId: pluginStatus.PluginID,
		State:    convertPluginState(pluginStatus.State),
		Running:  pluginStatus.Running,
		Error:    pluginStatus.Error,
		Uptime:   pluginStatus.Uptime,
		Stats:    pluginStatus.Stats,
	}, nil
}

// GetAvailablePlugins 获取可用插件列表
func (s *PluginServer) GetAvailablePlugins(ctx context.Context, req *pb.Empty) (*pb.AvailablePluginList, error) {
	// 返回预定义的可用插件列表
	// 实际应用中应该从远程仓库获取
	plugins := []*pb.AvailablePlugin{
		{
			Id:          "cloudflare-security",
			Name:        "Cloudflare 安全防护",
			Version:     "1.0.0",
			Description: "集成 Cloudflare 安全功能，自动封禁恶意 IP，防 DDoS 攻击。24/7 全天候运行在服务器上。",
			Author:      "Runixo",
			Icon:        "🛡️",
			Type:        pb.PluginType_PLUGIN_AGENT,
			Downloads:   5200,
			Rating:      4.7,
			RatingCount: 128,
			Tags:        []string{"安全", "Cloudflare", "防火墙", "DDoS"},
			Category:    "security",
			Official:    true,
			DownloadUrl: "https://plugins.runixo.dev/cloudflare-security",
			UpdatedAt:   "2024-01-20",
		},
		{
			Id:          "nginx-manager",
			Name:        "Nginx 管理",
			Version:     "1.0.0",
			Description: "可视化管理 Nginx 配置、虚拟主机和 SSL 证书",
			Author:      "Runixo",
			Icon:        "🌐",
			Type:        pb.PluginType_PLUGIN_HYBRID,
			Downloads:   6200,
			Rating:      4.6,
			RatingCount: 189,
			Tags:        []string{"Web服务器", "Nginx", "反向代理"},
			Category:    "web",
			Official:    true,
			DownloadUrl: "https://plugins.runixo.dev/nginx-manager",
			UpdatedAt:   "2024-01-15",
		},
		{
			Id:          "mysql-manager",
			Name:        "MySQL 管理",
			Version:     "1.0.0",
			Description: "数据库管理、备份恢复、性能监控",
			Author:      "Runixo",
			Icon:        "🗄️",
			Type:        pb.PluginType_PLUGIN_HYBRID,
			Downloads:   5100,
			Rating:      4.5,
			RatingCount: 167,
			Tags:        []string{"数据库", "MySQL", "SQL"},
			Category:    "database",
			Official:    true,
			DownloadUrl: "https://plugins.runixo.dev/mysql-manager",
			UpdatedAt:   "2024-01-10",
		},
		{
			Id:          "backup-manager",
			Name:        "自动备份",
			Version:     "1.0.0",
			Description: "定时备份文件和数据库到本地或云存储。在服务器上 24/7 运行。",
			Author:      "Runixo",
			Icon:        "💾",
			Type:        pb.PluginType_PLUGIN_AGENT,
			Downloads:   4200,
			Rating:      4.3,
			RatingCount: 98,
			Tags:        []string{"备份", "定时任务", "云存储"},
			Category:    "tools",
			Official:    true,
			DownloadUrl: "https://plugins.runixo.dev/backup-manager",
			UpdatedAt:   "2024-01-05",
		},
		{
			Id:          "advanced-monitor",
			Name:        "高级监控",
			Version:     "1.0.0",
			Description: "详细的性能监控、告警通知、历史数据。在服务器上持续收集数据。",
			Author:      "Runixo",
			Icon:        "📊",
			Type:        pb.PluginType_PLUGIN_AGENT,
			Downloads:   5600,
			Rating:      4.6,
			RatingCount: 145,
			Tags:        []string{"监控", "告警", "性能"},
			Category:    "monitor",
			Official:    true,
			DownloadUrl: "https://plugins.runixo.dev/advanced-monitor",
			UpdatedAt:   "2024-01-03",
		},
	}

	return &pb.AvailablePluginList{Plugins: plugins}, nil
}

// 转换函数
func convertPluginInfo(p *plugin.InstalledPlugin) *pb.PluginInfo {
	return &pb.PluginInfo{
		Id:          p.Manifest.ID,
		Name:        p.Manifest.Name,
		Version:     p.Manifest.Version,
		Description: p.Manifest.Description,
		Author:      p.Manifest.Author,
		Icon:        p.Manifest.Icon,
		State:       convertPluginState(p.State),
		Type:        convertPluginType(p.Manifest.Type),
		Permissions: p.Manifest.Permissions,
		InstalledAt: p.InstalledAt.Unix(),
		UpdatedAt:   p.UpdatedAt.Unix(),
	}
}

func convertPluginState(state plugin.PluginState) pb.PluginState {
	switch state {
	case plugin.StateInstalled:
		return pb.PluginState_PLUGIN_INSTALLED
	case plugin.StateEnabled:
		return pb.PluginState_PLUGIN_ENABLED
	case plugin.StateDisabled:
		return pb.PluginState_PLUGIN_DISABLED
	case plugin.StateError:
		return pb.PluginState_PLUGIN_ERROR
	case plugin.StateUpdating:
		return pb.PluginState_PLUGIN_UPDATING
	default:
		return pb.PluginState_PLUGIN_INSTALLED
	}
}

func convertPluginType(t plugin.PluginType) pb.PluginType {
	switch t {
	case plugin.TypeClient:
		return pb.PluginType_PLUGIN_CLIENT
	case plugin.TypeAgent:
		return pb.PluginType_PLUGIN_AGENT
	case plugin.TypeHybrid:
		return pb.PluginType_PLUGIN_HYBRID
	default:
		return pb.PluginType_PLUGIN_CLIENT
	}
}
