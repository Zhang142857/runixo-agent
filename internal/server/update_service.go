package server

import (
	"context"

	pb "github.com/runixo/agent/api/proto"
	"github.com/runixo/agent/internal/updater"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UpdateServer 实现 UpdateServiceServer
type UpdateServer struct {
	pb.UnimplementedUpdateServiceServer
	updater *updater.Updater
}

// NewUpdateServer 创建更新服务
func NewUpdateServer(u *updater.Updater) *UpdateServer {
	return &UpdateServer{
		updater: u,
	}
}

// CheckUpdate 检查更新
func (s *UpdateServer) CheckUpdate(ctx context.Context, req *pb.Empty) (*pb.UpdateInfo, error) {
	info, err := s.updater.CheckUpdate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "检查更新失败: %v", err)
	}

	return &pb.UpdateInfo{
		Available:      info.Available,
		CurrentVersion: info.CurrentVersion,
		LatestVersion:  info.LatestVersion,
		ReleaseNotes:   info.ReleaseNotes,
		DownloadUrl:    info.DownloadURL,
		Size:           info.Size,
		Checksum:       info.Checksum,
		ReleaseDate:    info.ReleaseDate,
		IsCritical:     info.IsCritical,
	}, nil
}

// DownloadUpdate 下载更新
func (s *UpdateServer) DownloadUpdate(req *pb.UpdateRequest, stream pb.UpdateService_DownloadUpdateServer) error {
	if req.Version == "" {
		return status.Error(codes.InvalidArgument, "版本号不能为空")
	}

	progressChan := make(chan *updater.DownloadProgress, 10)

	// 启动下载
	errChan := make(chan error, 1)
	go func() {
		_, err := s.updater.DownloadUpdate(req.Version, progressChan)
		errChan <- err
		close(progressChan)
	}()

	// 发送进度
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case progress, ok := <-progressChan:
			if !ok {
				// 通道关闭，等待下载完成
				return <-errChan
			}
			if err := stream.Send(&pb.DownloadProgress{
				Downloaded: progress.Downloaded,
				Total:      progress.Total,
				Percent:    int32(progress.Percent),
				Status:     progress.Status,
			}); err != nil {
				return err
			}
		case err := <-errChan:
			return err
		}
	}
}

// ApplyUpdate 应用更新
func (s *UpdateServer) ApplyUpdate(ctx context.Context, req *pb.UpdateRequest) (*pb.ActionResponse, error) {
	if req.Version == "" {
		return &pb.ActionResponse{Success: false, Error: "版本号不能为空"}, nil
	}

	if err := s.updater.ApplyUpdate(req.Version); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "更新已应用，服务即将重启"}, nil
}

// GetUpdateConfig 获取更新配置
func (s *UpdateServer) GetUpdateConfig(ctx context.Context, req *pb.Empty) (*pb.UpdateConfig, error) {
	config := s.updater.GetConfig()

	return &pb.UpdateConfig{
		AutoUpdate:    config.AutoUpdate,
		CheckInterval: int32(config.CheckInterval),
		UpdateChannel: config.UpdateChannel,
		LastCheck:     config.LastCheck,
		NotifyOnly:    config.NotifyOnly,
	}, nil
}

// SetUpdateConfig 设置更新配置
func (s *UpdateServer) SetUpdateConfig(ctx context.Context, req *pb.UpdateConfig) (*pb.ActionResponse, error) {
	config := &updater.Config{
		AutoUpdate:    req.AutoUpdate,
		CheckInterval: int(req.CheckInterval),
		UpdateChannel: req.UpdateChannel,
		LastCheck:     req.LastCheck,
		NotifyOnly:    req.NotifyOnly,
	}

	if err := s.updater.SetConfig(config); err != nil {
		return &pb.ActionResponse{Success: false, Error: err.Error()}, nil
	}

	return &pb.ActionResponse{Success: true, Message: "配置已保存"}, nil
}

// GetUpdateHistory 获取更新历史
func (s *UpdateServer) GetUpdateHistory(ctx context.Context, req *pb.Empty) (*pb.UpdateHistory, error) {
	history := s.updater.GetHistory()

	records := make([]*pb.UpdateRecord, 0, len(history))
	for _, h := range history {
		records = append(records, &pb.UpdateRecord{
			Version:     h.Version,
			FromVersion: h.FromVersion,
			Timestamp:   h.Timestamp,
			Success:     h.Success,
			Error:       h.Error,
		})
	}

	return &pb.UpdateHistory{Records: records}, nil
}
