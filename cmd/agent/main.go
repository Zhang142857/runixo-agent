package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	pb "github.com/runixo/agent/api/proto"
	"github.com/runixo/agent/internal/api"
	"github.com/runixo/agent/internal/auth"
	"github.com/runixo/agent/internal/plugin"
	"github.com/runixo/agent/internal/ratelimit"
	"github.com/runixo/agent/internal/server"
	"github.com/runixo/agent/internal/updater"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	version   = "0.1.0"
	buildTime = "unknown"
)

func main() {
	// 命令行参数
	configFile := flag.String("config", "/etc/runixo/agent.yaml", "配置文件路径")
	showVersion := flag.Bool("version", false, "显示版本信息")
	genToken := flag.Bool("gen-token", false, "生成新的认证令牌")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Runixo Agent v%s (built: %s)\n", version, buildTime)
		os.Exit(0)
	}

	if *genToken {
		token, err := auth.GenerateToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "生成令牌失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("新令牌: %s\n", token)
		os.Exit(0)
	}

	// 初始化日志
	setupLogger()

	// 加载配置
	if err := loadConfig(*configFile); err != nil {
		log.Fatal().Err(err).Msg("加载配置失败")
	}

	// 启动服务
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("服务启动失败")
	}
}

func setupLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// 开发环境使用彩色输出
	if os.Getenv("ENV") == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}

func loadConfig(configFile string) error {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	// 默认配置
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 9527)
	viper.SetDefault("server.api_port", 9528)
	viper.SetDefault("server.tls.enabled", true)
	viper.SetDefault("auth.token", "")
	viper.SetDefault("metrics.interval", 2)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("data.dir", "/var/lib/runixo")
	viper.SetDefault("plugins.dir", "/var/lib/runixo/plugins")
	viper.SetDefault("update.auto", false)
	viper.SetDefault("update.channel", "stable")
	viper.SetDefault("update.interval", 3600)

	// 环境变量覆盖
	viper.AutomaticEnv()

	// 尝试读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		log.Warn().Msg("配置文件不存在，使用默认配置")
	}

	// 设置日志级别
	level, err := zerolog.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	return nil
}

func run() error {
	host := viper.GetString("server.host")
	port := viper.GetInt("server.port")
	apiPort := viper.GetInt("server.api_port")
	addr := fmt.Sprintf("%s:%d", host, port)
	apiAddr := fmt.Sprintf("%s:%d", host, apiPort)
	token := viper.GetString("auth.token")
	dataDir := viper.GetString("data.dir")
	pluginsDir := viper.GetString("plugins.dir")

	// 创建数据目录
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}

	// 初始化插件管理器
	pluginManager, err := plugin.NewManager(pluginsDir)
	if err != nil {
		return fmt.Errorf("初始化插件管理器失败: %w", err)
	}
	defer pluginManager.Close()

	// 启动已启用的插件
	pluginManager.StartEnabledPlugins()

	// 初始化更新器
	agentUpdater, err := updater.NewUpdater(version, dataDir)
	if err != nil {
		return fmt.Errorf("初始化更新器失败: %w", err)
	}
	defer agentUpdater.Stop()

	// 配置更新器
	if viper.GetBool("update.auto") {
		agentUpdater.SetConfig(&updater.Config{
			AutoUpdate:    true,
			CheckInterval: viper.GetInt("update.interval"),
			UpdateChannel: viper.GetString("update.channel"),
			NotifyOnly:    false,
		})
		agentUpdater.Start()
	}

	// 创建 gRPC 监听器
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听端口失败: %w", err)
	}

	// gRPC 服务器选项
	var opts []grpc.ServerOption

	// TLS 证书路径（gRPC 和 REST API 共用）
	var certFile, keyFile string

	// TLS 配置
	if viper.GetBool("server.tls.enabled") {
		certFile = viper.GetString("server.tls.cert")
		keyFile = viper.GetString("server.tls.key")

		// 如果证书文件不存在，自动生成自签名证书
		if certFile == "" || keyFile == "" {
			certFile = filepath.Join(dataDir, "tls", "cert.pem")
			keyFile = filepath.Join(dataDir, "tls", "key.pem")
		}

		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			log.Info().Msg("TLS 证书不存在，自动生成自签名证书...")
			if err := generateSelfSignedCert(certFile, keyFile); err != nil {
				return fmt.Errorf("生成自签名证书失败: %w", err)
			}
			log.Info().Str("cert", certFile).Str("key", keyFile).Msg("自签名证书已生成")
		}

		// 设置环境变量供 DownloadCertificate 使用
		os.Setenv("TLS_CERT_FILE", certFile)

		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("加载TLS证书失败: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Info().Msg("TLS 已启用")
	} else {
		log.Warn().Msg("⚠️  TLS 已禁用，gRPC 通信未加密，强烈建议启用 TLS")
	}

	// 添加认证和速率限制拦截器
	if token == "" {
		log.Warn().Msg("未设置认证令牌，建议使用 --gen-token 生成")
	}
	authInterceptor := auth.NewAuthInterceptor(token)
	rateLimiter := ratelimit.NewLimiter(nil) // 使用默认配置

	opts = append(opts,
		grpc.ChainUnaryInterceptor(rateLimiter.UnaryInterceptor(), authInterceptor.Unary()),
		grpc.ChainStreamInterceptor(rateLimiter.StreamInterceptor(), authInterceptor.Stream()),
	)

	// 创建 gRPC 服务器
	grpcServer := grpc.NewServer(opts...)

	// 注册服务
	agentServer := server.NewAgentServer(version, token)
	pb.RegisterAgentServiceServer(grpcServer, agentServer)

	// 注册插件服务
	pluginServer := server.NewPluginServer(pluginManager)
	pb.RegisterPluginServiceServer(grpcServer, pluginServer)

	// 注册更新服务
	updateServer := server.NewUpdateServer(agentUpdater)
	pb.RegisterUpdateServiceServer(grpcServer, updateServer)

	// 创建 REST API 服务器
	apiServer := api.NewServer(token, version)
	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)
	httpServer := &http.Server{
		Addr:         apiAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Info().Msg("收到关闭信号，正在停止服务...")
		pluginManager.StopAllPlugins()
		grpcServer.GracefulStop()
		httpServer.Shutdown(ctx)
		cancel()
	}()

	log.Info().
		Str("version", version).
		Str("grpc", addr).
		Str("api", apiAddr).
		Bool("auto_update", viper.GetBool("update.auto")).
		Msg("Runixo Agent 已启动")

	// 启动 REST API 服务器（如果 TLS 启用则使用 HTTPS）
	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			// REST API 也使用 TLS
			httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			log.Info().Str("addr", apiAddr).Msg("REST API 使用 HTTPS")
			err = httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			log.Warn().Msg("⚠️  REST API 使用 HTTP（未加密），建议启用 TLS")
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("REST API 服务错误")
		}
	}()

	// 启动 gRPC 服务
	if err := grpcServer.Serve(listener); err != nil {
		return fmt.Errorf("gRPC服务错误: %w", err)
	}

	<-ctx.Done()
	log.Info().Msg("服务已停止")
	return nil
}

// generateSelfSignedCert 生成自签名 TLS 证书
func generateSelfSignedCert(certFile, keyFile string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// 收集本机所有 IP 地址
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				ips = append(ips, ipnet.IP)
			}
		}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Runixo Agent"}, CommonName: "runixo-agent"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // 自签名证书需要 CA 标志，否则 Electron(BoringSSL) 无法验证
		IPAddresses:           ips,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// 证书文件权限 0644（公开可读）
	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// 私钥文件权限 0600（仅 root 可读）
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return nil
}
