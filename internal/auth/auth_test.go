package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestNewAuthInterceptor(t *testing.T) {
	token := "test-token"
	interceptor := NewAuthInterceptor(token)

	if interceptor == nil {
		t.Fatal("NewAuthInterceptor() returned nil")
	}

	if interceptor.token != token {
		t.Errorf("Token mismatch: got %s, want %s", interceptor.token, token)
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	if token1 == "" {
		t.Error("GenerateToken() returned empty token")
	}

	// Token 应该是 64 个十六进制字符 (32 bytes * 2)
	if len(token1) != 64 {
		t.Errorf("Token length mismatch: got %d, want 64", len(token1))
	}

	// 生成第二个 token，应该不同
	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() second call error: %v", err)
	}

	if token1 == token2 {
		t.Error("Two generated tokens should be different")
	}
}

func TestAuthorizeWithNoToken(t *testing.T) {
	// 当没有设置 token 时，应该跳过认证
	interceptor := NewAuthInterceptor("")
	ctx := context.Background()

	err := interceptor.authorize(ctx)
	if err != nil {
		t.Errorf("authorize() with empty token should pass, got error: %v", err)
	}
}

func TestAuthorizeWithMissingMetadata(t *testing.T) {
	interceptor := NewAuthInterceptor("test-token")
	ctx := context.Background()

	err := interceptor.authorize(ctx)
	if err == nil {
		t.Error("authorize() should fail with missing metadata")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestAuthorizeWithMissingAuthHeader(t *testing.T) {
	interceptor := NewAuthInterceptor("test-token")

	// 创建带有元数据但没有 authorization 的上下文
	md := metadata.New(map[string]string{"other-header": "value"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := interceptor.authorize(ctx)
	if err == nil {
		t.Error("authorize() should fail with missing authorization header")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestAuthorizeWithInvalidToken(t *testing.T) {
	interceptor := NewAuthInterceptor("correct-token")

	md := metadata.New(map[string]string{"authorization": "wrong-token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := interceptor.authorize(ctx)
	if err == nil {
		t.Error("authorize() should fail with invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestAuthorizeWithValidToken(t *testing.T) {
	token := "valid-token"
	interceptor := NewAuthInterceptor(token)

	md := metadata.New(map[string]string{"authorization": token})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := interceptor.authorize(ctx)
	if err != nil {
		t.Errorf("authorize() should pass with valid token, got error: %v", err)
	}
}

func TestAuthorizeWithBearerToken(t *testing.T) {
	token := "valid-token"
	interceptor := NewAuthInterceptor(token)

	// 测试 Bearer token 格式
	md := metadata.New(map[string]string{"authorization": "Bearer " + token})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := interceptor.authorize(ctx)
	if err != nil {
		t.Errorf("authorize() should pass with Bearer token, got error: %v", err)
	}
}

func TestUnaryInterceptor(t *testing.T) {
	interceptor := NewAuthInterceptor("test-token")
	unary := interceptor.Unary()

	if unary == nil {
		t.Fatal("Unary() returned nil")
	}
}

func TestStreamInterceptor(t *testing.T) {
	interceptor := NewAuthInterceptor("test-token")
	stream := interceptor.Stream()

	if stream == nil {
		t.Fatal("Stream() returned nil")
	}
}

func TestTokenRandomness(t *testing.T) {
	// 生成多个 token 并确保它们都不同
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken() error on iteration %d: %v", i, err)
		}

		if tokens[token] {
			t.Errorf("Duplicate token generated: %s", token)
		}
		tokens[token] = true
	}
}

func TestTokenFormat(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	// 验证 token 只包含十六进制字符
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Token contains invalid character: %c", c)
		}
	}
}
