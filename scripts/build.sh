#!/bin/bash
#
# Runixo Agent 跨平台构建脚本
#
# 使用方法:
#   ./scripts/build.sh [version]
#
# 示例:
#   ./scripts/build.sh v0.1.0
#

set -e

# 配置
BINARY_NAME="runixo-agent"
BUILD_DIR="dist"
VERSION="${1:-v0.1.0}"
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')

# 目标平台
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/armv7"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "freebsd/amd64"
)

# 颜色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# 清理构建目录
clean() {
    log_info "清理构建目录..."
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
}

# 构建单个平台
build_platform() {
    local platform=$1
    local os=$(echo $platform | cut -d'/' -f1)
    local arch=$(echo $platform | cut -d'/' -f2)

    # 处理 arm 架构
    local goarch=$arch
    local goarm=""
    if [ "$arch" = "armv7" ]; then
        goarch="arm"
        goarm="7"
    fi

    local output_name="${BINARY_NAME}_${os}_${arch}"
    local output_dir="${BUILD_DIR}/${output_name}"

    log_info "构建 ${os}/${arch}..."

    mkdir -p "${output_dir}"

    # 设置环境变量并构建
    cd agent
    GOOS=$os GOARCH=$goarch GOARM=$goarm CGO_ENABLED=0 go build \
        -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
        -o "../${output_dir}/${BINARY_NAME}" \
        ./cmd/agent
    cd ..

    # 打包
    log_info "打包 ${output_name}.tar.gz..."
    cd "${BUILD_DIR}"
    tar -czf "${output_name}.tar.gz" "${output_name}"
    rm -rf "${output_name}"
    cd ..

    log_success "完成 ${os}/${arch}"
}

# 生成校验和
generate_checksums() {
    log_info "生成校验和..."
    cd "${BUILD_DIR}"
    sha256sum *.tar.gz > checksums.txt
    cd ..
    log_success "校验和已生成"
}

# 主函数
main() {
    echo ""
    echo "========================================"
    echo "  Runixo Agent 构建脚本"
    echo "  版本: ${VERSION}"
    echo "========================================"
    echo ""

    clean

    for platform in "${PLATFORMS[@]}"; do
        build_platform "$platform"
    done

    generate_checksums

    echo ""
    echo "========================================"
    log_success "构建完成!"
    echo "========================================"
    echo ""
    echo "构建产物:"
    ls -lh "${BUILD_DIR}"
    echo ""
}

main "$@"
