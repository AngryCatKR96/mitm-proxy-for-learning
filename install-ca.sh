#!/bin/bash

# MITM 프록시 CA 인증서 설치 스크립트

set -e

CA_CERT_FILE="mitm-proxy-ca.pem"
CERT_NAME="mitm-proxy-ca"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# CA 인증서 파일 존재 확인
if [ ! -f "$CA_CERT_FILE" ]; then
    echo_error "CA 인증서 파일 '$CA_CERT_FILE'을 찾을 수 없습니다."
    exit 1
fi

echo_info "MITM 프록시 CA 인증서를 시스템에 설치합니다..."

# Ubuntu/Debian 시스템인지 확인
if [ -f /etc/debian_version ]; then
    echo_info "Ubuntu/Debian 시스템이 감지되었습니다."
    
    # ca-certificates 패키지 설치 확인
    if ! dpkg -l | grep -q ca-certificates; then
        echo_info "ca-certificates 패키지를 설치합니다..."
        sudo apt update
        sudo apt install -y ca-certificates
    fi
    
    # CA 인증서를 시스템 디렉토리에 복사
    echo_info "CA 인증서를 /usr/local/share/ca-certificates/에 복사합니다..."
    sudo cp "$CA_CERT_FILE" "/usr/local/share/ca-certificates/${CERT_NAME}.crt"
    
    # 권한 설정
    sudo chmod 644 "/usr/local/share/ca-certificates/${CERT_NAME}.crt"
    
    # CA 인증서 업데이트
    echo_info "시스템 CA 저장소를 업데이트합니다..."
    sudo update-ca-certificates
    
    echo_info "CA 인증서가 성공적으로 설치되었습니다."
    
elif [ -f /etc/redhat-release ]; then
    echo_info "Red Hat/CentOS 시스템이 감지되었습니다."
    
    # CA 인증서를 시스템 디렉토리에 복사
    echo_info "CA 인증서를 /etc/pki/ca-trust/source/anchors/에 복사합니다..."
    sudo cp "$CA_CERT_FILE" "/etc/pki/ca-trust/source/anchors/${CERT_NAME}.pem"
    
    # 권한 설정
    sudo chmod 644 "/etc/pki/ca-trust/source/anchors/${CERT_NAME}.pem"
    
    # CA 인증서 업데이트
    echo_info "시스템 CA 저장소를 업데이트합니다..."
    sudo update-ca-trust
    
    echo_info "CA 인증서가 성공적으로 설치되었습니다."
    
else
    echo_error "지원되지 않는 운영체제입니다. Ubuntu/Debian 또는 Red Hat/CentOS만 지원됩니다."
    exit 1
fi

# 설치 확인
echo_info "설치된 CA 인증서를 확인합니다..."
if openssl x509 -in "$CA_CERT_FILE" -text -noout > /dev/null 2>&1; then
    echo_info "CA 인증서 형식이 올바릅니다."
    
    # 인증서 정보 표시
    echo_info "인증서 정보:"
    openssl x509 -in "$CA_CERT_FILE" -subject -issuer -dates -noout
else
    echo_error "CA 인증서 형식이 올바르지 않습니다."
    exit 1
fi

echo ""
echo_info "=========================================="
echo_info "CA 인증서 설치가 완료되었습니다!"
echo_info "=========================================="
echo ""
echo_info "이제 다음 명령으로 HTTPS 요청을 보낼 수 있습니다:"
echo_info "curl -x http://127.0.0.1:8080 -X POST -d \"test=data\" https://httpbin.org/post"
echo ""
echo_warn "주의: 이 CA 인증서는 개발/테스트 목적으로만 사용하세요."
echo_warn "프로덕션 환경에서는 사용하지 마세요."
