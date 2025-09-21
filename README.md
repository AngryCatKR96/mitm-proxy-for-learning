# VPN Traffic HTTP/HTTPS MITM Proxy

Golang 기반의 WireGuard VPN 트래픽을 대상으로 하는 HTTP/HTTPS MITM(Man-in-the-Middle) 프록시입니다.

## 주요 기능

### 1. VPN 트래픽 가로채기
- TUN/TAP 디바이스를 통한 VPN 트래픽 수신
- WireGuard VPN 프로토콜과 독립적으로 동작
- IP 패킷 파싱 및 분석

### 2. 트래픽 필터링 및 분류
- HTTP/HTTPS 트래픽 자동 식별
- HTTP/1.1 및 HTTP/2 프로토콜 지원
- 포트 무관 HTTP/HTTPS 감지
- 비-HTTP 트래픽은 변조 없이 passthrough

### 3. HTTP MITM 프록시
- 투명 HTTP 프록시 기능
- HTTP 요청/응답 가로채기 및 분석
- Keep-alive 연결 지원
- CONNECT 메소드 처리

### 4. HTTPS MITM 프록시
- 동적 SSL/TLS 인증서 생성
- SNI(Server Name Indication) 추출
- TLS 핸드셰이크 가로채기
- 클라이언트-서버 간 암복호화

### 5. 인증서 관리
- 루트 CA 자동 생성
- 도메인별 가짜 인증서 동적 발급
- 인증서 캐싱 및 만료 관리
- SAN(Subject Alternative Name) 지원

### 6. 로깅 시스템
- 상세한 HTTP/HTTPS 트래픽 로깅
- 민감한 정보 자동 마스킹
- 요청/응답 헤더 및 바디 기록
- 설정 가능한 로그 레벨

## 프로젝트 구조

```
vpn-mitm-proxy/
├── main.go                     # 메인 애플리케이션 진입점
├── go.mod                      # Go 모듈 정의
├── internal/
│   ├── tun/
│   │   └── device.go          # TUN 디바이스 인터페이스
│   ├── packet/
│   │   └── parser.go          # 패킷 파싱 및 분석
│   ├── cert/
│   │   └── manager.go         # 인증서 관리
│   ├── proxy/
│   │   ├── proxy.go           # 메인 MITM 프록시
│   │   ├── http.go            # HTTP 프록시
│   │   └── https.go           # HTTPS 프록시
│   └── logger/
│       └── logger.go          # 로깅 시스템
└── README.md
```

## 빌드 및 실행

### 빌드
```bash
go build -o vpn-mitm-proxy main.go
```

### 실행
```bash
# 기본 설정으로 실행
sudo ./vpn-mitm-proxy

# 커스텀 설정으로 실행
sudo ./vpn-mitm-proxy \
  -tun tun0 \
  -http-port 8080 \
  -https-port 8443 \
  -log-level DEBUG \
  -log-file /var/log/mitm-proxy.log \
  -traffic-log /var/log/mitm-traffic.log
```

### 명령행 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-tun` | `tun0` | TUN 인터페이스 이름 |
| `-http-port` | `8080` | HTTP 프록시 포트 |
| `-https-port` | `8443` | HTTPS 프록시 포트 |
| `-log-level` | `INFO` | 로그 레벨 (DEBUG, INFO, WARN, ERROR) |
| `-log-file` | `` | 로그 파일 경로 (빈 값은 콘솔 출력) |
| `-traffic-log` | `` | 트래픽 로그 파일 경로 |
| `-cert-cache` | `1000` | 인증서 캐시 크기 |
| `-max-conns` | `10000` | 최대 동시 연결 수 |

## 사용 전 설정

### 1. TUN 모듈 로드 확인
```bash
# TUN 모듈이 로드되어 있는지 확인
lsmod | grep tun

# TUN 모듈이 없으면 로드
sudo modprobe tun

# TUN 디바이스 파일 확인
ls -la /dev/net/tun
```

### 2. TUN 디바이스 생성
```bash
# TUN 디바이스 생성
sudo ip tuntap add dev tun0 mode tun

# IP 주소 할당
sudo ip addr add 10.0.0.1/24 dev tun0

# 인터페이스 활성화
sudo ip link set dev tun0 up
```

### 3. 권한 설정
- TUN 디바이스 액세스를 위해 루트 권한이 필요합니다
- 또는 `CAP_NET_ADMIN` 권한을 부여하세요:
```bash
# 실행 파일에 CAP_NET_ADMIN 권한 부여
sudo setcap cap_net_admin+ep ./vpn-mitm-proxy
```

### 4. 루트 CA 인증서 설치 (선택사항)
HTTPS MITM을 위해 클라이언트에 루트 CA 인증서를 설치할 수 있습니다.

## 문제 해결

### TUN 디바이스 읽기 에러
"Failed to read from TUN device: read /dev/net/tun: not pollable" 에러가 발생하는 경우:

1. **TUN 모듈 확인**:
   ```bash
   lsmod | grep tun
   sudo modprobe tun
   ```

2. **권한 확인**:
   ```bash
   ls -la /dev/net/tun
   sudo chmod 666 /dev/net/tun
   ```

3. **기존 TUN 인터페이스 정리**:
   ```bash
   sudo ip tuntap del dev tun0 mode tun
   ```

4. **프로그램을 루트 권한으로 실행**:
   ```bash
   sudo ./vpn-mitm-proxy
   ```

## 기술적 특징

### Native Go 구현
- 외부 라이브러리 없이 순수 Go 표준 라이브러리만 사용
- 경량화된 구현으로 높은 성능 제공
- 크로스 플랫폼 호환성

### 동시성 처리
- Goroutine을 활용한 고성능 동시 연결 처리
- 채널을 통한 안전한 상태 관리
- Graceful shutdown 지원

### 보안 고려사항
- 민감한 정보 자동 마스킹
- 안전한 인증서 저장
- 메모리 안전성 보장

## 제한사항

1. **Linux 전용**: TUN/TAP 디바이스는 Linux 시스템에서만 지원
2. **루트 권한 필요**: TUN 디바이스 액세스를 위해 관리자 권한 필요
3. **실험적 목적**: 보안 연구 및 교육 목적으로 설계됨

## 보안 고지

이 프로젝트는 보안 연구 및 교육 목적으로 개발되었습니다. 악의적인 목적으로 사용해서는 안 되며, 관련 법률과 규정을 준수해야 합니다.

## 라이센스

이 프로젝트는 교육 목적으로 제작되었습니다.