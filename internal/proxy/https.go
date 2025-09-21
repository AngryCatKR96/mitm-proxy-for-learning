package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"vpn-mitm-proxy/internal/cert"
	. "vpn-mitm-proxy/internal/global"
)

type HTTPSProxy struct {
	certManager *cert.CertificateManager
}

func NewHTTPSProxy(certManager *cert.CertificateManager, logger Logger) *HTTPSProxy {
	return &HTTPSProxy{
		certManager: certManager,
	}
}

func (h *HTTPSProxy) HandleConnection(clientConn net.Conn, hostname string) {
	defer clientConn.Close()

	// 호스트명에 대한 인증서 가져오기
	certInfo, err := h.certManager.GetCertificate(hostname)
	if err != nil {
		Error("Failed to get certificate for %s: %v", hostname, err)
		return
	}

	Info("Certificate obtained for %s", hostname)

	// 인증서 정보로부터 TLS 인증서 생성
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certInfo.Certificate.Raw},
		PrivateKey:  certInfo.PrivateKey,
	}

	// HTTP/1.1 TLS 설정 생성 - 더 안정적인 설정
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ServerName:   hostname,
		NextProtos:   []string{"http/1.1"},
		// Go의 기본 암호화 스위트 사용 (더 안정적)
		// CipherSuites를 지정하지 않으면 Go가 클라이언트와 서버 모두에서 지원하는 것을 자동 선택
	}

	// 클라이언트 연결을 TLS로 업그레이드
	clientTLSConn := tls.Server(clientConn, clientTLSConfig)

	// TLS 핸드셰이크 타임아웃 설정 (더 긴 시간 허용)
	clientTLSConn.SetDeadline(time.Now().Add(120 * time.Second))

	Info("Attempting TLS handshake for %s...", hostname)
	err = clientTLSConn.Handshake()
	if err != nil {
		Error("Failed to complete TLS handshake with client: %v", err)
		Error("TLS handshake error details for %s: %T", hostname, err)
		return
	}

	// 핸드셰이크 완료 후 데드라인 해제
	clientTLSConn.SetDeadline(time.Time{})

	Info("TLS handshake completed successfully for %s", hostname)

	// HTTP/1.1 연결 처리
	Info("TLS handshake completed with client for %s, using HTTP/1.1", hostname)
	h.handleHTTPSConnection(clientTLSConn, hostname)
}

func (h *HTTPSProxy) handleHTTPSConnection(clientTLSConn *tls.Conn, hostname string) {
	reader := bufio.NewReader(clientTLSConn)

	for {
		// 읽기 데드라인 설정 (더 긴 시간 허용)
		clientTLSConn.SetReadDeadline(time.Now().Add(60 * time.Second))

		Info("Waiting for HTTPS request from client...")
		// TLS를 통한 HTTP 요청 읽기
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				Error("Failed to read HTTPS request: %v", err)
			}
			Info("HTTPS connection closed for %s", hostname)
			return
		}

		Info("HTTPS request received from client")

		// 올바른 호스트와 스키마 설정
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = hostname
		}
		if req.Host == "" {
			req.Host = hostname
		}

		Info("HTTPS Request: %s %s", req.Method, req.URL.String())
		h.logHTTPSRequest(req, hostname)

		// 요청을 대상 서버로 전달
		err = h.forwardHTTPSRequest(clientTLSConn, req, hostname)
		if err != nil {
			Error("Failed to forward HTTPS request: %v", err)
			return
		}

		// 연결을 유지해야 하는지 확인
		if !h.shouldKeepAlive(req) {
			Info("Closing HTTPS connection for %s", hostname)
			return
		}
	}
}

func (h *HTTPSProxy) forwardHTTPSRequest(clientTLSConn *tls.Conn, req *http.Request, hostname string) error {
	// 대상 포트 결정
	targetAddr := hostname
	if !strings.Contains(hostname, ":") {
		targetAddr = hostname + ":443"
	}

	// 대상 서버에 대한 TLS 연결 생성
	targetTLSConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // MITM 목적을 위해
	}

	targetTLSConn, err := tls.Dial("tcp", targetAddr, targetTLSConfig)
	if err != nil {
		// 클라이언트에 오류 응답 전송
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}
		resp.Header.Set("Content-Length", "0")
		resp.Write(clientTLSConn)
		return fmt.Errorf("failed to connect to target server: %v", err)
	}
	defer targetTLSConn.Close()

	// 요청을 대상 서버로 전달
	err = req.Write(targetTLSConn)
	if err != nil {
		return fmt.Errorf("failed to write HTTPS request to target server: %v", err)
	}

	// 대상 서버로부터 응답 읽기
	targetReader := bufio.NewReader(targetTLSConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		return fmt.Errorf("failed to read HTTPS response from target server: %v", err)
	}
	defer resp.Body.Close()

	Info("HTTPS Response: %d %s", resp.StatusCode, resp.Status)
	h.logHTTPSResponse(resp, hostname)

	// 응답을 클라이언트로 전달
	err = resp.Write(clientTLSConn)
	if err != nil {
		return fmt.Errorf("failed to write HTTPS response to client: %v", err)
	}

	return nil
}

func (h *HTTPSProxy) shouldKeepAlive(req *http.Request) bool {
	// Connection 헤더 확인
	connection := strings.ToLower(req.Header.Get("Connection"))

	// HTTP/1.1은 기본적으로 keep-alive
	if req.ProtoMajor == 1 && req.ProtoMinor == 1 {
		return connection != "close"
	}

	// HTTP/1.0은 기본적으로 close
	return connection == "keep-alive"
}

func (h *HTTPSProxy) logHTTPSRequest(req *http.Request, hostname string) {
	Info("--- HTTPS Request to %s ---", hostname)
	Info("Method: %s", req.Method)
	Info("URL: %s", req.URL.String())
	Info("Proto: %s", req.Proto)
	Info("Host: %s", req.Host)

	// 중요한 헤더 로깅
	h.logHTTPHeaders(req.Header, "Request")

	// 모든 요청의 본문 로깅
	h.logRequestBody(req)
	Info("--- End HTTPS Request to %s ---", hostname)
}

func (h *HTTPSProxy) logHTTPSResponse(resp *http.Response, hostname string) {
	Info("--- HTTPS Response from %s ---", hostname)
	Info("Status: %d %s", resp.StatusCode, resp.Status)
	Info("Proto: %s", resp.Proto)

	// 중요한 헤더 로깅
	h.logHTTPHeaders(resp.Header, "Response")

	// 응답 본문 로깅
	h.logResponseBody(resp)
	Info("--- End HTTPS Response from %s ---", hostname)
}

func (h *HTTPSProxy) logHTTPHeaders(headers http.Header, direction string) {
	// 중요한 헤더들만 로깅
	importantHeaders := []string{
		"User-Agent",
		"Content-Type",
		"Content-Length",
		"Accept",
		"Authorization",
		"Cookie",
		"Set-Cookie",
		"Cache-Control",
		"Pragma",
		"Expires",
		"Last-Modified",
		"ETag",
		"Location",
		"Server",
		"Date",
		"Connection",
		"Upgrade",
		"Host",
	}

	for _, headerName := range importantHeaders {
		if values, exists := headers[headerName]; exists {
			for _, value := range values {
				Info("%s %s: %s", direction, headerName, value)
			}
		}
	}
}

func (h *HTTPSProxy) logRequestBody(req *http.Request) {
	Info("Content-Length: %d", req.ContentLength)

	// 본문이 있는지 확인하고 읽기
	body, err := io.ReadAll(req.Body)
	if err == nil && len(body) > 0 {
		if len(body) < 10240 { // 10KB 제한
			bodyStr := string(body)
			if h.containsSensitiveData(bodyStr) {
				Info("Request Body: [REDACTED - contains sensitive data]")
			} else {
				Info("Request Body: %s", bodyStr)
			}
		} else {
			Info("Request Body: [TOO LARGE - %d bytes]", len(body))
		}
		// 전달을 위해 본문 복원
		req.Body = io.NopCloser(strings.NewReader(string(body)))
	} else {
		Info("Request Body: [EMPTY or ERROR: %v]", err)
	}
}

func (h *HTTPSProxy) logResponseBody(resp *http.Response) {
	Info("Response Content-Length: %d", resp.ContentLength)

	// 응답 본문이 있는지 확인하고 읽기
	body, err := io.ReadAll(resp.Body)
	if err == nil && len(body) > 0 {
		if len(body) < 10240 { // 10KB 제한
			bodyStr := string(body)
			if h.containsSensitiveData(bodyStr) {
				Info("Response Body: [REDACTED - contains sensitive data]")
			} else {
				Info("Response Body: %s", bodyStr)
			}
		} else {
			Info("Response Body: [TOO LARGE - %d bytes]", len(body))
		}
		// 전달을 위해 본문 복원
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
	} else {
		Info("Response Body: [EMPTY or ERROR: %v]", err)
	}
}

func (h *HTTPSProxy) containsSensitiveData(data string) bool {
	// 민감한 데이터 패턴 검사
	sensitivePatterns := []string{
		"password",
		"token",
		"secret",
		"key",
		"auth",
		"credit",
		"ssn",
		"social",
	}

	lowerData := strings.ToLower(data)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerData, pattern) {
			return true
		}
	}
	return false
}
