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
)

type HTTPSProxy struct {
	certManager *cert.CertificateManager
	logger      Logger
}

func NewHTTPSProxy(certManager *cert.CertificateManager, logger Logger) *HTTPSProxy {
	return &HTTPSProxy{
		certManager: certManager,
		logger:      logger,
	}
}

func (h *HTTPSProxy) HandleConnection(clientConn net.Conn, hostname string) {
	defer clientConn.Close()

	// 호스트명에 대한 인증서 가져오기
	certInfo, err := h.certManager.GetCertificate(hostname)
	if err != nil {
		h.logger.Error("Failed to get certificate for %s: %v", hostname, err)
		return
	}

	// 인증서 정보로부터 TLS 인증서 생성
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certInfo.Certificate.Raw},
		PrivateKey:  certInfo.PrivateKey,
	}

	// 클라이언트 연결을 위한 TLS 설정 생성
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ServerName:   hostname,
	}

	// 클라이언트 연결을 TLS로 업그레이드
	clientTLSConn := tls.Server(clientConn, clientTLSConfig)
	err = clientTLSConn.Handshake()
	if err != nil {
		h.logger.Error("Failed to complete TLS handshake with client: %v", err)
		return
	}

	h.logger.Info("TLS handshake completed with client for %s", hostname)

	// HTTPS 연결 처리
	h.handleHTTPSConnection(clientTLSConn, hostname)
}

func (h *HTTPSProxy) handleHTTPSConnection(clientTLSConn *tls.Conn, hostname string) {
	reader := bufio.NewReader(clientTLSConn)

	for {
		// 읽기 데드라인 설정
		clientTLSConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// TLS를 통한 HTTP 요청 읽기
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				h.logger.Error("Failed to read HTTPS request: %v", err)
			}
			return
		}

		// 올바른 호스트와 스키마 설정
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = hostname
		}
		if req.Host == "" {
			req.Host = hostname
		}

		h.logger.Info("HTTPS Request: %s %s", req.Method, req.URL.String())
		h.logHTTPSRequest(req, hostname)

		// 요청을 대상 서버로 전달
		err = h.forwardHTTPSRequest(clientTLSConn, req, hostname)
		if err != nil {
			h.logger.Error("Failed to forward HTTPS request: %v", err)
			return
		}

		// 연결을 유지해야 하는지 확인
		if !h.shouldKeepAlive(req) {
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

	targetTLSConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", targetAddr, targetTLSConfig)
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
		return fmt.Errorf("failed to connect to target HTTPS server: %v", err)
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

	h.logger.Info("HTTPS Response: %d %s", resp.StatusCode, resp.Status)
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
	h.logger.Info("--- HTTPS Request to %s ---", hostname)
	h.logger.Info("Method: %s", req.Method)
	h.logger.Info("URL: %s", req.URL.String())
	h.logger.Info("Proto: %s", req.Proto)
	h.logger.Info("Host: %s", req.Host)

	// 중요한 헤더 로깅
	userAgent := req.Header.Get("User-Agent")
	if userAgent != "" {
		h.logger.Info("User-Agent: %s", userAgent)
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		h.logger.Info("Content-Type: %s", contentType)
	}

	contentLength := req.Header.Get("Content-Length")
	if contentLength != "" {
		h.logger.Info("Content-Length: %s", contentLength)
	}

	authorization := req.Header.Get("Authorization")
	if authorization != "" {
		// 인증 헤더 로깅하지만 민감한 데이터는 마스킹
		if strings.HasPrefix(authorization, "Bearer ") {
			h.logger.Info("Authorization: Bearer [REDACTED]")
		} else if strings.HasPrefix(authorization, "Basic ") {
			h.logger.Info("Authorization: Basic [REDACTED]")
		} else {
			h.logger.Info("Authorization: [REDACTED]")
		}
	}

	// 쿠키 로깅 (민감한 값은 마스킹)
	cookie := req.Header.Get("Cookie")
	if cookie != "" {
		h.logger.Info("Cookie: [PRESENT - %d chars]", len(cookie))
	}

	// 특정 메서드의 본문 로깅 (큰 본문은 제외)
	if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		if req.ContentLength > 0 && req.ContentLength < 1024 {
			body, err := io.ReadAll(req.Body)
			if err == nil && len(body) > 0 {
				// 본문에 민감한 데이터가 포함될 가능성 확인
				bodyStr := string(body)
				if h.containsSensitiveData(bodyStr) {
					h.logger.Info("Body: [REDACTED - contains sensitive data]")
				} else {
					h.logger.Info("Body: %s", bodyStr)
				}
				// 전달을 위해 본문 복원
				req.Body = io.NopCloser(strings.NewReader(bodyStr))
			}
		}
	}
}

func (h *HTTPSProxy) logHTTPSResponse(resp *http.Response, hostname string) {
	h.logger.Info("--- HTTPS Response from %s ---", hostname)
	h.logger.Info("Status: %d %s", resp.StatusCode, resp.Status)
	h.logger.Info("Proto: %s", resp.Proto)

	// 중요한 헤더 로깅
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		h.logger.Info("Content-Type: %s", contentType)
	}

	contentLength := resp.Header.Get("Content-Length")
	if contentLength != "" {
		h.logger.Info("Content-Length: %s", contentLength)
	}

	// 보안 헤더 로깅
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
	}

	for _, header := range securityHeaders {
		if value := resp.Header.Get(header); value != "" {
			h.logger.Info("%s: %s", header, value)
		}
	}

	// Set-Cookie 헤더 로깅 (민감한 값은 마스킹)
	setCookies := resp.Header["Set-Cookie"]
	for i, cookie := range setCookies {
		if h.containsSensitiveData(cookie) {
			h.logger.Info("Set-Cookie[%d]: [REDACTED - contains sensitive data]", i)
		} else {
			h.logger.Info("Set-Cookie[%d]: %s", i, cookie)
		}
	}
}

func (h *HTTPSProxy) containsSensitiveData(data string) bool {
	sensitiveKeywords := []string{
		"password",
		"passwd",
		"token",
		"secret",
		"key",
		"auth",
		"credential",
		"session",
		"csrf",
		"jwt",
	}

	dataLower := strings.ToLower(data)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(dataLower, keyword) {
			return true
		}
	}

	return false
}

// HTTPSRequestInfo는 가로챈 HTTPS 요청에 대한 정보를 담습니다
type HTTPSRequestInfo struct {
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
	Timestamp time.Time
	ClientIP  string
	UserAgent string
	Hostname  string
}

// HTTPSResponseInfo는 가로챈 HTTPS 응답에 대한 정보를 담습니다
type HTTPSResponseInfo struct {
	StatusCode    int
	Status        string
	Headers       http.Header
	Body          []byte
	Timestamp     time.Time
	ContentType   string
	ContentLength int64
	Hostname      string
}

func (h *HTTPSProxy) ExtractRequestInfo(req *http.Request, clientIP, hostname string) *HTTPSRequestInfo {
	info := &HTTPSRequestInfo{
		Method:    req.Method,
		URL:       req.URL.String(),
		Headers:   req.Header,
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		UserAgent: req.Header.Get("User-Agent"),
		Hostname:  hostname,
	}

	// 본문이 있고 너무 크지 않으면 추출
	if req.ContentLength > 0 && req.ContentLength < 10240 { // 10KB 제한
		body, err := io.ReadAll(req.Body)
		if err == nil {
			info.Body = body
			// 전달을 위해 본문 복원
			req.Body = io.NopCloser(strings.NewReader(string(body)))
		}
	}

	return info
}

func (h *HTTPSProxy) ExtractResponseInfo(resp *http.Response, hostname string) *HTTPSResponseInfo {
	info := &HTTPSResponseInfo{
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Headers:     resp.Header,
		Timestamp:   time.Now(),
		ContentType: resp.Header.Get("Content-Type"),
		Hostname:    hostname,
	}

	// 콘텐츠 길이 파싱
	if contentLengthStr := resp.Header.Get("Content-Length"); contentLengthStr != "" {
		if contentLength, err := fmt.Sscanf(contentLengthStr, "%d", &info.ContentLength); err == nil && contentLength == 1 {
			// 콘텐츠 길이 파싱 성공
		}
	}

	// 너무 크지 않고 텍스트 콘텐츠인 경우 본문 추출
	if info.ContentLength > 0 && info.ContentLength < 10240 { // 10KB 제한
		if strings.Contains(info.ContentType, "text/") ||
			strings.Contains(info.ContentType, "application/json") ||
			strings.Contains(info.ContentType, "application/xml") {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				info.Body = body
				// 전달을 위해 본문 복원
				resp.Body = io.NopCloser(strings.NewReader(string(body)))
			}
		}
	}

	return info
}
