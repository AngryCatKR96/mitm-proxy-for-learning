package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	. "vpn-mitm-proxy/internal/global"
)

type HTTPProxy struct {
}

func NewHTTPProxy(logger Logger) *HTTPProxy {
	return &HTTPProxy{}
}

func (h *HTTPProxy) HandleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)

	for {
		// 읽기 데드라인 설정
		clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// HTTP 요청 읽기
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				Error("Failed to read HTTP request: %v", err)
			}
			return
		}

		Info("HTTP Request: %s %s", req.Method, req.URL.String())
		h.LogHTTPRequest(req)

		// HTTPS 터널링을 위한 CONNECT 메서드 처리
		if req.Method == "CONNECT" {
			h.handleConnect(clientConn, req)
			return
		}

		// 일반 HTTP 요청 처리
		err = h.HandleHTTPRequest(clientConn, req)
		if err != nil {
			Error("Failed to handle HTTP request: %v", err)
			return
		}

		// 연결을 유지해야 하는지 확인
		if !h.shouldKeepAlive(req) {
			return
		}
	}
}

func (h *HTTPProxy) HandleHTTPRequest(clientConn net.Conn, req *http.Request) error {
	// 대상 URL 파싱
	targetURL := req.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = req.Host
	}

	// 포트가 없으면 기본 포트 추가
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	// 대상 서버에 연결 생성
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
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
		resp.Write(clientConn)
		return fmt.Errorf("failed to connect to target server: %v", err)
	}
	defer targetConn.Close()

	// 요청을 대상 서버로 전달
	err = req.Write(targetConn)
	if err != nil {
		return fmt.Errorf("failed to write request to target server: %v", err)
	}

	// 대상 서버로부터 응답 읽기
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		return fmt.Errorf("failed to read response from target server: %v", err)
	}
	defer resp.Body.Close()

	Info("HTTP Response: %d %s", resp.StatusCode, resp.Status)
	h.logHTTPResponse(resp)

	// 응답을 클라이언트로 전달
	err = resp.Write(clientConn)
	if err != nil {
		return fmt.Errorf("failed to write response to client: %v", err)
	}

	return nil
}

func (h *HTTPProxy) handleConnect(clientConn net.Conn, req *http.Request) {
	Info("CONNECT request to: %s", req.Host)

	// 대상 서버에 연결 생성
	targetConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		Error("Failed to connect to target server: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// 200 Connection Established 응답 전송
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 양방향 전달 시작
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(clientConn, targetConn)
	}()

	<-done
}

func (h *HTTPProxy) shouldKeepAlive(req *http.Request) bool {
	// Connection 헤더 확인
	connection := strings.ToLower(req.Header.Get("Connection"))

	// HTTP/1.1은 기본적으로 keep-alive
	if req.ProtoMajor == 1 && req.ProtoMinor == 1 {
		return connection != "close"
	}

	// HTTP/1.0은 기본적으로 close
	return connection == "keep-alive"
}

func (h *HTTPProxy) LogHTTPRequest(req *http.Request) {
	Info("--- HTTP Request ---")
	Info("Method: %s", req.Method)
	Info("URL: %s", req.URL.String())
	Info("Proto: %s", req.Proto)
	Info("Host: %s", req.Host)

	// 헤더 로깅
	for name, values := range req.Header {
		for _, value := range values {
			Info("Header: %s: %s", name, value)
		}
	}

	// 모든 요청의 본문 로깅 (큰 본문은 제외)
	Info("Content-Length: %d", req.ContentLength)

	// 본문이 있는지 확인하고 읽기
	body, err := io.ReadAll(req.Body)
	if err == nil && len(body) > 0 {
		if len(body) < 10240 { // 10KB 제한
			Info("Request Body: %s", string(body))
		} else {
			Info("Request Body: [TOO LARGE - %d bytes]", len(body))
		}
		// 전달을 위해 본문 복원
		req.Body = io.NopCloser(strings.NewReader(string(body)))
	} else {
		Info("Request Body: [EMPTY or ERROR: %v]", err)
	}

	Info("--- End HTTP Request ---")
}

func (h *HTTPProxy) logHTTPResponse(resp *http.Response) {
	Info("--- HTTP Response ---")
	Info("Status: %d %s", resp.StatusCode, resp.Status)
	Info("Proto: %s", resp.Proto)

	// 헤더 로깅
	for name, values := range resp.Header {
		for _, value := range values {
			Info("Header: %s: %s", name, value)
		}
	}

	// 콘텐츠 타입과 길이 로깅
	contentType := resp.Header.Get("Content-Type")
	contentLength := resp.Header.Get("Content-Length")
	if contentType != "" {
		Info("Content-Type: %s", contentType)
	}
	if contentLength != "" {
		Info("Content-Length: %s", contentLength)
	}

	// 응답 본문 로깅 (큰 본문은 제외)
	if resp.ContentLength > 0 && resp.ContentLength < 10240 { // 10KB 제한
		body, err := io.ReadAll(resp.Body)
		if err == nil && len(body) > 0 {
			Info("Response Body: %s", string(body))
			// 전달을 위해 본문 복원
			resp.Body = io.NopCloser(strings.NewReader(string(body)))
		}
	} else if resp.ContentLength > 0 {
		Info("Response Body: [TOO LARGE - %d bytes]", resp.ContentLength)
	}

	Info("--- End HTTP Response ---")
}

// HTTPRequestInfo HTTPRequestInfo는 가로챈 HTTP 요청에 대한 정보를 담습니다
type HTTPRequestInfo struct {
	Method    string
	URL       *url.URL
	Headers   http.Header
	Body      []byte
	Timestamp time.Time
	ClientIP  string
	UserAgent string
}

// HTTPResponseInfo HTTPResponseInfo는 가로챈 HTTP 응답에 대한 정보를 담습니다
type HTTPResponseInfo struct {
	StatusCode    int
	Status        string
	Headers       http.Header
	Body          []byte
	Timestamp     time.Time
	ContentType   string
	ContentLength int64
}

func (h *HTTPProxy) extractRequestInfo(req *http.Request, clientIP string) *HTTPRequestInfo {
	info := &HTTPRequestInfo{
		Method:    req.Method,
		URL:       req.URL,
		Headers:   req.Header,
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		UserAgent: req.Header.Get("User-Agent"),
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

func (h *HTTPProxy) extractResponseInfo(resp *http.Response) *HTTPResponseInfo {
	info := &HTTPResponseInfo{
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Headers:     resp.Header,
		Timestamp:   time.Now(),
		ContentType: resp.Header.Get("Content-Type"),
	}

	// 콘텐츠 길이 파싱
	if contentLengthStr := resp.Header.Get("Content-Length"); contentLengthStr != "" {
		if contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64); err == nil {
			info.ContentLength = contentLength
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
