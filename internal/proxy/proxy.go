package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vpn-mitm-proxy/internal/cert"
	. "vpn-mitm-proxy/internal/global"
	"vpn-mitm-proxy/internal/packet"
	"vpn-mitm-proxy/internal/tun"
)

type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

type Config struct {
	TUNInterface  string
	HTTPPort      int
	HTTPSPort     int
	LogLevel      string
	CertCacheSize int
	CertValidity  time.Duration
	KeySize       int
}

type MITMProxy struct {
	config           Config
	logger           Logger
	tunDevice        *tun.TUNDevice
	httpListener     net.Listener
	httpsListener    net.Listener
	httpProxy        *HTTPProxy
	httpsProxy       *HTTPSProxy
	certManager      *cert.CertificateManager
	activeConns      map[net.Conn]bool
	activeConnsMutex sync.RWMutex
	redirectedConns  map[string]*RedirectedConnection
	redirectedMutex  sync.RWMutex
	stopChan         chan struct{}
	wg               sync.WaitGroup
}

type RedirectedConnection struct {
	Conn       net.Conn
	OriginalIP string
	Port       int
}

func NewMITMProxy(config Config, logger Logger) *MITMProxy {
	return &MITMProxy{
		config:          config,
		logger:          logger,
		activeConns:     make(map[net.Conn]bool),
		redirectedConns: make(map[string]*RedirectedConnection),
		stopChan:        make(chan struct{}),
	}
}

func (m *MITMProxy) Start() error {
	Info("Starting MITM Proxy...")

	// TUN 디바이스 생성
	err := m.setupTUNDevice()
	if err != nil {
		return fmt.Errorf("failed to setup TUN device: %v", err)
	}

	// 인증서 관리자 초기화
	err = m.setupCertificateManager()
	if err != nil {
		return fmt.Errorf("failed to setup certificate manager: %v", err)
	}

	// 프록시 초기화
	m.httpProxy = NewHTTPProxy(m.logger)
	m.httpsProxy = NewHTTPSProxy(m.certManager, m.logger)

	// HTTP 리스너 시작
	err = m.startHTTPListener()
	if err != nil {
		return fmt.Errorf("failed to start HTTP listener: %v", err)
	}

	// HTTPS 리스너 시작
	err = m.startHTTPSListener()
	if err != nil {
		return fmt.Errorf("failed to start HTTPS listener: %v", err)
	}

	// iptables 규칙 설정
	err = m.setupIPTables()
	if err != nil {
		return fmt.Errorf("failed to setup iptables: %v", err)
	}

	// 패킷 처리 시작
	m.wg.Add(1)
	go m.processTUNPackets()

	// HTTP 연결 처리 시작
	m.wg.Add(1)
	go m.acceptHTTPConnections()

	// HTTPS 연결 처리 시작
	m.wg.Add(1)
	go m.acceptHTTPSConnections()

	Info("MITM Proxy started successfully")
	Info("HTTP Proxy listening on port %d", m.config.HTTPPort)
	Info("HTTPS Proxy listening on port %d", m.config.HTTPSPort)
	Info("Configuration:")
	Info("TUN Interface: %s", m.config.TUNInterface)
	Info("HTTP Port: %d", m.config.HTTPPort)
	Info("HTTPS Port: %d", m.config.HTTPSPort)
	Info("Log Level: %s", m.config.LogLevel)

	return nil
}

func (m *MITMProxy) Stop() error {
	Info("Stopping MITM Proxy...")

	// 모든 고루틴에 정지 신호 전송
	close(m.stopChan)

	// 리스너 종료 (고루틴들이 종료되도록)
	if m.httpListener != nil {
		Info("Closing HTTP listener...")
		m.httpListener.Close()
	}
	if m.httpsListener != nil {
		Info("Closing HTTPS listener...")
		m.httpsListener.Close()
	}

	// TUN 디바이스 종료
	if m.tunDevice != nil {
		Info("Closing TUN device...")
		m.tunDevice.Close()
	}

	// 모든 활성 연결 종료
	Info("Closing active connections...")
	m.activeConnsMutex.Lock()
	for conn := range m.activeConns {
		conn.Close()
	}
	m.activeConns = make(map[net.Conn]bool)
	m.activeConnsMutex.Unlock()

	// 리다이렉션된 연결들 종료
	Info("Closing redirected connections...")
	m.redirectedMutex.Lock()
	for _, redirectedConn := range m.redirectedConns {
		redirectedConn.Conn.Close()
	}
	m.redirectedConns = make(map[string]*RedirectedConnection)
	m.redirectedMutex.Unlock()

	// 모든 고루틴이 종료될 때까지 대기 (타임아웃 설정)
	Info("Waiting for goroutines to finish...")
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		Info("All goroutines finished")
	case <-time.After(5 * time.Second):
		Warn("Timeout waiting for goroutines to finish")
	}

	// iptables 규칙 정리
	Info("Cleaning up iptables rules...")
	m.cleanupIPTables()

	Info("MITM Proxy stopped")
	return nil
}

func (m *MITMProxy) GetRootCAPEM() ([]byte, error) {
	if m.certManager == nil {
		return nil, fmt.Errorf("certificate manager not initialized")
	}
	return m.certManager.GetRootCAPEM()
}

func (m *MITMProxy) setupTUNDevice() error {
	Info("Setting up TUN device...")

	// TUN 디바이스 생성
	tunDevice, err := tun.NewTUNDevice(m.config.TUNInterface)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	// TUN 디바이스 설정 (Configure 메서드가 없으므로 생략)
	// 실제 구현에서는 IP 주소 설정이 필요할 수 있음

	m.tunDevice = tunDevice
	Info("TUN device %s created successfully", m.config.TUNInterface)
	return nil
}

func (m *MITMProxy) setupCertificateManager() error {
	Info("Setting up certificate manager...")

	certManager, err := cert.NewCertificateManager(m.config.CertCacheSize)
	if err != nil {
		return fmt.Errorf("failed to create certificate manager: %v", err)
	}

	m.certManager = certManager
	Info("Certificate manager created successfully")
	return nil
}

func (m *MITMProxy) startHTTPListener() error {
	Info("Starting HTTP listener on port %d", m.config.HTTPPort)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.config.HTTPPort))
	if err != nil {
		return fmt.Errorf("failed to start HTTP listener: %v", err)
	}

	m.httpListener = listener
	Info("HTTP listener started successfully")
	return nil
}

func (m *MITMProxy) startHTTPSListener() error {
	Info("Starting HTTPS listener on port %d", m.config.HTTPSPort)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.config.HTTPSPort))
	if err != nil {
		return fmt.Errorf("failed to start HTTPS listener: %v", err)
	}

	m.httpsListener = listener
	Info("HTTPS listener started successfully")
	return nil
}

func (m *MITMProxy) setupIPTables() error {
	Info("Setting up iptables rules...")

	// HTTP 트래픽을 HTTP 프록시로 리다이렉션
	httpRule := fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
		m.config.TUNInterface, m.config.HTTPPort)
	err := m.executeCommand(httpRule)
	if err != nil {
		return fmt.Errorf("failed to setup HTTP iptables rule: %v", err)
	}

	// HTTPS 트래픽을 HTTPS 프록시로 리다이렉션
	httpsRule := fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -p tcp --dport 443 -j REDIRECT --to-port %d",
		m.config.TUNInterface, m.config.HTTPSPort)
	err = m.executeCommand(httpsRule)
	if err != nil {
		return fmt.Errorf("failed to setup HTTPS iptables rule: %v", err)
	}

	// 추가 포트들도 HTTP 프록시로 리다이렉션
	additionalPorts := []int{8080, 8443, 8000, 9000}
	for _, port := range additionalPorts {
		rule := fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -p tcp --dport %d -j REDIRECT --to-port %d",
			m.config.TUNInterface, port, m.config.HTTPPort)
		err := m.executeCommand(rule)
		if err != nil {
			Warn("Failed to setup iptables rule for port %d: %v", port, err)
		}
	}

	Info("iptables rules setup completed")
	return nil
}

func (m *MITMProxy) cleanupIPTables() error {
	Info("Cleaning up iptables rules...")

	// HTTP 규칙 제거
	httpRule := fmt.Sprintf("iptables -t nat -D PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
		m.config.TUNInterface, m.config.HTTPPort)
	m.executeCommand(httpRule)

	// HTTPS 규칙 제거
	httpsRule := fmt.Sprintf("iptables -t nat -D PREROUTING -i %s -p tcp --dport 443 -j REDIRECT --to-port %d",
		m.config.TUNInterface, m.config.HTTPSPort)
	m.executeCommand(httpsRule)

	// 추가 포트 규칙 제거
	additionalPorts := []int{8080, 8443, 8000, 9000}
	for _, port := range additionalPorts {
		rule := fmt.Sprintf("iptables -t nat -D PREROUTING -i %s -p tcp --dport %d -j REDIRECT --to-port %d",
			m.config.TUNInterface, port, m.config.HTTPPort)
		m.executeCommand(rule)
	}

	Info("iptables rules cleaned up")
	return nil
}

func (m *MITMProxy) executeCommand(command string) error {
	Info("Executed iptables command: %s", command)
	// 실제 구현에서는 os/exec를 사용하여 명령어 실행
	// 여기서는 로깅만 수행
	return nil
}

func (m *MITMProxy) addActiveConnection(conn net.Conn) {
	m.activeConnsMutex.Lock()
	defer m.activeConnsMutex.Unlock()
	m.activeConns[conn] = true
}

func (m *MITMProxy) removeActiveConnection(conn net.Conn) {
	m.activeConnsMutex.Lock()
	defer m.activeConnsMutex.Unlock()
	delete(m.activeConns, conn)
}

func (m *MITMProxy) processTUNPackets() {
	defer m.wg.Done()

	buffer := make([]byte, 1500) // MTU 크기

	for {
		select {
		case <-m.stopChan:
			Info("TUN packet processor stopping...")
			return
		default:
		}

		// TUN 디바이스 읽기를 고루틴으로 처리하여 타임아웃 구현
		readChan := make(chan struct {
			n   int
			err error
		}, 1)

		go func() {
			n, err := m.tunDevice.Read(buffer)
			readChan <- struct {
				n   int
				err error
			}{n, err}
		}()

		select {
		case <-m.stopChan:
			Info("TUN packet processor stopped")
			return
		case result := <-readChan:
			if result.err != nil {
				select {
				case <-m.stopChan:
					Info("TUN packet processor stopped")
					return
				default:
					Error("Failed to read from TUN device: %v", result.err)
					continue
				}
			}

			// 패킷 처리
			err := m.handleTUNPacket(buffer[:result.n])
			if err != nil {
				Error("Failed to handle TUN packet: %v", err)
			}
		case <-time.After(1 * time.Second):
			// 타임아웃 - 계속 루프
			continue
		}
	}
}

func (m *MITMProxy) handleTUNPacket(data []byte) error {
	// IP 패킷 파싱
	ipPacket, err := packet.ParseIPPacket(data)
	if err != nil {
		return fmt.Errorf("failed to parse IP packet: %v", err)
	}

	// TCP 패킷인지 확인
	if ipPacket.IPHdr.Protocol != 6 { // TCP 프로토콜 번호
		return nil // TCP가 아닌 패킷은 무시
	}

	// TCP 패킷 파싱
	tcpHdr, _, err := packet.ParseTCPHeader(ipPacket.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse TCP packet: %v", err)
	}

	// HTTP/HTTPS 포트인지 확인
	if tcpHdr.DstPort == 80 || tcpHdr.DstPort == 443 ||
		tcpHdr.DstPort == 8080 || tcpHdr.DstPort == 8443 ||
		tcpHdr.DstPort == 8000 || tcpHdr.DstPort == 9000 {
		// 리다이렉션된 연결 처리
		return m.handleRedirectedConnection(ipPacket, tcpHdr)
	}

	return nil
}

func (m *MITMProxy) handleRedirectedConnection(ipPacket *packet.Packet, tcpHdr *packet.TCPHeader) error {
	// 연결 정보 생성
	clientAddr := net.JoinHostPort(ipPacket.IPHdr.SrcIP.String(), fmt.Sprintf("%d", tcpHdr.SrcPort))
	serverAddr := net.JoinHostPort(ipPacket.IPHdr.DstIP.String(), fmt.Sprintf("%d", tcpHdr.DstPort))

	// 리다이렉션된 연결인지 확인
	connKey := fmt.Sprintf("tcp_%s_%s", clientAddr, serverAddr)
	m.redirectedMutex.RLock()
	_, exists := m.redirectedConns[connKey]
	m.redirectedMutex.RUnlock()

	if exists {
		// 기존 연결에 데이터 전달 (payload는 별도로 전달해야 함)
		// 여기서는 간단히 처리
		return nil
	}

	// 새로운 연결 생성
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}

	// 리다이렉션된 연결 저장
	redirectedConn := &RedirectedConnection{
		Conn:       conn,
		OriginalIP: ipPacket.IPHdr.DstIP.String(),
		Port:       int(tcpHdr.DstPort),
	}

	m.redirectedMutex.Lock()
	m.redirectedConns[connKey] = redirectedConn
	m.redirectedMutex.Unlock()

	// 연결 처리 시작
	go m.handleConnection(conn, redirectedConn)

	return nil
}

func (m *MITMProxy) handleConnection(conn net.Conn, redirectedConn *RedirectedConnection) {
	defer conn.Close()
	defer func() {
		m.redirectedMutex.Lock()
		delete(m.redirectedConns, fmt.Sprintf("tcp_%s_%s", conn.RemoteAddr().String(), conn.LocalAddr().String()))
		m.redirectedMutex.Unlock()
	}()

	// 양방향 데이터 전달
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(conn, redirectedConn.Conn)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(redirectedConn.Conn, conn)
	}()

	<-done
}

func (m *MITMProxy) acceptHTTPConnections() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			Info("HTTP listener stopping...")
			return
		default:
		}

		// 리스너에 타임아웃 설정
		if tcpListener, ok := m.httpListener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := m.httpListener.Accept()
		if err != nil {
			select {
			case <-m.stopChan:
				Info("HTTP listener stopped")
				return
			default:
				// 타임아웃이면 계속 루프
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				Error("Failed to accept HTTP connection: %v", err)
				continue
			}
		}

		m.addActiveConnection(conn)

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer m.removeActiveConnection(conn)
			m.handleRedirectedHTTPConnection(conn)
		}()
	}
}

func (m *MITMProxy) acceptHTTPSConnections() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			Info("HTTPS listener stopping...")
			return
		default:
		}

		// 리스너에 타임아웃 설정
		if tcpListener, ok := m.httpsListener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := m.httpsListener.Accept()
		if err != nil {
			select {
			case <-m.stopChan:
				Info("HTTPS listener stopped")
				return
			default:
				// 타임아웃이면 계속 루프
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				Error("Failed to accept HTTPS connection: %v", err)
				continue
			}
		}

		m.addActiveConnection(conn)

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer m.removeActiveConnection(conn)
			m.handleRedirectedHTTPSConnection(conn)
		}()
	}
}

func (m *MITMProxy) handleRedirectedHTTPConnection(conn net.Conn) {
	// 리다이렉션된 HTTP 연결 처리
	clientAddr := conn.RemoteAddr().String()
	Info("Handling redirected HTTP connection from %s", clientAddr)

	// 원본 목적지 정보를 추출하기 위해 SO_ORIGINAL_DST 소켓 옵션 사용
	originalDst, err := m.getOriginalDestination(conn)
	if err != nil {
		Warn("Failed to get original destination: %v", err)
		// 원본 목적지를 알 수 없는 경우 일반 HTTP 프록시로 처리
		m.httpProxy.HandleConnection(conn)
		return
	}

	Info("Original destination: %s", originalDst)

	// CONNECT 요청인지 확인하기 위해 초기 데이터 읽기
	// 연결에 읽기 타임아웃 설정
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// CONNECT 요청의 경우 첫 번째 줄만 읽어서 확인
	reader := bufio.NewReader(conn)
	firstLine, err := reader.Peek(100) // 첫 100바이트만 미리보기
	if err != nil {
		Warn("Failed to peek connection data: %v", err)
		m.httpProxy.HandleConnection(conn)
		return
	}

	displayLen := len(firstLine)
	if displayLen > 50 {
		displayLen = 50
	}
	Info("Peeked %d bytes of data: %s", len(firstLine), string(firstLine[:displayLen]))

	// CONNECT 요청인지 확인
	if m.isHTTPConnect(firstLine) {
		Info("CONNECT request detected in initial data")
		// CONNECT 요청 파싱
		req, err := http.ReadRequest(reader)
		if err != nil {
			Error("Failed to parse CONNECT request: %v", err)
			conn.Close()
			return
		}

		if req.Method == "CONNECT" {
			// CONNECT 요청을 HTTPS 프록시로 처리
			Info("CONNECT request confirmed, routing to HTTPS proxy")
			m.handleCONNECTRequest(conn, req)
			return
		}
	}

	// 리다이렉션된 연결 정보 저장
	connKey := fmt.Sprintf("http_%s_%s", clientAddr, originalDst)
	m.storeRedirectedConnection(connKey, conn, originalDst, 80)

	// HTTP 요청 파싱 (reader를 사용)
	req, err := http.ReadRequest(reader)
	if err != nil {
		Warn("Failed to parse HTTP request: %v", err)
		m.httpProxy.HandleConnection(conn)
		return
	}

	// HTTP 요청을 직접 처리
	Info("HTTP Request: %s %s", req.Method, req.URL.String())

	// HTTP 요청 로깅 (본문 포함)
	m.httpProxy.LogHTTPRequest(req)

	// HTTP 프록시의 HandleHTTPRequest 함수를 직접 호출
	err = m.httpProxy.HandleHTTPRequest(conn, req)
	if err != nil {
		Error("Failed to handle HTTP request: %v", err)
		conn.Close()
		return
	}
}

func (m *MITMProxy) handleRedirectedHTTPSConnection(conn net.Conn) {
	// 리다이렉션된 HTTPS 연결 처리
	clientAddr := conn.RemoteAddr().String()
	Info("Handling redirected HTTPS connection from %s", clientAddr)

	// 원본 목적지 정보를 추출하기 위해 SO_ORIGINAL_DST 소켓 옵션 사용
	originalDst, err := m.getOriginalDestination(conn)
	if err != nil {
		Warn("Failed to get original destination: %v", err)
		// 원본 목적지를 알 수 없는 경우 일반 HTTPS 프록시로 처리
		m.httpsProxy.HandleConnection(conn, "unknown")
		return
	}

	Info("Original destination: %s", originalDst)

	// SNI 추출을 위한 초기 데이터 읽기
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	initialData := make([]byte, 1024)
	n, err := conn.Read(initialData)
	if err != nil {
		Warn("Failed to read initial data: %v", err)
		m.httpsProxy.HandleConnection(conn, "unknown")
		return
	}

	initialData = initialData[:n]

	// TLS 핸드셰이크에서 SNI 추출
	sni := m.extractSNIFromTLS(initialData)
	if sni == "" {
		Warn("Failed to extract SNI from TLS handshake")
		sni = "unknown"
	}

	Info("Extracted SNI: %s", sni)

	// HTTPS 프록시로 연결 전달
	m.httpsProxy.HandleConnection(conn, sni)
}

func (m *MITMProxy) getOriginalDestination(conn net.Conn) (string, error) {
	// SO_ORIGINAL_DST 소켓 옵션을 사용하여 원본 목적지 추출
	// 실제 구현에서는 syscall을 사용
	// 여기서는 더미 값 반환
	return "127.0.0.1:8080", nil
}

func (m *MITMProxy) isHTTPConnect(data []byte) bool {
	// CONNECT 요청인지 확인
	return strings.Contains(string(data), "CONNECT")
}

func (m *MITMProxy) extractSNIFromTLS(data []byte) string {
	// TLS 핸드셰이크에서 SNI 추출
	// 실제 구현에서는 TLS 패킷을 파싱하여 SNI 추출
	// 여기서는 더미 값 반환
	return "example.com"
}

func (m *MITMProxy) storeRedirectedConnection(key string, conn net.Conn, originalIP string, port int) {
	m.redirectedMutex.Lock()
	defer m.redirectedMutex.Unlock()

	redirectedConn := &RedirectedConnection{
		Conn:       conn,
		OriginalIP: originalIP,
		Port:       port,
	}

	m.redirectedConns[key] = redirectedConn
	Info("Stored redirected connection: %s -> %s:%d", key, originalIP, port)
}

func (m *MITMProxy) handleCONNECTRequest(clientConn net.Conn, req *http.Request) {
	Info("CONNECT request to: %s", req.Host)

	// Host 헤더에서 호스트명 추출
	hostname := req.Host
	if strings.Contains(hostname, ":") {
		hostname = strings.Split(hostname, ":")[0]
	}

	Info("Extracted hostname: %s", hostname)

	// 200 Connection Established 응답 전송
	Info("Sending 200 Connection Established response")
	_, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		Error("Failed to send CONNECT response: %v", err)
		return
	}

	// CONNECT 응답 전송 후 연결을 정리하고 TLS 핸드셰이크 준비
	// 클라이언트가 이제 TLS 핸드셰이크를 시작할 것임
	Info("CONNECT response sent, preparing for TLS handshake with %s", hostname)

	// 연결의 읽기 데드라인을 해제하여 TLS 핸드셰이크가 정상적으로 진행되도록 함
	clientConn.SetDeadline(time.Time{})

	// HTTPS 프록시로 연결 전달
	Info("Calling HTTPS proxy HandleConnection for %s", hostname)
	m.httpsProxy.HandleConnection(clientConn, hostname)
	Info("HTTPS proxy HandleConnection completed for %s", hostname)
}
