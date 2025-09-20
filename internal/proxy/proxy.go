package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vpn-mitm-proxy/internal/cert"
	"vpn-mitm-proxy/internal/logger"
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
	TUNInterface   string
	HTTPPort       int
	HTTPSPort      int
	LogLevel       string
	CertCacheSize  int
	MaxConnections int
	LogFile        string
	TrafficLogFile string
}

type MITMProxy struct {
	config        *Config
	tunDevice     *tun.TUNDevice
	certManager   *cert.CertificateManager
	httpProxy     *HTTPProxy
	httpsProxy    *HTTPSProxy
	logger        Logger
	trafficLogger *logger.HTTPTrafficLogger
	httpListener  net.Listener
	httpsListener net.Listener
	stopChan      chan struct{}
	wg            sync.WaitGroup
	activeConns   map[net.Conn]struct{}
	connMutex     sync.RWMutex
}

func NewMITMProxy(config *Config) (*MITMProxy, error) {
	// 로거 초기화
	mainLogger, err := logger.NewLogger(config.LogLevel, config.LogFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %v", err)
	}

	// 트래픽 로거 초기화
	trafficLogger, err := logger.NewHTTPTrafficLogger(config.TrafficLogFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create traffic logger: %v", err)
	}

	// 인증서 관리자 초기화
	certManager, err := cert.NewCertificateManager(config.CertCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// HTTP 및 HTTPS 프록시 초기화
	httpProxy := NewHTTPProxy(mainLogger)
	httpsProxy := NewHTTPSProxy(certManager, mainLogger)

	proxy := &MITMProxy{
		config:        config,
		certManager:   certManager,
		httpProxy:     httpProxy,
		httpsProxy:    httpsProxy,
		logger:        mainLogger,
		trafficLogger: trafficLogger,
		stopChan:      make(chan struct{}),
		activeConns:   make(map[net.Conn]struct{}),
	}

	return proxy, nil
}

func (m *MITMProxy) Start() error {
	m.logger.Info("Starting MITM Proxy...")

	// TUN 디바이스 초기화
	if err := m.initTUNDevice(); err != nil {
		return fmt.Errorf("failed to initialize TUN device: %v", err)
	}

	// HTTP 프록시 리스너 시작
	if err := m.startHTTPListener(); err != nil {
		return fmt.Errorf("failed to start HTTP listener: %v", err)
	}

	// HTTPS 프록시 리스너 시작
	if err := m.startHTTPSListener(); err != nil {
		return fmt.Errorf("failed to start HTTPS listener: %v", err)
	}

	// TUN 패킷 처리 시작
	m.wg.Add(1)
	go m.processTUNPackets()

	m.logger.Info("MITM Proxy started successfully")
	m.logger.Info("HTTP Proxy listening on port %d", m.config.HTTPPort)
	m.logger.Info("HTTPS Proxy listening on port %d", m.config.HTTPSPort)

	return nil
}

func (m *MITMProxy) initTUNDevice() error {
	var err error
	m.tunDevice, err = tun.NewTUNDevice(m.config.TUNInterface)
	if err != nil {
		return err
	}

	m.logger.Info("TUN device %s created successfully", m.tunDevice.Name())
	return nil
}

func (m *MITMProxy) startHTTPListener() error {
	var err error
	m.httpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", m.config.HTTPPort))
	if err != nil {
		return err
	}

	m.wg.Add(1)
	go m.acceptHTTPConnections()

	return nil
}

func (m *MITMProxy) startHTTPSListener() error {
	var err error
	m.httpsListener, err = net.Listen("tcp", fmt.Sprintf(":%d", m.config.HTTPSPort))
	if err != nil {
		return err
	}

	m.wg.Add(1)
	go m.acceptHTTPSConnections()

	return nil
}

func (m *MITMProxy) acceptHTTPConnections() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			return
		default:
		}

		conn, err := m.httpListener.Accept()
		if err != nil {
			select {
			case <-m.stopChan:
				return
			default:
				m.logger.Error("Failed to accept HTTP connection: %v", err)
				continue
			}
		}

		m.addActiveConnection(conn)

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer m.removeActiveConnection(conn)
			m.httpProxy.HandleConnection(conn)
		}()
	}
}

func (m *MITMProxy) acceptHTTPSConnections() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			return
		default:
		}

		conn, err := m.httpsListener.Accept()
		if err != nil {
			select {
			case <-m.stopChan:
				return
			default:
				m.logger.Error("Failed to accept HTTPS connection: %v", err)
				continue
			}
		}

		m.addActiveConnection(conn)

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer m.removeActiveConnection(conn)
			m.handleHTTPSConnection(conn)
		}()
	}
}

func (m *MITMProxy) handleHTTPSConnection(conn net.Conn) {
	// SNI 추출을 위해 초기 데이터 읽기
	reader := bufio.NewReader(conn)

	// CONNECT 요청인지 직접 TLS인지 판단하기 위해 처음 몇 바이트 확인
	initialData, err := reader.Peek(1024)
	if err != nil {
		m.logger.Error("Failed to peek at connection data: %v", err)
		return
	}

	// HTTP CONNECT 요청처럼 보이는지 확인
	if m.isHTTPConnect(initialData) {
		// HTTP CONNECT로 처리
		req, err := http.ReadRequest(reader)
		if err != nil {
			m.logger.Error("Failed to read CONNECT request: %v", err)
			return
		}

		if req.Method == "CONNECT" {
			m.handleCONNECTRequest(conn, req)
		}
		return
	}

	// TLS 핸드셰이크에서 SNI 추출
	sni := m.extractSNIFromTLS(initialData)
	if sni == "" {
		m.logger.Warn("No SNI found in TLS handshake")
		sni = "unknown.local"
	}

	m.logger.Info("Handling HTTPS connection for SNI: %s", sni)
	m.httpsProxy.HandleConnection(conn, sni)
}

func (m *MITMProxy) isHTTPConnect(data []byte) bool {
	return len(data) >= 7 && string(data[:7]) == "CONNECT"
}

func (m *MITMProxy) extractSNIFromTLS(data []byte) string {
	// SNI 추출을 위해 TLS 핸드셰이크 파싱
	if len(data) < 43 {
		return ""
	}

	// TLS 핸드셰이크인지 확인 (0x16 = 핸드셰이크)
	if data[0] != 0x16 {
		return ""
	}

	// 기존 SNI 추출 기능을 사용하기 위해 모의 패킷 생성
	mockPacket := &packet.Packet{
		Payload: data,
	}

	return mockPacket.GetSNI()
}

func (m *MITMProxy) handleCONNECTRequest(clientConn net.Conn, req *http.Request) {
	m.logger.Info("CONNECT request to: %s", req.Host)

	// Host 헤더에서 호스트명 추출
	hostname := req.Host
	if strings.Contains(hostname, ":") {
		hostname = strings.Split(hostname, ":")[0]
	}

	// 200 Connection Established 응답 전송
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 이제 HTTPS MITM으로 처리
	m.httpsProxy.HandleConnection(clientConn, hostname)
}

func (m *MITMProxy) processTUNPackets() {
	defer m.wg.Done()

	buffer := make([]byte, 1500) // MTU 크기

	for {
		select {
		case <-m.stopChan:
			return
		default:
		}

		// 무한정 블로킹을 방지하기 위해 읽기 데드라인 설정
		m.tunDevice.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, err := m.tunDevice.Read(buffer)
		if err != nil {
			m.logger.Error("Failed to read from TUN device: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		// IP 패킷 파싱
		pkt, err := packet.ParseIPPacket(buffer[:n])
		if err != nil {
			m.logger.Debug("Failed to parse IP packet: %v", err)
			continue
		}

		// 패킷 처리
		m.processPacket(pkt)
	}
}

func (m *MITMProxy) processPacket(pkt *packet.Packet) {
	// TCP 패킷만 처리
	if pkt.IPHdr.Protocol != 6 || pkt.TCPHdr == nil {
		// TCP가 아닌 패킷은 변경 없이 전달
		m.forwardPacket(pkt)
		return
	}

	m.logger.Debug("Processing TCP packet: %s:%d -> %s:%d",
		pkt.IPHdr.SrcIP, pkt.TCPHdr.SrcPort,
		pkt.IPHdr.DstIP, pkt.TCPHdr.DstPort)

	// HTTP 또는 HTTPS 트래픽인지 확인
	if pkt.IsHTTP() {
		m.logger.Info("Detected HTTP traffic to %s:%d", pkt.IPHdr.DstIP, pkt.TCPHdr.DstPort)
		m.redirectToHTTPProxy(pkt)
	} else if pkt.IsHTTPS() {
		m.logger.Info("Detected HTTPS traffic to %s:%d", pkt.IPHdr.DstIP, pkt.TCPHdr.DstPort)
		m.redirectToHTTPSProxy(pkt)
	} else {
		// 다른 TCP 트래픽은 변경 없이 전달
		m.forwardPacket(pkt)
	}
}

func (m *MITMProxy) redirectToHTTPProxy(pkt *packet.Packet) {
	// HTTP 트래픽을 HTTP 프록시로 리다이렉트
	// 패킷을 리다이렉트하는 NAT와 같은 기능이 필요
	// 간단히 하기 위해 리다이렉션을 로그로만 기록
	m.logger.Info("Redirecting HTTP traffic from %s:%d to proxy port %d",
		pkt.IPHdr.SrcIP, pkt.TCPHdr.SrcPort, m.config.HTTPPort)
}

func (m *MITMProxy) redirectToHTTPSProxy(pkt *packet.Packet) {
	// HTTPS 트래픽을 HTTPS 프록시로 리다이렉트
	// 가능한 경우 SNI 추출
	sni := pkt.GetSNI()
	if sni != "" {
		m.logger.Info("Redirecting HTTPS traffic (SNI: %s) from %s:%d to proxy port %d",
			sni, pkt.IPHdr.SrcIP, pkt.TCPHdr.SrcPort, m.config.HTTPSPort)
	} else {
		m.logger.Info("Redirecting HTTPS traffic from %s:%d to proxy port %d",
			pkt.IPHdr.SrcIP, pkt.TCPHdr.SrcPort, m.config.HTTPSPort)
	}
}

func (m *MITMProxy) forwardPacket(pkt *packet.Packet) {
	// 패킷을 변경 없이 전달 (패스스루)
	_, err := m.tunDevice.Write(pkt.Raw)
	if err != nil {
		m.logger.Error("Failed to forward packet: %v", err)
	}
}

func (m *MITMProxy) addActiveConnection(conn net.Conn) {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	m.activeConns[conn] = struct{}{}
}

func (m *MITMProxy) removeActiveConnection(conn net.Conn) {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	delete(m.activeConns, conn)
}

func (m *MITMProxy) closeActiveConnections() {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()

	for conn := range m.activeConns {
		conn.Close()
	}
	m.activeConns = make(map[net.Conn]struct{})
}

func (m *MITMProxy) Stop() {
	m.logger.Info("Stopping MITM Proxy...")

	// 모든 고루틴에 중지 신호 전송
	close(m.stopChan)

	// 리스너 닫기
	if m.httpListener != nil {
		m.httpListener.Close()
	}
	if m.httpsListener != nil {
		m.httpsListener.Close()
	}

	// 활성 연결 닫기
	m.closeActiveConnections()

	// TUN 디바이스 닫기
	if m.tunDevice != nil {
		m.tunDevice.Close()
	}

	// 모든 고루틴이 완료될 때까지 대기
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	// 우아한 종료 또는 타임아웃까지 대기
	select {
	case <-done:
		m.logger.Info("MITM Proxy stopped gracefully")
	case <-time.After(10 * time.Second):
		m.logger.Warn("MITM Proxy shutdown timeout")
	}

	// 로거 닫기
	if closer, ok := m.logger.(interface{ Close() error }); ok {
		closer.Close()
	}
	if m.trafficLogger != nil {
		m.trafficLogger.Close()
	}
}

func (m *MITMProxy) GetStats() map[string]interface{} {
	m.connMutex.RLock()
	defer m.connMutex.RUnlock()

	return map[string]interface{}{
		"active_connections": len(m.activeConns),
		"cert_cache_size":    m.certManager.GetCacheSize(),
		"tun_device":         m.tunDevice.Name(),
		"http_port":          m.config.HTTPPort,
		"https_port":         m.config.HTTPSPort,
	}
}
