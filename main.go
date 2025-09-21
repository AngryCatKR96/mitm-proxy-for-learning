package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	. "vpn-mitm-proxy/internal/global"
	"vpn-mitm-proxy/internal/proxy"
)

func main() {
	// command line flags
	var (
		tunInterface   = flag.String("tun", "tun0", "TUN interface name")
		httpPort       = flag.Int("http-port", 8080, "HTTP proxy port")
		httpsPort      = flag.Int("https-port", 8443, "HTTPS proxy port")
		logLevel       = flag.String("log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
		logFile        = flag.String("log-file", "", "Log file path (empty for console)")
		trafficLogFile = flag.String("traffic-log", "", "Traffic log file path")
		certCacheSize  = flag.Int("cert-cache", 1000, "Certificate cache size")
	)
	flag.Parse()

	// 전역 로거 초기화
	if err := InitLogger(*logLevel, *logFile); err != nil {
		println("Failed to initialize global logger:", err)
		os.Exit(1)
	}

	// 전역 로거 사용
	Info("Starting VPN MITM Proxy...")

	config := proxy.Config{
		TUNInterface:  *tunInterface,
		HTTPPort:      *httpPort,
		HTTPSPort:     *httpsPort,
		LogLevel:      *logLevel,
		CertCacheSize: *certCacheSize,
		CertValidity:  24 * time.Hour,
		KeySize:       2048,
	}

	mitm := proxy.NewMITMProxy(config, nil)

	if err := mitm.Start(); err != nil {
		Error("Failed to start MITM proxy: %v", err)
		os.Exit(1)
	}

	// 시작 정보 출력
	Info("Configuration:")
	Info("  TUN Interface: %s", *tunInterface)
	Info("  HTTP Port: %d", *httpPort)
	Info("  HTTPS Port: %d", *httpsPort)
	Info("  Log Level: %s", *logLevel)
	if *logFile != "" {
		Info("  Log File: %s", *logFile)
	}
	if *trafficLogFile != "" {
		Info("  Traffic Log: %s", *trafficLogFile)
	}

	// 루트 CA 인증서 출력
	rootCAPEM, err := mitm.GetRootCAPEM()
	if err != nil {
		Warn("Failed to get root CA: %v", err)
	} else {
		Info("Root CA Certificate (add this to your system's trusted certificates):")
		Info("-----BEGIN CERTIFICATE-----")
		Info("%s", string(rootCAPEM))
		Info("-----END CERTIFICATE-----")
	}

	// graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	Info("Shutting down VPN MITM Proxy...")
	mitm.Stop()
	Close()
}
