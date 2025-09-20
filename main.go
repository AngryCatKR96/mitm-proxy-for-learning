package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

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
		maxConns       = flag.Int("max-conns", 10000, "Maximum concurrent connections")
	)
	flag.Parse()

	log.Println("Starting VPN MITM Proxy...")

	config := &proxy.Config{
		TUNInterface:   *tunInterface,
		HTTPPort:       *httpPort,
		HTTPSPort:      *httpsPort,
		LogLevel:       *logLevel,
		LogFile:        *logFile,
		TrafficLogFile: *trafficLogFile,
		CertCacheSize:  *certCacheSize,
		MaxConnections: *maxConns,
	}

	mitm, err := proxy.NewMITMProxy(config)
	if err != nil {
		log.Fatalf("Failed to create MITM proxy: %v", err)
	}

	if err := mitm.Start(); err != nil {
		log.Fatalf("Failed to start MITM proxy: %v", err)
	}

	// 시작 정보 출력
	log.Printf("Configuration:")
	log.Printf("  TUN Interface: %s", *tunInterface)
	log.Printf("  HTTP Port: %d", *httpPort)
	log.Printf("  HTTPS Port: %d", *httpsPort)
	log.Printf("  Log Level: %s", *logLevel)
	if *logFile != "" {
		log.Printf("  Log File: %s", *logFile)
	}
	if *trafficLogFile != "" {
		log.Printf("  Traffic Log: %s", *trafficLogFile)
	}

	// 우아한 종료 처리
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down VPN MITM Proxy...")
	mitm.Stop()
}
