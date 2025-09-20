package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

type CertificateManager struct {
	rootCA       *x509.Certificate
	rootKey      *rsa.PrivateKey
	certCache    map[string]*CertInfo
	cacheMutex   sync.RWMutex
	maxCacheSize int
}

type CertInfo struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	PEMCert     []byte
	PEMKey      []byte
	CreatedAt   time.Time
}

func NewCertificateManager(maxCacheSize int) (*CertificateManager, error) {
	rootCA, rootKey, err := generateRootCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate root CA: %v", err)
	}

	return &CertificateManager{
		rootCA:       rootCA,
		rootKey:      rootKey,
		certCache:    make(map[string]*CertInfo),
		maxCacheSize: maxCacheSize,
	}, nil
}

func generateRootCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// 루트 CA용 개인키 생성
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate root CA private key: %v", err)
	}

	// 루트 CA 인증서 템플릿 생성
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"MITM Proxy Root CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 루트 CA 인증서 생성
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create root CA certificate: %v", err)
	}

	// 인증서 파싱
	rootCA, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root CA certificate: %v", err)
	}

	return rootCA, rootKey, nil
}

func (cm *CertificateManager) GetRootCAPEM() ([]byte, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.rootCA.Raw,
	})
	return certPEM, nil
}

func (cm *CertificateManager) GetCertificate(hostname string) (*CertInfo, error) {
	// 먼저 캐시 확인
	cm.cacheMutex.RLock()
	if certInfo, exists := cm.certCache[hostname]; exists {
		// 인증서가 여전히 유효한지 확인 (만료되지 않음)
		if time.Now().Before(certInfo.Certificate.NotAfter.Add(-24 * time.Hour)) {
			cm.cacheMutex.RUnlock()
			return certInfo, nil
		}
	}
	cm.cacheMutex.RUnlock()

	// 새 인증서 생성
	certInfo, err := cm.generateCertificate(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %v", hostname, err)
	}

	// 캐시에 추가
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	// 캐시가 너무 크면 정리
	if len(cm.certCache) >= cm.maxCacheSize {
		cm.cleanOldestEntries()
	}

	cm.certCache[hostname] = certInfo
	return certInfo, nil
}

func (cm *CertificateManager) generateCertificate(hostname string) (*CertInfo, error) {
	// 인증서용 개인키 생성
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// 인증서 템플릿 생성
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:  []string{"MITM Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
		DNSNames:    []string{hostname},
	}

	// 호스트명이 IP인 경우 IP 주소 추가
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}

	// 와일드카드 지원 추가
	if len(hostname) > 0 && hostname[0] != '*' {
		template.DNSNames = append(template.DNSNames, "*."+hostname)
	}

	// 인증서 생성
	certDER, err := x509.CreateCertificate(rand.Reader, &template, cm.rootCA, &privateKey.PublicKey, cm.rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// 인증서 파싱
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// PEM 형식으로 인코딩
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &CertInfo{
		Certificate: certificate,
		PrivateKey:  privateKey,
		PEMCert:     certPEM,
		PEMKey:      keyPEM,
		CreatedAt:   time.Now(),
	}, nil
}

func (cm *CertificateManager) cleanOldestEntries() {
	// 캐시가 가득 찰 때 가장 오래된 25% 항목 제거
	removeCount := cm.maxCacheSize / 4
	if removeCount == 0 {
		removeCount = 1
	}

	type entry struct {
		hostname  string
		createdAt time.Time
	}

	var entries []entry
	for hostname, certInfo := range cm.certCache {
		entries = append(entries, entry{
			hostname:  hostname,
			createdAt: certInfo.CreatedAt,
		})
	}

	// 생성 시간으로 정렬
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].createdAt.After(entries[j].createdAt) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// 가장 오래된 항목 제거
	for i := 0; i < removeCount && i < len(entries); i++ {
		delete(cm.certCache, entries[i].hostname)
	}
}

func (cm *CertificateManager) ClearCache() {
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()
	cm.certCache = make(map[string]*CertInfo)
}

func (cm *CertificateManager) GetCacheSize() int {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()
	return len(cm.certCache)
}
