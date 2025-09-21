package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

const (
	TUNSETIFF = 0x400454ca // TUN 인터페이스 설정
	IFF_TUN   = 0x0001     // TUN 인터페이스
	IFF_NO_PI = 0x1000     // no protocol
)

type TUNDevice struct {
	file     *os.File
	name     string
	mtu      int
	stopChan chan struct{}
}

// ifReq TUN 인터페이스 요청 구조체
type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte
}

func NewTUNDevice(name string) (*TUNDevice, error) {
	// TUN 디바이스 파일이 존재하는지 확인
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		return nil, fmt.Errorf("TUN device file /dev/net/tun does not exist. Please ensure the TUN module is loaded")
	}

	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open TUN device: %v. Make sure you have permission to access /dev/net/tun", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, file.Fd(), TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("failed to create TUN interface %s: %v. Make sure the interface name is available and you have sufficient privileges", name, errno)
	}

	actualName := string(req.Name[:])
	for i, b := range req.Name {
		if b == 0 {
			actualName = string(req.Name[:i])
			break
		}
	}

	return &TUNDevice{
		file:     file,
		name:     actualName,
		mtu:      1500, // max transmission unit
		stopChan: make(chan struct{}),
	}, nil
}

func (t *TUNDevice) Read(buf []byte) (int, error) {
	// TUN 디바이스는 일반적으로 블로킹 I/O를 사용
	// SetReadDeadline을 사용하지 않고 직접 읽기
	return t.file.Read(buf)
}

func (t *TUNDevice) SetReadDeadline(deadline time.Time) error {
	// TUN 디바이스는 폴링 기반이 아니므로 데드라인 설정을 비활성화
	// 대신 상위 레벨에서 타임아웃 처리
	return nil
}

func (t *TUNDevice) Write(buf []byte) (int, error) {
	return t.file.Write(buf)
}

func (t *TUNDevice) Close() error {
	close(t.stopChan)
	return t.file.Close()
}

func (t *TUNDevice) Name() string {
	return t.name
}

func (t *TUNDevice) MTU() int {
	return t.mtu
}

func (t *TUNDevice) ConfigureInterface(ip net.IP, subnet *net.IPNet) error {
	// IP 주소 할당
	ipWithMask := fmt.Sprintf("%s/%d", ip.String(), getMaskBits(subnet.Mask))
	cmd := exec.Command("ip", "addr", "add", ipWithMask, "dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to assign IP address %s to interface %s: %v", ipWithMask, t.name, err)
	}

	// 인터페이스 활성화
	cmd = exec.Command("ip", "link", "set", "dev", t.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to activate interface %s: %v", t.name, err)
	}

	// 라우팅 설정 (서브넷에 대한 라우트 추가)
	cmd = exec.Command("ip", "route", "add", subnet.String(), "dev", t.name)
	if err := cmd.Run(); err != nil {
		// 라우팅 설정 실패는 치명적이지 않을 수 있으므로 경고만 출력
		fmt.Printf("Warning: failed to add route %s for interface %s: %v\n", subnet.String(), t.name, err)
	}

	return nil
}

// getMaskBits는 net.IPMask에서 CIDR 비트 수를 계산합니다
func getMaskBits(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}
