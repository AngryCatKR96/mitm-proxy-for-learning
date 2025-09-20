package tun

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type TUNDevice struct {
	file     *os.File
	name     string
	mtu      int
	stopChan chan struct{}
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte
}

func NewTUNDevice(name string) (*TUNDevice, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open TUN device: %v", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, file.Fd(), TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("failed to create TUN interface: %v", errno)
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
		mtu:      1500,
		stopChan: make(chan struct{}),
	}, nil
}

func (t *TUNDevice) Read(buf []byte) (int, error) {
	return t.file.Read(buf)
}

func (t *TUNDevice) SetReadDeadline(deadline time.Time) error {
	return t.file.SetReadDeadline(deadline)
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
	// 시스템 명령어를 사용하여 IP 주소 설정
	// 일반적으로 ip 명령어 호출이나 netlink 사용이 필요
	// 간단히 하기 위해 인터페이스가 외부에서 설정되었다고 가정
	return nil
}
