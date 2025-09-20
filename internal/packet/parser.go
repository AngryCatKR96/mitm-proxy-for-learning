package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type IPHeader struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []byte
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
}

type Packet struct {
	Raw     []byte
	IPHdr   *IPHeader
	TCPHdr  *TCPHeader
	Payload []byte
}

func ParseIPPacket(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short for IP header")
	}

	packet := &Packet{Raw: data}

	// IP 헤더 파싱
	ipHdr := &IPHeader{}
	ipHdr.Version = (data[0] >> 4) & 0xF
	ipHdr.IHL = data[0] & 0xF
	ipHdr.TOS = data[1]
	ipHdr.Length = binary.BigEndian.Uint16(data[2:4])
	ipHdr.ID = binary.BigEndian.Uint16(data[4:6])

	flagsAndFrag := binary.BigEndian.Uint16(data[6:8])
	ipHdr.Flags = uint8((flagsAndFrag >> 13) & 0x7)
	ipHdr.FragOffset = flagsAndFrag & 0x1FFF

	ipHdr.TTL = data[8]
	ipHdr.Protocol = data[9]
	ipHdr.Checksum = binary.BigEndian.Uint16(data[10:12])

	ipHdr.SrcIP = net.IP(data[12:16])
	ipHdr.DstIP = net.IP(data[16:20])

	headerLen := int(ipHdr.IHL) * 4
	if len(data) < headerLen {
		return nil, fmt.Errorf("packet too short for IP header with options")
	}

	if headerLen > 20 {
		ipHdr.Options = data[20:headerLen]
	}

	packet.IPHdr = ipHdr

	// TCP 패킷인 경우 TCP 헤더 파싱
	if ipHdr.Protocol == 6 && len(data) > headerLen {
		tcpData := data[headerLen:]
		if tcpHdr, payload, err := ParseTCPHeader(tcpData); err == nil {
			packet.TCPHdr = tcpHdr
			packet.Payload = payload
		}
	} else if len(data) > headerLen {
		packet.Payload = data[headerLen:]
	}

	return packet, nil
}

func ParseTCPHeader(data []byte) (*TCPHeader, []byte, error) {
	if len(data) < 20 {
		return nil, nil, fmt.Errorf("packet too short for TCP header")
	}

	tcpHdr := &TCPHeader{}
	tcpHdr.SrcPort = binary.BigEndian.Uint16(data[0:2])
	tcpHdr.DstPort = binary.BigEndian.Uint16(data[2:4])
	tcpHdr.SeqNum = binary.BigEndian.Uint32(data[4:8])
	tcpHdr.AckNum = binary.BigEndian.Uint32(data[8:12])

	tcpHdr.DataOffset = (data[12] >> 4) & 0xF
	tcpHdr.Flags = data[13]
	tcpHdr.Window = binary.BigEndian.Uint16(data[14:16])
	tcpHdr.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcpHdr.Urgent = binary.BigEndian.Uint16(data[18:20])

	headerLen := int(tcpHdr.DataOffset) * 4
	if len(data) < headerLen {
		return nil, nil, fmt.Errorf("packet too short for TCP header with options")
	}

	if headerLen > 20 {
		tcpHdr.Options = data[20:headerLen]
	}

	var payload []byte
	if len(data) > headerLen {
		payload = data[headerLen:]
	}

	return tcpHdr, payload, nil
}

func (p *Packet) IsHTTP() bool {
	if p.TCPHdr == nil || len(p.Payload) == 0 {
		return false
	}

	// HTTP 메서드 확인
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE "}
	for _, method := range httpMethods {
		if bytes.HasPrefix(p.Payload, []byte(method)) {
			return true
		}
	}

	// HTTP 응답 확인
	if bytes.HasPrefix(p.Payload, []byte("HTTP/")) {
		return true
	}

	return false
}

func (p *Packet) IsHTTPS() bool {
	if p.TCPHdr == nil || len(p.Payload) == 0 {
		return false
	}

	// TLS 핸드셰이크 레코드 타입 (0x16 = 핸드셰이크)
	if len(p.Payload) >= 6 && p.Payload[0] == 0x16 {
		// TLS 버전 확인 (0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
		version := binary.BigEndian.Uint16(p.Payload[1:3])
		if version >= 0x0301 && version <= 0x0304 {
			return true
		}
	}

	return false
}

func (p *Packet) GetSNI() string {
	if !p.IsHTTPS() || len(p.Payload) < 43 {
		return ""
	}

	data := p.Payload

	// TLS 레코드 헤더 건너뛰기 (5 바이트)
	if len(data) < 5 {
		return ""
	}
	data = data[5:]

	// 핸드셰이크 헤더 건너뛰기 (4 바이트)
	if len(data) < 4 {
		return ""
	}
	data = data[4:]

	// 클라이언트 헬로 고정 부분 건너뛰기 (최소 34 바이트)
	if len(data) < 34 {
		return ""
	}
	data = data[34:]

	// 세션 ID 건너뛰기
	if len(data) < 1 {
		return ""
	}
	sessionIDLen := int(data[0])
	if len(data) < 1+sessionIDLen {
		return ""
	}
	data = data[1+sessionIDLen:]

	// 암호화 스위트 건너뛰기
	if len(data) < 2 {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+cipherSuitesLen {
		return ""
	}
	data = data[2+cipherSuitesLen:]

	// 압축 방법 건너뛰기
	if len(data) < 1 {
		return ""
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return ""
	}
	data = data[1+compressionMethodsLen:]

	// 확장 파싱
	if len(data) < 2 {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+extensionsLen {
		return ""
	}
	data = data[2:]

	// SNI 확장 찾기 (타입 0x0000)
	for len(data) >= 4 {
		extType := binary.BigEndian.Uint16(data[0:2])
		extLen := int(binary.BigEndian.Uint16(data[2:4]))

		if len(data) < 4+extLen {
			break
		}

		if extType == 0x0000 { // SNI 확장
			return parseSNIExtension(data[4 : 4+extLen])
		}

		data = data[4+extLen:]
	}

	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return ""
	}
	data = data[2:]

	for len(data) >= 3 {
		nameType := data[0]
		if nameType != 0x00 { // 호스트명
			return ""
		}

		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		if len(data) < 3+nameLen {
			return ""
		}

		return string(data[3 : 3+nameLen])
	}

	return ""
}
