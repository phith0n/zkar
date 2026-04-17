package rmi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/phith0n/zkar/commons"
)

// Handshake is the client-to-server opening: "JRMI" magic + uint16 version + 1-byte sub-protocol flag.
type Handshake struct {
	Magic    []byte
	Version  uint16
	Protocol byte
}

// Acknowledge is the server's reply to a Stream-protocol handshake:
// 0x4E flag + DataOutput.writeUTF(clientHost) + int32(clientPort).
// Used only for the server→client direction.
type Acknowledge struct {
	Flag byte
	Host string
	Port int32
}

func readHandshake(s *commons.Stream) (*Handshake, error) {
	magic, err := s.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read JRMI magic failed on index %v: %w", s.CurrentIndex(), err)
	}
	if !bytes.Equal(magic, JRMI_MAGIC) {
		return nil, fmt.Errorf("invalid JRMI magic %s on index %v", commons.Hexify(magic), s.CurrentIndex()-4)
	}

	versionBs, err := s.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read JRMI version failed on index %v: %w", s.CurrentIndex(), err)
	}

	protoBs, err := s.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read JRMI protocol flag failed on index %v: %w", s.CurrentIndex(), err)
	}
	if protoBs[0] != ProtocolStream {
		return nil, fmt.Errorf("unsupported JRMP sub-protocol %s on index %v; only Stream (0x4B) is supported",
			commons.Hexify(protoBs[0]), s.CurrentIndex()-1)
	}

	return &Handshake{
		Magic:    append([]byte{}, magic...),
		Version:  binary.BigEndian.Uint16(versionBs),
		Protocol: protoBs[0],
	}, nil
}

func readAcknowledge(s *commons.Stream) (*Acknowledge, error) {
	flagBs, err := s.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read ProtocolAck flag failed on index %v: %w", s.CurrentIndex(), err)
	}
	if flagBs[0] != AckFlag {
		return nil, fmt.Errorf("expected ProtocolAck flag 0x4E on index %v, got %s",
			s.CurrentIndex()-1, commons.Hexify(flagBs[0]))
	}

	host, err := readModifiedUTF(s)
	if err != nil {
		return nil, fmt.Errorf("read ProtocolAck host: %w", err)
	}

	portBs, err := s.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read ProtocolAck port failed on index %v: %w", s.CurrentIndex(), err)
	}

	return &Acknowledge{
		Flag: flagBs[0],
		Host: host,
		Port: int32(binary.BigEndian.Uint32(portBs)),
	}, nil
}

// readModifiedUTF consumes a java.io.DataOutput#writeUTF payload:
// uint16 length + modified-UTF-8 bytes. Hostnames are overwhelmingly ASCII
// where modified UTF-8 is byte-for-byte identical to UTF-8, so we pass the
// bytes through untouched. Callers needing exotic hostnames can decode
// themselves from the returned string's raw bytes.
func readModifiedUTF(s *commons.Stream) (string, error) {
	lengthBs, err := s.ReadN(2)
	if err != nil {
		return "", fmt.Errorf("read modified-UTF length failed on index %v: %w", s.CurrentIndex(), err)
	}
	length := binary.BigEndian.Uint16(lengthBs)
	if length == 0 {
		return "", nil
	}
	data, err := s.ReadN(int(length))
	if err != nil {
		return "", fmt.Errorf("read modified-UTF payload failed on index %v: %w", s.CurrentIndex(), err)
	}
	return string(data), nil
}

func (h *Handshake) ToString() string {
	b := commons.NewPrinter()
	b.Printf("@Handshake")
	b.IncreaseIndent()
	b.Printf("@Magic - %s", commons.Hexify(h.Magic))
	b.Printf("@Version - %d - %s", h.Version, commons.Hexify(h.Version))
	b.Printf("@Protocol - %s (Stream)", commons.Hexify(h.Protocol))
	return b.String()
}

func (a *Acknowledge) ToString() string {
	b := commons.NewPrinter()
	b.Printf("@Acknowledge")
	b.IncreaseIndent()
	b.Printf("@Flag - %s", commons.Hexify(a.Flag))
	b.Printf("@Host")
	b.IncreaseIndent()
	b.Printf("@Length - %d - %s", len(a.Host), commons.Hexify(uint16(len(a.Host))))
	b.Printf("@Value - %s - %s", a.Host, commons.Hexify(a.Host))
	b.DecreaseIndent()
	b.Printf("@Port - %d - %s", a.Port, commons.Hexify(a.Port))
	return b.String()
}
