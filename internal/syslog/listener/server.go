package listener

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/config"
	"github.com/syslog-platform/logger/internal/syslog/pipeline"
)

// Server encapsulates UDP, TCP, and TLS listeners
type Server struct {
	cfg      config.SyslogConfig
	pipeline *pipeline.Pipeline
	udpConn  *net.UDPConn
	tcpLn    net.Listener
	tlsLn    net.Listener
	wg       sync.WaitGroup
	stopCh   chan struct{}
}

func NewServer(cfg config.SyslogConfig, pipe *pipeline.Pipeline) *Server {
	return &Server{
		cfg:      cfg,
		pipeline: pipe,
		stopCh:   make(chan struct{}),
	}
}

// Start initiates all enabled listeners
func (s *Server) Start() error {
	if s.cfg.UDP.Enabled {
		if err := s.startUDP(); err != nil {
			return fmt.Errorf("starting UDP listener: %w", err)
		}
	}

	if s.cfg.TCP.Enabled {
		if err := s.startTCP(); err != nil {
			return fmt.Errorf("starting TCP listener: %w", err)
		}
	}

	if s.cfg.TLS.Enabled {
		if err := s.startTLS(); err != nil {
			return fmt.Errorf("starting TLS listener: %w", err)
		}
	}

	return nil
}

func (s *Server) startUDP() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.UDP.ListenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	// Increase OS socket receive buffer to prevent kernel packet drops during bursts
	_ = conn.SetReadBuffer(16 * 1024 * 1024)

	s.udpConn = conn
	log.Printf("[Syslog] UDP listener started on %s", s.cfg.UDP.ListenAddr)

	// Spawn multiple concurrent UDP readers
	numReaders := 4
	for i := 0; i < numReaders; i++ {
		s.wg.Add(1)
		go s.udpReaderLoop()
	}
	return nil
}

func (s *Server) udpReaderLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.stopCh:
			return
		default:
			n, raddr, err := s.udpConn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					continue
				}
			}

			if n > 0 {
				payload := make([]byte, n)
				copy(payload, buf[:n])
				s.pipeline.Ingest(pipeline.RawPacket{
					Data:       payload,
					SourceIP:   raddr.IP,
					SourcePort: uint16(raddr.Port),
					Protocol:   "UDP",
					ReceivedAt: time.Now().UTC(),
				})
			}
		}
	}
}

func (s *Server) startTCP() error {
	ln, err := net.Listen("tcp", s.cfg.TCP.ListenAddr)
	if err != nil {
		return err
	}
	s.tcpLn = ln
	log.Printf("[Syslog] TCP listener started on %s", s.cfg.TCP.ListenAddr)

	s.wg.Add(1)
	go s.acceptLoop(ln, "TCP")
	return nil
}

func (s *Server) startTLS() error {
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS cert/key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", s.cfg.TLS.ListenAddr, tlsConfig)
	if err != nil {
		return err
	}
	s.tlsLn = ln
	log.Printf("[Syslog] TLS listener started on %s", s.cfg.TLS.ListenAddr)

	s.wg.Add(1)
	go s.acceptLoop(ln, "TLS")
	return nil
}

func (s *Server) acceptLoop(ln net.Listener, proto string) {
	defer s.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				log.Printf("[Syslog] %s Accept error: %v", proto, err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleTCPConnection(conn, proto)
	}
}

func (s *Server) handleTCPConnection(conn net.Conn, proto string) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}

	reader := bufio.NewReaderSize(conn, 64*1024)

	for {
		select {
		case <-s.stopCh:
			return
		default:
			// Read up to newline delimiter (RFC 6587 octet counting / non-transparent framing fallback)
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				payload := make([]byte, len(line))
				copy(payload, line)
				s.pipeline.Ingest(pipeline.RawPacket{
					Data:       payload,
					SourceIP:   remoteAddr.IP,
					SourcePort: uint16(remoteAddr.Port),
					Protocol:   proto,
					ReceivedAt: time.Now().UTC(),
				})
			}
			if err != nil {
				if err != io.EOF {
					// Client closed or reset
				}
				return
			}
		}
	}
}

func (s *Server) Stop() {
	close(s.stopCh)
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	if s.tcpLn != nil {
		_ = s.tcpLn.Close()
	}
	if s.tlsLn != nil {
		_ = s.tlsLn.Close()
	}
	s.wg.Wait()
	log.Println("[Syslog] Listeners stopped")
}
