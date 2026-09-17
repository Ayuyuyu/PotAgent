package common

import (
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// DummyUDPConn 是 UDP 包在 ForwardUDPPacketToChan 中的通道元素：
// 携带本次数据报的字节与源地址，并复用底层 UDPConn 的 Read/Write 能力。
type DummyUDPConn struct {
	Data         []byte       // 本次数据报收到的字节
	UDPAddr      *net.UDPAddr // 数据报源地址
	*net.UDPConn              // 用于写回应答
}

// ForwardUDPPacketToChan 与 ForwardListenerToChan 的 UDP 版本。
// 返回 (UDP 连接, 包通道)；读取 goroutine 在 ReadFrom 出错时直接退出，
// 由调用方通过 select 的 ctx.Done() 决定何时关闭。
func ForwardUDPPacketToChan(conn *net.UDPConn) chan *DummyUDPConn {
	packetChan := make(chan *DummyUDPConn)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packetChan <- &DummyUDPConn{
				Data:    buf[:n],
				UDPAddr: raddr,
				UDPConn: conn,
			}
		}
	}()
	return packetChan
}

// func ForwardUDPToChan(listen *net.UDPConn) chan net.Conn {
// 	connChan := make(chan net.Conn)

// 	// 将net.Listener.Accept转为chan，从而使用select来接管
// 	go func() {
// 		for {
// 			var buf [65535]byte
// 			n, raddr, err := listen.ReadFromUDP(buf[:])
// 			if err != nil {
// 				// log.Log.Error("Error reading udp:", err.Error())
// 				return
// 			}

// 			connChan <- &DummyUDPConn{
// 				Buffer: buf[:n],
// 				Laddr:  listen.LocalAddr(),
// 				Raddr:  raddr,
// 				Fn:     listen.WriteToUDP,
// 			}

// 		}
// 	}()

// 	return connChan
// }

func ForwardListenerToChan(listen net.Listener) chan net.Conn {
	connChan := make(chan net.Conn)

	// 将net.Listener.Accept转为chan，从而使用select来接管
	go func() {
		for {
			conn, err := listen.Accept()

			// An error means that the listener was closed, or another event
			// happened where we can't continue listening for connections.
			if err != nil {
				return
			}

			connChan <- conn
		}
	}()

	return connChan
}

type Addr struct {
	IP   string
	Port uint16
}

func GetSSHConnSrcIPAndSrcPort(n *ssh.ConnMetadata) (a Addr, err error) {
	a, err = splitConnIPAndPort((*n).RemoteAddr().String())
	return a, err
}

func GetSSHConnDstIPAndDstPort(n *ssh.ConnMetadata) (a Addr, err error) {
	a, err = splitConnIPAndPort((*n).LocalAddr().String())
	return a, err
}

func GetConnSrcIPAndSrcPort(n *net.Conn) (a Addr, err error) {
	a, err = splitConnIPAndPort((*n).RemoteAddr().String())
	return a, err
}

func GetConnDstIPAndDstPort(n *net.Conn) (a Addr, err error) {
	a, err = splitConnIPAndPort((*n).LocalAddr().String())
	return a, err
}

func splitConnIPAndPort(s string) (a Addr, err error) {
	// 使用 net.SplitHostPort 正确处理 IPv4 与 IPv6（含 [::1]:port 括号形式）
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return a, err
	}
	var portNum uint64
	portNum, err = strconv.ParseUint(port, 10, 16)
	if err != nil {
		return a, err
	}
	a.IP = host
	a.Port = uint16(portNum)
	return a, nil
}
