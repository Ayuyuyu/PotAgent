package common

import (
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

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
	splited := strings.Split(s, ":")
	// fmt.Println("splited:", splited)
	var port uint64
	port, err = strconv.ParseUint(splited[1], 10, 16)
	if err != nil {
		return a, err
	}
	a.Port = uint16(port)
	a.IP = splited[0]
	return a, nil
}
