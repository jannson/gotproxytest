package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const big = 0xFFFFFF
const IP_ORIGADDRS = 20

func ipToSocksAddr(family int, ip net.IP, port int, zone string) (unix.Sockaddr, error) {
	switch family {
	case unix.AF_INET:
		if len(ip) == 0 {
			ip = net.IPv4zero
		}
		if ip = ip.To4(); ip == nil {
			return nil, net.InvalidAddrError("non-IPv4 address")
		}
		sa := new(unix.SockaddrInet4)
		for i := 0; i < net.IPv4len; i++ {
			sa.Addr[i] = ip[i]
		}
		sa.Port = port
		return sa, nil
	case unix.AF_INET6:
		if len(ip) == 0 {
			ip = net.IPv6zero
		}
		// IPv4 callers use 0.0.0.0 to mean "announce on any available address".
		// In IPv6 mode, Linux treats that as meaning "announce on 0.0.0.0",
		// which it refuses to do.  Rewrite to the IPv6 unspecified address.
		if ip.Equal(net.IPv4zero) {
			ip = net.IPv6zero
		}
		if ip = ip.To16(); ip == nil {
			return nil, net.InvalidAddrError("non-IPv6 address")
		}
		sa := new(unix.SockaddrInet6)
		for i := 0; i < net.IPv6len; i++ {
			sa.Addr[i] = ip[i]
		}
		sa.Port = port
		sa.ZoneId = uint32(zoneToInt(zone))
		return sa, nil
	}
	return nil, net.InvalidAddrError("unexpected socket family")
}

func zoneToInt(zone string) int {
	if zone == "" {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return ifi.Index
	}
	n, _, _ := dtoi(zone, 0)
	return n
}

func dtoi(s string, i0 int) (n int, i int, ok bool) {
	n = 0
	for i = i0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return 0, i, false
		}
	}
	if i == i0 {
		return 0, i, false
	}
	return n, i, true
}

func IPv6TcpAddrToUnixSocksAddr(addr string) (sa unix.Sockaddr, err error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp6", addr)
	if err != nil {
		return nil, err
	}
	return ipToSocksAddr(unix.AF_INET6, tcpAddr.IP, tcpAddr.Port, tcpAddr.Zone)
}

func IPv6UdpAddrToUnixSocksAddr(addr string) (sa unix.Sockaddr, err error) {
	tcpAddr, err := net.ResolveTCPAddr("udp6", addr)
	if err != nil {
		return nil, err
	}
	return ipToSocksAddr(unix.AF_INET6, tcpAddr.IP, tcpAddr.Port, tcpAddr.Zone)
}

// TcpListen is listening for incoming IP packets which are being intercepted.
// In conflict to regular Listen mehtod the socket destination and source addresses
// are of the intercepted connection.
// Else then that it works exactly like net package net.Listen.
func TcpListen(listenAddr string) (listener net.Listener, err error) {
	s, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(s)
	err = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err != nil {
		return nil, err
	}

	sa, err := IPv6TcpAddrToUnixSocksAddr(listenAddr)
	if err != nil {
		return nil, err
	}
	err = unix.Bind(s, sa)
	if err != nil {
		return nil, err
	}
	err = unix.Listen(s, unix.SOMAXCONN)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(s), "TProxy")
	defer f.Close()
	return net.FileListener(f)
}

// TcpDial is a special tcp connection which binds a non local address as the source.
// Except then the option to bind to a specific local address which the machine doesn't posses
// it is exactly like any other net.Conn connection.
// It is advised to use port numbered 0 in the localAddr and leave the kernel to choose which
// Local port to use in order to avoid errors and binding conflicts.
func TcpDial(localAddr, remoteAddr string) (conn net.Conn, err error) {
	fmt.Println(localAddr)
	fmt.Println(remoteAddr)
	s, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)

	//In a case there was a need for a non-blocking socket an example
	//s, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM |unix.SOCK_NONBLOCK, 0)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer unix.Close(s)
	err = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	err = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	rhost, rport, err := net.SplitHostPort(localAddr)
	_ = rport
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	sa, err := IPv6TcpAddrToUnixSocksAddr(rhost + ":0")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	remoteSocket, err := IPv6TcpAddrToUnixSocksAddr(remoteAddr)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	err = unix.Bind(s, sa)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	err = unix.Connect(s, remoteSocket)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	f := os.NewFile(uintptr(s), "TProxyTcpClient")
	client, err := net.FileConn(f)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	fmt.Println(client.LocalAddr())
	fmt.Println(client.RemoteAddr())
	return client, err
}

func UdpTProxyConn(listenAddr string) (udp *net.UDPConn, err error) {
	var c net.Conn
	s, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(s)
	err = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err != nil {
		return nil, err
	}

	sa, err := IPv6TcpAddrToUnixSocksAddr(listenAddr)
	if err != nil {
		return nil, err
	}
	err = unix.Bind(s, sa)
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(s), "TProxy")
	defer f.Close()
	c, err = net.FileConn(f)
	if err != nil {
		return nil, err
	}

	var ok bool
	if udp, ok = c.(*net.UDPConn); ok {
		return
	} else {
		c.Close()
		return nil, errors.New("type error")
	}
}

func main() {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println("Error Getting Rlimit ", err)
	}
	fmt.Print("Maximum FD per process: ")
	fmt.Println(rLimit)

	addr := flag.String("l", ":9090", "ip:port for listening or plain \":port\" for listening all IPs")

	flag.Parse()

	tproxyUdp, err := UdpTProxyConn(*addr)
	if err != nil {
		fmt.Println("UdpProxyConn err", err)
	}

	b1 := make([]byte, 1500)
	ctl := make([]byte, 64)

	for {

		var hdr syscall.Msghdr
		var unixAddr unix.Sockaddr
		hdr.Namelen = uint32(unsafe.Sizeof(unixAddr))
		hdr.Name = (*byte)(unsafe.Pointer(&unixAddr))
		hdr.Control = (*byte)(unsafe.Pointer(&ctl))
		hdr.Controllen = uint32(len(ctl))
		hdr.Iovlen = 2
		hdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&[2]syscall.Iovec{}))
		//http://grokbase.com/t/gg/golang-nuts/13aprnjk7m/go-nuts-how-to-get-memory-from-c-and-cast-to-byte
		oop := ((*[1 << 30]byte)(unsafe.Pointer(&hdr)))[0:unsafe.Sizeof(hdr)]

		n, oobn, flags, addr, err := tproxyUdp.ReadMsgUDP(b1, oop)
		if err != nil {
			fmt.Println("ReadMsgUDP err=", err)
			return
		}

		fmt.Println(" result ", n, oobn, flags, addr, err, unixAddr, hdr.Controllen)

		//TODO why the oobn is 0???

		//http://lxr.free-electrons.com/source/include/linux/socket.h#L102
		ctrlMsgs, err := syscall.ParseSocketControlMessage(ctl[:hdr.Controllen])
		if err != nil {
			fmt.Println("ParseSocketControlMessage err=", err)
			return
		}

		for _, msg := range ctrlMsgs {
			fmt.Println("msg=", msg)
		}
	}
}
