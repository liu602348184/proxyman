/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-20 22:47:28
*/
package network

import(
    // "errors"
    "fmt"
    // "net"
    // "reflect"
    "syscall"
    // "binary.BigEndian"
)

const(
    TYPE_IP uint16  = 0x0800
)

var FD int

type Raw struct {
    Fd int
}

func (r *Raw) Listen() (*chan []byte,   error ){
    fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(uint16(syscall.ETH_P_ALL)))) 
    FD = fd
    if err != nil {
        return nil, err
    }

    r.Fd = fd
    bytes := make(chan []byte, 1514)
    
    go func() {
        defer syscall.Close(fd)

        for {
            buf := make([]byte, 1514)
            n, _, _ := syscall.Recvfrom(fd, buf, 0)
            _ = n
            bytes <- buf
            // fmt.Println(n)
            // fmt.Println(buf)
        }
    }()

    return &bytes, nil
}

func  Htons(i uint16) uint16 {
    return (i<<8)&0xff00 | i>>8
}

func (r *Raw) Send(b []byte,  eth Ethernet) {
    var addr [8]byte
    copy(addr[:], eth.DstMac)

    fmt.Println("-----------------------------")
    // fmt.Println(b)

    to := &syscall.SockaddrLinklayer {
        Ifindex: IFI.Index,
        Halen: 6,
        Addr: addr,
        Protocol: Htons(eth.EtherType),
    }

    syscall.Sendto(r.Fd, b, 0, to)
}

func Ntohs() {
    
}