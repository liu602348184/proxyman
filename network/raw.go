/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-12 04:18:45
*/
package network

import(
    // "errors"
    // "fmt"
    // "net"
    "syscall"
    // "binary.BigEndian"
)

const(
    TYPE_IP uint16  = 0x0800
)

type Raw struct {

}

func (r *Raw) Listen() (*chan []byte,   error ){
    fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(uint16(syscall.ETH_P_ALL)))) 

    if err != nil {
        return nil, err
    }

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

func Ntohs() {
    
}