/*
* @Author: liuyujie
* @Date:   2018-07-31 22:53:44
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-07-31 23:46:53
*/
/**
RFC793
RFC813
RFC879
RFC896
RFC2525
RFC2581
RFC2988
**/
package network

import (
    "fmt"
)
//指针位/控制位
type Control struct {
    URG bool
    ACK bool
    PSH bool
    RST bool
    SYN bool
    FIN bool
}

type TCP struct {
    ScePort uint16
    DstPort uint16
    Serial uint32
    AckSerial uint32
    Hlen uint8
    Control Control
    Window uint16
    Checksum uint16
    UrgentPointer uint16
    Options []byte
    IPV4 IPV4
}

func (tcp TCP) Listen() (*chan TCP, error) {
    ipv4 := IPV4{}
    ipv4chan, err := ipv4.Listen()
    
    if err != nil {
        return nil, err
    }

    tcpchan := make(chan TCP, 2)

    for {
        ip4 := <-*ipv4chan
        fmt.Println(ip4.Payload)
    }

    return &tcpchan, nil
}