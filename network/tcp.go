/*
* @Author: liuyujie
* @Date:   2018-07-31 22:53:44
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-04 23:16:49
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
    "log"
    // "errors"
    "encoding/binary"
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
    Payload []byte
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
        // log.Println(ip4.Protocol)
        if ip4.Protocol != 6 {
            continue
        }

        tcpdata, err := tcp.Format(ip4.Payload)
        // log.Println(tcpdata)
        if err != nil {
            log.Println(err)
        }
        log.Println(tcpdata.Payload)
        tcpchan <- tcpdata
    }

    return &tcpchan, nil
}

func(tcp TCP) Format (b []byte)  (TCP, error)  {
    sceport := binary.BigEndian.Uint16(b[0: 2])
    dstport := binary.BigEndian.Uint16(b[2: 4])
    serial := binary.BigEndian.Uint32(b[4: 8])
    ackserial := binary.BigEndian.Uint32(b[8: 12])
    hrp := binary.BigEndian.Uint16(b[12: 14])
    hlen := uint8((hrp >> 12 & 0x0F) * 4)
    // log.Println(hrp >> 12 & 0x0F)
    // log.Println(b)
    // reserved := hrp >> 6 & 0x3F
    ctr_urg := (hrp >> 5 & 1) == 1
    ctr_ack := (hrp >> 4 & 1) == 1
    ctr_psh := (hrp >> 3 & 1) == 1
    ctr_rst := (hrp >> 2 & 1) == 1
    ctr_syn := (hrp >> 1 & 1) == 1
    ctr_fin := (hrp & 1) == 1
    window := binary.BigEndian.Uint16(b[16: 18])
    checksum := binary.BigEndian.Uint16(b[18: 20])
    urg_pointer := binary.BigEndian.Uint16(b[20: 22])
    payload := b[hlen:]
   
    control := Control{
        URG: ctr_urg,
        ACK: ctr_ack,
        PSH: ctr_psh,
        RST: ctr_rst,
        SYN: ctr_syn,
        FIN: ctr_fin,
    }

    tcpdata := TCP{
        ScePort: sceport,
        DstPort: dstport,
        Serial: serial,
        AckSerial: ackserial,
        Hlen: hlen,
        Control: control,
        Window: window,
        Checksum: checksum,
        UrgentPointer: urg_pointer,
        Payload: payload,
    }

    return tcpdata, nil
}