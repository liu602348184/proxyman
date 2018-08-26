/*
* @Author: liuyujie
* @Date:   2018-07-31 22:53:44
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-26 21:32:33
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
    // "fmt"
    // "errors"
    "encoding/binary"
)
//指针位/控制位
type Control struct {
    CWR bool
    ECE bool
    URG bool
    ACK bool
    PSH bool
    RST bool
    SYN bool
    FIN bool
}

type Option struct {
    Kind uint8
    Length uint8
    Value []byte
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
    Options []Option
    Payload []byte
    IPV4 *IPV4
}

func (tcp TCP) Listen() (*chan TCP, error) {
    ipv4 := IPV4{}
    ipv4chan, err := ipv4.Listen()
    
    if err != nil {
        return nil, err
    }

    tcpchan := make(chan TCP, 2)

    go func() {
        for {
            ip4 := <-*ipv4chan
            // log.Println(ip4.Protocol)
            if ip4.Protocol != 6 {
                continue
            }

            tcpdata, err := tcp.Format(ip4.Payload)
            // fmt.Println("payload")
            // fmt.Println(ip4.Payload)
            if err != nil {
                log.Println(err)
            }

            tcpdata.IPV4 = &ip4
            // log.Println(tcpdata.Payload)
            tcpchan <- tcpdata
        }
    }()

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
    ctr_cwr := (hrp >> 7 & 1) == 1
    ctr_ece := (hrp >> 6 & 1) == 1
    ctr_urg := (hrp >> 5 & 1) == 1
    ctr_ack := (hrp >> 4 & 1) == 1
    ctr_psh := (hrp >> 3 & 1) == 1
    ctr_rst := (hrp >> 2 & 1) == 1
    ctr_syn := (hrp >> 1 & 1) == 1
    ctr_fin := (hrp & 1) == 1
    window := binary.BigEndian.Uint16(b[14: 16])
    checksum := binary.BigEndian.Uint16(b[16: 18])
    urg_pointer := binary.BigEndian.Uint16(b[18: 20])
    optionlen := hlen - 20
    // log.Println(hlen)
    // log.Println(b)
    var options []Option
    var err error

    if optionlen > 0 {
        options, err = getOptions(b[20: hlen])
        
        if err != nil {
            log.Println(err)
        }
    }

    payload := b[hlen:]
   
    control := Control {
        CWR: ctr_cwr,
        ECE: ctr_ece,
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
        Options: options,
        Payload: payload,
    }

    return tcpdata, nil
}

func getOptions(opt []byte) ([]Option, error) {
    // opt = []byte{1, 1, 8, 10, 193, 34, 128, 208, 0, 82, 62, 56}
    // log.Println(opt)
    b := opt
    var options []Option
    var option Option
    l := uint8(len(b))
    var length uint8
    // log.Println(opt)
    for {
        kind := uint8(b[0])
        b = b[1:]
        // log.Println(kind)
        if kind != 0 && kind != 1 {
            length = uint8(b[0])
            b = b[1:]
            l = uint8(len(b))
            length =  length - 2
            var value []byte

            if l == length {
                value = b[0:]
                b = []byte{}
            } else {
                value = b[0:length]
                b = b[length: ]
            }

            option = Option{
                Kind: kind,
                Length: length + 2,
                Value: value,
            }
        } else {
            option = Option {
                Kind: kind,
                Length: 1,
            }
        }

        options = append(options, option)

        if len(b) == 0 {
            break
        }
    }
    return options, nil
}

func (tcp *TCP) ToBytes() []byte {
    // log.Println(tcp.Checksum)
    // log.Println(tcp.Checksum)
    var sceport [2]byte
    binary.BigEndian.PutUint16(sceport[:], tcp.ScePort)
    var dstport [2]byte
    binary.BigEndian.PutUint16(dstport[:], tcp.DstPort)
    var serial [4]byte
    binary.BigEndian.PutUint32(serial[:], tcp.Serial)
    var ack_serial [4]byte
    binary.BigEndian.PutUint32(ack_serial[:], tcp.AckSerial)
    hlen_resv := uint8(tcp.Hlen / 4)
    hlen_resv = hlen_resv << 4
    //control
    c_b := getCtrBytes(tcp.Control)
    var win [2]byte
    binary.BigEndian.PutUint16(win[:], tcp.Window)
    var checksum [2]byte
    binary.BigEndian.PutUint16(checksum[:], tcp.Checksum)
    var urg_pointer [2]byte
    binary.BigEndian.PutUint16(urg_pointer[:], tcp.UrgentPointer)
    var opts = getOptBytes(tcp.Options)

    // var b []byte
    b := append(sceport[:], dstport[:]...)
    b = append(b, serial[:]...)
    b = append(b, ack_serial[:]...)
    b = append(b, hlen_resv)
    b = append(b, c_b)
    b = append(b, win[:]...)
    b = append(b, checksum[:]...)
    b = append(b, urg_pointer[:]...)
    b = append(b, opts[:]...)
    var cksum_b [2]byte
    cksum := tcp.TcpCksum(b)
    binary.BigEndian.PutUint16(cksum_b[:], cksum)
    b[16] = cksum_b[0]
    b[17] = cksum_b[1]
    b = append(b, tcp.Payload...)

    return b
}

func (tcp *TCP) TcpCksum(tcpheader []byte) uint16 {
    var pseudoheader [12]byte
    sceip := tcp.IPV4.SceIP
    dstip := tcp.IPV4.DstIP
    copy(pseudoheader[0: 4], sceip[:])
    copy(pseudoheader[4: 8], dstip[:])
    pseudoheader[8] = 0
    pseudoheader[9] = 6

    tcplen := uint16(len(tcp.IPV4.Payload))
    var tcplenbytes [2]byte 
    binary.BigEndian.PutUint16(tcplenbytes[:], tcplen)
    pseudoheader[10] = tcplenbytes[0]
    pseudoheader[11] = tcplenbytes[1]
    calccksum := ChecksumFunc(0, pseudoheader[:])
    // tcpheader := tcp.IPV4.Payload[0: tcp.Hlen]
    tcpheader[16]  = 0
    tcpheader[17]  = 0
    calccksum = ChecksumFunc(uint32(^calccksum), tcpheader)
    // tcp.Checksum = calccksum
    return  calccksum
    // return tcplenbytes
}

func getCtrBytes(ctr Control) byte {
    control := byte(0)
    
    if ctr.CWR {
        control = 128
    }

    if ctr.ECE {
        control = control | 64
    }

    if ctr.URG {
        control = control | 32
    }

    if ctr.ACK {
        control = control | 16
    }

    if ctr.PSH {
        control = control | 8
    }

    if ctr.RST {
        control = control | 4
    }

    if ctr.SYN {
        control = control | 2
    }

    if ctr.FIN {
        control = control | 1
    }

    return control
}

func getOptBytes(opts []Option) []byte {
    var bytes []byte
    
    for _, opt := range opts {
        bytes = append(bytes, byte(opt.Kind))
        
        if opt.Kind != 0 && opt.Kind != 1 {
            bytes = append(bytes, byte(opt.Length))
            bytes = append(bytes, opt.Value...)
        }
    }

    return bytes
}

func (tcp TCP) Send(payload []byte) {
    copy(tcp.Payload[:], payload[:])
    tcp.IPV4.Send(tcp.ToBytes())
}