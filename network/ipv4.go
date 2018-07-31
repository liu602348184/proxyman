/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-07-31 23:18:23
*/
/**
RFC-791
https://tools.ietf.org/html/rfc791
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
package network
import(
   // "log"
   // "fmt"
   "errors"
    "encoding/binary"
)
//前三比特已经废弃最后一位设置为0
type TOS struct {
    MinDalay bool
    MaxIO bool
    MaxReliability bool
    MinCost bool
}
/**
Bit 0: reserved, must be zero
Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
          0   1   2
        +---+---+---+
        |   | D | M |
        | 0 | F | F |
        +---+---+---+
*/
type Flag struct {
    DF bool
    MF bool
}

type IPV4 struct {
    Version uint        //ipv4 0x4
    HeaderLen uint
    TOS TOS
    Length uint16
    Id uint16  // IP 报文的唯一id，分片报文的id 相同，便于进行重组。 
    Flag Flag
    Offset uint16  //13位片偏移
    TTL uint8
    Protocol uint8
    Checksum uint16
    SceIP [4]byte
    DstIP [4]byte
    Options []byte
    Payload []byte
    Ethernet Ethernet
}

func (ipv4 IPV4) Listen() (*chan IPV4, error){
    ethernet := Ethernet{}
    ethchan, err := ethernet.Listen()
    if err != nil {
        return nil, err
    }

    ipv4chan := make(chan IPV4, 2)

    go func() {
        for{
            eth := <- *ethchan
            ipdata, ferr := ipv4.Format(eth.Payload)

            if ferr != nil {
                continue
            }
            // _ = ipdata
            ipv4chan <- ipdata
        }
    }()

    return &ipv4chan, nil
}

func (ipv4 IPV4) Format(b []byte)  (IPV4, error){
    // version and length of header
    ver_hlen := b[0]
    ver := uint(ver_hlen >> 4 & 0x0F)
    hlen := uint(ver_hlen & 0x0F)

    if ver != 4 {
        return IPV4{}, errors.New("the version of ip must be ipv4")
    }
    // TOS
    tos_byte := b[1]
    //00011110
    max_dalay :=  (tos_byte >> 4 & 1) == 1
    max_io := (tos_byte >> 3 & 1) == 1
    max_reli := (tos_byte >> 2 & 1) == 1
    max_cost := ( tos_byte >> 1 & 1) == 1
    
    tos := TOS{
        max_dalay,
        max_io,
        max_reli,
        max_cost,
    }
    //total length
    length := binary.BigEndian.Uint16(b[2:4])
    //ID
    id := binary.BigEndian.Uint16(b[4:6])
    // Flag&offset
    flag_offset := binary.BigEndian.Uint16(b[6:8])
    df := (flag_offset >> 14 & 1) == 1
    mf := (flag_offset >> 13 & 1) == 1
    
    flag := Flag{
        df,
        mf,
    }
    ex := flag_offset << 3
    offset := ex >> 3

    ttl := uint8(b[8])
    // Protocol ICMP：1，TCP：6，UDP：17
    protocol := uint8(b[9])

    if hlen < 5 {
        return IPV4{}, errors.New("bad ip package")
    }

    checksum := binary.BigEndian.Uint16(b[10: 12])
    hlen = hlen * 4
    result := checksumFunc(b[0: hlen])

    if result != 0 {
        return IPV4{}, errors.New("bad ip package")
    }

   sceip := b[12: 16]
   dstip := b[16: 20]

    ip4 := IPV4{
        Version: ver,
        HeaderLen: hlen ,
        TOS: tos,
        Length: length,
        Id: id,
        Flag: flag,
        Offset: offset,
        TTL: ttl,
        Protocol: protocol,
        Checksum: checksum,
        Payload: b[(hlen - 1) : length],
        // SceIP: sceip,
        // DstIP: dstip,
    }
    copy(ip4.SceIP[:], sceip)
    copy(ip4.DstIP[:], dstip)
    // fmt.Println(result)
    // fmt.Println(ip4.Payload)
    return ip4, nil
}

func checksumFunc(header []byte)  uint16 {
    var u16 [2]byte
    var sum uint32
   // header[10] = 0;
   // header[11] = 0;
    for idx, value := range header {
        i := idx % 2
        u16[i] = value
        if i != 0 {
            sum += uint32(binary.BigEndian.Uint16(u16[0:]))
        }
    }
    // fmt.Println(checksum)
    for {
        if (sum >> 16)  > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        } else {
            // fmt.Println(^uint16(sum))
            break
        }
    }

    return ^uint16(sum)
}