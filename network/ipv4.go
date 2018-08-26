/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-26 19:15:21
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
   "log"
    _"fmt"
    "errors"
    "syscall"
    // "reflect"
    "net"
    // "unsafe"
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
    Version uint8        //ipv4 0x4
    HeaderLen uint8
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
    Ethernet *Ethernet
}

var internal_ip [4]byte
var extranet_ip [4]byte
var mask [4]byte
var broadcast [4]byte
var netaddr [4]byte

func init() {
    ifi, ifi_err := GetInterFace()
    
    if ifi_err != nil {
        log.Fatal(ifi_err)
    }

    addrs, addrs_err := ifi.Addrs()

    if addrs_err != nil {
        log.Fatal(addrs_err)
    }

    for _, addr := range addrs {
        ipaddr, ok := addr.(*net.IPNet)

        if !ok {
            continue
        }
        // log.Println(len(ipaddr.IP))
        ip := ipaddr.IP.To4()
        // log.Println(ipaddr.Mask.To4())
        var ip_tmp [4]byte

        if ip != nil {
            copy(ip_tmp[:], ip)
        }

        if ip_tmp[0] == 10 || ip_tmp[0] == 172 || ip_tmp[0] == 192 {
            copy(internal_ip[:], ip_tmp[:])
            copy(mask[:], ipaddr.Mask)
        } else {
            copy(extranet_ip[:], ip_tmp[:])
        }
    }
    setBroadcast()
    // log.Println(mask)
}

func setBroadcast() {
    ip_num := binary.BigEndian.Uint32(internal_ip[:])
    mask_num := binary.BigEndian.Uint32(mask[:])

    if ip_num == 0 && mask_num == 0 {
        return
    }

    var na [4]byte
    var bc [4]byte
    for i, b := range internal_ip {
        na[i] = mask[i] & b
        bc[i] = (255 - mask[i]) + na[i]
    }

    copy(netaddr[:], na[:])
    copy(broadcast[:], bc[:])
    // log.Println(netaddr)
    // log.Println(broadcast)
    // log.Println(mask)
}

func GetBroadcast() [4]byte {
    return broadcast
}

func GetNetAddr() [4]byte {
    return netaddr
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
            
            if syscall.ETH_P_IP != eth.EtherType {
                continue
            }
            ipdata, ferr := ipv4.Format(eth.Payload)
            ipdata.Ethernet = &eth
            // log.Println("payload")
            // log.Println(ipdata.SceIP)
            // log.Println(ipdata.DstIP)

            if ferr != nil {
                log.Println(ferr)
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
    ver := uint8(ver_hlen >> 4 & 0x0F)
    hlen := uint8(ver_hlen & 0x0F)

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
    result := ChecksumFunc(0, b[0: hlen])

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
        Payload: b[hlen : length],
        // SceIP: sceip,
        // DstIP: dstip,
    }
    copy(ip4.SceIP[:], sceip)
    copy(ip4.DstIP[:], dstip)
    // fmt.Println(result)
    // fmt.Println(ip4.Payload)
    return ip4, nil
}
func ChecksumFunc(initcksum uint32, header []byte)  uint16 {
    var u16 [2]byte
    sum := initcksum
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
/*
    MinDalay bool
    MaxIO bool
    MaxReliability bool
    MinCost bool
*/
func (ipv4 IPV4) ToBytes() ([]byte){
    var bytes []byte
    ver_hlen := byte((ipv4.Version << 4 & 0xF0) | ((ipv4.HeaderLen / 4) & 0x0F))
    tos := ipv4.TOS
    tos_b  := uint8(0)
    
    if tos.MinDalay {
        tos_b = 1 << 4
    }

    if tos.MaxIO {
        tos_b = tos_b | (1 << 3)
    }

    if tos.MaxReliability {
        tos_b = tos_b| (1 << 2)
    }

    if tos.MinCost {
        tos_b = tos_b | (1 << 1)
    }

    var len_b [2]byte
    binary.BigEndian.PutUint16(len_b[:], ipv4.Length)
    var id_b [2]byte
    binary.BigEndian.PutUint16(id_b[:], ipv4.Id)

    flag := ipv4.Flag
    offset := ipv4.Offset
    flag_offset := uint16(0)

    if flag.DF {
        flag_offset = 1 << 14
    }

    if flag.MF {
        flag_offset = flag_offset | (1 << 13)
    }

    flag_offset = flag_offset | offset
    var flag_offset_b [2]byte
    binary.BigEndian.PutUint16(flag_offset_b[:], flag_offset)
    ttl := byte(ipv4.TTL)
    protocol := byte(ipv4.Protocol)
    // checksum := ipv4.Checksum
    checksum := uint16(0)
    var checksum_b [2]byte
    binary.BigEndian.PutUint16(checksum_b[:], checksum) 
    sceip := ipv4.SceIP
    dstip := ipv4.DstIP

    bytes = append(bytes, ver_hlen)
    bytes = append(bytes, tos_b)
    bytes = append(bytes, len_b[:]...)
    bytes = append(bytes, id_b[:]...)
    bytes = append(bytes, flag_offset_b[:]...)
    bytes = append(bytes, ttl)
    bytes = append(bytes, protocol)
    bytes = append(bytes, checksum_b[:]...)
    bytes = append(bytes, sceip[:]...)
    bytes = append(bytes, dstip[:]...)
    bytes = append(bytes, ipv4.Options[:]...)
    bytes = append(bytes, ipv4.Payload[:]...)
    //if  ip header has been changed
    checksum = ChecksumFunc(0, bytes[0: ipv4.HeaderLen])
    binary.BigEndian.PutUint16(checksum_b[:], checksum) 
    bytes[10] = checksum_b[0]
    bytes[11] = checksum_b[1]
    
    return bytes
}

func (ipv4 IPV4) Send(payload []byte) {
    copy(ipv4.Payload[:], payload[:])
    data := ipv4.ToBytes()
    // log.Println(payload)
    // log.Println(data)
    ipv4.Ethernet.Send(data)
    // fmt.Println(data)
}