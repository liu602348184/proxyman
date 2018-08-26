/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-21 03:03:28
*/
package network
/**
Ethernet II frames
**/
import (
    "net"
    // "fmt"
    "log"
    "hash/crc32"
    // "reflect"
    "encoding/binary"
)

type Ethernet struct {
    IFI *net.Interface
    DstMac net.HardwareAddr
    SceMac net.HardwareAddr
    EtherType uint16
    Payload []byte
    CRC uint32
    Raw *Raw
}

var MTU int
var IFI *net.Interface

func init(){
    ifi, _ := GetMTU("eth0")
    MTU = ifi.MTU
    IFI = ifi
}

func (e Ethernet) Listen() (*chan Ethernet, error) {
    raw := Raw{}
    rawchan, err := raw.Listen()

    if err != nil {
        return nil, err
    }

    ethchan := make(chan Ethernet, 2)
    
    go func(){
        localHw, err := GetHwAddr("eth0")
        
        if err != nil {
            log.Fatal(err)
        }

        for{
            bytes := <- *rawchan
            eth := e.Format(bytes)
            // log.Println(eth.DstMac.String());
            if eth.DstMac.String() == localHw.String() {
                eth.Raw = &raw
                ethchan <- eth
            }
        }
    }()
    return &ethchan, nil
}

func GetHwAddr(ethAtp string) (net.HardwareAddr, error) {
    ifi, err := net.InterfaceByName(ethAtp)
     
    if err !=  nil {
       return nil, err
    }
    
    return ifi.HardwareAddr, nil   
}

func GetMTU(ethAtp string) (*net.Interface, error) {
    ifi, err := net.InterfaceByName(ethAtp)
     
    if err !=  nil {
       return nil, err
    }
    
    return ifi, nil   
}

func GetInterFace() (*net.Interface, error) {
    ifi, err := net.InterfaceByName("eth0")

    if err != nil {
        log.Println(err)
        return nil, err
    }

    return ifi, nil
}

//前导字节和尾部crc签名将被过滤
func (e Ethernet) Format(b []byte) (Ethernet){
    eth := Ethernet{
        DstMac: net.HardwareAddr{b[0], b[1], b[2], b[3], b[4], b[5]},
        SceMac: net.HardwareAddr{b[6], b[7], b[8], b[9], b[10], b[11]},
        EtherType: binary.BigEndian.Uint16(b[12:14]),
        Payload: b[14:],
    }

    return eth
}

func (e Ethernet) ToBytes() ([]byte) {
    var eth_bytes []byte
    dmac := []byte{e.DstMac[0], e.DstMac[1], e.DstMac[2], e.DstMac[3], e.DstMac[4], e.DstMac[5]}
    smac :=  []byte{e.SceMac[0], e.SceMac[1], e.SceMac[2], e.SceMac[3], e.SceMac[4], e.SceMac[5]}
    eth_bytes = append(eth_bytes, dmac[:]...)
    eth_bytes = append(eth_bytes, smac[:]...)
    eth_type := make([]byte, 2)
    binary.BigEndian.PutUint16(eth_type, e.EtherType)
    eth_bytes = append(eth_bytes, eth_type[:]...)
    eth_bytes = append(eth_bytes, e.Payload[:]...)
    // eth_len := MTU - len(eth_bytes)
    // data := make([]byte, eth_len)
    // eth_bytes = append(eth_bytes, data[:]...)
    return eth_bytes
}

func (e Ethernet) Send(payload []byte) {
    e.Payload = payload
    data := e.ToBytes()
    // h := crc32.NewIEEE()
    // h.Write(payload)
    var fcs [4]byte
    // crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
    binary.LittleEndian.PutUint32(fcs[:], crc32.Checksum(data, crc32.MakeTable(crc32.IEEE)))
    log.Println(fcs)
    // data = append(data, fcs)
    // fcs := reverse_table_crc(data)
    // eth_len := MTU - len(data)
    // padding := make([]byte, eth_len)
    // data = append(data, padding[:]...)
    data = append(data, fcs[:]...)
    e.Raw.Send(data, e)
    // fmt.Println(data)
}

func getFcs(b []byte) [4]byte {
    crc_table := get_crc_table()
    offset := 0
    length := len(b)
    // var crc uint32
    crc := uint32(0xFFFFFFFF)

    for i := length; i >= 1; i -= 1 {
        b_num := uint32(b[offset])
        crc = crc_table[(crc ^ b_num) & 0xFF] ^ (crc >> 8)
        offset += 1
    }
    crc = ^crc
    var fcs [4]byte
    binary.BigEndian.PutUint32(fcs[:], crc)
    return fcs
}

func get_crc_table() [256]uint32 {
    var crcTable [256]uint32
    for n, _ := range crcTable {
        c := uint32(n)
        for i := 8; i >= 1; i -= 1 {
            if (c & 1) != 0 {
                c = 0xEDB88320 ^ (c >> 1);
            }
        }
        crcTable[n] = c
    }

    return crcTable
}

func reverse_table_crc(b []byte) [4]byte {
    crc := uint32(0xFFFFFFFF)
    table, _ := gen_normal_table()
    for n, _ := range b {
        crc = table[(crc ^ uint32(b[n])) & 0xFF] ^ (crc >> 8)
    }

    var fcs [4]byte
    binary.BigEndian.PutUint32(fcs[:], ^crc)
    return fcs
}

func gen_normal_table() ([256]uint32, uint32) {
    gx := uint32(0x04c11db7)
    var temp uint32
    var crc uint32
    var crcTable [256]uint32
    
    for n, _ := range crcTable {
        temp = bit_reflect(uint32(n), 8)
        crcTable[n] = (temp << 24)

        for j := 0; j < 8; j+=1 {
            flag := (crcTable[n] &  0x80000000)
            t1 := (crcTable[n] << 1)
            var t2 uint32
            
            if flag == 0 {
                t2 = 0
            } else {
                t2 = gx
                crcTable[n] = uint32(t1 ^ t2)
            }
            crc = crcTable[n]
            crcTable[n] = bit_reflect(crcTable[n], 32)
        }
    }
    return crcTable, crc
}

func bit_reflect(ref uint32, ch uint8) uint32 {
     value := uint32(0);

    for i := 1; i < int( ch + 1 ); i++  {
        if ref & 1 == 1 {
            value |= 1 << ( ch - uint8(i));
        }
        ref >>= 1;
    }
    return value;
}