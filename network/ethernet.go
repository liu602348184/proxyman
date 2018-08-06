/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-06 23:47:01
*/
package network
/**
Ethernet II frames
**/
import (
    "net"
    "fmt"
    "log"
    "encoding/binary"
)

type Ethernet struct {
    DstMac net.HardwareAddr
    SceMac net.HardwareAddr
    EtherType uint16
    Payload []byte
    CRC uint32
    Raw *Raw
}
var MTU int

func init(){
    MTU, _ = GetMTU("eth0")
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

func GetMTU(ethAtp string) (int, error) {
    ifi, err := net.InterfaceByName(ethAtp)
     
    if err !=  nil {
       return 0, err
    }
    
    return ifi.MTU, nil   
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
    eth_len := MTU - len(eth_bytes)
    data := make([]byte, eth_len)
    eth_bytes = append(eth_bytes, data[:]...)
    return eth_bytes
}

func (e Ethernet) Send(payload []byte) {
    e.Payload = payload
    data := e.ToBytes()
    fmt.Println(data)
}