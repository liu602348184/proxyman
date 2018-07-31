/*
* @Author: liuyujie
* @Date:   2018-07-29 18:12:07
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-07-29 22:46:12
*/
package network
/**
Ethernet II frames
**/
import (
    "net"
    _"fmt"
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