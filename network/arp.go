/*
* @Author: liuyujie
* @Date:   2018-08-12 02:32:58
* @Last Modified by:   liuyujie
* @Last Modified time: 2018-08-12 04:30:46
*/
package network
import (
    "net"
    // "errors"
    "log"
    "syscall"
    "encoding/binary"
)

type ARP struct {
    HwType uint16
    ProtoType uint16
    HwAddrLen uint8
    ProtoAddrLen uint8
    Option uint16   // 1 request 2 reply
    SceEthAddr net.HardwareAddr
    SceIPAddr [4]byte
    DstEthAddr net.HardwareAddr
    DstIPAddr [4]byte
    Ethernet Ethernet
}

func (arp ARP) Listen() (*chan ARP, error) {
    ethernet := Ethernet{}
    ethchan, err := ethernet.Listen()

    if err != nil {
        return nil, err
    }

    arpchan := make(chan ARP, 2)

    go func() {
        for {
            eth := <- *ethchan
            
            if eth.EtherType != syscall.ETH_P_ARP {
                continue
            }

            arpdata, ferr := arp.Format(eth.Payload)

            if ferr != nil {
                log.Println(ferr)
                continue
            }
            arpchan <- arpdata
        }
    }()

    return &arpchan, nil
}

func (arp ARP) Format(b []byte) (ARP, error) {
    hw_type := binary.BigEndian.Uint16(b[0: 2])
    proto_type := binary.BigEndian.Uint16(b[2: 4])
    hw_t_len := uint8(b[4])
    proto_t_len := uint8(b[5])
    option := binary.BigEndian.Uint16(b[6: 8])
    sce_eth_addr := net.HardwareAddr{b[8], b[9], b[10], b[11], b[12], b[13]}
    sce_ip_addr := b[14: 18]
    dst_eth_addr := net.HardwareAddr{b[18], b[19], b[20], b[21], b[22], b[23]}
    dst_ip_addr := b[24:]

    a := ARP{
        HwType: hw_type,
        ProtoType: proto_type,
        HwAddrLen: hw_t_len,
        ProtoAddrLen: proto_t_len,
        Option: option,
        SceEthAddr: sce_eth_addr,
        // SceIPAddr: sce_ip_addr[:],
        DstEthAddr: dst_eth_addr,
        // DstIPAddr: dst_ip_addr[:],
    }
    copy(a.SceIPAddr[:],  sce_ip_addr)
    copy(a.DstIPAddr[:],  dst_ip_addr)
    return a, nil
}