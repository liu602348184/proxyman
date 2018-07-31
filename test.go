package main

import (
    "fmt"
    // "net"
    "log"
    // "reflect"
    // "syscall"
    "./network"
    // "golang.org/x/net/bpf"
    // "encoding/binary"
)

func main()  {
    // fmt.Println("hello world!")
    // ifi, err := net.InterfaceByName("eth0")
    // if err !=  nil {
    //     fmt.Println(err)
    //     return
    // }

    // fmt.Println(network.TYPE_IP)
    // fmt.Println(reflect.TypeOf(ifi.HardwareAddr))
    // net_type := make([]byte, 2)
    // binary.BigEndian.PutUint16(net_type, 0x0800)
    // int_type := binary.BigEndian.Uint16(net_type)
    // fmt.Println(int(htons(uint16(0x0800))))
    tcp := network.TCP{}
    tcpchan, err := tcp.Listen()
    if err != nil {
        log.Fatal(err)
    }
    // fmt.Println(eth)
    // fmt.Println(ethchan)
    // var bytes  []byte
    for{
        a := <- *tcpchan
        // _ = a
        fmt.Println(a)
    }
}