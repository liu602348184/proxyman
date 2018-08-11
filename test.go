package main

import (
    "fmt"
    // "net"
    "log"
    // "reflect"
    // "syscall"
    "./network"
    "sync"
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
    // tcp := network.TCP{}
    // tcpchan, err := tcp.Listen()
    // if err != nil {
    //     log.Fatal(err)
    // }
    // fmt.Println(eth)
    // fmt.Println(ethchan)
    // var bytes  []byte
    // mtu, _ := network.GetMTU("eth0")
    // fmt.Println(mtu)
    // for{
    //     a := <- *tcpchan
    //     // _ = a
    //     fmt.Println(a.Payload)
    // }

    ip := network.IPV4{}
    ipchan, err := ip.Listen()
    
    if err != nil {
        log.Fatal(err)
    }

    var wg sync.WaitGroup
    wg.Add(1)

    go func() {
        for {
            a := <-*ipchan
            // test := []byte{0x00, 0x01}
            // a.Send(test)
            fmt.Println(a.SceIP)
        }
    }()

    arp := network.ARP{}
    arpchan, err2 := arp.Listen()
    
    if err != nil {
        log.Fatal(err2)
    }

    go func() {
        for {
            a2 := <-*arpchan
            // test := []byte{0x00, 0x01}
            // a.Send(test)
            fmt.Println(a2.SceEthAddr)
        }
    }()

    wg.Wait()
}