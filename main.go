package main

import (
	"log"
	"github.com/google/gopacket/pcap"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	ch := make(chan string)

	for _, device := range devices {
		fmt.Println("Name: " + device.Name)
		fmt.Println("Description: " + device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP: " + address.IP.String())
			fmt.Println("- NetMask: " + address.Netmask.String())
		}
		fmt.Println("")

		go logPacket(ch, device.Name)
	}

	log.Println(<-ch)
}

type Packet struct {
	Device string
	SourceIP string
	DestinationIP string
	SourceMac string
	DestinationMac string
}

func logPacket(ch chan string, device string) {
	handle, err := pcap.OpenLive(device, int32(0xFFFF), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//for _, layer := range packet.Layers() {
		//	fmt.Println(layer.LayerType())
		//}
		p := Packet{Device:device}
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			eth, _ := ethernetLayer.(*layers.Ethernet)
			p.SourceMac = eth.SrcMAC.String()
			p.DestinationMac = eth.DstMAC.String()
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			p.SourceIP = ip.SrcIP.String()
			p.DestinationIP = ip.DstIP.String()
		}
		fmt.Printf("%+v\n", p)
	}

	ch <- device
}
