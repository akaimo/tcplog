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

	for _, device := range devices {
		fmt.Println("Name: " + device.Name)
		fmt.Println("Description: " + device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP: " + address.IP.String())
			fmt.Println("- NetMask: " + address.Netmask.String())
		}
		fmt.Println("")
	}

	handle, err := pcap.OpenLive("en0", int32(0xFFFF), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for _, layer := range packet.Layers() {
			fmt.Println(layer.LayerType())
		}
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			fmt.Println("[*] Ethernet Layer")
			eth, _ := ethernetLayer.(*layers.Ethernet)
			fmt.Printf("\t%s -> %s\n", eth.SrcMAC, eth.DstMAC)
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			fmt.Println("[*] IPv4 layer")
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("\t%s -> %s\n", ip.SrcIP, ip.DstIP)
		}
	}
}
