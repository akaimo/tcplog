package main

import (
	"log"
	"github.com/google/gopacket/pcap"
	"fmt"
	"github.com/google/gopacket"
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
		fmt.Println(packet.String())
	}
}
