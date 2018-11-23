package main

import (
	"log"
	"github.com/google/gopacket/pcap"
	"fmt"
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
}
