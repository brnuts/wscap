package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
	// Assuming your generated protobuf package is named pb
	"github.com/brnuts/wscap/packetinfo"
)

// Define your WebSocket URL
const wsURL = "ws://example.com/ws"

// main function to capture packets and send them via WebSocket
func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <sourceIP> <destinationIP>")
		return
	}
	ifname := os.Args[1]
	sourceIP := os.Args[2]
	destinationIP := os.Args[3]

	// Open device for packet capture
	handle, err := pcap.OpenLive(ifname, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter = fmt.Sprintf("ip src %s and ip dst %s", sourceIP, destinationIP)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	// Set up WebSocket connection
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Extract packet information
		info := extractPacketInfo(packet)

		// Serialize packet information using protobuf
		data, err := proto.Marshal(&info)
		if err != nil {
			log.Fatal("marshaling error: ", err)
		}

		// Send serialized data over WebSocket
		if err := c.WriteMessage(websocket.BinaryMessage, data); err != nil {
			log.Println("write:", err)
			return
		}
	}
}

func extractPacketInfo(packet gopacket.Packet) packetinfo.PacketInfo {
	var info packetinfo.PacketInfo

	// Get IP layer information
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SourceIP = ip.SrcIP.String()
		info.DestinationIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
	}

	// Get TCP layer information
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SourcePort = int32(tcp.SrcPort)
		info.DestinationPort = int32(tcp.DstPort)

		// TCP Flags
		flags := ""
		if tcp.FIN {
			flags += "FIN "
		}
		if tcp.SYN {
			flags += "SYN "
		}
		if tcp.RST {
			flags += "RST "
		}
		if tcp.PSH {
			flags += "PSH "
		}
		if tcp.ACK {
			flags += "ACK "
		}
		if tcp.URG {
			flags += "URG "
		}
		if tcp.ECE {
			flags += "ECE "
		}
		if tcp.CWR {
			flags += "CWR "
		}
		if tcp.NS {
			flags += "NS "
		}
		info.TcpFlags = flags
	}

	// Get UDP layer information
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SourcePort = int32(udp.SrcPort)
		info.DestinationPort = int32(udp.DstPort)
	}

	// Packet size
	info.Size = int32(packet.Metadata().Length)

	return info
}
