//
// 功能：内网主机扫描
// 作者: Ease
// 日期：2018.7.7
// 说明：1. 通过ARP包进行搜索
//      2. 通过mDNS获取 (即多播dns,基于UDP,组播地址:224.0.0.251(ipv6： FF02::FB) 端口为5353)
//      3. 通过nbns获取主机名称
//

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	termbox "github.com/nsf/termbox-go"
	"github.com/timest/gomanuf"
)

type IP uint32

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	Debug        bool
	SendTime     int      //数据包发送时间间隔（分钟）
	LiveIp       []IpInfo //存活设备
)

type iface struct {
	name string
	ip   *net.IPNet
	addr net.HardwareAddr
}

type IpInfo struct {
	Hostname string           // 主机名
	Manuf    string           // 厂商信息
	IP       string           //IP
	Live     string           //存活时间
	Mac      net.HardwareAddr // IP地址
	Prot     string           //协议
}

type Buffer struct {
	data  []byte
	start int
}

func NewBuffer() *Buffer {
	return &Buffer{}
}

func (b *Buffer) PrependBytes(n int) []byte {
	length := cap(b.data) + n
	newData := make([]byte, length)
	copy(newData, b.data)
	b.start = cap(b.data)
	b.data = newData
	return b.data[b.start:]
}

// []byte --> IP
func ParseIP(b []byte) IP {
	return IP(IP(b[0])<<24 + IP(b[1])<<16 + IP(b[2])<<8 + IP(b[3]))
}

//十进制转十六进制
func Dec2Hex(dec []byte) string {
	var sa = make([]string, 0)
	for _, v := range dec {
		sa = append(sa, fmt.Sprintf("%02X ", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

func Dec2Str(dec []byte) string {
	var sa string
	for _, v := range dec {
		sa = sa + string(v)
	}
	return sa
}

// 将 IP(uint32) 转换成 可读性IP字符串
func (ip IP) String() string {
	var bf bytes.Buffer
	for i := 1; i <= 4; i++ {
		bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			bf.WriteByte('.')
		}
	}
	return bf.String()
}

// 显示详细信息
func debug_show(format string, args ...interface{}) {
	if Debug {
		fmt.Printf(format, args...)
	}
}

// 出错
func error_show(e error, info string) error {
	if e != nil {
		fmt.Println(info, err)
	}
	return e
}

// 获取网卡
func setupNetInfo(f string) (iface_info iface) {
	var ifs []net.Interface
	var err error

	if f == "" {
		ifs, err = net.Interfaces()
	} else {
		// 已经选择iface
		var it *net.Interface
		it, err = net.InterfaceByName(f)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	error_show(err, "无法获取本地网络信息:")
	debug_show("发现以下网卡信息\n----------------------------------------------------------\n")
	for _, n := range ifs {
		debug_show("接口名称:%-20s最大传输单元:%-10d硬件地址:%s\n", n.Name, n.MTU, n.HardwareAddr.String())
	}
	debug_show("-----------------------------------------------------------\n")

	for _, it := range ifs {
		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					iface_info.ip = ip
					iface_info.addr = it.HardwareAddr
					iface_info.name = it.Name
					return
				}
			}
		}
	}
	return
}

// 根据IP和mask换算内网IP范围
func Table(ipNet *net.IPNet) []IP {
	ip := ipNet.IP.To4()
	debug_show("本机ip:%s\n", ip.String())
	var min, max IP
	var data []IP
	for i := 0; i < 4; i++ {
		b := IP(ip[i] & ipNet.Mask[i])
		min += b << ((3 - uint(i)) * 8)
	}
	one, _ := ipNet.Mask.Size()
	max = min | IP(math.Pow(2, float64(32-one))-1)
	debug_show("内网IP范围:%s --- %s\n", min, max)
	// max 是广播地址，忽略
	// i & 0x000000ff  == 0 是尾段为0的IP，根据RFC的规定，忽略
	for i := min; i < max; i++ {
		if i&0x000000ff == 0 {
			continue
		}
		data = append(data, i)
	}
	return data
}

// 发送arp包
// ip 目标IP地址
func sendArpPackage(iface_info iface, ip IP) {
	srcIp := net.ParseIP(iface_info.ip.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		fmt.Println("ip 解析出问题")
	}
	// 以太网首部
	// EthernetType 0x0806  ARP
	ether := &layers.Ethernet{
		SrcMAC:       iface_info.addr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress:   iface_info.addr,
		SourceProtAddress: srcIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface_info.name, 2048, false, 30*time.Second)
	error_show(err, "pcap打开失败:")
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	error_show(err, "发送arp数据包失败..")
}

// 发送arp包
func sendARP(iface_info iface) {
	// ips 是内网IP地址集合
	ips := Table(iface_info.ip)
	// 循环间隔时间发送几次
	for {
		fmt.Println("发送广播包...")
		for _, ip := range ips {
			go sendArpPackage(iface_info, ip) //发送arp包
		}
		if SendTime == 0 {
			break
		} else {
			time.Sleep(time.Duration(SendTime) * time.Minute)
		}
	}
}

func ListenARP(myiface iface) {
	var tip IpInfo

	// Open device
	handle, err = pcap.OpenLive(myiface.name, snapshot_len, promiscuous, timeout)
	error_show(err, "")
	defer handle.Close()

	// Set filter
	var filter string = "arp"
	err = handle.SetBPFFilter(filter)
	error_show(err, "")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
		if arp.Operation == 2 {
			tip.Mac = net.HardwareAddr(arp.SourceHwAddress)
			tip.IP = ParseIP(arp.SourceProtAddress).String()
			tip.Manuf = manuf.Search(tip.Mac.String())
			tip.Prot = "ARP"
			SaveLive(myiface, tip)
		}
	}

}

// mDNS协议侦听
func listenMDNS(myiface iface) {
	handle, err := pcap.OpenLive(myiface.name, 1024, false, 10*time.Second)
	error_show(err, "pcap打开失败:")
	defer handle.Close()
	handle.SetBPFFilter("udp and port 5353")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range ps.Packets() {
		var srcMAC net.HardwareAddr
		var srcIP string
		var tip IpInfo

		//获取MAC
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			srcMAC = ethernetPacket.SrcMAC
		}

		//获取IP
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
		}

		if len(packet.Layers()) == 4 {
			c := packet.Layers()[3].LayerContents()
			if c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01 { //如果是应答帧
				tip.Hostname = ParseMdns(c)
			}
		}

		if srcMAC.String() != "" && srcIP != "" {
			tip.Mac = srcMAC
			tip.IP = srcIP
			tip.Manuf = manuf.Search(srcMAC.String())
			tip.Prot = "mDNS"
			SaveLive(myiface, tip)
		}

	}
}

// 根据ip生成含mdns请求包，包存储在 buffer里
func nbns(buffer *Buffer) {
	rand.Seed(time.Now().UnixNano())
	tid := rand.Intn(0x7fff)
	b := buffer.PrependBytes(12)
	binary.BigEndian.PutUint16(b, uint16(tid))        // 0x0000 标识
	binary.BigEndian.PutUint16(b[2:], uint16(0x0010)) // 标识
	binary.BigEndian.PutUint16(b[4:], uint16(1))      // 问题数
	binary.BigEndian.PutUint16(b[6:], uint16(0))      // 资源数
	binary.BigEndian.PutUint16(b[8:], uint16(0))      // 授权资源记录数
	binary.BigEndian.PutUint16(b[10:], uint16(0))     // 额外资源记录数
	// 查询问题
	b = buffer.PrependBytes(1)
	b[0] = 0x20
	b = buffer.PrependBytes(32)
	copy(b, []byte{0x43, 0x4b})
	for i := 2; i < 32; i++ {
		b[i] = 0x41
	}

	b = buffer.PrependBytes(1)
	// terminator
	b[0] = 0
	// type 和 classIn
	b = buffer.PrependBytes(4)
	binary.BigEndian.PutUint16(b, uint16(33))
	binary.BigEndian.PutUint16(b[2:], 1)
}

func sendNbns(myiface iface, ip string, mhaddr net.HardwareAddr) {
	srcIp := net.ParseIP(myiface.ip.IP.String()).To4()
	dstIp := net.ParseIP(ip).To4()
	ether := &layers.Ethernet{
		SrcMAC:       myiface.addr,
		DstMAC:       mhaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(5),
		TTL:      uint8(255),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIp,
		DstIP:    dstIp,
	}
	bf := NewBuffer()
	nbns(bf)
	udpPayload := bf.data
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(61666),
		DstPort: layers.UDPPort(137),
	}
	udp.SetNetworkLayerForChecksum(ip4)
	udp.Payload = udpPayload
	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true, // 自动计算长度
		ComputeChecksums: true, // 自动计算checksum
	}
	err := gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
	if err != nil {
		fmt.Println("Serialize layers出现问题:", err)
	}
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(myiface.name, 1024, false, 10*time.Second)
	if err != nil {
		fmt.Println("pcap打开失败:", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("发送udp数据包失败..")
	}
}

func listenNBNS(myiface iface) {
	var tip IpInfo
	handle, err := pcap.OpenLive(myiface.name, 1024, false, 10*time.Second)
	error_show(err, "pcap打开失败:")
	defer handle.Close()
	handle.SetBPFFilter("udp and port 137 and dst host " + myiface.ip.IP.String())
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {
		if len(p.Layers()) == 4 {
			c := p.Layers()[3].LayerContents()
			if len(c) > 8 && c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01 {
				// 从网络层(ipv4)拿IP, 不考虑IPv6
				i := p.Layer(layers.LayerTypeIPv4)
				if i == nil {
					continue
				}
				ipv4 := i.(*layers.IPv4)
				tip.IP = ipv4.SrcIP.String()
				// 把 hostname 存入到数据库
				tip.Hostname = ParseNBNS(c)
				SaveLive(myiface, tip)
			}
		}
	}

}

func ParseNBNS(data []byte) string {
	var buf bytes.Buffer
	i := bytes.Index(data, []byte{0x20, 0x43, 0x4b, 0x41, 0x41})
	if i < 0 || len(data) < 32 {
		return ""
	}
	index := i + 1 + 0x20 + 12
	// data[index-1]是在 number of names 的索引上，如果number of names 为0，退出
	if data[index-1] == 0x00 {
		return ""
	}
	for t := index; ; t++ {
		// 0x20 和 0x00 是终止符
		if data[t] == 0x20 || data[t] == 0x00 {
			break
		}
		buf.WriteByte(data[t])
	}
	return buf.String()
}

// 参数data  开头是 dns的协议头 0x0000 0x8400 0x0000 0x0001(ans) 0x0000 0x0000
// 从 mdns响应报文中获取主机名
func ParseMdns(data []byte) string {
	i := bytes.Index(data, []byte{0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00}) //查询是否存在.local字符
	if i < 0 {
		return ""
	}

	return Dec2Str(data[13:i])

}

func bto16(b []byte) uint16 {
	if len(b) != 2 {
		fmt.Println("b只能是2个字节")
	}
	return uint16(b[0])<<8 + uint16(b[1])
}

// 反转字符串
func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

// 存在检测
func SaveLive(myiface iface, tip IpInfo) {
	for i, n := range LiveIp {
		if tip.IP == n.IP {
			if n.Hostname == "" && tip.Hostname != "" {
				LiveIp[i].Hostname = tip.Hostname
				fmt.Printf("更新存活设备%-3d个, %-6s %-17s [%-17s] %-40s %-20s %-20s\n",
					len(LiveIp), n.Prot, n.IP, n.Mac.String(), n.Manuf, tip.Hostname, tip.Live)
			}
			LiveIp[i].Live = time.Now().Format("2006-01-02 15:04:05") //更新时间
			return
		}
	}
	tip.Live = time.Now().Format("2006-01-02 15:04:05")
	LiveIp = append(LiveIp, tip)
	if tip.Hostname == "" { //请求名称
		sendNbns(myiface, tip.IP, tip.Mac)
	}
	fmt.Printf("发现存活设备%-3d个, %-6s %-17s [%-17s] %-40s %-20s %-20s\n", len(LiveIp), tip.Prot, tip.IP, tip.Mac.String(), tip.Manuf, tip.Hostname, tip.Live)
}

func LiveList() {
	fmt.Println("----------------------存活主机列表-------------------------")
	for i, n := range LiveIp {
		fmt.Printf("%-2d. %-6s %-17s [%-17s] %-40s %-20s %-20s\n", i+1, n.Prot, n.IP, n.Mac.String(), n.Manuf, n.Hostname, n.Live)
	}
	fmt.Println("---------------------------------------------------------")
}

func main() {
	var Iface_name string
	flag.StringVar(&Iface_name, "i", "", "指定网卡")
	flag.BoolVar(&Debug, "d", false, "显示调试信息")
	flag.IntVar(&SendTime, "t", 0, "ARP数据包发送间隔,0表示只发送一次")
	flag.Parse()

	//实现按ESC退出
	error_show(termbox.Init(), "")
	defer termbox.Close()

	myiface := setupNetInfo(Iface_name)

	if myiface.ip == nil || len(myiface.addr) == 0 {
		fmt.Println("无法获取本地网络信息")
		return
	}

	debug_show("获取本机IP:%s, MAC:%s\n", myiface.ip.String(), myiface.addr.String())

	go sendARP(myiface)    //发送ARP
	go listenNBNS(myiface) //侦听NBNS
	go ListenARP(myiface)  //侦听ARP
	go listenMDNS(myiface) //侦听mDNS

	fmt.Println("开始侦听，按Enter发送ARP包，按空格键显示主机列表，按ESC键退出。")

	for {
		ev := termbox.PollEvent()
		if ev.Type == termbox.EventKey {
			if ev.Key == termbox.KeyEsc {
				return
			} else if ev.Key == termbox.KeyEnter {
				go sendARP(myiface) //发送ARP
			} else if ev.Key == termbox.KeySpace {
				LiveList()
			}
		}
	}
}
