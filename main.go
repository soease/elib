package elib

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net/http"
)

// PingCheck(ip string, num int) bool     ping网址，返回是否通讯正常, num ping几次
// GetOSName() string                     获取操作系统名
// Config_json(name string) string        获取与程序同名的json配置文件 Config_json("abc.defg")

// 获取操作系统名
func GetOSName() string {
	return strings.ToUpper(runtime.GOOS)
}

//ping网址，返回是否通讯正常
func PingCheck(ip string, num int) bool {
	ping, err := Run(ip, 8, Data)
	if err != nil {
		return false
	}
	defer ping.Close()
	return ping.Ping(num)
}

//读取json配置文件
func Config_json(name string) string {
	var conf_filename string
	filename := path.Base(os.Args[0])
	conf_filename = strings.TrimSuffix(filename, path.Ext(filename)) + ".json" //配置文件名与程序同名，扩展名为json
	dat, err := ioutil.ReadFile(conf_filename)
	if err == nil {
		return gjson.Get(string(dat), name).String()
	} else {
		return ""
	}
}

//远程运行命令，返回运行结果
func SSH_Cmd(ssh SSHInfo, cmd string) (string, error) {
	client, _ := ssh_dial(ssh.User, ssh.Pass, ssh.Ip, ssh.Port)
	return ssh_cmd(client, cmd)
}

//获取网址内容
func HttpGet(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

//过滤控制符
func FilterControlChar(str string) string {
	str = strings.Replace(str, "\n", "", -1)
	str = strings.Replace(str, "\t", "", -1)
	str = strings.Replace(str, "\r", "", -1)
	return str
}

// 以下为内部调用 -----------------------------------------------------------------------------------

// ping ---------------------------------------------
type ping struct {
	Addr string
	Conn net.Conn
	Data []byte
}

var Data = []byte("abcdefghijklmnopqrstuvwabcdefghi")

type Reply struct {
	Time  int64
	TTL   uint8
	Error error
}

func Lookup(host string) (string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	if len(addrs) < 1 {
		return "", errors.New("unknown host")
	}
	rd := rand.New(rand.NewSource(time.Now().UnixNano()))
	return addrs[rd.Intn(len(addrs))], nil
}

func MarshalMsg(req int, data []byte) ([]byte, error) {
	xid, xseq := os.Getpid()&0xffff, req
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: xid, Seq: xseq,
			Data: data,
		},
	}
	return wm.Marshal(nil)
}

func (self *ping) Dail() (err error) {
	self.Conn, err = net.Dial("ip4:icmp", self.Addr)
	if err != nil {
		return err
	}
	return nil
}

func (self *ping) SetDeadline(timeout int) error {
	return self.Conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
}

func (self *ping) Close() error {
	return self.Conn.Close()
}

func (self *ping) Ping(count int) bool {
	var num int
	if err := self.Dail(); err != nil {
		fmt.Println("Not found remote host")
		return false
	}
	//fmt.Println("Start ping from ", self.Conn.LocalAddr())

	self.SetDeadline(10)
	for i := 0; i < count; i++ {
		r := sendPingMsg(self.Conn, self.Data)
		if r.Error != nil {
			if opt, ok := r.Error.(*net.OpError); ok && opt.Timeout() {
				//fmt.Printf("From %s reply: TimeOut\n", self.Addr)
				if err := self.Dail(); err != nil {
					//fmt.Println("Not found remote host")
				}
			} else {
				//fmt.Printf("From %s reply: %s\n", self.Addr, r.Error)
			}
		} else {
			//fmt.Printf("From %s reply: time=%d ttl=%d\n", self.Addr, r.Time, r.TTL)
			num++
		}
		//time.Sleep(time.Second * 1)
	}
	return num > count/3
}

func (self *ping) PingCount(count int) (reply []Reply) {
	if err := self.Dail(); err != nil {
		fmt.Println("Not found remote host")
		return
	}
	self.SetDeadline(10)
	for i := 0; i < count; i++ {
		r := sendPingMsg(self.Conn, self.Data)
		reply = append(reply, r)
		time.Sleep(1e9)
	}
	return
}

func Run(addr string, req int, data []byte) (*ping, error) {
	wb, err := MarshalMsg(req, data)
	if err != nil {
		return nil, err
	}
	addr, err = Lookup(addr)

	if err != nil {
		return nil, err
	}
	return &ping{Data: wb, Addr: addr}, nil
}

func sendPingMsg(c net.Conn, wb []byte) (reply Reply) {
	start := time.Now()

	if _, reply.Error = c.Write(wb); reply.Error != nil {
		return
	}

	rb := make([]byte, 1500)
	var n int
	n, reply.Error = c.Read(rb)
	if reply.Error != nil {
		return
	}

	duration := time.Now().Sub(start)
	ttl := uint8(rb[8])
	rb = func(b []byte) []byte {
		if len(b) < 20 {
			return b
		}
		hdrlen := int(b[0]&0x0f) << 2
		return b[hdrlen:]
	}(rb)
	var rm *icmp.Message
	rm, reply.Error = icmp.ParseMessage(1, rb[:n])
	if reply.Error != nil {
		return
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		t := int64(duration / time.Millisecond)
		reply = Reply{t, ttl, nil}
	case ipv4.ICMPTypeDestinationUnreachable:
		reply.Error = errors.New("Destination Unreachable")
	default:
		reply.Error = fmt.Errorf("Not ICMPTypeEchoReply %v", rm)
	}
	return
}

// ping ---------------------------------------------

// SSH ----------------------------------------------

type SSHInfo struct {
	Ip   string
	User string
	Pass string
	Port int
}

// ssh连接
func ssh_dial(user string, password string, ip string, port int) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	return client, err
}

// ssh命令
func ssh_cmd(client *ssh.Client, cmd string) (string, error) {
	var b bytes.Buffer
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
		return "", err
	}

	session.Stdout = &b
	if err := session.Run(cmd); err != nil {
		log.Fatal("Failed to run: " + err.Error())
		return "", err
	}
	defer session.Close()
	return b.String(), nil
}

// 文件传送
func scp(client *ssh.Client, File io.Reader, size int64, path string) {
	filename := filepath.Base(path)
	dirname := strings.Replace(filepath.Dir(path), "\\", "/", -1)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
		return
	}

	go func() {
		w, _ := session.StdinPipe()
		fmt.Fprintln(w, "C0644", size, filename)
		io.CopyN(w, File, size)
		fmt.Fprint(w, "\x00")
		w.Close()
	}()

	if err := session.Run(fmt.Sprintf("/usr/bin/scp -qrt %s", dirname)); err != nil {
		log.Fatal("Failed to run scp: ", err)
		return
	} else {
		log.Fatal(client.RemoteAddr())
		session.Close()
	}
}

// SSH ----------------------------------------------
