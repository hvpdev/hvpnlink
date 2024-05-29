package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const CFLINK_V0_TAG = uint8(0)
const CFLINK_V0_PREFIX = "https://hvpn.io/"

type WgClientConfig struct {
	Vid          uint32
	IpAddr       string
	PrivKey      string
	ServerPubKey string
	ServerIp     string
	ServerPort   uint
	Dns          []string
	PresharedKey string // Add PresharedKey field
}

type AppLinkData struct {
	Vid       uint32   `cbor:"1,keyasint"`            // config id (VID)
	Type      uint8    `cbor:"2,keyasint"`            // config type (0 == wireguard ver 0)
	CfgData   []byte   `cbor:"3,keyasint"`            // config data as CBOR
	LocalIp   uint32   `cbor:"4,keyasint"`            // client local IP
	MinAppVer uint16   `cbor:"5,keyasint"`            // Min compatible app version
	DnsIp4    []uint32 `cbor:"10,keyasint,omitempty"` // IPv4 DNS: 1.1.1.1, 8.8.8.8
	Mtu       *uint16  `cbor:"11,keyasint,omitempty"` // MTU, default=1280
	Keepalive *uint8   `cbor:"12,keyasint,omitempty"` // 25
}

type WgConfigLinkData struct {
	PrivKey      [32]byte `cbor:"1,keyasint"` // wg private key
	ServerPubKey [32]byte `cbor:"2,keyasint"` // server public key
	ServerIp4    uint32   `cbor:"3,keyasint"`
	ServerPort   uint16   `cbor:"4,keyasint"`
	ObfType      uint8    `cbor:"5,keyasint"`
	ServerIp6    []byte   `cbor:"6,keyasint,omitempty"`
	PresharedKey [32]byte `cbor:"7,keyasint,omitempty"`
}

func wgKeyTo32(k string) [32]byte {
	bytes, _ := base64.StdEncoding.DecodeString(k) // normal std encoding used in wg library
	var key [32]byte
	copy(key[:], bytes)
	return key
}

func standardizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func MakeCfLinkV0Data(wc *WgClientConfig) []byte {
	ald := AppLinkData{
		Vid:       uint32(wc.Vid),
		Type:      0,
		LocalIp:   StringToIp(wc.IpAddr),
		MinAppVer: 0,
	}

	for _, dns := range wc.Dns {
		ald.DnsIp4 = append(ald.DnsIp4, StringToIp(dns))
	}

	wgd := WgConfigLinkData{
		PrivKey:      wgKeyTo32(wc.PrivKey),
		ServerPubKey: wgKeyTo32(wc.ServerPubKey),
		ServerIp4:    StringToIp(wc.ServerIp),
		ServerPort:   uint16(wc.ServerPort),
		PresharedKey: wgKeyTo32(wc.PresharedKey),
	}
	wgd_data_bytes, _ := cbor.Marshal(&wgd)
	ald.CfgData = wgd_data_bytes
	link_data_bytes, _ := cbor.Marshal(&ald)
	hash := sha256.New()
	hash.Write([]byte{CFLINK_V0_TAG})
	hash.Write(link_data_bytes)
	link_bytes := make([]byte, 0, len(link_data_bytes)+9)
	link_bytes = append(link_bytes, CFLINK_V0_TAG)
	link_bytes = append(link_bytes, hash.Sum(nil)[0:8]...)
	link_bytes = append(link_bytes, link_data_bytes...)
	return link_bytes
}

func MakeCfLinkV0(wcc *WgClientConfig) string {
	return CFLINK_V0_PREFIX + base64.RawURLEncoding.EncodeToString(MakeCfLinkV0Data(wcc))
}

func StringToIp(ips string) uint32 {
	if ipn := net.ParseIP(ips); nil != ipn {
		return binary.BigEndian.Uint32(ipn.To4())
	}
	return 0
}

func parseWgConfig(filePath string) (map[string]string, error) {
	// Read the file content
	configData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Handle the case where the configuration file is empty
	if len(configData) == 0 {
		return nil, fmt.Errorf("configuration file is empty")
	}

	configLines := strings.Split(string(configData), "\n")
	configMap := make(map[string]string)

	// Parse each line into key-value pairs
	for _, line := range configLines {
		// Trim space to ignore empty lines and lines with only whitespace
		line = standardizeSpaces(line)
		line = strings.TrimSpace(line)
		//fmt.Println(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "[Peer]" || line == "[Interface]" {
			continue // Skip empty lines, comments, and section headers
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid configuration line: '%s'", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Ensure that the key is expected and not duplicated
		if _, exists := configMap[key]; exists {
			return nil, fmt.Errorf("duplicate key found: '%s'", key)
		}

		configMap[key] = value
	}

	// Check if necessary keys are present
	requiredKeys := []string{"PrivateKey", "Address", "PublicKey", "Endpoint"}
	for _, key := range requiredKeys {
		if _, ok := configMap[key]; !ok {
			return nil, fmt.Errorf("missing required configuration key: '%s'", key)
		}
	}

	return configMap, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide the path to the WireGuard configuration file")
		return
	}
	filePath := os.Args[1]
	configMap, err := parseWgConfig(filePath)
	if err != nil {
		fmt.Println("Please provide a correct WireGuard configuration file.")
		fmt.Println(err)
		return
	}

	wc := WgClientConfig{}

	for key, value := range configMap {
		switch key {
		case "PrivateKey":
			wc.PrivKey = value
		case "Address":
			wc.IpAddr = strings.Split(value, "/")[0]
		case "PublicKey":
			wc.ServerPubKey = value
		case "Endpoint":
			endpoint := strings.Split(value, ":")
			host := endpoint[0]
			port, err := strconv.Atoi(endpoint[1])
			if err != nil {
				fmt.Println("Error converting port:", err)
				return
			}
			wc.ServerPort = uint(port)

			// Resolve the hostname to an IP address
			ipAddrs, err := net.LookupHost(host)
			if err != nil {
				fmt.Println("Error resolving hostname to IP:", err)
				return
			}
			// Use the first resolved IP address
			wc.ServerIp = ipAddrs[0]
		case "DNS":
			wc.Dns = strings.Split(value, ",")
		case "PresharedKey":
			wc.PresharedKey = value
		}
	}

	link := MakeCfLinkV0(&wc)
	fmt.Println(link)
}
