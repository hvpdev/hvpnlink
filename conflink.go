package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"

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
	Dns          string
}

type AppLinkData struct {
	Vid     uint32 `cbor:"1,keyasint"` // config id (VID)
	Type    uint8  `cbor:"2,keyasint"` // config type (0 == wireguard ver 0)
	CfgData []byte `cbor:"3,keyasint"` // config data as CBOR
	LocalIp uint32 `cbor:"4,keyasint"` // client local IP

	MinAppVer uint16 `cbor:"5,keyasint"` // Min compatible app version

	// can be ignored for now, use defaults
	DnsIp4    []uint32 `cbor:"10,keyasint,omitempty"` // IPv4 DNS: 1.1.1.1, 8.8.8.8
	Mtu       *uint16  `cbor:"11,keyasint,omitempty"` // MTU, default=1280
	Keepalive *uint8   `cbor:"12,keyasint,omitempty"` // 25
}

// Wireguard config
type WgConfigLinkData struct {
	PrivKey      [32]byte `cbor:"1,keyasint"` // wg private key
	ServerPubKey [32]byte `cbor:"2,keyasint"` // server public key
	ServerIp4    uint32   `cbor:"3,keyasint"`
	ServerPort   uint16   `cbor:"4,keyasint"`
	ObfType      uint8    `cbor:"5,keyasint"`

	// can be ignored for now
	ServerIp6 []byte `cbor:"6,keyasint,omitempty"`
}

type DecodedAppLinkData struct {
	AppLinkData
	WgConfigLinkData
}

func wgKeyTo32(k string) [32]byte {
	bytes, _ := base64.StdEncoding.DecodeString(k) // normal std encoding used in wg library
	var key [32]byte
	copy(key[:], bytes)
	return key
}

func MakeCfLinkV0Data(wc *WgClientConfig) []byte {
	ald := AppLinkData{
		Vid:       uint32(wc.Vid),
		Type:      0, // wireguard
		LocalIp:   StringToIp(wc.IpAddr),
		MinAppVer: 0,
	}
	wgd := WgConfigLinkData{
		PrivKey:      wgKeyTo32(wc.PrivKey),
		ServerPubKey: wgKeyTo32(wc.ServerPubKey),
		ServerIp4:    StringToIp(wc.ServerIp),
		ServerPort:   uint16(wc.ServerPort),
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

func StringToIp(ips string) uint32 { // returns 0 on error
	if ipn := net.ParseIP(ips); nil != ipn {
		return binary.BigEndian.Uint32(ipn.To4())
	}
	return 0
}
