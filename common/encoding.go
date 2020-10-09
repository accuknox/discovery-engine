package common

import (
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

var nativeEndian binary.ByteOrder

// init Function
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb

	if b == 0x04 {
		nativeEndian = binary.LittleEndian
	} else {
		nativeEndian = binary.BigEndian
	}
}

// Htons Function
func Htons(a uint16) uint16 {
	var arr [2]byte
	binary.BigEndian.PutUint16(arr[:], a)
	return nativeEndian.Uint16(arr[:])
}

// Htonl Function
func Htonl(a uint32) uint32 {
	var arr [4]byte
	binary.BigEndian.PutUint32(arr[:], a)
	return nativeEndian.Uint32(arr[:])
}

// IP2int Function
func IP2int(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	ip = ip.To4()
	return nativeEndian.Uint32(ip)
}

// Int2IP Function
func Int2IP(ipLong uint32) string {
	ipByte := make([]byte, 4)

	nativeEndian.PutUint32(ipByte, ipLong)

	ip := net.IP(ipByte)
	return ip.String()
}

// Mac2long Function
func Mac2long(macStr string) uint64 {
	// aa:bb:cc:dd:ee:ff --> 0000aabbccddeeff
	mac := strings.ReplaceAll(macStr, ":", "")
	mac = "0000" + mac
	val, _ := strconv.ParseUint(mac, 16, 64)
	return val
}

// Long2mac Function
func Long2mac(macLong uint64) string {
	// 0000aabbccddeeff --> aa:bb:cc:dd:ee:ff
	b := make([]byte, 8)

	binary.BigEndian.PutUint64(b, uint64(macLong))
	str := hex.EncodeToString(b)
	str = str[4:]

	macStr := ""
	for i, c := range strings.Split(str, "") {
		if i != 0 && i%2 == 0 {
			macStr = macStr + ":"
		}
		macStr = macStr + c
	}

	return macStr
}

// I64tob Function
func I64tob(val uint64) []byte {
	r := make([]byte, 8)
	for i := uint64(0); i < 8; i++ {
		r[i] = byte((val >> (i * 8)) & 0xff)
	}
	return r
}

// Btoi64 Function
func Btoi64(val []byte) uint64 {
	r := uint64(0)
	for i := uint64(0); i < 8; i++ {
		r |= uint64(val[i]) << (8 * i)
	}
	return r
}

// I32tob Function
func I32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

// Btoi32 Function
func Btoi32(val []byte) uint32 {
	r := uint32(0)
	for i := uint32(0); i < 4; i++ {
		r |= uint32(val[i]) << (8 * i)
	}
	return r
}

// Int8ToStr Function
func Int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

// Sum32 represents Jenkins's one_at_a_time hash
type Sum32 uint32

// New32 returns a new 32-bit Jenkins's one_at_a_time hash
func New32() hash.Hash32 {
	var s Sum32
	return &s
}

// Reset resets the hash to its initial state
func (s *Sum32) Reset() { *s = 0 }

// Sum32 returns the hash value
func (s *Sum32) Sum32() uint32 {
	hash := *s

	hash += (hash << 3)
	hash ^= hash >> 11
	hash += hash << 15

	return uint32(hash)
}

// Write adds more data to the running hash
func (s *Sum32) Write(data []byte) (int, error) {
	hash := *s
	for _, b := range data {
		hash += Sum32(b)
		hash += hash << 10
		hash ^= hash >> 6
	}
	*s = hash
	return len(data), nil
}

// Size returns the number of bytes Sum will return
func (s *Sum32) Size() int { return 4 }

// BlockSize returns the hash's underlying block size
func (s *Sum32) BlockSize() int { return 1 }

// Sum appends the current hash to in and returns the resulting slice
func (s *Sum32) Sum(in []byte) []byte {
	v := s.Sum32()
	return append(in, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
