// Copyright 2015 David du Colombier. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pcap implements access to pcap files.
//
// References:
//   http://www.tcpdump.org/
//   https://wiki.wireshark.org/Development/LibpcapFileFormat
package pcap

// A Header represents the global header in a pcap file.
type Header struct {
	Magic        uint32 // Magic number.
	VersionMajor uint16 // Major version number.
	VersionMinor uint16 // Minor version number.
	ThisZone     int32  // GMT to local correction.
	SigFigs      uint32 // Accuracy of timestamps.
	SnapLen      uint32 // Max length of captured packets.
	LinkType     uint32 // Data link type.
}

// A RecordHeader represents a record header in a pcap file.
type RecordHeader struct {
	TsSec  uint32 // Timestamp seconds.
	TsUsec uint32 // Timestamp microseconds.
	CapLen uint32 // Length of packet saved in file.
	Len    uint32 // Actual length of packet.
}
