// Copyright 2015 David du Colombier. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pcap_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/0intro/pcap"
)

type Ethernet struct {
	DstAddr [6]byte
	SrcAddr [6]byte
	Type    uint16
}

func Example() {
	// Create a buffer to write our pcap file to.
	buf := new(bytes.Buffer)

	// Create a new pcap file.
	pw := pcap.NewWriter(buf)
	defer func() {
		if err := pw.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	// Add some records to the pcap file.
	var records = []Ethernet{
		{
			DstAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xBA, 0xBE},
			SrcAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xCA, 0xFE},
			Type:    0x0800,
		},
		{
			DstAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xCA, 0xFE},
			SrcAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xBA, 0xBE},
			Type:    0x0800,
		},
		{
			DstAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xBE, 0xEF},
			SrcAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xDE, 0xAD},
			Type:    0x0800,
		},
		{
			DstAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xDE, 0xAD},
			SrcAddr: [6]byte{0x00, 0x50, 0x56, 0x00, 0xBE, 0xEF},
			Type:    0x0800,
		},
	}
	hdr := &pcap.Header{
		LinkType: pcap.LINKTYPE_ETHERNET,
	}
	if err := pw.WriteHeader(hdr); err != nil {
		log.Fatalln(err)
	}
	for i, record := range records {
		rhdr := &pcap.RecordHeader{
			TsSec:  uint32(i),
			TsUsec: 0,
			CapLen: uint32(14),
			Len:    uint32(14),
		}
		if err := pw.WriteRecordHeader(rhdr); err != nil {
			log.Fatalln(err)
		}
		if err := binary.Write(pw, binary.BigEndian, record); err != nil {
			log.Fatalln(err)
		}
	}
	// Make sure to check the error on Close.
	if err := pw.Close(); err != nil {
		log.Fatalln(err)
	}

	// Open the pcap file for reading.
	r := bytes.NewReader(buf.Bytes())
	pr, err := pcap.NewReader(r)
	if err != nil {
		log.Fatalln(err)
	}

	// Iterate through the files in the pcap file.
	for {
		hdr, err := pr.Next()
		if err == io.EOF {
			// end of pcap file
			break
		}
		if err != nil {
			log.Fatalln(err)
		}
		eth := &Ethernet{}
		if err = binary.Read(pr, binary.BigEndian, eth); err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%d.%.6d %d %x -> %x %x\n", hdr.TsSec, hdr.TsUsec, hdr.Len, eth.SrcAddr, eth.DstAddr, eth.Type)
	}

	// Output:
	// 0.000000 14 00505600cafe -> 00505600babe 800
	// 1.000000 14 00505600babe -> 00505600cafe 800
	// 2.000000 14 00505600dead -> 00505600beef 800
	// 3.000000 14 00505600beef -> 00505600dead 800
}
