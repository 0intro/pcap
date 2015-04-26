// Copyright 2015 David du Colombier. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/0intro/pcap"
)

const (
	maxSnapLen   = 65536
)

var verbose = flag.Bool("v", false, "verbose")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: pcaplive file.pcap\n")
	os.Exit(1)
}

func htons(n int) int {
	return int(uint16(byte(n))<<8 | uint16(byte(n>>8)))
}

func main() {
	flag.Parse()
	args := flag.Args()

	if flag.NArg() != 1 {
		usage()
	}

	f, err := os.Create(args[0])
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	pw := pcap.NewWriter(f)
	defer func() {
		if err := pw.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	hdr := &pcap.Header{
		SnapLen:  maxSnapLen,
		LinkType: pcap.LINKTYPE_ETHERNET,
	}
	if err := pw.WriteHeader(hdr); err != nil {
		log.Fatal(err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(syscall.ETH_P_ALL))
	if err != nil {
		log.Fatal(err)
	}

	var buf [maxSnapLen]byte
	for {
		n, _, err := syscall.Recvfrom(fd, buf[:], 0)
		if err != nil {
			log.Fatal(err)
		}
		record := &pcap.RecordHeader{TsSec: 0, TsUsec: 0, CapLen: uint32(n), Len: uint32(n)}
		if err := pw.WriteRecordHeader(record); err != nil {
			log.Fatal(err)
		}
		if _, err = pw.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
	}
}
