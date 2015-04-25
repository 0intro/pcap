// Copyright 2015 David du Colombier. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/0intro/pcap"
)

var verbose = flag.Bool("v", false, "verbose")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: pcapdump [ -v ] file.pcap\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	args := flag.Args()

	if flag.NArg() != 1 {
		usage()
	}

	f, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	pr, err := pcap.NewReader(f)
	if err != nil {
		log.Fatal(err)
	}

	if *verbose {
		fmt.Println("Header")
		fmt.Printf("Magic 0x%.8x\n", pr.Header.Magic)
		fmt.Println("VersionMajor", pr.Header.VersionMajor)
		fmt.Println("VersionMinor", pr.Header.VersionMinor)
		fmt.Println("ThisZone", pr.Header.ThisZone)
		fmt.Println("SigFigs", pr.Header.SigFigs)
		fmt.Println("SnapLen", pr.Header.SnapLen)
		fmt.Println("LinkType", pr.Header.LinkType)
	}

	for {
		record, err := pr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}

		if *verbose {
			fmt.Println()
			fmt.Println("RecordHeader")
			fmt.Println("TsSec", record.TsSec)
			fmt.Println("TsUsec", record.TsUsec)
			fmt.Println("CapLen", record.CapLen)
			fmt.Println("Len", record.Len)
		}

		buf, err := ioutil.ReadAll(pr)
		if err != nil {
			log.Fatal(err)
		}

		if *verbose {
			fmt.Println()
			fmt.Println("Payload")
			fmt.Println(buf)
		}
	}
}
