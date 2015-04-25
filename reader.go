// Copyright 2015 David du Colombier. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

var (
	ErrBadMagic = errors.New("pcap: bad magic number")
)

// A Reader provides sequential access to the contents of a pcap file.
// A pcap file consists of a sequence of records.
// The Next method advances to the next record in the archive (including the first),
// and then it can be treated as an io.Reader to access the file's data.
type Reader struct {
	Header
	r         io.Reader
	err       error
	curr      numBytesReader // reader for current file record
	byteOrder binary.ByteOrder
}

// A numBytesReader is an io.Reader with a numBytes method, returning the number
// of bytes remaining in the underlying encoded data.
type numBytesReader interface {
	io.Reader
	numBytes() uint32
}

// A recordReader is a numBytesReader for reading record data from a pcap file.
type recordReader struct {
	r  io.Reader // underlying reader
	nb uint32    // number of unread bytes for current file record
}

// NewReader creates a new Reader reading from r.
func NewReader(r io.Reader) (*Reader, error) {
	pr := &Reader{r: r}
	hdr := pr.readHeader()
	if hdr == nil {
		return nil, pr.err
	}
	pr.Header = *hdr
	return pr, nil
}

// Next advances to the next record in the pcap file.
//
// io.EOF is returned at the end of the input.
func (pr *Reader) Next() (*RecordHeader, error) {
	if pr.err == nil {
		pr.skipUnread()
	}
	if pr.err != nil {
		return nil, pr.err
	}
	hdr := pr.readRecordHeader()
	if hdr == nil {
		return nil, pr.err
	}
	return hdr, pr.err
}

// skipUnread skips any unread bytes in the existing record.
func (pr *Reader) skipUnread() {
	nr := int64(pr.numBytes())
	pr.curr = nil
	if sr, ok := pr.r.(io.Seeker); ok {
		if _, err := sr.Seek(nr, os.SEEK_CUR); err == nil {
			return
		}
	}
	_, pr.err = io.CopyN(ioutil.Discard, pr.r, nr)
}

func (pr *Reader) parseMagic(magic []byte) (uint32, error) {
	m := binary.LittleEndian.Uint32(magic)
	pr.byteOrder = binary.LittleEndian
	if m != Magic {
		m := binary.BigEndian.Uint32(magic)
		pr.byteOrder = binary.BigEndian
		if m != Magic {
			return m, ErrBadMagic
		}
	}
	return m, nil
}

func (pr *Reader) readHeader() *Header {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(pr.r, header[:]); err != nil {
		return nil
	}
	_, pr.err = pr.parseMagic(header[:4])
	if pr.err != nil {
		return nil
	}
	r := bytes.NewReader(header[:])
	hdr := &Header{}
	if pr.err = binary.Read(r, pr.byteOrder, hdr); pr.err != nil {
		return nil
	}
	return hdr
}

func (pr *Reader) readRecordHeader() *RecordHeader {
	hdr := &RecordHeader{}
	if pr.err = binary.Read(pr.r, pr.byteOrder, hdr); pr.err != nil {
		return nil
	}
	pr.curr = &recordReader{r: pr.r, nb: hdr.CapLen}
	return hdr
}

// numBytes returns the number of bytes left to read in the current file's record
// in the pcap file, or 0 if there is no current file.
func (pr *Reader) numBytes() uint32 {
	if pr.curr == nil {
		// No current file, so no bytes
		return 0
	}
	return pr.curr.numBytes()
}

// Read reads from the current record in the pcap file.
// It returns 0, io.EOF when it reaches the end of that record,
// until Next is called to advance to the next record.
func (pr *Reader) Read(b []byte) (n int, err error) {
	if pr.curr == nil {
		return 0, io.EOF
	}
	n, err = pr.curr.Read(b)
	if err != nil && err != io.EOF {
		pr.err = err
	}
	return
}

func (rr *recordReader) numBytes() uint32 {
	return rr.nb
}

func (rr *recordReader) Read(b []byte) (n int, err error) {
	if rr.nb == 0 {
		// file consumed
		return 0, io.EOF
	}
	if uint32(len(b)) > rr.nb {
		b = b[0:rr.nb]
	}
	n, err = rr.r.Read(b)
	rr.nb -= uint32(n)

	if err == io.EOF && rr.nb > 0 {
		err = io.ErrUnexpectedEOF
	}
	return
}
