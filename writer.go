// Copyright 2015 David du Colombier. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pcap

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrWriteTooLong    = errors.New("pcap: write too long")
	ErrWriteAfterClose = errors.New("pcap: write after close")
)

// A Writer provides sequential writing of a pcap file.
// A pcap file consists of a sequence of records.
// Call WriteRecordHeader to begin a new record, and then call Write to supply that record's data,
// writing at most hdr.Size bytes in total.
type Writer struct {
	w      io.Writer
	err    error
	nb     uint32 // number of unwritten bytes for current record
	closed bool
}

// NewWriter creates a new Writer writing to w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// WriteHeader writes hdr and prepares to accept the record's contents.
// Calling after a Close will return ErrWriteAfterClose.
func (pw *Writer) WriteHeader(hdr *Header) error {
	hdr.Magic = Magic
	hdr.VersionMajor = 2
	hdr.VersionMinor = 4
	if hdr.SnapLen == 0 {
		hdr.SnapLen = MaxSnapLen
	}
	return pw.writeHeader(hdr)
}

func (pw *Writer) writeHeader(hdr *Header) error {
	if pw.closed {
		return ErrWriteAfterClose
	}
	if pw.err != nil {
		return pw.err
	}
	err := binary.Write(pw.w, binary.LittleEndian, hdr)
	if err != nil {
		return err
	}
	return nil
}

// WriteRecordHeader writes hdr and prepares to accept the record's contents.
// Calling after a Close will return ErrWriteAfterClose.
func (pw *Writer) WriteRecordHeader(hdr *RecordHeader) error {
	if pw.closed {
		return ErrWriteAfterClose
	}
	if pw.err != nil {
		return pw.err
	}
	err := binary.Write(pw.w, binary.LittleEndian, hdr)
	if err != nil {
		return err
	}
	pw.nb = hdr.CapLen
	return nil
}

// Write writes to the current record in the pcap file.
// Write returns the error ErrWriteTooLong if more than
// hdr.CapLen bytes are written after WriteHeader.
func (pw *Writer) Write(b []byte) (n int, err error) {
	if pw.closed {
		err = ErrWriteAfterClose
		return
	}
	overwrite := false
	if uint32(len(b)) > pw.nb {
		b = b[0:pw.nb]
		overwrite = true
	}
	n, err = pw.w.Write(b)
	pw.nb -= uint32(n)
	if err == nil && overwrite {
		err = ErrWriteTooLong
		return
	}
	pw.err = err
	return
}

// Close closes the pcap file.
func (pw *Writer) Close() error {
	if pw.err != nil || pw.closed {
		return pw.err
	}
	pw.closed = true
	if pw.err != nil {
		return pw.err
	}

	return pw.err
}
