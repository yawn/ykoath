// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"os"
	"strings"
)

// Dump will dump a buffer into a format suitable for the inclusion in go
// tests (e.g. the send and res buffers from the send() function)
func Dump(buf []byte) {
	const lim = 12

	var chunk []byte

	chunks := make([][]byte, 0, len(buf)/lim+1)

	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}

	if len(buf) > 0 {
		chunks = append(chunks, buf)
	}

	for _, chunk := range chunks {
		var line []string

		for _, e := range chunk {
			line = append(line, fmt.Sprintf("0x%02x", e))
		}

		fmt.Fprintf(os.Stderr, "%s,\n", strings.Join(line, ", "))
	}
}
