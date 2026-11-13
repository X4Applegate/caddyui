// SPDX-License-Identifier: Apache-2.0

// sshsink is the upstream the layer4 SSH route proxies to. It echoes back the
// banner it received, so a connection can prove the bytes that reached the
// upstream are its OWN bytes — the matched-route side of the same
// cross-contamination check the TLS clients make on the hijacked side.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:22222", "listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshsink: listen %s: %v\n", *addr, err)
		os.Exit(1)
	}
	fmt.Printf("sshsink: listening on %s\n", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			buf := make([]byte, 512)
			n, err := c.Read(buf)
			if err != nil && n == 0 {
				return
			}
			// Echo verbatim. The driver asserts its own token is in the reply.
			_, _ = c.Write(append([]byte("SSHSINK:"), buf[:n]...))
		}(c)
	}
}
