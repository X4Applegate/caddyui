// SPDX-License-Identifier: Apache-2.0

// labelsink is the observable upstream for the T-0713 precedence differential.
//
// WHY A LABELLED SINK RATHER THAN INFERENCE
// -----------------------------------------
// T-0713 asks which route handled a given set of first bytes. The first design
// inferred it from whether the connection succeeded, which cannot distinguish
// "route 2 matched" from "route 0 matched and its upstream was down" — two
// different answers that produce the same observation. So each route gets its
// own sink on its own port, and the sink announces WHICH route it is:
//
//	LANDED=<label> BYTES=<n> HEX=<first 32 bytes>
//
// The driver reads that line, so the landing route is observed directly. BYTES
// and HEX are there because the bytes that reach the upstream are themselves
// evidence: caddy-l4 replays the prefetched bytes to the handler, so a route
// that matched on a partial read still forwards everything it buffered. A
// landing with FEWER bytes than were sent would mean the wrapper dropped some,
// which is worth seeing even though it is not what this card is about.
//
// One sink process serves every label: -labels 22301=ssh,22302=postgres,...
// Running five processes was the first version and made a port-binding failure
// look like a routing result.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	labels := flag.String("labels", "", "comma-separated port=label pairs, e.g. 22301=ssh,22302=rdp")
	flag.Parse()

	if strings.TrimSpace(*labels) == "" {
		fmt.Fprintln(os.Stderr, "labelsink: -labels is required")
		os.Exit(2)
	}

	var wg sync.WaitGroup
	started := 0
	for _, pair := range strings.Split(*labels, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		port, label, ok := strings.Cut(pair, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "labelsink: bad pair %q, want port=label\n", pair)
			os.Exit(2)
		}
		addr := "127.0.0.1:" + strings.TrimSpace(port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// Exit rather than carry on: a sink that failed to bind would make
			// every connection to that route look like a routing decision
			// ("nothing answered") when it is a harness fault.
			fmt.Fprintf(os.Stderr, "labelsink: listen %s: %v\n", addr, err)
			os.Exit(2)
		}
		started++
		wg.Add(1)
		go func(ln net.Listener, label string) {
			defer wg.Done()
			serve(ln, strings.TrimSpace(label))
		}(ln, label)
	}
	fmt.Printf("labelsink: listening on %d ports\n", started)
	wg.Wait()
}

func serve(ln net.Listener, label string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))

			// One read is enough: caddy-l4 replays the whole prefetched buffer
			// in the first write to the upstream, so the first read carries the
			// client's first bytes. A short read is reported as what it is
			// rather than waited on, because a hanging sink would be scored as
			// "no route answered".
			buf := make([]byte, 4096)
			n, _ := c.Read(buf)

			show := n
			if show > 32 {
				show = 32
			}
			_, _ = fmt.Fprintf(c, "LANDED=%s BYTES=%d HEX=%s\n",
				label, n, hex.EncodeToString(buf[:show]))
		}(c)
	}
}
