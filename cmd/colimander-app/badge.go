//go:build desktop && darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// setDockBadge shows label on the Dock icon, or clears it when label is empty.
static void setDockBadge(const char *label) {
	NSString *s = (label && label[0]) ? [NSString stringWithUTF8String:label] : nil;
	dispatch_async(dispatch_get_main_queue(), ^{
		[[NSApp dockTile] setBadgeLabel:s];
	});
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
	"unsafe"
)

// watchApprovals keeps the Dock badge at the number of database writes waiting
// for approval, so a paused agent is visible even when the window is hidden.
// It long-polls the database proxy, which answers as soon as the count
// changes, so the badge updates at once without repeated checks.
func watchApprovals(ctx context.Context, socket string) {
	client := &http.Client{
		Timeout: 40 * time.Second, // above the server's 25-second hold
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	var version uint64
	shown := -1
	backoff := time.Second
	for ctx.Err() == nil {
		v, n, err := watchOnce(ctx, client, version)
		if err != nil {
			// The proxy is down or restarting. Nothing can wait for approval
			// meanwhile, so clear the badge and retry, more slowly each time.
			n, version = 0, 0
			if shown != 0 {
				setBadge(0)
				shown = 0
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
		} else {
			version, backoff = v, time.Second
		}
		if n != shown {
			setBadge(n)
			shown = n
		}
	}
}

func setBadge(n int) {
	label := ""
	if n > 0 {
		label = strconv.Itoa(n)
	}
	cs := C.CString(label)
	C.setDockBadge(cs)
	C.free(unsafe.Pointer(cs))
}

func watchOnce(ctx context.Context, client *http.Client, after uint64) (uint64, int, error) {
	url := "http://db/api/approvals/watch?after=" + strconv.FormatUint(after, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	var got struct {
		Version uint64 `json:"version"`
		Pending int    `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return 0, 0, err
	}
	return got.Version, got.Pending, nil
}
