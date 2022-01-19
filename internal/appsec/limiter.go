// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

//go:build appsec
// +build appsec

package appsec

import (
	"sync/atomic"
	"time"
)

//TODO: comments

//Simple limiter that allows a specific amount of tokens to be used per second
//If Limiter.SetRate is not called, the limiter defaults to bypass mode (0 token allowed)
type Limiter struct {
	lastUpdate int64
	nsPerToken int64
	bypass     int32 //used as boolean, int32 for atomic reasons
}

func (l *Limiter) Reset() {
	atomic.StoreInt64(&l.lastUpdate, 0)
}

func (l *Limiter) SetRate(tokenPerSec int64) {
	if tokenPerSec == 0 {
		atomic.StoreInt32(&l.bypass, 1)
	} else if tokenPerSec < 0 {
		atomic.StoreInt64(&l.nsPerToken, 0)
	} else {
		atomic.StoreInt64(&l.nsPerToken, time.Second.Nanoseconds()/tokenPerSec)
	}
}

//Allow() checks the time interval between the last Allow() call that returned true and the current call.
//If this time interval respects the limiter's rate, allow will return true.
//This is a very simplistic design and the algorithm is very bad at handling bursts of Allow() requests
//since the check is made on the delay between Allow() calls, not the number of Allow() calls (sliding window)
//The limiter should be redesigned in the future to better handle bursts. A good solution is using a token bucket
//algorithm. A first step could be trying to use/modify APM's existing implementation to fit our needs.
func (l *Limiter) Allow() bool {
	for atomic.LoadInt32(&l.bypass) == 0 {
		lastUpdate := atomic.LoadInt64(&l.lastUpdate)
		timeNow := int64(time.Now().UnixNano())

		if timeNow-lastUpdate < atomic.LoadInt64(&l.nsPerToken) {
			break
		}

		if atomic.CompareAndSwapInt64(&l.lastUpdate, lastUpdate, timeNow) {
			return true
		}
	}

	return false
}
