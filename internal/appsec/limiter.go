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
