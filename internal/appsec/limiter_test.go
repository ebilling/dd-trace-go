// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

//go:build appsec
// +build appsec

package appsec

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLimiterUnit(t *testing.T) {
	l := &Limiter{}

	t.Run("consecutive-allow", func(t *testing.T) {
		l.SetRate(100)
		require.True(t, l.Allow(), "First call to limiter.Allow() should return True")
		require.False(t, l.Allow(), "Second call to limiter.Allow() should return False")
	})

	t.Run("10ms-sleep-gapped-allow", func(t *testing.T) {
		l.Reset()
		l.SetRate(100)
		require.True(t, l.Allow(), "First call to limiter.Allow() should return True")
		time.Sleep(10 * time.Millisecond)
		require.True(t, l.Allow(), "Second call to limiter.Allow() after 10ms should return True")
	})

	t.Run("9ms-sleep-gapped-allow", func(t *testing.T) {
		l.Reset()
		l.SetRate(100)
		require.True(t, l.Allow(), "First call to limiter.Allow() should return True")
		time.Sleep(9 * time.Millisecond)
		require.False(t, l.Allow(), "Second call to limiter.Allow() after 9ms should return False")
	})

	t.Run("no-limit", func(t *testing.T) {
		l.Reset()
		l.SetRate(-1)
		require.True(t, l.Allow(), "First call to limiter.Allow() should return True with no rate limit")
		require.True(t, l.Allow(), "Second call to limiter.Allow() should return True with no rate limit")
	})

	t.Run("1s-rate", func(t *testing.T) {
		l.Reset()
		l.SetRate(1)
		require.True(t, l.Allow(), "First call to limiter.Allow() should return True with 1s per token")
		require.False(t, l.Allow(), "Second call to limiter.Allow() should return False with 1s per Token")
	})

	t.Run("bypass", func(t *testing.T) {
		l.Reset()
		l.SetRate(0)
		require.False(t, l.Allow(), "limiter.Allow() should return False when bypassed")
		require.False(t, l.Allow(), "limiter.Allow() should return False when bypassed")
	})
}

func TestLimiter(t *testing.T) {
	//Limiter rate of 100 reqs/sec
	limiterRate := int64(100)

	//Tests the limiter's ability to sample the traces when subjected to a continuous flow of requests
	//Each goroutine will continuously call the WAF and the rate limiter for 1 second
	for nbUsers := 10; nbUsers <= 200; nbUsers += 10 {
		t.Run("continuous-requests", func(t *testing.T) {
			var startBarrier, stopBarrier sync.WaitGroup
			// Create a start barrier to synchronize every goroutine's launch and
			// increase the chances of parallel accesses
			startBarrier.Add(1)
			// Create a stopBarrier to signal when all user goroutines are done.
			stopBarrier.Add(nbUsers)
			skipped := int64(0)
			kept := int64(0)
			l := &Limiter{}
			l.SetRate(limiterRate)

			for n := 0; n < nbUsers; n++ {
				go func(l *Limiter, kept *int64, skipped *int64) {
					startBarrier.Wait()      // Sync the starts of the goroutines
					defer stopBarrier.Done() // Signal we are done when returning

					for tStart := time.Now(); time.Now().Sub(tStart) <= 1*time.Second; {
						if !l.Allow() {
							atomic.AddInt64(skipped, 1)
						} else {
							atomic.AddInt64(kept, 1)
						}
					}
				}(l, &kept, &skipped)
			}

			startBarrier.Done() // Unblock the user goroutines
			stopBarrier.Wait()  // Wait for the user goroutines to be done
			fmt.Println("Nb users: ", nbUsers)
			fmt.Println("Skipped: ", skipped)
			fmt.Println("Kept: ", kept)
		})
	}

	//Tests the limiter's ability to sample the traces when subjected sporadic bursts of requests.
	//With the current implementation, this is expected to showcase the limitations of the rate limiter which
	//cannot deal with bursts (i.e number of kept traces should be lower than expected)
	t.Run("requests-bursts", func(t *testing.T) {
		burstFreq := 100 * time.Millisecond
		burstSize := 10
		skipped := 0
		kept := 0
		reqCount := 0
		l := &Limiter{}
		l.SetRate(limiterRate)

		for tStart := time.Now(); time.Now().Sub(tStart) <= 1*time.Second; {
			for i := 0; i < burstSize; i++ {
				reqCount++
				//Let's not run the WAF if we already know the limiter will ask to discard the trace
				if !l.Allow() {
					skipped++
				} else {
					kept++
				}
			}
			//Sleep until next burst
			time.Sleep(burstFreq)
		}

		maxExpectedKept := reqCount / burstSize
		if maxExpectedKept > 100 {
			maxExpectedKept = 100
		}
		minExpectedSkipped := reqCount - maxExpectedKept

		require.LessOrEqual(t, kept, maxExpectedKept, "Expected at most %d kept requests", maxExpectedKept)
		require.GreaterOrEqual(t, skipped, minExpectedSkipped, "Expected at least%d skipped requests", minExpectedSkipped)
	})
}
