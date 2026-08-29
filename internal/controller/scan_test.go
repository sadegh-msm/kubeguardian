/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"testing"
	"time"
)

func TestRequeueAfterIsOffWhenTheIntervalIsNotSet(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Minute} {
		scanner := Scanner{RescanInterval: interval}
		if got := scanner.requeueAfter(); got != 0 {
			t.Errorf("RescanInterval %s: got %s, want no periodic requeue", interval, got)
		}
	}
}

func TestRequeueAfterStaysWithinTenPercentOfTheInterval(t *testing.T) {
	scanner := Scanner{RescanInterval: 3 * time.Hour}

	for range 200 {
		got := scanner.requeueAfter()
		if got < 2*time.Hour+42*time.Minute || got >= 3*time.Hour+18*time.Minute {
			t.Fatalf("got %s, want it within 10%% of 3h", got)
		}
	}
}

func TestNextRequeueUsesTheExpiryDeadlineWhenItComesFirst(t *testing.T) {
	soon := time.Now().Add(90 * time.Second)

	cases := []struct {
		name     string
		interval time.Duration
		deadline *time.Time
		want     func(time.Duration) bool
	}{
		{
			name:     "no periodic rescan and no expiry means never come back",
			interval: 0,
			deadline: nil,
			want:     func(d time.Duration) bool { return d == 0 },
		},
		{
			name:     "an expiry is a reason to come back even with no periodic rescan",
			interval: 0,
			deadline: &soon,
			want:     func(d time.Duration) bool { return d > time.Minute && d < 2*time.Minute },
		},
		{
			name:     "the nearer expiry wins over a distant rescan",
			interval: 3 * time.Hour,
			deadline: &soon,
			want:     func(d time.Duration) bool { return d > time.Minute && d < 2*time.Minute },
		},
		{
			name:     "a distant expiry does not delay the periodic rescan",
			interval: time.Minute,
			deadline: ptrTime(time.Now().Add(3 * time.Hour)),
			want:     func(d time.Duration) bool { return d < 2*time.Minute },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := Scanner{RescanInterval: tc.interval}
			if got := scanner.nextRequeue(tc.deadline); !tc.want(got) {
				t.Errorf("got %s", got)
			}
		})
	}
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
