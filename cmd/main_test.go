/*
Copyright 2026.

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
package main

import (
	"strings"
	"testing"
	"time"
)

func TestResyncIntervalFromEnvironment(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		set     bool
		want    time.Duration
		wantErr bool
	}{
		{name: "shall use the default when unset", want: 10 * time.Minute},
		{name: "shall use a valid duration", value: "10s", set: true, want: 10 * time.Second},
		{name: "shall reject a value that is not a duration", value: "soon", set: true, wantErr: true},
		{name: "shall reject zero", value: "0s", set: true, wantErr: true},
		{name: "shall reject a negative duration", value: "-1m", set: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("RESYNC_INTERVAL", tc.value)
			}
			got, err := durationFromEnv("RESYNC_INTERVAL", 10*time.Minute)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "RESYNC_INTERVAL") {
					t.Fatalf("want an error naming RESYNC_INTERVAL, got %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
