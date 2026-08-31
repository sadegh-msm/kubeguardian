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

package policy

import (
	"sync"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

// Registry caches compiled checks by name and generation. Compiling is far more
// expensive than evaluating, so doing it once per edit rather than once per scan
// is what keeps a scan comparable in cost to the Go checks this replaced.
//
// Failures are cached too. A check with a syntax error would otherwise be
// recompiled on every scan of every namespace, only to fail the same way.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]entry
}

type entry struct {
	generation int64
	compiled   *Compiled
	err        error
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]entry)}
}

// Get returns the compiled form of a check, compiling it if this is the first
// time or if the spec has changed since last time.
func (r *Registry) Get(check *securityv1alpha1.SecurityCheck) (*Compiled, error) {
	r.mu.RLock()
	cached, ok := r.entries[check.Name]
	r.mu.RUnlock()

	if ok && cached.generation == check.Generation {
		return cached.compiled, cached.err
	}

	compiled, err := Compile(check.Spec)

	r.mu.Lock()
	r.entries[check.Name] = entry{generation: check.Generation, compiled: compiled, err: err}
	r.mu.Unlock()

	return compiled, err
}

// Forget drops a check that no longer exists, so a registry does not grow for the
// lifetime of the process.
func (r *Registry) Forget(name string) {
	r.mu.Lock()
	delete(r.entries, name)
	r.mu.Unlock()
}
