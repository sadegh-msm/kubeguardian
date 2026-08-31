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
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"

	securityv1alpha1 "github.com/sadegh-msm/kubeguardian/api/v1alpha1"
)

// Compiled is a SecurityCheck whose expressions have been type checked and turned
// into programs. Compiling is the expensive part, so it happens once per
// generation rather than once per scan.
type Compiled struct {
	Spec securityv1alpha1.SecurityCheckSpec

	bindings    []binding
	violation   cel.Program
	message     template
	suggestion  template
	remediation template
}

type binding struct {
	name    string
	program cel.Program
}

// segment is one piece of an interpolated string: either literal text or a
// program whose result is converted to a string.
type segment struct {
	literal string
	program cel.Program
}

type template []segment

// Compile type checks every expression in a check against the variables its scope
// provides. A check that does not compile produces no findings, and the error is
// what the SecurityCheck's Ready condition reports.
func Compile(spec securityv1alpha1.SecurityCheckSpec) (*Compiled, error) {
	env, err := newEnv(spec.Scope)
	if err != nil {
		return nil, err
	}

	compiled := &Compiled{Spec: spec}

	// Bindings extend the environment for everything after them, and they are
	// declared in a map, so the order has to be made deterministic or a check
	// would compile differently between restarts.
	for _, name := range slices.Sorted(maps.Keys(spec.Bindings)) {
		program, outputType, err := compileExpression(env, spec.Bindings[name])
		if err != nil {
			return nil, fmt.Errorf("binding %q: %w", name, err)
		}
		compiled.bindings = append(compiled.bindings, binding{name: name, program: program})

		env, err = env.Extend(cel.Variable(name, outputType))
		if err != nil {
			return nil, fmt.Errorf("binding %q: %w", name, err)
		}
	}

	violation, outputType, err := compileExpression(env, spec.Violation)
	if err != nil {
		return nil, fmt.Errorf("violation: %w", err)
	}
	if outputType != cel.BoolType {
		return nil, fmt.Errorf("violation: must evaluate to a bool, got %s", outputType)
	}
	compiled.violation = violation

	for _, field := range []struct {
		name   string
		source string
		into   *template
	}{
		{"message", spec.Message, &compiled.message},
		{"suggestion", spec.Suggestion, &compiled.suggestion},
		{"remediation", spec.Remediation, &compiled.remediation},
	} {
		parsed, err := compileTemplate(env, field.source)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field.name, err)
		}
		*field.into = parsed
	}

	return compiled, nil
}

func compileExpression(env *cel.Env, source string) (cel.Program, *cel.Type, error) {
	ast, issues := env.Compile(source)
	if issues != nil && issues.Err() != nil {
		return nil, nil, issues.Err()
	}

	program, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, nil, err
	}
	return program, ast.OutputType(), nil
}

// compileTemplate splits a string on ${...} and compiles what is inside. Keeping
// the literal text literal is what lets a remediation stay a readable YAML block
// rather than a string concatenation.
func compileTemplate(env *cel.Env, source string) (template, error) {
	var parsed template

	for {
		start := strings.Index(source, "${")
		if start == -1 {
			break
		}
		end := strings.Index(source[start:], "}")
		if end == -1 {
			return nil, fmt.Errorf("unterminated ${ at offset %d", start)
		}
		end += start

		if start > 0 {
			parsed = append(parsed, segment{literal: source[:start]})
		}

		program, _, err := compileExpression(env, source[start+2:end])
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, segment{program: program})

		source = source[end+1:]
	}

	if source != "" {
		parsed = append(parsed, segment{literal: source})
	}
	return parsed, nil
}
