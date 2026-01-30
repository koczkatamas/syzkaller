// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patchcrasher

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/osutil"
)

var testReproTool = aflow.NewFuncTool("test_repro", testRepro, `
Compile the C reproducer code, build the kernel (if needed), run the reproducer in the VM, and return the execution result.
Ensure you include "PATCHCRASHER" in any printed output you want to see.
`)
var writeReproTool = testReproTool // Keeping the old name might be confusing, but I'll update the usage.

var testSyzReproTool = aflow.NewFuncTool("test_syz_repro", testSyzRepro, `
Run a Syzkaller program (syz-lang) in the VM and return the execution result.
Use this to verifying if a generated syz-lang program reproduces the crash.
The output will contain the execution logs which you should analyze to see if descriptions are missing or incorrect.
`)

type testReproState struct {
	Syzkaller        string
	Image            string
	Type             string
	VM               json.RawMessage
	ReproOpts        string
	ReproSyz         string
	SyzkallerCommit  string
	KernelScratchSrc string
	KernelConfig     string
	KernelCommit     string
	KernelSrc        string
}

type testReproArgs struct {
	Code string `jsonschema:"The C code of the reproducer."`
}

type testSyzReproArgs struct {
	SyzProg string `jsonschema:"The Syzkaller program code (syz-lang)."`
}

type testReproResult struct {
	Status string `jsonschema:"Result status of the test (e.g. 'CrashFound', 'NoCrash', 'KernelBuildFailed')"`
	Output string `jsonschema:"Output of the execution, including filtered logs and crash report if found"`
}

func testRepro(ctx *aflow.Context, state testReproState, args testReproArgs) (testReproResult, error) {
	return runReproInternal(ctx, state, args.Code, "", "repro.c")
}

func testSyzRepro(ctx *aflow.Context, state testReproState, args testSyzReproArgs) (testReproResult, error) {
	return runReproInternal(ctx, state, "", args.SyzProg, "repro.syz")
}

func runReproInternal(ctx *aflow.Context, state testReproState, reproC, reproSyz, fileName string) (testReproResult, error) {
	if state.KernelScratchSrc == "" {
		// Fallback to KernelSrc if Scratch isn't separate
		if state.KernelSrc != "" {
			state.KernelScratchSrc = state.KernelSrc
		} else {
			return testReproResult{}, aflow.BadCallError("KernelSrc/KernelScratchSrc is not initialized")
		}
	}

	// 1. Write the repro file (for debugging/artifacts)
	file := filepath.Join(ctx.Workdir, fileName)
	content := reproC
	if reproSyz != "" {
		content = reproSyz
	}
	if err := osutil.WriteFile(file, []byte(content)); err != nil {
		return testReproResult{}, err
	}

	// 2. Build the kernel
	// The kernel might have been modified by other tools (codeeditor), so we rebuild.
	if err := kernel.BuildKernel(state.KernelScratchSrc, state.KernelScratchSrc, state.KernelConfig, false); err != nil {
		return testReproResult{
			Status: "KernelBuildFailed",
			Output: fmt.Sprintf("Kernel build failed: %v", err),
		}, nil
	}

	workdir, err := ctx.TempDir()
	if err != nil {
		return testReproResult{}, err
	}

	reproOpts := state.ReproOpts
	if reproSyz != "" && reproOpts == "" {
		reproOpts = "{}"
	}

	reproduceArgs := crash.ReproduceArgs{
		Syzkaller:       state.Syzkaller,
		Image:           state.Image,
		Type:            state.Type,
		VM:              state.VM,
		ReproOpts:       reproOpts,
		ReproSyz:        reproSyz,
		ReproC:          reproC,
		SyzkallerCommit: state.SyzkallerCommit,
		KernelSrc:       state.KernelScratchSrc,
		KernelObj:       state.KernelScratchSrc,
		KernelCommit:    state.KernelCommit,
		KernelConfig:    state.KernelConfig,
	}

	// 3. Run Reproducer
	rep, reportLog, rawOutput, err := crash.ReproduceCrash(reproduceArgs, workdir)
	if err != nil {
		return testReproResult{}, err
	}

	// 4. Filter Output
	var filteredOutput []string
	lines := strings.Split(string(rawOutput), "\n")
	for _, line := range lines {
		// Include PATCHCRASHER logs and typical syz-executor output which might indicate missing descriptions
		if strings.Contains(line, "PATCHCRASHER") || strings.Contains(line, "syz-executor") || strings.Contains(line, "executor") {
			filteredOutput = append(filteredOutput, line)
		}
	}

	status := "NoCrash"
	if rep != nil {
		status = "CrashFound"
		// If crashed, maybe we want the report too?
		reportLog = string(rep.Report)
	}

	output := strings.Join(filteredOutput, "\n")
	if output == "" {
		output = reportLog
		if output == "" {
			output = "No output with 'PATCHCRASHER' or executor logs found and no crash log. Full output might be too large."
		}
	} else {
		if reportLog != "" {
			output += "\n\nCrash Log:\n" + reportLog
		}
	}

	// Write status to file for flow control
	statusFile := filepath.Join(ctx.Workdir, "repro_status.txt")
	_ = osutil.WriteFile(statusFile, []byte(status))

	return testReproResult{
		Status: status,
		Output: output,
	}, nil
}
