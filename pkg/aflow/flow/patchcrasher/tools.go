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

type testReproResult struct {
	Status string `jsonschema:"Result status of the test (e.g. 'CrashFound', 'NoCrash', 'KernelBuildFailed')"`
	Output string `jsonschema:"Output of the execution, including filtered logs and crash report if found"`
}

func testRepro(ctx *aflow.Context, state testReproState, args testReproArgs) (testReproResult, error) {
	if state.KernelScratchSrc == "" {
		// Fallback to KernelSrc if Scratch isn't separate
		if state.KernelSrc != "" {
			state.KernelScratchSrc = state.KernelSrc
		} else {
			return testReproResult{}, aflow.BadCallError("KernelSrc/KernelScratchSrc is not initialized")
		}
	}

	// 1. Write the repro
	file := filepath.Join(state.KernelScratchSrc, "repro.c")
	if err := osutil.WriteFile(file, []byte(args.Code)); err != nil {
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

	reproduceArgs := crash.ReproduceArgs{
		Syzkaller:       state.Syzkaller,
		Image:           state.Image,
		Type:            state.Type,
		VM:              state.VM,
		ReproOpts:       state.ReproOpts,
		ReproSyz:        state.ReproSyz,
		ReproC:          args.Code,
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
		if strings.Contains(line, "PATCHCRASHER") {
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
			output = "No output with 'PATCHCRASHER' found and no crash log."
		}
	} else {
		if reportLog != "" {
			output += "\n\nCrash Log:\n" + reportLog
		}
	}

	// Write status to file for flow control
	statusFile := filepath.Join(state.KernelScratchSrc, "repro_status.txt")
	_ = osutil.WriteFile(statusFile, []byte(status))

	return testReproResult{
		Status: status,
		Output: output,
	}, nil
}
