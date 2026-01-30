// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patchcrasher

import (
	"encoding/json"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/tool/codeeditor"
	"github.com/google/syzkaller/pkg/aflow/tool/codeexpert"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type Inputs struct {
	PatchCommit string `json:"patch_commit"`

	// Standard syzkaller inputs
	Syzkaller         string
	CodesearchToolBin string
	Image             string
	Type              string
	VM                json.RawMessage
	KernelConfig      string
	SyzkallerCommit   string
	ReproOpts         string
	ReproSyz          string
}

type Outputs struct {
	CRepro string
}

func createFlow(name string, summaryWindow int) *aflow.Flow {

	return &aflow.Flow{
		Name: name,
		Root: aflow.Pipeline(
			// 1. Prepare source (Get info, find parent, checkout)
			prepareSource,
			// 2. Build kernel (with KASAN input config)
			kernel.Build,
			// 6. Prepare search index
			codesearcher.PrepareIndex,
			// 7. Loop: Generate/Debug Repro
			&aflow.DoWhile{
				Do: aflow.Pipeline(
					&aflow.LLMAgent{
						Name:        "repro-generator",
						Model:       aflow.BestExpensiveModel,
						Reply:       "ReproExplanation",
						Temperature: 1,
						Instruction: reproInstruction,
						Prompt:      reproPrompt,
						Tools: slices.Clip(append([]aflow.Tool{
							codeexpert.Tool,
							codeeditor.Tool,
							testReproTool,
							testSyzReproTool,
						}, codesearcher.Tools...)),
						SummaryWindow: summaryWindow,
					},
					checkStatus,
				),
				While:         "NeedRetry",
				MaxIterations: 20,
			},
		),
	}
}

func init() {
	aflow.Register[Inputs, Outputs](
		"patch-crasher",
		"create a C reproducer for a vulnerability fixed in a specific patch",
		createFlow("", 0),
		createFlow("summary", 10),
	)
}

const reproInstruction = `
You are an expert Linux kernel security researcher.
Your task is to create a C program (reproducer) that triggers the bug fixed in the provided patch commit.
You are working on the *parent* commit of the patch (unpatched version).

Workflow:
1. Analyze the Patch Info to understand the vulnerability.
2. Use 'codesearcher' to explore the relevant kernel code.
3. Establish a theory of how to trigger the bug.
4. Verify your theory and debug the kernel behavior:
   - Use 'codeeditor' to insert debug prints (printk) into the kernel code to trace the execution flow and verify conditions.
   - Use 'test_repro' to run a C program that attempts to trigger these paths.
   - MANDATORY: The C code MUST contain detailed comments explaining each step, what it does, and why it's required to reach the vulnerable code path.
   - IMPORTANT: To save time, batch multiple verification steps or questions into a single 'test_repro' run if possible.
     For example, write a C program that tries multiple syscall variants or arguments, and check the debug output to see which one reached the target code.
5. Tracking execution flow:
   - Use debug lines to confirm if you can reach the vulnerable function from user-space.
   - If not, use the debug output to understand where the execution stops or diverges.
6. The 'test_repro' tool filters output:
   - You MUST include the string "PATCHCRASHER" in any printk messages you add via 'codeeditor' or printf in C code.
   - Example: pr_err("PATCHCRASHER: value is %d\n", val);
7. Iterate:
   - If 'Status: NoCrash', analyze the "PATCHCRASHER" debug output. Refine your theory and the reproducer.
   - If 'Status: CrashFound', you succeed.
8. Final Step:
   - Once you have a working C reproducer that crashes the kernel:
   - Create a Syzkaller program (syz-lang) that triggers the same bug.
   - Use 'test_syz_repro' to verify it.
   - If the syz-lang program fails, analyze the executor logs to fix descriptions.
`

const reproPrompt = `
Patch Commit Info:
{{.CommitInfo}}

{{if .ReproExplanation}}
Your previous explanation:
{{.ReproExplanation}}
{{end}}
`
