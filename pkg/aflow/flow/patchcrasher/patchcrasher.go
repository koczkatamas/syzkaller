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
3. Write/Test a C reproducer using 'test_repro'.
   - This tool compiles your code, builds the kernel (if needed), and runs it in a VM.
   - It returns the execution output.
4. IMPORTANT: The tool by default returns filtered output (lines containing "PATCHCRASHER" and crash reports).
   - You MUST include the string "PATCHCRASHER" in any printk/pr_err messages you add via 'codeeditor' or your C code (printf) if you want to see them.
   - Example: pr_err("PATCHCRASHER: value is %d\n", val);
5. Iterate:
   - If the reproducer crashes the kernel (Status: CrashFound), you succeed.
   - If 'Status: NoCrash', analyze the output and refine your reproducer.
   - Use 'codeeditor' to add more tracing if needed.
`

const reproPrompt = `
Patch Commit Info:
{{.CommitInfo}}

{{if .ReproExplanation}}
Your previous explanation:
{{.ReproExplanation}}
{{end}}
`
