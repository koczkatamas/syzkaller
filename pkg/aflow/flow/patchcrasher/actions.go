// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patchcrasher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

const defaultRepo = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"

// prepareSource combines commit info retrieval, parent identification, and kernel checkout.
var prepareSource = aflow.NewFuncAction("prepare-source", func(ctx *aflow.Context, args struct{ PatchCommit string }) (struct {
	CommitInfo       string
	KernelSrc        string
	KernelScratchSrc string
	KernelCommit     string
}, error) {
	var res struct {
		CommitInfo       string
		KernelSrc        string
		KernelScratchSrc string
		KernelCommit     string
	}

	err := kernel.UseLinuxRepo(ctx, func(repoDir string, repo vcs.Repo) error {
		// Cache the entire operation to avoid polling/fetching/checking out on repeated runs.
		// The result of this cache block is the directory containing the checkout and metadata files.
		dir, err := ctx.Cache("patch-source", args.PatchCommit, func(dir string) error {
			// Inside this block, we are filling 'dir' with the result.

			// 1. Ensure latest master
			if _, err := repo.Poll(defaultRepo, "master"); err != nil {
				return err
			}

			// 2. Get Commit Info from shared repo and save to 'dir'
			out, err := osutil.RunCmd(time.Minute, repoDir, "git", "show", args.PatchCommit)
			if err != nil {
				return fmt.Errorf("failed to get commit info: %w", err)
			}
			if err := osutil.WriteFile(filepath.Join(dir, "commit_info.txt"), out); err != nil {
				return err
			}

			// 3. Get Parent Commit from shared repo and save to 'dir'
			out, err = osutil.RunCmd(time.Minute, repoDir, "git", "log", "-n", "1", "--format=%P", args.PatchCommit)
			if err != nil {
				return fmt.Errorf("failed to get parent commit: %w", err)
			}
			parents := strings.Fields(strings.TrimSpace(string(out)))
			if len(parents) == 0 {
				return fmt.Errorf("commit %s has no parents", args.PatchCommit)
			}
			parentInfo := parents[0]
			if err := osutil.WriteFile(filepath.Join(dir, "parent_commit.txt"), []byte(parentInfo)); err != nil {
				return err
			}

			// 4. Switch shared repo to Parent Commit
			if _, err := repo.SwitchCommit(parentInfo); err != nil {
				if _, err := repo.CheckoutCommit(defaultRepo, parentInfo); err != nil {
					return err
				}
			}

			// 5. Shallow clone into 'dir/src'
			srcDir := filepath.Join(dir, "src")
			if err := os.MkdirAll(srcDir, 0755); err != nil {
				return err
			}
			// Use kernel.ShallowGitClone which we exported.
			return kernel.ShallowGitClone(srcDir, repoDir)
		})
		if err != nil {
			return err
		}

		// Read back results from cache
		commitInfoBytes, err := os.ReadFile(filepath.Join(dir, "commit_info.txt"))
		if err != nil {
			return err
		}
		res.CommitInfo = string(commitInfoBytes)

		parentCommitBytes, err := os.ReadFile(filepath.Join(dir, "parent_commit.txt"))
		if err != nil {
			return err
		}
		res.KernelCommit = string(parentCommitBytes)
		res.KernelSrc = filepath.Join(dir, "src")
		res.KernelScratchSrc = res.KernelSrc

		// Ensure the cached directory is clean, because we might have modified it in previous runs
		// (since we reuse it as ScratchSrc).
		if _, err := osutil.RunCmd(time.Minute, res.KernelSrc, "git", "reset", "--hard"); err != nil {
			return fmt.Errorf("failed to reset source: %w", err)
		}
		if _, err := osutil.RunCmd(time.Minute, res.KernelSrc, "git", "clean", "-fd"); err != nil {
			return fmt.Errorf("failed to clean source: %w", err)
		}

		return nil
	})

	return res, err
})

var checkStatus = aflow.NewFuncAction("check-status", func(ctx *aflow.Context, args struct{ KernelScratchSrc string }) (struct {
	NeedRetry string
	CRepro    string
}, error) {
	var res struct {
		NeedRetry string
		CRepro    string
	}
	res.NeedRetry = "yes" // Default to retrying

	statusFile := filepath.Join(args.KernelScratchSrc, "repro_status.txt")
	statusBytes, err := os.ReadFile(statusFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No status file yet (maybe first turn or tool not run), keep retrying
			return res, nil
		}
		return res, err
	}
	status := string(statusBytes)

	if status == "CrashFound" {
		res.NeedRetry = ""

		reproFile := filepath.Join(args.KernelScratchSrc, "repro.c")
		if reproBytes, err := os.ReadFile(reproFile); err == nil {
			res.CRepro = string(reproBytes)
		}
	}
	// "NoCrash" or others -> NeedRetry stays "yes"

	return res, nil
})
