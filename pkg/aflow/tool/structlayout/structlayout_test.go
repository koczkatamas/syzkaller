// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structlayout

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStructLayout(t *testing.T) {
	// 1. Create a C file with a known struct
	dir := t.TempDir()
	cFile := filepath.Join(dir, "test.c")
	objFile := filepath.Join(dir, "test.o")

	cSource := `
struct Inner {
	int x;
};

struct Test {
	int a;
	long b;
	char c[10];
	struct Inner inner;
};

struct Test t;

struct Forward;
struct Forward {
	int y;
};
struct Forward f;
`
	if err := os.WriteFile(cFile, []byte(cSource), 0644); err != nil {
		t.Fatalf("failed to write c file: %v", err)
	}

	// 2. Compile with debug info
	// We check if gcc is available, otherwise skip test.
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found")
	}

	cmd := exec.Command("gcc", "-g", "-c", cFile, "-o", objFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile: %v\n%s", err, out)
	}

	// 3. Build Index (Extract Layouts)
	extractedLayouts, err := ExtractAllLayouts(objFile)
	if err != nil {
		t.Fatalf("ExtractAllLayouts failed: %v", err)
	}
	
	if _, ok := extractedLayouts["Test"]; !ok {
		t.Errorf("struct Test not found in layouts")
	}
	if l, ok := extractedLayouts["Forward"]; !ok {
		t.Errorf("struct Forward not found in layouts")
	} else if l.Size == 0 {
		t.Errorf("struct Forward has 0 size")
	}

	// 4. Test logic via public helpers
	// Create a prepareResult manually
	state := prepareResult{
		Layouts: layouts{&layoutsData{data: extractedLayouts}},
	}

	// Helper to load layout
	getLayoutHelper := func(name string) (getLayoutResult, error) {
		return getLayout(nil, state, getLayoutArgs{Struct: name})
	}

	layout, err := getLayoutHelper("Test")
	if err != nil {
		t.Fatalf("getLayout failed: %v", err)
	}

	fields := layout.Fields
	size := layout.Size

	expectedFields := []string{"a", "b", "c", "inner"}
	if len(fields) != len(expectedFields) {
		t.Errorf("expected %d fields, got %d", len(expectedFields), len(fields))
	}

	for i, f := range fields {
		if f.Name != expectedFields[i] {
			t.Errorf("field %d: expected %s, got %s", i, expectedFields[i], f.Name)
		}
	}
	
	if size == 0 {
		t.Errorf("size is 0")
	}

	// 5. Test getFieldAtOffset
	
	// Find offset of b from layout
	var offsetB int64 = -1
	var sizeB int64
	for _, f := range fields {
		if f.Name == "b" {
			offsetB = f.Offset
			sizeB = f.Size
		}
	}
	
	if offsetB == -1 {
		t.Fatalf("field b not found")
	}

	// Test exact match
	res, err := getFieldAtOffset(nil, state, fieldAtOffsetArgs{
		Struct: "Test",
		Offset: offsetB,
	})
	if err != nil {
		t.Fatalf("getFieldAtOffset failed: %v", err)
	}
	if res.Field != "b" {
		t.Errorf("expected field b, got %v", res.Field)
	}

	// Test inside field (e.g. byte 1 of b)
	if sizeB > 1 {
		res, err = getFieldAtOffset(nil, state, fieldAtOffsetArgs{
			Struct: "Test",
			Offset: offsetB + 1,
		})
		if err != nil {
			t.Fatalf("getFieldAtOffset failed: %v", err)
		}
		if res.Field != "b" {
			t.Errorf("expected field b, got %v", res.Field)
		}
		if res.OffsetInField != 1 {
			t.Errorf("expected OffsetInField 1, got %v", res.OffsetInField)
		}
	}
}
