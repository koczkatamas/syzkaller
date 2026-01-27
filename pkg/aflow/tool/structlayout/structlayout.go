// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structlayout

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tools = []aflow.Tool{
	aflow.NewFuncTool("structlayout-get-field-at-offset", getFieldAtOffset, `
Tool returns the field definition located at the specified offset within a struct from vmlinux.
It is useful for mapping raw memory offsets to struct fields.
`),
	aflow.NewFuncTool("structlayout-get-layout", getLayout, `
Tool returns the full layout (fields and offsets) of a struct from vmlinux.
`),
}

var Prepare = aflow.NewFuncAction("structlayout-prepare", prepare)

type prepareArgs struct {
	KernelObj    string
	KernelCommit string
}

type prepareResult struct {
	Layouts layouts
}

type layoutsData struct {
	data map[string]getLayoutResult
}

// layouts prevents full JSON marshalling of the struct layouts,
// so that they do not appear in logs/journal, and also ensures
// that the index does not pass JSON marshalling round-trip.
type layouts struct {
	*layoutsData
}

func (layouts) MarshalJSON() ([]byte, error) {
	return []byte(`"structlayout-index"`), nil
}

func (layouts) UnmarshalJSON([]byte) error {
	return fmt.Errorf("structlayout-index cannot be unmarshalled")
}

type fieldAtOffsetArgs struct {
	Struct string `jsonschema:"Name of the struct, e.g. 'xfrm_state'"`
	Offset int64  `jsonschema:"Byte offset within the struct"`
}

type fieldAtOffsetResult struct {
	Field            string `jsonschema:"Name of the field"`
	Type             string `jsonschema:"Type of the field"`
	Start            int64  `jsonschema:"Start offset of the field"`
	End              int64  `jsonschema:"End offset of the field (exclusive)"`
	Size             int64  `jsonschema:"Size of the field in bytes"`
	OffsetInField    int64  `jsonschema:"The requested offset relative to the start of this field"`
	ContainingStruct string `jsonschema:"Name of the containing struct (if nested)"`
}

type getLayoutArgs struct {
	Struct string `jsonschema:"Name of the struct"`
}

type getLayoutResult struct {
	Size   int64         `jsonschema:"Total size of the struct"`
	Fields []layoutField `jsonschema:"List of fields"`
}

type layoutField struct {
	Name   string `jsonschema:"Name of the field"`
	Type   string `jsonschema:"Type of the field"`
	Offset int64  `jsonschema:"Offset of the field"`
	Size   int64  `jsonschema:"Size of the field"`
}

func prepare(ctx *aflow.Context, args prepareArgs) (prepareResult, error) {
	vmlinux := ""
	if args.KernelObj != "" {
		vmlinux = filepath.Join(args.KernelObj, "vmlinux")
	}
	if vmlinux == "" {
		return prepareResult{}, fmt.Errorf("vmlinux path is empty")
	}

	// Use KernelCommit in the cache key.
	desc := fmt.Sprintf("structlayout index for kernel commit %v", args.KernelCommit)
	
	// We use the directory cache.
	dir, err := ctx.Cache("structlayout", desc, func(dir string) error {
		layouts, err := ExtractAllLayouts(vmlinux)
		if err != nil {
			return err
		}

		data, err := json.Marshal(layouts)
		if err != nil {
			return err
		}
		return osutil.WriteFile(filepath.Join(dir, "index.json"), data)
	})

	if err != nil {
		return prepareResult{}, err
	}

	// Load the index into memory
	indexBytes, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return prepareResult{}, fmt.Errorf("failed to read index: %w", err)
	}
	var data map[string]getLayoutResult
	if err := json.Unmarshal(indexBytes, &data); err != nil {
		return prepareResult{}, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	return prepareResult{
		Layouts: layouts{&layoutsData{data: data}},
	}, nil
}

func getFieldAtOffset(ctx *aflow.Context, state prepareResult, args fieldAtOffsetArgs) (fieldAtOffsetResult, error) {
	layout, ok := state.Layouts.data[args.Struct]
	if !ok {
		return fieldAtOffsetResult{}, fmt.Errorf("struct %s not found in structlayout index", args.Struct)
	}

	// Search for the field
	for _, f := range layout.Fields {
		if args.Offset >= f.Offset && args.Offset < f.Offset+f.Size {
			return fieldAtOffsetResult{
				Field:            f.Name,
				Type:             f.Type,
				Start:            f.Offset,
				End:              f.Offset + f.Size,
				Size:             f.Size,
				OffsetInField:    args.Offset - f.Offset,
				ContainingStruct: args.Struct,
			}, nil
		}
	}
	
	return fieldAtOffsetResult{}, fmt.Errorf("offset %d not found in struct %s (size %d)", args.Offset, args.Struct, layout.Size)
}

func getLayout(ctx *aflow.Context, state prepareResult, args getLayoutArgs) (getLayoutResult, error) {
	layout, ok := state.Layouts.data[args.Struct]
	if !ok {
		return getLayoutResult{}, fmt.Errorf("struct %s not found in structlayout index", args.Struct)
	}
	return getLayoutResult{
		Size:   layout.Size,
		Fields: layout.Fields,
	}, nil
}

// ExtractAllLayouts scans vmlinux and extracts layout for all structs.
func ExtractAllLayouts(vmlinuxPath string) (map[string]getLayoutResult, error) {
	f, err := os.Open(vmlinuxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open vmlinux: %w", err)
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF: %w", err)
	}
	
	dw, err := ef.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to parse DWARF: %w", err)
	}

	layouts := make(map[string]getLayoutResult)
	r := dw.Reader()
	
	for {
		entry, err := r.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagCompileUnit {
			continue
		}
		
		if entry.Tag == dwarf.TagStructType {
			name, _ := entry.Val(dwarf.AttrName).(string)
			if name != "" {
				// Skip declarations (forward declarations)
				if isDecl, _ := entry.Val(dwarf.AttrDeclaration).(bool); isDecl {
					if entry.Children {
						r.SkipChildren()
					}
					continue
				}

				size, _ := entry.Val(dwarf.AttrByteSize).(int64)
				var fields []layoutField
				
				if entry.Children {
					// Read fields
					for {
						child, err := r.Next()
						if err != nil || child == nil {
							break 
						}
						if child.Tag == 0 {
							break
						}
						if child.Tag == dwarf.TagMember {
							fName, _ := child.Val(dwarf.AttrName).(string)
							fTypeOffset, _ := child.Val(dwarf.AttrType).(dwarf.Offset)
							fLoc, _ := child.Val(dwarf.AttrDataMemberLoc).(int64)
							
							fType, fSize, _ := resolveType(dw, fTypeOffset)
							if fType == "" {
								fType = "unknown"
							}
							
							fields = append(fields, layoutField{
								Name:   fName,
								Type:   fType,
								Offset: fLoc,
								Size:   fSize,
							})
						} else if child.Children {
							r.SkipChildren()
						}
					}
				}
				
				sort.Slice(fields, func(i, j int) bool {
					return fields[i].Offset < fields[j].Offset
				})
				
				// Only overwrite if we have a better definition (e.g. non-zero size)
				// or if it didn't exist.
				if existing, ok := layouts[name]; ok {
					if existing.Size > 0 && size == 0 {
						continue
					}
					if len(existing.Fields) > 0 && len(fields) == 0 {
						continue
					}
				}
				
				layouts[name] = getLayoutResult{
					Size:   size,
					Fields: fields,
				}
			} else {
				if entry.Children {
					r.SkipChildren()
				}
			}
		} else if entry.Children {
			r.SkipChildren()
		}
	}
	return layouts, nil
}

// resolveType follows the DWARF type chain to get a readable name and size
func resolveType(dw *dwarf.Data, offset dwarf.Offset) (string, int64, error) {
	r := dw.Reader()
	r.Seek(offset)
	entry, err := r.Next()
	if err != nil || entry == nil {
		return "", 0, fmt.Errorf("type not found")
	}

	name, _ := entry.Val(dwarf.AttrName).(string)
	size, _ := entry.Val(dwarf.AttrByteSize).(int64)
	
	switch entry.Tag {
	case dwarf.TagBaseType:
		return name, size, nil
	case dwarf.TagTypedef:
		refType, _ := entry.Val(dwarf.AttrType).(dwarf.Offset)
		tName, tSize, _ := resolveType(dw, refType)
		if size == 0 {
			size = tSize
		}
		if name == "" {
			name = tName
		}
		return name, size, nil
	case dwarf.TagPointerType:
		if size == 0 {
			size = 8 
		}
		return name + "*", size, nil
	case dwarf.TagStructType:
		if name == "" {
			name = "<struct>"
		}
		return "struct " + name, size, nil
	case dwarf.TagUnionType:
		if name == "" {
			name = "<union>"
		}
		return "union " + name, size, nil
	case dwarf.TagArrayType:
		return "array", size, nil
	case dwarf.TagConstType, dwarf.TagVolatileType:
		refType, _ := entry.Val(dwarf.AttrType).(dwarf.Offset)
		tName, tSize, _ := resolveType(dw, refType)
		return tName, tSize, nil
	default:
		return name, size, nil
	}
}
