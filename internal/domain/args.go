package domain

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// FlattenArgs turns a tool call's structured arguments into one field per
// leaf (a top-level argument by its own name, a nested one by its dotted
// path, e.g. "edits.0.newString") and a text blob of every leaf for
// detectors that scan free text. Numbers and booleans are fields too, so a
// phone number sent as a number is still found. Null leaves are skipped.
func FlattenArgs(args map[string]any) (fields map[string]string, text string) {
	fields = make(map[string]string)
	for key, value := range args {
		flattenLeaf(key, value, fields)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString(": ")
		b.WriteString(fields[key])
		b.WriteString("\n")
	}
	return fields, b.String()
}

func flattenLeaf(path string, value any, fields map[string]string) {
	switch v := value.(type) {
	case nil:
	case map[string]any:
		for key, child := range v {
			flattenLeaf(path+"."+key, child, fields)
		}
	case []any:
		for i, child := range v {
			flattenLeaf(path+"."+strconv.Itoa(i), child, fields)
		}
	case string:
		fields[path] = v
	default:
		fields[path] = fmt.Sprintf("%v", v)
	}
}

// RebuildArgs returns a copy of args with every leaf whose field in fields
// changed replaced by the new string, and every other leaf kept as it was,
// with its type. A number or boolean only becomes a string when veil
// rewrote it (it held personal data). Leaves missing from fields are kept.
// With no args (an event built without them) the fields are the answer.
func RebuildArgs(args map[string]any, fields map[string]string) map[string]any {
	if args == nil {
		if fields == nil {
			return nil
		}
		out := make(map[string]any, len(fields))
		for key, value := range fields {
			out[key] = value
		}
		return out
	}
	out := make(map[string]any, len(args))
	for key, value := range args {
		out[key] = rebuildLeaf(key, value, fields)
	}
	return out
}

func rebuildLeaf(path string, value any, fields map[string]string) any {
	switch v := value.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[key] = rebuildLeaf(path+"."+key, child, fields)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = rebuildLeaf(path+"."+strconv.Itoa(i), child, fields)
		}
		return out
	case string:
		if s, ok := fields[path]; ok {
			return s
		}
		return v
	default:
		if s, ok := fields[path]; ok && s != fmt.Sprintf("%v", v) {
			return s
		}
		return v
	}
}
