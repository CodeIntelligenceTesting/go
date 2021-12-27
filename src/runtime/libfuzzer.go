// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build libfuzzer

package runtime

import "unsafe" // for go:linkname

const retSledSize = 512

func libfuzzerCallTraceIntCmp(fn *byte, arg0, arg1, fakePC uintptr)
func libfuzzerCallHookStrCmp(fn *byte, fakePC uintptr, s1, s2 unsafe.Pointer, result uintptr)

func libfuzzerTraceCmp1(arg0, arg1 uint8, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_cmp1, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceCmp2(arg0, arg1 uint16, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_cmp2, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceCmp4(arg0, arg1 uint32, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_cmp4, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceCmp8(arg0, arg1 uint64, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_cmp8, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceConstCmp1(arg0, arg1 uint8, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_const_cmp1, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceConstCmp2(arg0, arg1 uint16, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_const_cmp2, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceConstCmp4(arg0, arg1 uint32, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_const_cmp4, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerTraceConstCmp8(arg0, arg1 uint64, fakePC int) {
	fakePC = fakePC % retSledSize
	libfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_const_cmp8, uintptr(arg0), uintptr(arg1), uintptr(fakePC))
}

func libfuzzerHookStrCmp(s1, s2 string, result, fakePC int) {
	libfuzzerCallHookStrCmp(&__sanitizer_weak_hook_strcmp, uintptr(fakePC), cstring(s1), cstring(s2), uintptr(result))
}

// TODO(khaled) add documentation
func libfuzzerIncrementCounter(counter *uint8) {
	if *counter == 0xff {
		*counter = 1
	} else {
		*counter++
	}
}

//go:linkname __sanitizer_cov_trace_cmp1 __sanitizer_cov_trace_cmp1
//go:cgo_import_static __sanitizer_cov_trace_cmp1
var __sanitizer_cov_trace_cmp1 byte

//go:linkname __sanitizer_cov_trace_cmp2 __sanitizer_cov_trace_cmp2
//go:cgo_import_static __sanitizer_cov_trace_cmp2
var __sanitizer_cov_trace_cmp2 byte

//go:linkname __sanitizer_cov_trace_cmp4 __sanitizer_cov_trace_cmp4
//go:cgo_import_static __sanitizer_cov_trace_cmp4
var __sanitizer_cov_trace_cmp4 byte

//go:linkname __sanitizer_cov_trace_cmp8 __sanitizer_cov_trace_cmp8
//go:cgo_import_static __sanitizer_cov_trace_cmp8
var __sanitizer_cov_trace_cmp8 byte

//go:linkname __sanitizer_cov_trace_const_cmp1 __sanitizer_cov_trace_const_cmp1
//go:cgo_import_static __sanitizer_cov_trace_const_cmp1
var __sanitizer_cov_trace_const_cmp1 byte

//go:linkname __sanitizer_cov_trace_const_cmp2 __sanitizer_cov_trace_const_cmp2
//go:cgo_import_static __sanitizer_cov_trace_const_cmp2
var __sanitizer_cov_trace_const_cmp2 byte

//go:linkname __sanitizer_cov_trace_const_cmp4 __sanitizer_cov_trace_const_cmp4
//go:cgo_import_static __sanitizer_cov_trace_const_cmp4
var __sanitizer_cov_trace_const_cmp4 byte

//go:linkname __sanitizer_cov_trace_const_cmp8 __sanitizer_cov_trace_const_cmp8
//go:cgo_import_static __sanitizer_cov_trace_const_cmp8
var __sanitizer_cov_trace_const_cmp8 byte

//go:linkname __sanitizer_weak_hook_strcmp __sanitizer_weak_hook_strcmp
//go:cgo_import_static __sanitizer_weak_hook_strcmp
var __sanitizer_weak_hook_strcmp byte
