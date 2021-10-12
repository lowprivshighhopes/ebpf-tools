// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

type EventType int32

const (
	eventArg EventType = iota
	eventRet
)

type execveEvent struct {
	Pid    uint64
	Ppid   uint64
	Comm   [16]byte
	Type   int32
	Argv   [128]byte
	RetVal int32
	Hash   uint32
}

type eventPayload struct {
	Time   string `json:"time,omitempty"`
	Comm   string `json:"comm"`
	Pid    uint64 `json:"pid"`
	Ppid   string `json:"ppid"`
	Argv   string `json:"argv"`
	RetVal int32  `json:"retval"`
	Hash   uint32 `json:"hash"`
}

// get_ppid is a fallback to read the parent PID from /proc.
// Some kernel versions, like 4.13.0 return 0 getting the parent PID
// from the current task, so we need to use this fallback to have
// the parent PID in any kernel.
func get_ppid(pid uint64) uint64 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return i
		}
	}
	return 0
}

func main() {
	run()
}

func run() {
	traceFailed := flag.Bool("x", false, "trace failed exec()s")
	timestamps := flag.Bool("t", false, "include timestamps")
	quotemarks := flag.Bool("q", false, `add "quotemarks" around arguments`)
	filterComm := flag.String("n", "", `only print command lines containing a name, for example "main"`)
	filterArg := flag.String("l", "", `only print command where arguments contain an argument, for example "tpkg"`)
	format := flag.String("o", "table", "output format, either table or json")
	pretty := flag.Bool("p", false, "pretty print json output")
	maxArgs := flag.Uint64("m", 20, "maximum number of arguments parsed and displayed, defaults to 20")

	flag.Parse()

	b, err := ioutil.ReadFile("bpf_hooks/bpf_hooks.c") // this contains the BPF programs
	if err != nil {
		fmt.Print(err)
	}
	bpf_hooks_src := string(b)

	// replace bpf program constants where needed
	m := bpf.NewModule(strings.Replace(bpf_hooks_src, "MAX_ARGS", strconv.FormatUint(*maxArgs, 10), -1), []string{})
	defer m.Close()

	// hook execve
	fnName := bpf.GetSyscallFnName("execve")
	kprobe, err := m.LoadKprobe("syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load syscall__execve: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach syscall__execve: %s\n", err)
		os.Exit(1)
	}

	// kretprobe, err := m.LoadKprobe("hook_ret_sys_execve")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to load do_ret_sys_execve: %s\n", err)
	// 	os.Exit(1)
	// }

	// if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to attach do_ret_sys_execve: %s\n", err)
	// 	os.Exit(1)
	// }

	//=======================

	// hook_elf_map, err := m.LoadKprobe("hook_elf_map")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to load hook_elf_map: %s\n", err)
	// 	os.Exit(1)
	// }

	// if err := m.AttachKprobe("elf_map", hook_elf_map, -1); err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to attach hook_elf_map: %s\n", err)
	// 	os.Exit(1)
	// }

	hook_ret_elf_map, err := m.LoadKprobe("hook_ret_elf_map")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hook_ret_elf_map: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKretprobe("elf_map", hook_ret_elf_map, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hook_ret_elf_map: %s\n", err)
		os.Exit(1)
	}

	// hook_do_open_execat
	hook_do_open_execat, err := m.LoadKprobe("hook_do_open_execat")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hook_do_open_execat: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe("do_open_execat", hook_do_open_execat, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hook_do_open_execat: %s\n", err)
		os.Exit(1)
	}

	// hook_map_vdso
	hook_map_vdso, err := m.LoadKprobe("hook_map_vdso")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hook_do_open_execat: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe("map_vdso", hook_map_vdso, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hook_map_vdso: %s\n", err)
		os.Exit(1)
	}

	// hook_start_thread
	hook_start_thread, err := m.LoadKprobe("hook_start_thread")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hook_start_thread: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe("start_thread", hook_start_thread, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hook_start_thread: %s\n", err)
		os.Exit(1)
	}

	// hook_ret_start_thread
	/*
		hook_ret_start_thread, err := m.LoadKprobe("hook_ret_start_thread")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load hook_ret_start_thread: %s\n", err)
			os.Exit(1)
		}

		if err := m.AttachKretprobe("start_thread", hook_ret_start_thread, -1); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach hook_ret_start_thread: %s\n", err)
			os.Exit(1)
		}
	*/

	// hook_load_elf_binary
	hook_load_elf_binary, err := m.LoadKprobe("hook_load_elf_binary")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hook_load_elf_binary: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe("load_elf_binary", hook_load_elf_binary, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hook_load_elf_binary: %s\n", err)
		os.Exit(1)
	}

	// hook_ret_load_elf_binary
	/*
		hook_ret_load_elf_binary, err := m.LoadKprobe("hook_ret_load_elf_binary")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load hook_load_elf_binary: %s\n", err)
			os.Exit(1)
		}

		if err := m.AttachKretprobe("load_elf_binary", hook_ret_load_elf_binary, -1); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach hook_ret_load_elf_binary: %s\n", err)
			os.Exit(1)
		}
	*/
	// hook_create_elf_tables
	hook_create_elf_tables, err := m.LoadKprobe("hook_create_elf_tables")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hook_create_elf_tables: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe("create_elf_tables", hook_create_elf_tables, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hook_create_elf_tables: %s\n", err)
		os.Exit(1)
	}

	hook_dlopen, err := m.LoadUprobe("hook_dlopen")
	if err != nil {
		panic(err)
	}
	err = m.AttachUprobe("/lib/x86_64-linux-gnu/libdl.so.2", "dlopen", hook_dlopen, -1)
	if err != nil {
		panic(err)
	}

	hook_dl_allocate_tls_init, err := m.LoadUprobe("hook_dl_allocate_tls_init")
	if err != nil {
		panic(err)
	}
	err = m.AttachUprobe("/lib64/ld-linux-x86-64.so.2", "_dl_allocate_tls_init", hook_dl_allocate_tls_init, -1)
	if err != nil {
		panic(err)
	}

	hook_dl_allocate_tls, err := m.LoadUprobe("hook_dl_allocate_tls")
	if err != nil {
		panic(err)
	}
	err = m.AttachUprobe("/lib64/ld-linux-x86-64.so.2", "_dl_allocate_tls", hook_dl_allocate_tls, -1)
	if err != nil {
		panic(err)
	}

	hook_ret_dl_find_dso_for_object, err := m.LoadUprobe("hook_ret_dl_find_dso_for_object")
	if err != nil {
		panic(err)
	}
	err = m.AttachUretprobe("/lib64/ld-linux-x86-64.so.2", "_dl_find_dso_for_object", hook_ret_dl_find_dso_for_object, -1)
	if err != nil {
		panic(err)
	}

	hook__libc_init, err := m.LoadUprobe("hook__libc_init")
	if err != nil {
		panic(err)
	}
	err = m.AttachUprobe("/lib/x86_64-linux-gnu/libc.so.6", "__libc_init_first", hook__libc_init, -1)
	if err != nil {
		panic(err)
	}

	table := bpf.NewTable(m.TableId("events"), m)

	channel := make(chan []byte, 1000)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		out := newOutput(*format, *pretty, *timestamps)
		out.PrintHeader()

		return
		args := make(map[uint64][]string)

		for {
			data := <-channel

			var event execveEvent
			err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)

			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			if eventArg == EventType(event.Type) {
				e, ok := args[event.Pid]
				if !ok {
					e = make([]string, 0)
				}
				argv := (*C.char)(unsafe.Pointer(&event.Argv))

				e = append(e, C.GoString(argv))
				args[event.Pid] = e
			} else {
				if event.RetVal != 0 && !*traceFailed {
					delete(args, event.Pid)
					continue
				}

				comm := C.GoString((*C.char)(unsafe.Pointer(&event.Comm)))
				if *filterComm != "" && !strings.Contains(comm, *filterComm) {
					delete(args, event.Pid)
					continue
				}

				argv, ok := args[event.Pid]
				if !ok {
					continue
				}

				if *filterArg != "" && !strings.Contains(strings.Join(argv, " "), *filterArg) {
					delete(args, event.Pid)
					continue
				}

				p := eventPayload{
					Pid:    event.Pid,
					Ppid:   "?",
					Comm:   comm,
					RetVal: event.RetVal,
				}

				if event.Ppid == 0 {
					event.Ppid = get_ppid(event.Pid)
				}

				if event.Ppid != 0 {
					p.Ppid = strconv.FormatUint(event.Ppid, 10)
				}

				if *quotemarks {
					var b bytes.Buffer
					for i, a := range argv {
						b.WriteString(strings.Replace(a, `"`, `\"`, -1))
						if i != len(argv)-1 {
							b.WriteString(" ")
						}
					}
					p.Argv = b.String()
				} else {
					p.Argv = strings.Join(argv, " ")
				}
				p.Argv = strings.TrimSpace(strings.Replace(p.Argv, "\n", "\\n", -1))

				out.PrintLine(p)
				delete(args, event.Pid)
			}
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
