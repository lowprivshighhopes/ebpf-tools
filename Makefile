all: ebpf-squirt


ebpf-squirt: *.go
	go build -o $@ $^

test:
	@echo To view output: sudo cat /sys/kernel/debug/tracing/trace_pipe
	sudo -E go run *.go

clean:
	rm -f ebpf-squirt
