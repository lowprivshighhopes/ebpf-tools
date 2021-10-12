# ebpf-tools

ebpf-squirt currently implements all of the demo hooks from the Toorcon 21 talk Extra Better Program Finagling (eBPF) for Attack and Defense  

A refactor into distinct tools is on the TODO

Current version will disallow execution of executables matching the hash of /usr/bin/id on my system. It will also intercept and break the execution of sudo as the demo only injects /tmp/tc.so into sudo and exits rather than continuing execution cleanly. 



