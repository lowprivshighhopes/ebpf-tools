int hook_clock_gettime(struct pt_regs *ctx)
{    
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    if(pid == 1)
        bpf_trace_printk("[ebpf-squirt]: hooked\n");
    //dump_mem(ctx->sp, 8);
    return 0;    
}  

