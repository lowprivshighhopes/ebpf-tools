#include <uapi/linux/ptrace.h>
#include <uapi/linux/elf.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include "bpf_hooks/bpf_includes.h"

#include "bpf_hooks/hook_all_procs_often.h"


int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    squirt_t s = {};

    s.uid = bpf_get_current_uid_gid() & 0xffffffff;
    s.pid = bpf_get_current_pid_tgid() >> 32;
    s.ppid = task->real_parent->tgid;
    squirt_ctx.update(&s.pid, &s);

    bpf_trace_printk("==========================\n");
    bpf_trace_printk("execve() uid=%d pid=%d path=%s\n", s.uid, s.pid, filename);    

    // s.type = EVENT_ARG;
    // __submit_arg(ctx, (void *)filename, &s);

    // // skip first arg, as we submitted filename
    // #pragma unroll
    // for (int i = 1; i < MAX_ARGS; i++) {
    //     if (submit_arg(ctx, (void *)&__argv[i], &s) == 0)
    //          goto out;
    // }

    // // handle truncated argument list
    // char ellipsis[] = "...";
    // __submit_arg(ctx, (void *)ellipsis, &s);

out:
    return 0;
}


// int hook_ret_sys_execve(struct pt_regs *ctx)
// {
    // bpf_get_current_comm(&data.comm, sizeof(data.comm));
    // data.type = EVENT_RET;
    // data.retval = PT_REGS_RC(ctx);
    // events.perf_submit(ctx, &data, sizeof(data));

//     return 0;
// }


// static int load_elf_binary(struct linux_binprm *bprm);
int hook_load_elf_binary(struct pt_regs *ctx, struct linux_binprm *bprm)
{    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = task->pid;
    squirt_t *s = squirt_ctx.lookup(&pid);
    char probe_buf[256] = {};     
    void *probe_ptr;

    if(s != NULL)
    {
        if(bpf_probe_read_user(probe_buf, sizeof(probe_buf), bprm->buf))
        {
            bpf_trace_printk("    hook_load_elf_binary(): Error reading data to hash: %llx\n", probe_ptr);
        }
        else 
        {
            unsigned long hash = MurmurHash2(probe_buf, sizeof(probe_buf), 31337);
            bpf_trace_printk("    hook_load_elf_binary() bprm_buf_hash: %llx\n", pid, hash);
        }
    }
    return 0;    
}



// int hook_elf_map(struct pt_regs *ctx,
//         struct file *filep, unsigned long addr,
// 		const struct elf_phdr *eppnt, int prot, int type,
// 		unsigned long total_size)
// {
//         bpf_trace_printk("      elf_map segment: %llx total_size: %d\n", addr, total_size);
// }
 
int hook_ret_elf_map(struct pt_regs *ctx)
{
    void *load_addr = (void *)PT_REGS_RC(ctx);
    bpf_trace_printk("      elf_map() segment: %llx\n", load_addr);
    return 0;
}


int hook_do_open_execat(struct pt_regs *ctx,
    const int __user fd, 
    const struct _filename __user *filename,
    const int __user flags)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = task->pid;
    
    squirt_t *s = squirt_ctx.lookup(&pid);
    if(s != NULL)
    {
        if(s->load_addr == 0) 
            s->path = filename->name;
    }    
    bpf_trace_printk("  do_open_execat() filename: %s \n", filename->name);
    return 0;    
}


// static int map_vdso(const struct vdso_image *image, unsigned long addr)
int hook_map_vdso(struct pt_regs *ctx,
    const struct vdso_image *image, 
    const unsigned long addr)
{    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = task->pid;
    
    squirt_t *s = squirt_ctx.lookup(&pid);
    if(s != NULL)
    {
        s->vdso_map = addr;
        bpf_trace_printk("  map_vdso()   map addr: %llx\n", addr);
    }

    return 0;    
}


// static int
// create_elf_tables(struct linux_binprm *bprm, const struct elfhdr *exec,
//		unsigned long load_addr, unsigned long interp_load_addr,
//		unsigned long e_entry)
int hook_create_elf_tables(struct pt_regs *ctx,
        struct linux_binprm *bprm, const struct elfhdr *exec,
		unsigned long load_addr, unsigned long interp_load_addr,
		unsigned long e_entry)
{   
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = task->pid;

    bpf_trace_printk("  create_elf_tables() \n");
    squirt_t *s = squirt_ctx.lookup(&pid);
    if(s != NULL)
    {    
        s->load_addr = (void *)load_addr;
        //s->load_addr = exec->e_entry;
        s->interp_load_addr = interp_load_addr;
        
        bpf_trace_printk("              load_addr: %llx\n", load_addr);
        bpf_trace_printk("       interp_load_addr: %llx\n", interp_load_addr);
        bpf_trace_printk("          exec->e_entry: %llx\n", exec->e_entry); 
    }
out:
    return 0;    
}  

int hook_start_thread(struct pt_regs *ctx,
    struct pt_regs *regs, 
    unsigned long new_ip, 
    unsigned long new_sp)
{    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = task->pid;
    
    squirt_t *s = squirt_ctx.lookup(&pid);
    if(s != NULL)
    {
        bpf_trace_printk("  start_thread()\n");
        bpf_trace_printk("      uid=%d addr=%llx path=%s\n", s->uid, new_ip, s->path);
    }
    bpf_trace_printk("----------------------\n");       

out:
    return 0;    
}


int hook_ret_dl_find_dso_for_object(struct pt_regs *ctx) 
{   
    struct link_map *map = (struct link_map *)PT_REGS_RC(ctx);
    bpf_trace_printk("hook_dl_find_dso_for_object: map=%llx %llx\n", map, ctx->ip);
    bpf_trace_printk("[LINK_HOOK] entry=%llx path=%s\n", map->l_entry, map->l_name);
    return 0;
}

// only called for pthread?
int hook_dl_allocate_tls(struct pt_regs *ctx, void *p)
{    
    bpf_trace_printk("hook_dl_allocate_tls\n");
    return 0; 
}

int hook_dl_allocate_tls_init(struct pt_regs *ctx, void *p)
{    
    bpf_trace_printk("hook_dl_allocate_tls_init %llx\n", ctx->ip);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = task->pid;
    squirt_t *s = squirt_ctx.lookup(&pid);
    uint64_t probe_ptr;
    char probe_buf[256] = {};     
    if(s != NULL)
    {
        bpf_trace_printk("[SQUIRT_EDR]: uid=%d pid=%d path=%s\n", s->uid, s->pid, s->path);
        if(bpf_probe_read_user(probe_buf, sizeof(probe_buf), s->load_addr))
        {
            bpf_trace_printk("[SQUIRT_EDR]: Error reading data to hash: %llx\n", probe_ptr);
        }

        int ret = 0;
        unsigned long hash = MurmurHash2(probe_buf, 256, 31337);
        bpf_trace_printk("[SQUIRT_EDR]: hash: %x\n", hash);
        s->exe_hash = hash;
        events.perf_submit(ctx, s, sizeof(s));
        if(hash == 0xe832b4d6) // hash for /usr/bin/id
        {
            const char toorcon_slap[] = "hello toorcon!";

            bpf_trace_printk("[SQUIRT_EDR] BAD HASH! Attempting to kill program! %llx\n", ctx->ip);
            ret = bpf_probe_write_user((void *)ctx->sp, (void *)toorcon_slap, sizeof(toorcon_slap));
            if (ret) 
            {
                bpf_trace_printk("[SQUIRT_EDR]: Error writing code to process: %d addr: %llx\n", s->pid,  probe_ptr);
            }
            else
            {
                bpf_trace_printk("[SQUIRT_EDR] PROGRAM TERMINATED WITH TOORCON SLAP\n");
            }
        }
    }
    return 0;    
}  

//hook_dl_make_stack_executable

int hook__libc_init(struct pt_regs *ctx,
    int argc, char **argv, char **envp)
{        
    bpf_trace_printk("hook__libc_init()\n");
    return 0;    
}  


int hook_dlopen(struct pt_regs *ctx, const char *filename, int flags)
{    
    char inject_lib[] = "/tmp/tc.so";
    char comm[256];
    bpf_get_current_comm(&comm, sizeof(comm));
    if(!memcmp(comm, "sudo", 4)) 
    {
        u64 ret = bpf_probe_write_user((void *)ctx->di, &inject_lib, sizeof(inject_lib));
        bpf_trace_printk("dlopen: %s %d \n", ctx->di, ret);
    }
    return 0;    
}  


