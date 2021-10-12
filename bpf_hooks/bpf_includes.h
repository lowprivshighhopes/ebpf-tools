
static unsigned int MurmurHash2 (unsigned char * key, int len, unsigned int seed );

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

char path[PATH_MAX];

typedef struct _squirt_t {
    uint64_t pid;       // PID as in the userspace term (i.e. task->tgid in kernel)
    uint64_t uid;
    uint64_t ppid;      // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    void * load_addr; // pointer to first pt_load segment
    uint64_t interp_load_addr; // pointer to first pt_load segment
    uint64_t vdso_map;
    uint64_t bprm_buf_hash;
    uint32_t exe_hash;   
    const char *path;
    char p[256];
    //u64 interp_hash;    
} squirt_t;

// hash table key = pid, value = squirt_t pointer
BPF_TABLE("hash", u64, squirt_t, squirt_ctx, 65536);
//BPF_ARRAY_OF_MAPS(pid_ctx, squirt_ctx, 65536);
BPF_PERF_OUTPUT(events);

//const int kNumMapEntries = 65536;
//BPF_STACK_TRACE(stack_traces, kNumMapEntries);

// Sample the user stack trace, and record in the stack_traces structure.
//int user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

// Sample the kernel stack trace, and record in the stack_traces structure.
//int kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);

static int __submit_arg(struct pt_regs *ctx, void *ptr, squirt_t *data)
{
    // bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    // events.perf_submit(ctx, data, sizeof(squirt_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, squirt_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}



struct linux_binprm {
    struct vm_area_struct *vma;
    unsigned long vma_pages;
    struct mm_struct *mm;
    unsigned long p; /* current top of mem */
    unsigned long argmin; /* rlimit marker for copy_strings() */
    unsigned int
        have_execfd:1,
        execfd_creds:1,
        secureexec:1,
        point_of_no_return:1;
    struct file *executable; /* Executable to pass to the interpreter */
    struct file *interpreter;
    struct file *file;
    struct cred *cred;	/* new credentials */
    int unsafe;		/* how unsafe this exec is (mask of LSM_UNSAFE_*) */
    unsigned int per_clear;	/* bits to clear in current->personality */
    int argc, envc;
    const char *filename;	/* Name of binary as seen by procps */
    const char *interp;	/* Name of the binary really executed. Most
                    of the time same as filename, but could be
                    different for binfmt_{misc,script} */
    const char *fdpath;	/* generated filename for execveat */
    unsigned interp_flags;
    int execfd;		/* File descriptor of the executable */
    unsigned long loader, exec;

    struct rlimit rlim_stack; /* Saved RLIMIT_STACK used during exec. */

    char buf[256]; // BINPRM_BUF_SIZE
};    


// for open_execat
struct audit_names;
struct _filename {
	const char		*name;	/* pointer to actual string */
	const __user char	*uptr;	/* original userland pointer */
	int			refcnt;
	struct audit_names	*aname;
	const char		iname[];
};


struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */
    void * l_addr;                /* Difference between the address in the ELF
                                   file and the addresses in memory.  */
    char *l_name;                /* Absolute file name object was found in.  */
    void *l_ld;                /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;
    /* Number of the namespace this link map belongs to.  */
    long l_ns;
#define DT_NUM                35                /* Number used */
#define DT_THISPROCNUM        0
#define DT_VERSIONTAGNUM 16
#define DT_EXTRANUM        3
#define DT_VALNUM 12
#define DT_ADDRNUM 11

    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */
    void *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    void * l_phdr;        /* Pointer to program header table in core.  */
    void * l_entry;                /* Entry point location.  */
  };











static void dump_mem(unsigned long ptr, int words)
{
    unsigned long p = ptr;
    for(int i = 0; i < words; i++)
    {        
        unsigned long m; 
        bpf_probe_read_user(&m, sizeof(m), (void *)p); // + i * sizeof(stk[0]))
        bpf_trace_printk("mem[%llx]: %llx\n", p, m);
        p += 8;        
    }
}


static unsigned long get_frame(unsigned long *bp) {
    uint64_t ret = 0;
    if (*bp) {
        // The following stack walker is x86_64 specific        
        if (bpf_probe_read_user(&ret, sizeof(ret), (void *)(*bp+8)))
        {
            ret = 0;
        }
        else if (bpf_probe_read_user(bp, sizeof(*bp), (void *)*bp))
            *bp = 0;
    }
    return ret;
}

static int trace_count(struct pt_regs *ctx) {
    unsigned long bp = ctx->bp;
    bpf_trace_printk("trace_count %llx %llx\n", bp, ctx->ip);
    dump_mem(bp, 4);
    for(int i = 0; i < 8; i++)
    {
        uint64_t addr = get_frame(&bp);
        if(addr)
        {
            bpf_trace_printk("frame=%llx\n", bp);
            dump_mem(bp, 4);
            bpf_trace_printk("---\n");
        }
        else 
            break;

    }
    return 0;
}










// MurmurHash2, by Austin Appleby
static unsigned int MurmurHash2 (unsigned char * key, int len, unsigned int seed )
{
	const unsigned int m = 0x5bd1e995;
	const int r = 24;

    unsigned int s = 0; 
    if (seed != 0) s = seed;

	// Initialize the hash to a 'random' value
	unsigned int h = s ^ len;

	// Mix 4 bytes at a time into the hash
	unsigned char * data = key;

	while(len >= 4)
	{
		unsigned int k = *(unsigned int *)data;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		
		h *= m; 
		h ^= k;

		data += 4;
		len -= 4;
	}
	
	// Handle the last few bytes of the input array
	switch(len)
	{
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
	        h *= m;
	};

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
} 
