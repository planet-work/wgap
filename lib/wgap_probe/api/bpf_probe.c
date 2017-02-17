#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <net/sock.h>
#include <bcc/proto.h>

// the key for the output summary
struct val_t {
	u64 id;
	u64 ts;
    u32 uid;
    u32 gid;
    u32 name_len;
    char comm[TASK_COMM_LEN];
    // de->d_name.name may point to de->d_iname so limit len accordingly
	const char *fname;
    char name[64];
    char type;
	int optype;
	/*char parent1[32];
	char parent2[32];
	char parent3[32];
	char parent4[32];
	u32 directory_len;
    unsigned long inode; */
};

// the value of the output summary
struct data_t {
    u64 id;
    u64 ts;
	int ret;
    u32 pid;
    u32 uid;
	char comm[TASK_COMM_LEN]; 
    char fname[NAME_MAX]; 
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);


int trace_sys_open_entry(struct pt_regs *ctx, const char __user *filename)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
    u32 gid = bpf_get_current_uid_gid() >> 32;

    if (TGID_FILTER)
        return 0;
    if (GID_FILTER)
        return 0;
    if (UID_FILTER)
        return 0;

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        val.fname = filename;
        val.uid = uid;
        infotmp.update(&id, &val);
    }

    return 0;
}

int trace_sys_open_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
	data.uid = (u32) bpf_get_current_uid_gid();

    data.ts = tsp / 1000;
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}

/*
static int do_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, int is_read)
{
	struct task_struct *task; 
    struct dentry *tmp_de;

	char buffer[32];
    int buff_start = 0;

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    u32 uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
    if (TGID_FILTER)
        return 0;
    if (GID_FILTER)
        return 0;
    if (UID_FILTER)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    int mode = file->f_inode->i_mode;
    if (de->d_name.len == 0 || !S_ISREG(mode))
        return 0;

    // store fileops and sizes by pid & file
    struct info_t info = {.pid = pid};
    bpf_probe_read(&info.name, sizeof(info.name), (void *)de->d_name.name);
	//info.fp = file->f_path;
	
	tmp_de = de->d_parent;
   	bpf_probe_read(&buffer, 32, (void *) tmp_de->d_name.name);
	int i;
	for(i = 0; i< sizeof(info.parent1); i++) {
          info.parent1[i+buff_start] = buffer[i];
	}
  
	if (tmp_de->d_parent != NULL) {
    	tmp_de = tmp_de->d_parent;
   	    bpf_probe_read(&buffer, 32, (void *) tmp_de->d_name.name);
	    for(i = 0; i< sizeof(info.parent2); i++) {
              info.parent2[i+buff_start] = buffer[i];
	    }
	}

	if (tmp_de->d_parent != NULL) {
    	tmp_de = tmp_de->d_parent;
   	    bpf_probe_read(&buffer, 32, (void *) tmp_de->d_name.name);
	    for(i = 0; i< sizeof(info.parent3); i++) {
              info.parent3[i+buff_start] = buffer[i];
	    }
	}

	if (tmp_de->d_parent != NULL) {
    	tmp_de = tmp_de->d_parent;
   	    bpf_probe_read(&buffer, 32, (void *) tmp_de->d_name.name);
	    for(i = 0; i< sizeof(info.parent4); i++) {
              info.parent4[i+buff_start] = buffer[i];
	    }
	}

	info.inode = file->f_inode->i_ino;

    bpf_get_current_comm(&info.comm, sizeof(info.comm));
	task = (struct task_struct *)bpf_get_current_task(); 


    info.name_len = de->d_name.len;
    info.uid = uid;
    if (is_read) {
        info.type = 'R';
	} else {
        info.type = 'W';
	}

    struct val_t *valp, zero = {};
    valp = fileops.lookup_or_init(&info, &zero);
	info.optype = 12;
    if (is_read) {
        info.type = 'R';
		info.optype = 1;
        valp->reads++;
        valp->rbytes += count;
    } else {
        info.type = 'W';
		info.optype = 2;
        valp->writes++;
        valp->wbytes += count;
    }

    return 0;
}

int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return do_entry(ctx, file, buf, count, 0);
}

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return do_entry(ctx, file, buf, count, 1);
}*/


BPF_HASH(currsock, u32, struct sock *);
/*
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
        u32 pid = bpf_get_current_pid_tgid();

        // stash the sock ptr for lookup on return
        currsock.update(&pid, &sk);

        return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid();

        struct sock **skpp;
        skpp = currsock.lookup(&pid);
        if (skpp == 0) {
                return 0;       // missed entry
        }

        if (ret != 0) {
                // failed to send SYNC packet, may not have populated
                // socket __sk_common.{skc_rcv_saddr, ...}
                currsock.delete(&pid);
                return 0;
        }

        // pull in details
        struct sock *skp = *skpp;
        u32 saddr = 0, daddr = 0;
        u16 dport = 0;
        bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
        bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

        // output
        bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

        currsock.delete(&pid);

        return 0;
}
*/

