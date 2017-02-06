#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <net/sock.h>
#include <bcc/proto.h>

// the key for the output summary
struct info_t {
    u32 pid;
    u32 uid;
    u32 name_len;
    char comm[TASK_COMM_LEN];
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN];
    //char directory[1024];
    char type;
};

// the value of the output summary
struct val_t {
    u64 reads;
    u64 writes;
    u64 rbytes;
    u64 wbytes;
};

BPF_HASH(counts, struct info_t, struct val_t);

static int do_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, int is_read)
{
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
    //if (de->d_name.len == 0)
    //    return 0;

    // store counts and sizes by pid & file
    struct info_t info = {.pid = pid};
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.name_len = de->d_name.len;
    bpf_probe_read(&info.name, sizeof(info.name), (void *)de->d_name.name);
    info.uid = uid;

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_init(&info, &zero);
    if (is_read) {
        info.type = 'R';
        valp->reads++;
        valp->rbytes += count;
    } else {
        info.type = 'W';
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
}


BPF_HASH(currsock, u32, struct sock *);

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

