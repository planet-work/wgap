#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h> 
#include <bcc/proto.h>


#define MAXARG   20
#define ARGSIZE  128


// the key for the output summary
struct val_t {
    u64 id;
    u64 ts_us;
    u32 uid;
    u32 gid;
    u32 name_len;
    u32 flags;
    char comm[TASK_COMM_LEN];
    // de->d_name.name may point to de->d_iname so limit len accordingly
    const char *data1;
    char name[64];
    char mode;
    int optype;
};


// the value of the output summary
struct data_t {
    u64 id;
    u64 ts_us;
    int ret;
    u32 pid;
    u32 uid;
    u32 gid;
    char mode;
    char comm[TASK_COMM_LEN]; 
    char data1[NAME_MAX]; 
	u64 proto;
	u64 laddr[2]; // IPv4: store in laddr[0] 
	u64 raddr[2]; // IPv4: store in laddr[0] 
	u64 lport;
	u64 rport;
	//char argv[ARGSIZE];
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(events);


int trace_sys_open_entry(struct pt_regs *ctx, const char __user *filename, int flags, umode_t mode)
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

    val.mode = 'R';
    if (flags & (O_WRONLY | O_RDWR)) {
        val.mode = 'W';
    } 
    if (MODE_FILTER)
        return 0;

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.ts_us = bpf_ktime_get_ns() / 1000;
        val.data1 = filename;
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

    u64 tsp = bpf_ktime_get_ns() / 1000;

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.data1, sizeof(data.data1), (void *)valp->data1);
    data.id = valp->id;
	data.pid = id >> 32;
    data.uid = (u32) bpf_get_current_uid_gid();
    data.mode = valp->mode;
    data.ts_us = tsp / 1000;
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->data1, sizeof(data->data1), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}


int trace_sys_execve(struct pt_regs *ctx, struct filename *filename,
	    const char __user *const __user *__argv,
	    const char __user *const __user *__envp)
{
	struct data_t data = {};
	data.mode = 'E'; // Exec
	data.pid = bpf_get_current_pid_tgid() >> 32;

    u32 uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
    u32 gid = bpf_get_current_uid_gid() >> 32;
	data.uid = uid;
	//data.gid = gid;
    data.ts_us = bpf_ktime_get_ns() / 1000;

    if (GID_FILTER)
        return 0;
    if (UID_FILTER)
        return 0;

	bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __submit_arg(ctx, (void *)filename, &data);

	return 0; // No args yet !
    
    int i = 1;  // skip first arg, as we submitted filename

    // unrolled loop to walk argv[] (MAXARG)
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++; // X
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++; // XX
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}


int trace_inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog)
{
	// cast types. Intermediate cast not needed, kept for readability
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);

	// Built event for userland
    struct data_t data = {};
	
	data.mode = 'L'; // Listen
	bpf_get_current_comm(data.comm, TASK_COMM_LEN);

	u32 uid = (u32) bpf_get_current_uid_gid();
	u32 gid = bpf_get_current_uid_gid() >> 32;

	// Get socket IP family
	u16 family = sk->__sk_common.skc_family;
	data.proto = family << 16 | SOCK_STREAM;
    data.ts_us = bpf_ktime_get_ns() / 1000;

	// Get PID
	data.pid = bpf_get_current_pid_tgid() >>32;
	data.uid = uid;

    if (GID_FILTER)
        return 0;
    if (UID_FILTER)
        return 0;
	
	//##FILTER_PID##

	// Get port
	bpf_probe_read(&data.lport, sizeof(u16), &(inet->inet_sport));
	data.lport = ntohs(data.lport);

	// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	//evt.netns = sk->__sk_common.skc_net.net->ns.inum;
#else
	//evt.netns = 0;
#endif

	//##FILTER_NETNS##

	// Get IP
	if (family == AF_INET) {
		bpf_probe_read(data.laddr, sizeof(u32), &(inet->inet_rcv_saddr));
		data.laddr[0] = be32_to_cpu(data.laddr[0]);
	} else if (family == AF_INET6) {
		bpf_probe_read(data.laddr, sizeof(data.laddr),
						sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		data.laddr[0] = be64_to_cpu(data.laddr[0]);
		data.laddr[1] = be64_to_cpu(data.laddr[1]);
	}

	// Send event to userland
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
};

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    // stash the sock ptr for lookup on return

	u32 pid = bpf_get_current_pid_tgid();
    u32 uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
    u32 gid = bpf_get_current_uid_gid() >> 32;
    if (GID_FILTER)
        return 0;
    if (UID_FILTER)
        return 0;

    currsock.update(&pid, &sk);
    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    if(PORT_FILTER) {
        currsock.delete(&pid);
        return 0;
    }

    struct data_t data = {};
	data.mode = 'C';
    data.uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
	data.pid = pid;
    data.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.rport = ntohs(dport);

	u16 family = 0; //&skp->__sk_common.skc_family;

    if (ipver == 4) {
		family = AF_INET;
        bpf_probe_read(&data.laddr[0], sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data.raddr[0], sizeof(u32),
            &skp->__sk_common.skc_daddr);
		data.laddr[0] = be32_to_cpu(data.laddr[0]);
		data.raddr[0] = be32_to_cpu(data.raddr[0]);
    } else {
		family = AF_INET6;

		bpf_probe_read(data.laddr, sizeof(data.laddr),
						&skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(data.raddr, sizeof(data.raddr),
						&skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		data.laddr[0] = be64_to_cpu(data.laddr[0]);
		data.laddr[1] = be64_to_cpu(data.laddr[1]);
		data.raddr[0] = be64_to_cpu(data.raddr[0]);
		data.raddr[1] = be64_to_cpu(data.raddr[1]);
        //data.laddr[0] = be64_to_cpu(data.laddr[0]);
		//data.laddr[1] = be64_to_cpu(data.laddr[1]);
		/*
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		*/
    }
	data.proto = family << 16 | SOCK_STREAM;	

	events.perf_submit(ctx, &data, sizeof(data));
    currsock.delete(&pid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
