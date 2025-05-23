//go:build ignore

#include "include/common.h"

// #include "bpf/bpf_helpers.h"
// #include "bpf/bpf_core_read.h"
// #include "bpf/bpf_tracing.h"

#include "bpf/bpf_core_read.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "include/vmlinux.h"

#define MAX_STACK_DEPTH 128

char __license[] SEC("license") = "Dual MIT/GPL";

struct mapbucket {
  __u64 size;
  __u64 nstk;
  __u64 stk[MAX_STACK_DEPTH];
};

struct gobucket {
  struct gobucket *next;
  struct gobucket *allnext;
  __u64 bucketType; // memBucket or blockBucket (includes mutexProfile)
  __u64 hash;
  __u64 size;
  __u64 nstk;
  //__u64 stk[MAX_STACK_DEPTH];
};

struct BadnessRecord {
  struct task_struct *current_task;
  // Highest score we've seen
  __u32 canary_pid;
  __u32 canary_score;
  // 2nd highest score
  __u32 target_pid;
  __u32 target_score;
  struct gobucket gob;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(struct BadnessRecord));
  __uint(max_entries, 1);
} badness_record SEC(".maps");

// This is the definition for the global map which both our
// bpf program and user space program can access.
// More info and map types can be found here:
// https://www.man7.org/linux/man-pages/man2/bpf.2.html
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct mapbucket);
  __uint(max_entries, 179999);
} mem_buckets SEC(".maps");

// Map of go procs to mbuckets address
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1024);
} go_procs SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process_handler) {
  bpf_printk("oom_kill_process_handler\n");
  int key = 0;
  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }
  u64 *addr = bpf_map_lookup_elem(&go_procs, &br->target_pid);
  if (!addr) {
    bpf_printk("go_procs lookup failed\n");
    return 0;
  }
  if (!*addr) {
	bpf_printk("go_procs lookup addr is null, no MemProfileRate reference in program or possibly stripped\n");
	return 0;
  }
  struct gobucket *gobp = (struct gobucket *)*addr;
  bpf_printk("recording profile buckets for %d \n", br->target_pid);
  int i = 0;
  while (gobp && i++ < 10000) {
    if (bpf_probe_read_user(&br->gob, sizeof(struct gobucket), gobp)) {
      bpf_printk("mbuckets lookup failed\n");
      return 0;
    }
    gobp = br->gob.next;
  }
  bpf_printk("found %d gobuckets: %p\n", i);
  return 0;
}

SEC("kprobe/oom_badness")
int oom_badness_entry(struct pt_regs *ctx) {
  int key = 0;
  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }
  br->current_task = (struct task_struct *)PT_REGS_PARM1(ctx);
  return 0;
}

SEC("kretprobe/oom_badness")
int oom_badness_return(struct pt_regs *ctx) {
  int key = 0;
  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }
  long score = PT_REGS_RC(ctx);
  if (br->canary_score < score) {
    br->canary_pid = BPF_CORE_READ(br->current_task, pid);
    br->canary_score = score;
  } else if (br->target_score < score) {
    br->target_pid = BPF_CORE_READ(br->current_task, pid);
    br->target_score = score;
  }
  return 0;
}

// SEC("kretprobe/get_signal")
// int BPF_KPROBE(get_signal_handler) {
// 	// lookup the current pid
// 	__u32 pid = bpf_get_current_pid_tgid() >> 32;
// 	__u64 *addr = bpf_map_lookup_elem(&go_procs, &pid);
// 	if (!addr) {
// //		bpf_printk("go_procs lookup failed\n");
// 		return 0;
// 	}
// 	struct gobucket *gobp = (struct gobucket *)(*addr & ~1ULL);
// 	if ((*addr & 0x1) == 0) {
// 		bpf_printk("record profile bit not set\n");
// 		return 0;
// 	}
// 	bpf_printk("recording profile buckets for %d \n", pid);
// 	struct gobucket gob;
// 	int i =0;
// 	while (addr && i++ < 10000) {
// 		if (bpf_probe_read_user(&gob, sizeof(gob), gobp)) {
// 			bpf_printk("mbuckets lookup failed\n");
// 			return 0;
// 		}
// 		gobp = gob.next;
// 	}
// 	bpf_printk("found %d gobuckets: %p\n", i);
// 	return 0;
// }
