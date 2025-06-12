// clang-format off
//go:build ignore
// clang-format on

// Produced by:
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
#include "include/vmlinux.h"

// ARM64 compatibility definitions
#include "include/arm64_compat.h"

#include "include/bpf_core_read.h"
#include "include/bpf_helpers.h"
#include "include/bpf_tracing.h"

// Override bpf_printk to always use bpf_trace_printk for compatibility with older kernels
#undef bpf_printk
#define bpf_printk(fmt, args...) \
({ \
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##args); \
})

#define MAX_STACK_DEPTH 64

char __license[] SEC("license") = "Dual MIT/GPL";

struct mapbucket {
  u64 size;
  u64 nstk;
  u64 stk[MAX_STACK_DEPTH];
};

struct memRecordCycle {
  u64 allocs;
  u64 frees;
  u64 allocBytes;
  u64 freeBytes;
};

struct memRecord {
  struct memRecordCycle active;
  struct memRecordCycle	future[3];
};

struct gobucket_header {
  u64 next;
  u64 allnext;
  u64 bucketType; // memBucket or blockBucket (includes mutexProfile)
  u64 hash;
  u64 size;
  u64 nstk;
};

struct gobucket {
  struct gobucket_header header;
  u64 stk[MAX_STACK_DEPTH];
  // In Go this structure comes after the stack
  struct memRecord mem;
};

struct BadnessRecord {
  u64 current_task;
  // Highest score we've seen
  pid_t canary_pid;
  s32 canary_score;
  u64 canary_task;
  // 2nd highest score
  pid_t target_pid;
  s32 target_score;
  u64 target_task;
  struct gobucket gob;
};

struct GoProc {
  u64 mbuckets; // static doesn't change
  u32 num_buckets;  // updated after each profile is recorded
};

struct Event {
    u32 event_type;
    u32 payload;
};

struct ProfileState {
    u32 pid;
    u64 gobp;
    u32 bucket_count;
    u32 current_bucket;
    u32 max_buckets;
};

// CPU local scratch for communication between oom kprobes
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct BadnessRecord);
  __uint(max_entries, 1);
} badness_record SEC(".maps");

// Tail call map for bucket processing
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 2);
  __type(key, u32);
  __type(value, u32);
} tail_call_map SEC(".maps");

// State for tail call bucket processing
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct ProfileState);
  __uint(max_entries, 1);
} profile_state SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct gobucket);
  // This is probably way too big, but we can always reduce it later.
  __uint(max_entries, 179999);
} mem_buckets SEC(".maps");

// Map of go procs to mbuckets address
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct GoProc);
  __uint(max_entries, 1024);
} go_procs SEC(".maps");

// Global entry for the pid of the process we are profiling, key always 0
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, pid_t);
  __uint(max_entries, 1);
} profile_pid SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  //__type(key, u32);
  //__type(value, u32);  // Should be u32 (file descriptor)
  //__uint(max_entries, 1024);
  __type(value, struct Event);
} signal_events SEC(".maps");

// Dummy map just to export the struct - never actually used
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct Event);  // This forces BTF generation
    __uint(max_entries, 1);
} dummy_event_map SEC(".maps");

// Dummy map just to export the struct - never actually used
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct memRecord);  // This forces BTF generation
    __uint(max_entries, 1);
} dummy_record_map SEC(".maps");

static inline __attribute__((__always_inline__)) int
record_profile_buckets(struct BadnessRecord *br, pid_t pid) {
  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &pid);
  if (!gop) {
    bpf_printk("go_procs lookup failed: %d\n", pid);
    return 0;
  }
  if (gop->mbuckets == 0) {
    bpf_printk("mbuckets is NULL, no MemProfileRate reference in program or "
               "possibly stripped\n");
    return 0;
  }

  u64 gobp;

  bpf_printk("recording profile buckets for pid: %d mbuckets:%llx\n", pid, gobp);
  if (bpf_probe_read_user(&gobp, sizeof(void*), (void*)gop->mbuckets)) {
    bpf_printk("failed to read mbuckets pointer for pid: %d\n", pid);
    return 0;
  }


  u32 i = 0;
  for (; gobp != 0; i++) {
    // Loop limit to avoid verifier issues
    if (i >= 1000) {
      bpf_printk("hit 10000 bucket limit\n");
      break;
    }

    int key = i;
    struct gobucket *mbp = bpf_map_lookup_elem(&mem_buckets, &key);
    if (!mbp) {
      bpf_printk("mem_buckets lookup failed %d:%llx\n", i, gobp);
      return 0;
    }
    // Read the entire bucket structure in one go
    // This reads: header + MAX_STACK_DEPTH stack slots + memRecord
    u64 total_size = sizeof(struct gobucket_header) +
                     (MAX_STACK_DEPTH * sizeof(u64)) +
                     sizeof(struct memRecord);

    if (bpf_probe_read_user(mbp, total_size, (void*)gobp)) {
      bpf_printk("failed to read full bucket at %llx\n", gobp);
      break;
    }


    // Skip buckets with stack depth > MAX_STACK_DEPTH
    if (mbp->header.nstk > MAX_STACK_DEPTH) {
      bpf_printk("skipping bucket %d: nstk=%llu > MAX=%d\n", i, mbp->header.nstk, MAX_STACK_DEPTH);
      gobp = mbp->header.next;
      continue;
    }

    // Only log buckets with actual allocations
    if (mbp->header.size > 0) {
      bpf_printk("bucket %d: size=%llu nstk=%llu\n", i, mbp->header.size, mbp->header.nstk);
    }

    // Move to the next bucket
    gobp = mbp->header.next;
  }

  bpf_printk("found %d gobuckets\n", i);
  gop->num_buckets = i;

  return 0;
}

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process_handler, struct oom_control *oc) {
  bpf_printk("oom_kill_process_handler\n");
  int key = 0;
  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }

  struct task_struct *victim = BPF_CORE_READ(oc, chosen);
  if (!victim) {
    bpf_printk("oom_kill_process_handler: victim is null\n");
    return 0;
  }
  pid_t victim_pid = BPF_CORE_READ(victim, tgid);
  pid_t victim_points = BPF_CORE_READ(oc, chosen_points);
  if (br->canary_pid != victim_pid) {
    bpf_printk("oom_kill_process_handler: failed to determine correct canary! %d\n", br->canary_pid);
    return 0;
  }

  bpf_printk("oom_kill_process_handler: victim pid: %d, score: %d\n",
    victim_pid, victim_points);

  bpf_printk("oom_kill_process_handler: canary pid: %d, score: %d\n",
             br->canary_pid, br->canary_score);
  bpf_printk("  target pid: %d, score: %d\n",
             br->target_pid, br->target_score);

  // We have an opportunity here to record the profile but probably better to let
  // the kernel proceed and nuke the canary and do it outside the oom context.
  // pid_t pid = bpf_get_current_pid_tgid() >> 32;
  // if (br->target_pid == pid) {
  //   br->target_pid = 0;
  //   record_profile_buckets(br, pid);
  //   return 0;
  // }

  // Send an event to user land to signal_probe to run in in target pid address
  // space.
  // TODO: Can we conditionally send a signal directly with 6.13 kernels?
  // if (__kernel__ > 6.13) {
  //   bpf_send_signal(...)
  // }
  pid_t *target_pid = bpf_map_lookup_elem(&profile_pid, &key);
  if (!target_pid) {
    bpf_printk("profile_pid lookup failed\n");
    return 0;
  }
  if (*target_pid != 0) {
    bpf_printk("oom_kill_process_handler: target pid already set: %d\n", *target_pid);
    return 0;
  }
  if (br->target_pid != 0) {
    bpf_printk("oom_kill_process_probe triggering target pid event: %d\n", br->target_pid);

    // Set the target PID in the profile_pid map so signal_probe can read it
    *target_pid = br->target_pid;

    struct Event ev = { .event_type = 0, .payload = br->target_pid};
    bpf_perf_event_output(ctx, &signal_events, BPF_F_CURRENT_CPU,
                          &ev, sizeof(struct Event));
  }
  return 0;
}

#define BADNESS_LOGGING 0

#if BADNESS_LOGGING
#define badness_log(fmt, args...) \
  bpf_printk(fmt, ##args)
#else
#define badness_log(fmt, args...) \
  do { } while (0)
#endif

SEC("kprobe/oom_badness")
int BPF_KPROBE(oom_badness_entry, struct task_struct *p) {
  int key = 0;
  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }
  br->current_task = (u64)p;
  return 0;
}

SEC("kretprobe/oom_badness")
int BPF_KRETPROBE(oom_badness_return, int score) {
  int key = 0;
  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }
  struct task_struct *task = (struct task_struct*)br->current_task;
  if (!task) {
    bpf_printk("current_task is null\n");
    return 0;
  }
  pid_t pid = BPF_CORE_READ(task, tgid);
  if (br->canary_score < score) {
    badness_log("moving canary to target, score: %d, pid: %d\n", br->canary_score, br->canary_pid);
    br->target_pid = br->canary_pid;
    br->target_score = br->canary_score;
    br->target_task = br->canary_task;
    badness_log("canary score %d->%d\n", br->canary_score, score);
    badness_log("  canary pid: %d->%d\n", br->canary_pid, pid);
    br->canary_pid = pid;
    br->canary_score = score;
    br->canary_task = (u64)task;
  } else if (br->target_score < score) {
    badness_log("target score %d->%d\n", br->target_score, score);
    badness_log("  target pid: %d->%d\n", br->target_pid, pid);
    br->target_pid = pid;
    br->target_score = score;
    br->target_task = (u64)task;
  }
  return 0;
}


// There's no scheduler tracepoint that runs in the the target process address space
// so we use signals instead.
SEC("tracepoint/signal/signal_deliver")
int signal_probe(void *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  int key = 0;
  pid_t *target_pid = bpf_map_lookup_elem(&profile_pid, &key);
  if (!target_pid || *target_pid == 0) {
    return 0;
  }
  if (*target_pid != pid) {
    return 0;
  }
  bpf_printk("target pid got signal: %d\n", pid);

  struct BadnessRecord *br = bpf_map_lookup_elem(&badness_record, &key);
  if (!br) {
    return 0;
  }
  record_profile_buckets(br, pid);

  // Signal userland
  bpf_printk("sending profile recorded event: %d\n", *target_pid);
  struct Event ev = { .event_type = 1, .payload = *target_pid};
  bpf_perf_event_output(ctx, &signal_events, BPF_F_CURRENT_CPU,
                        &ev, sizeof(struct Event));
  // perf recorded, don't do it again
  *target_pid = 0;
  return 0;
}
