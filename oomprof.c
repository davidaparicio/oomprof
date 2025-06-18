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
// FIXME: regenerate headers using a 5.4 kernel
#undef bpf_printk
#define bpf_printk(fmt, args...) \
({ \
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##args); \
})

#define MAX_STACK_DEPTH 128

char __license[] SEC("license") = "Dual MIT/GPL";

// https://github.com/golang/go/blob/6885bad7dd/src/runtime/mprof.go#L148
struct memRecordCycle {
  u64 allocs;
  u64 frees;
  u64 allocBytes;
  u64 freeBytes;
};

// https://github.com/golang/go/blob/6885bad7dd/src/runtime/mprof.go#L87
struct memRecord {
  struct memRecordCycle active;
  struct memRecordCycle	future[3];
};

// https://github.com/golang/go/blob/6885bad7dd/src/runtime/mprof.go#L75
struct gobucket_header {
  u64 next;
  u64 allnext;
  u64 bucketType; // memBucket or blockBucket (includes mutexProfile)
  u64 hash;
  u64 size;
  u64 nstk;
};

// This isn't the real Go structure, we have a fixed stack and there's
// is variable, we calculate the address of the memRecord in Go.
struct gobucket {
  struct gobucket_header header;
  u64 stk[MAX_STACK_DEPTH];
  // In Go this structure comes after the stack
  struct memRecord _wrong_dont_use;
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
record_profile_buckets(pid_t pid) {
  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &pid);
  if (!gop) {
    bpf_printk("go_procs lookup failed: %d\n", pid);
    return 0;
  }
  if (gop->mbuckets == 0) {
    bpf_printk("mbuckets is NULL, no MemProfileRate ref in program or possibly stripped\n");
    return 0;
  }

  u64 gobp;
  if (bpf_probe_read_user(&gobp, sizeof(void*), (void*)gop->mbuckets)) {
    bpf_printk("failed to read mbuckets pointer for pid: %d\n", pid);
    return 0;
  }

  bpf_printk("recording profile buckets for pid: %d mbuckets:%llx\n", pid, gobp);
  struct gobucket *mbp = 0;
  u32 i = 0;
  for (; gobp != 0; i++, gobp = mbp->header.allnext) {
    // Loop limit to avoid verifier issues
    if (i >= 3000) {
      bpf_printk("hit bucket limit\n");
      break;
    }

    int key = i;
    mbp = bpf_map_lookup_elem(&mem_buckets, &key);
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
      // TODO: investigate why this can fail
      bpf_printk("failed to read full bucket at %llx\n", gobp);
      break;
    }

    // Skip buckets with stack depth > MAX_STACK_DEPTH
    if (mbp->header.nstk > MAX_STACK_DEPTH) {
      bpf_printk("skipping bucket %d: nstk=%llu > MAX=%d\n", i, mbp->header.nstk, MAX_STACK_DEPTH);
      continue;
    }
  }

  bpf_printk("found %d gobuckets\n", i);
  gop->num_buckets = i;

  return 0;
}

// don't rely on BTF
struct _trace_event_raw_mark_victim {
	__u64 unused;
	int pid;
};

SEC("tracepoint/oom/mark_victim")
int oom_mark_victim_handler(struct _trace_event_raw_mark_victim *args) {
  pid_t victim_pid = args->pid;
  bpf_printk("oom_mark_victim_handler: victim pid: %d\n", victim_pid);

  int key=0;
  pid_t *target_pid = bpf_map_lookup_elem(&profile_pid, &key);
  if (!target_pid) {
    bpf_printk("profile_pid lookup failed\n");
    return 0;
  }

  if (*target_pid != 0) {
    bpf_printk("profile_pid already set to %d, ignoring new victim pid %d\n",
               *target_pid, victim_pid);
    return 0;
  }

  // Set the target PID in the profile_pid map so signal_probe can read it
  // so we can distinguish true oom kills from non-oom kills.
  *target_pid = victim_pid;

  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &victim_pid);
  if (!gop) {
    bpf_printk("oommark_victim: go_procs lookup failed, timing issue? %d\n", victim_pid);
    return 0;
  }


  return 0;
}


SEC("tracepoint/signal/signal_deliver")
int signal_probe(struct trace_event_raw_signal_deliver *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &pid);
  if (!gop) {
    //bpf_printk("signal_probe: go_procs lookup failed: %d\n", pid);
    return 0;
  }

  int key=0;
  pid_t *target_pid = bpf_map_lookup_elem(&profile_pid, &key);
  if (!target_pid) {
    bpf_printk("profile_pid lookup failed\n");
    return 0;
  }
  if (*target_pid != pid) {
//    bpf_printk("signal_probe: target pid not current pid, ignoring signal\n");
    return 0;
  }
  // Usually we get a couple cracks at this and if first one fails num_buckets is 0
  if (gop->num_buckets > 0) {
    bpf_printk("signal_probe: already recorded profile for pid %d, ignoring signal\n", pid);
    return 0;
  }
  bpf_printk("go proc %d got signal\n", pid);
  record_profile_buckets(pid);

  // Signal userland
  bpf_printk("sending profile recorded event: %d\n", *target_pid);
  struct Event ev = { .event_type = 1, .payload = *target_pid};
  bpf_perf_event_output(ctx, &signal_events, BPF_F_CURRENT_CPU,
                        &ev, sizeof(struct Event));

  return 0;
}
