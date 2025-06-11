// ARM64 compatibility definitions for cross-compilation
#ifndef __ARM64_COMPAT_H__
#define __ARM64_COMPAT_H__

#if defined(__aarch64__) || defined(__TARGET_ARCH_arm64)

// ARM64 user_pt_regs structure
// This matches the kernel's definition for ARM64
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

#endif // __aarch64__ || __TARGET_ARCH_arm64

#endif // __ARM64_COMPAT_H__