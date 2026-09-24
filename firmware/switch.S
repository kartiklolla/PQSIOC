/* void coro_switch(coro_ctx *from, coro_ctx *to)
 *
 * Save the callee-saved state of the running coroutine into *from and resume
 * *to. Everything else is caller-saved, so the C compiler has already spilled
 * it. Works for RV32 and RV64 (integer ABI; the simulated VexRiscv has no FPU).
 */
#if __riscv_xlen == 64
#define STORE sd
#define LOAD  ld
#define R     8
#else
#define STORE sw
#define LOAD  lw
#define R     4
#endif

    .text
    .globl coro_switch
    .type  coro_switch, @function
coro_switch:
    STORE ra,   0*R(a0)
    STORE sp,   1*R(a0)
    STORE s0,   2*R(a0)
    STORE s1,   3*R(a0)
    STORE s2,   4*R(a0)
    STORE s3,   5*R(a0)
    STORE s4,   6*R(a0)
    STORE s5,   7*R(a0)
    STORE s6,   8*R(a0)
    STORE s7,   9*R(a0)
    STORE s8,  10*R(a0)
    STORE s9,  11*R(a0)
    STORE s10, 12*R(a0)
    STORE s11, 13*R(a0)

    LOAD  ra,   0*R(a1)
    LOAD  sp,   1*R(a1)
    LOAD  s0,   2*R(a1)
    LOAD  s1,   3*R(a1)
    LOAD  s2,   4*R(a1)
    LOAD  s3,   5*R(a1)
    LOAD  s4,   6*R(a1)
    LOAD  s5,   7*R(a1)
    LOAD  s6,   8*R(a1)
    LOAD  s7,   9*R(a1)
    LOAD  s8,  10*R(a1)
    LOAD  s9,  11*R(a1)
    LOAD  s10, 12*R(a1)
    LOAD  s11, 13*R(a1)
    ret
    .size coro_switch, .-coro_switch
