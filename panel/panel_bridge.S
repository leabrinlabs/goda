/* Position-independent bridge copied into SceShellCore executable memory. */
#include "sm_shellcore_protocol_defs.h"

    .text
    .p2align 4
    .global sm_shellcore_bridge_blob_start
    .global sm_shellcore_bridge_base_end
    .global sm_shellcore_bridge_blob_end
    .global sm_shellcore_bridge_launch_hook
    .global sm_shellcore_bridge_sandbox_hook
    .global sm_shellcore_bridge_sandbox_original
    .global sm_shellcore_bridge_install_all_hook
    .global sm_shellcore_bridge_launch_trampoline
    .global sm_shellcore_bridge_install_all_trampoline
    .global sm_shellcore_bridge_install_title_dir
    .global sm_shellcore_bridge_install_armed
    .global sm_shellcore_bridge_install_title_id_0
    .global sm_shellcore_bridge_install_title_id_1
    .global sm_shellcore_bridge_install_dir_0
    .global sm_shellcore_bridge_install_dir_1
    .global sm_shellcore_bridge_thread
    .global sm_shellcore_bridge_socket
    .global sm_shellcore_bridge_setsockopt
    .global sm_shellcore_bridge_connect
    .global sm_shellcore_bridge_read
    .global sm_shellcore_bridge_write
    .global sm_shellcore_bridge_close

/*
 * SceShellCore text is execute-only. The patched address must therefore be
 * fetched as part of a movabs instruction, never loaded from a data slot.
 */
    .macro bridge_call_import slot
    .byte 0x49, 0xbb               /* movabsq $address, %r11 */
\slot:
    .quad 0
    call *%r11
    .endm

    .macro bridge_load_qword slot, stack_offset
    .byte 0x48, 0xb8               /* movabsq $value, %rax */
\slot:
    .quad 0
    movq %rax, \stack_offset(%rsp)
    .endm

sm_shellcore_bridge_blob_start:
    /* Bridge ABI v2 marker; also prevents recovery as an older bridge. */
    .byte 0x67, 0x90
sm_shellcore_bridge_launch_hook:
#ifdef D3TR_REGISTRAR
    /* Launch RPC is only a carrier; never run the original launch. */
    testq %rsi, %rsi
    je .Lregistration_denied
    movabsq $0x30303030444c4650, %rax /* PFLD0000 */
    cmpq %rax, 0(%rsi)
    jne .Lregistration_denied
    cmpw $0x0031, 8(%rsi)
    jne .Lregistration_denied
    jmp sm_shellcore_bridge_install_all_hook
#endif
    pushq %rbx
    pushq %r12
    movq %rsi, %r12
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    subq $8, %rsp
    movl $SM_SHELLCORE_REQUEST_LAUNCH_VALUE, %edi
    /* RSI still contains title_id. */
    call sm_shellcore_bridge_exchange
    addq $8, %rsp
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    testl %eax, %eax
    jz .Llaunch_allowed
    cmpl $16, %eax /* EBUSY: belongs to a different/repeated launch, do not report it as owner failure. */
    movl $0x80020005, %ebx
    je .Llaunch_done
    movl $SM_SHELLCORE_REQUEST_LAUNCH_FAILED_VALUE, %edi
    movq %r12, %rsi
    subq $8, %rsp
    call sm_shellcore_bridge_exchange
    addq $8, %rsp
    jmp .Llaunch_done
.Llaunch_allowed:
    subq $8, %rsp
    call .Llaunch_trampoline
    addq $8, %rsp
    movq %rax, %rbx
    testl %eax, %eax
    jns .Lspawn_success
    movl $SM_SHELLCORE_REQUEST_LAUNCH_FAILED_VALUE, %edi
    jmp .Lspawn_report
.Lspawn_success:
    movl $4, %edi
.Lspawn_report:
    movq %r12, %rsi
    subq $8, %rsp
    call sm_shellcore_bridge_exchange
    addq $8, %rsp
1:
.Llaunch_done:
    movq %rbx, %rax
    popq %r12
    popq %rbx
    ret

    .p2align 4
sm_shellcore_bridge_sandbox_hook:
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    subq $8, %rsp
    movl $SM_SHELLCORE_REQUEST_SANDBOX_READY_VALUE, %edi
    xorl %esi, %esi
    call sm_shellcore_bridge_exchange
    addq $8, %rsp
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    testl %eax, %eax
    jz .Lsandbox_allowed
    movl $0x80020005, %eax
    ret
.Lsandbox_allowed:
    .byte 0x49, 0xbb               /* movabsq $original, %r11 */
sm_shellcore_bridge_sandbox_original:
    .quad 0
    jmp *%r11

    .p2align 4
/* int exchange(uint16_t operation, const char *title_id) */
sm_shellcore_bridge_exchange:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    subq $120, %rsp

    /* Build the fixed-size request. */
    pxor %xmm0, %xmm0
    movups %xmm0, -80(%rbp)
    movups %xmm0, -64(%rbp)
    movq $0, -48(%rbp)
    movl $SM_SHELLCORE_PROTOCOL_MAGIC, -80(%rbp)
    movw $SM_SHELLCORE_PROTOCOL_VERSION, -76(%rbp)
    movw %di, -74(%rbp)
    testq %rsi, %rsi
    je 2f
    leaq -72(%rbp), %rdi
    movl $(SM_SHELLCORE_REQUEST_TITLE_ID_SIZE - 1), %ecx
1:
    movb (%rsi), %al
    testb %al, %al
    je 2f
    movb %al, (%rdi)
    incq %rsi
    incq %rdi
    decl %ecx
    jne 1b
2:
    bridge_call_import sm_shellcore_bridge_thread
    movl %eax, %eax
    movq %rax, -40(%rbp)
    /* Use libkernel_sys wrappers. Direct syscalls from SceShellCore are fatal. */
    movl $1, %edi
    movl $1, %esi
    xorl %edx, %edx
    bridge_call_import sm_shellcore_bridge_socket
    testl %eax, %eax
    js 8f
    movl %eax, %ebx

    /*
     * The mount preparation service is intentionally synchronous, but a
     * stalled payload must not hold SceLncServiceIpcJobQueue indefinitely.
     */
    movq $SM_SHELLCORE_BRIDGE_IO_TIMEOUT_SEC, -112(%rbp)
    cmpw $SM_SHELLCORE_REQUEST_SANDBOX_READY_VALUE, -74(%rbp)
    jne 6f
    movq $SM_SHELLCORE_BRIDGE_SANDBOX_TIMEOUT_SEC, -112(%rbp)
6:
    movq $0, -104(%rbp)
    movl %ebx, %edi
    movl $SM_SHELLCORE_BRIDGE_SOL_SOCKET, %esi
    movl $SM_SHELLCORE_BRIDGE_SO_SNDTIMEO, %edx
    leaq -112(%rbp), %rcx
    movl $SM_SHELLCORE_BRIDGE_TIMEVAL_SIZE, %r8d
    .byte 0x49, 0xbd               /* movabsq $address, %r13 */
sm_shellcore_bridge_setsockopt:
    .quad 0
    call *%r13
    testl %eax, %eax
    jne 7f
    movl %ebx, %edi
    movl $SM_SHELLCORE_BRIDGE_SOL_SOCKET, %esi
    movl $SM_SHELLCORE_BRIDGE_SO_RCVTIMEO, %edx
    leaq -112(%rbp), %rcx
    movl $SM_SHELLCORE_BRIDGE_TIMEVAL_SIZE, %r8d
    call *%r13
    testl %eax, %eax
    jne 7f

    /* Dedicated launcher AF_UNIX address, stack resident. */
    movabsq $0x65747379732f011e, %rax
    movq %rax, -144(%rbp)
    movabsq $0x33642f706d745f6d, %rax
    movq %rax, -136(%rbp)
    movabsq $0x68636e75616c7274, %rax
    movq %rax, -128(%rbp)
    movabsq $0x0000006b636f732e, %rax
    movq %rax, -120(%rbp)

    /* connect(fd, &sockaddr, sockaddr.sun_len) */
    movl %ebx, %edi
    leaq -144(%rbp), %rsi
    movl $SM_SHELLCORE_BRIDGE_SOCKADDR_SIZE, %edx
    bridge_call_import sm_shellcore_bridge_connect
    testl %eax, %eax
    jne 7f

    /* write(fd, &request, sizeof(request)) */
    movl %ebx, %edi
    leaq -80(%rbp), %rsi
    movl $SM_SHELLCORE_REQUEST_SIZE, %edx
    bridge_call_import sm_shellcore_bridge_write
    cmpq $SM_SHELLCORE_REQUEST_SIZE, %rax
    jne 7f

    /* Only status is needed by launch and launch-failure requests. */
    movl %ebx, %edi
    leaq -84(%rbp), %rsi
    movl $SM_SHELLCORE_RESPONSE_SIZE, %edx
    bridge_call_import sm_shellcore_bridge_read
    cmpq $SM_SHELLCORE_RESPONSE_SIZE, %rax
    jne 7f
    movl -84(%rbp), %r12d
    jmp 5f
7:
    movl $5, %r12d
5:
    movl %ebx, %edi
    bridge_call_import sm_shellcore_bridge_close
    movl %r12d, %eax
    jmp 9f
8:
    movl $5, %eax
9:
    addq $120, %rsp
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

    /*
     * C replaces these reserved blocks with the copied prologue followed by
     * a relative jump back into SceShellCore. Direct branches keep the
     * trampoline targets immutable after installation.
    */
    .p2align 4
.Llaunch_trampoline:
sm_shellcore_bridge_launch_trampoline:
    .fill SM_SHELLCORE_BRIDGE_TRAMPOLINE_SIZE, 1, 0x90
    /*
     * Firmware before 12.00 copies only this compact base. Keep the optional
     * install compatibility bridge after it so the 11.60 tail cave still fits.
     */
    .p2align 4
sm_shellcore_bridge_base_end:

/*
 * FW 12+ removed the public AppInstallTitleDir RPC. AppInstallAll still
 * reaches this internal dispatcher, so one explicitly armed request is
 * redirected to the internal TitleDir implementation. Every ordinary
 * AppInstallAll call follows its original trampoline unchanged.
 */
sm_shellcore_bridge_install_all_hook:
    .byte 0xb0                    /* movb $armed, %al */
sm_shellcore_bridge_install_armed:
    .byte 0
    testb %al, %al
#ifdef D3TR_REGISTRAR
    /* Registration build never falls through to the stock batch installer. */
    je .Lregistration_denied
    pushq %rbx
    subq $32, %rsp
#else
    je 1f

    /* Materialize both patched strings in readable stack memory. */
    subq $40, %rsp
#endif
    bridge_load_qword sm_shellcore_bridge_install_title_id_0, 0
    bridge_load_qword sm_shellcore_bridge_install_title_id_1, 8
    bridge_load_qword sm_shellcore_bridge_install_dir_0, 16
    bridge_load_qword sm_shellcore_bridge_install_dir_1, 24
#ifdef D3TR_REGISTRAR
    movl $10, %edi
    leaq 0(%rsp), %rsi
    call sm_shellcore_bridge_exchange
    testl %eax, %eax
    jne .Lregistration_gate_failed
#endif
    leaq 0(%rsp), %rdi
    leaq 16(%rsp), %rsi
    movl $1, %edx
    xorl %ecx, %ecx
    .byte 0x49, 0xbb             /* movabsq $address, %r11 */
sm_shellcore_bridge_install_title_dir:
    .quad 0
    call *%r11
#ifdef D3TR_REGISTRAR
    movl %eax, %ebx
    movl $11, %edi
    testl %eax, %eax
    je .Lregistration_report
    cmpl $0x80990002, %eax
    je .Lregistration_report
    movl $12, %edi
.Lregistration_report:
    leaq 0(%rsp), %rsi
    call sm_shellcore_bridge_exchange
    testl %eax, %eax
    jne .Lregistration_gate_failed
    movl %ebx, %eax
    addq $32, %rsp
    popq %rbx
    ret
.Lregistration_gate_failed:
    addq $32, %rsp
    popq %rbx
.Lregistration_denied:
    movl $0x80020010, %eax
    ret
#else
    addq $40, %rsp
    ret
1:
    jmp .Linstall_all_trampoline
#endif

    .p2align 4
.Linstall_all_trampoline:
sm_shellcore_bridge_install_all_trampoline:
    .fill SM_SHELLCORE_BRIDGE_TRAMPOLINE_SIZE, 1, 0x90

    .p2align 3
sm_shellcore_bridge_blob_end:
    .section .note.GNU-stack,"",@progbits
