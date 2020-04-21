	.text
	.file	"just_bc.6bksiek5-cgu.0"
	.p2align	4, 0x90         # -- Begin function _ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE
	.type	_ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE,@function
_ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE: # @"_ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE"
	.cfi_startproc
# %bb.0:                                # %start
	movabsq	$1229646359891580772, %rax # imm = 0x111094D970B09764
	retq
.Lfunc_end0:
	.size	_ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE, .Lfunc_end0-_ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE
	.cfi_endproc
                                        # -- End function
	.hidden	_ZN3std2rt10lang_start17h9a376649ad328233E # -- Begin function _ZN3std2rt10lang_start17h9a376649ad328233E
	.globl	_ZN3std2rt10lang_start17h9a376649ad328233E
	.p2align	4, 0x90
	.type	_ZN3std2rt10lang_start17h9a376649ad328233E,@function
_ZN3std2rt10lang_start17h9a376649ad328233E: # @_ZN3std2rt10lang_start17h9a376649ad328233E
.L_ZN3std2rt10lang_start17h9a376649ad328233E$local:
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movq	%rdi, (%rsp)
	movq	%rsp, %rdi
	movl	$.Lvtable.0, %esi
	callq	*_ZN3std2rt19lang_start_internal17h14e7168ba039f170E@GOTPCREL(%rip)
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end1:
	.size	_ZN3std2rt10lang_start17h9a376649ad328233E, .Lfunc_end1-_ZN3std2rt10lang_start17h9a376649ad328233E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE
	.type	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE,@function
_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE: # @"_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE"
.Lfunc_begin0:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception0
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	subq	$80, %rsp
	.cfi_def_cfa_offset 96
	.cfi_offset %rbx, -16
	callq	*(%rdi)
	testq	%rax, %rax
	je	.LBB2_1
# %bb.2:                                # %bb5.i
	movq	%rax, (%rsp)
	movq	%rdx, 8(%rsp)
	movq	%rsp, %rax
	movq	%rax, 16(%rsp)
	movq	$_ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE, 24(%rsp)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.59, 32(%rsp)
	movq	$2, 40(%rsp)
	movq	$0, 48(%rsp)
	leaq	16(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	$1, 72(%rsp)
.Ltmp0:
	leaq	32(%rsp), %rdi
	callq	*_ZN3std2io5stdio7_eprint17h32bc25122c22ccfdE@GOTPCREL(%rip)
.Ltmp1:
# %bb.3:                                # %bb7.i.i
	movq	(%rsp), %rdi
	movq	8(%rsp), %rax
.Ltmp3:
	callq	*(%rax)
.Ltmp4:
# %bb.4:                                # %bb3.i.i10.i
	movq	8(%rsp), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB2_6
# %bb.5:                                # %bb4.i.i.i11.i
	movq	(%rsp), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB2_6:                                # %"_ZN83_$LT$core..result..Result$LT$$u21$$C$E$GT$$u20$as$u20$std..process..Termination$GT$6report17h57b7ecb7ec2880dcE.exit.i"
	movl	$1, %eax
	jmp	.LBB2_7
.LBB2_1:
	xorl	%eax, %eax
.LBB2_7:                                # %"_ZN86_$LT$core..result..Result$LT$$LP$$RP$$C$E$GT$$u20$as$u20$std..process..Termination$GT$6report17h26cc0489eabbfa95E.exit"
	addq	$80, %rsp
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.LBB2_8:                                # %cleanup.i.i12.i
	.cfi_def_cfa_offset 96
.Ltmp5:
	movq	%rax, %rbx
	movq	(%rsp), %rdi
	movq	8(%rsp), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.LBB2_9:                                # %cleanup.i.i
.Ltmp2:
	movq	%rax, %rbx
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end2:
	.size	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE, .Lfunc_end2-_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table2:
.Lexception0:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end0-.Lcst_begin0
.Lcst_begin0:
	.uleb128 .Lfunc_begin0-.Lfunc_begin0 # >> Call Site 1 <<
	.uleb128 .Ltmp0-.Lfunc_begin0   #   Call between .Lfunc_begin0 and .Ltmp0
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp0-.Lfunc_begin0   # >> Call Site 2 <<
	.uleb128 .Ltmp1-.Ltmp0          #   Call between .Ltmp0 and .Ltmp1
	.uleb128 .Ltmp2-.Lfunc_begin0   #     jumps to .Ltmp2
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp3-.Lfunc_begin0   # >> Call Site 3 <<
	.uleb128 .Ltmp4-.Ltmp3          #   Call between .Ltmp3 and .Ltmp4
	.uleb128 .Ltmp5-.Lfunc_begin0   #     jumps to .Ltmp5
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp4-.Lfunc_begin0   # >> Call Site 4 <<
	.uleb128 .Lfunc_end2-.Ltmp4     #   Call between .Ltmp4 and .Lfunc_end2
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end0:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN3std5error5Error7type_id17h59d9d71ba629941fE
	.type	_ZN3std5error5Error7type_id17h59d9d71ba629941fE,@function
_ZN3std5error5Error7type_id17h59d9d71ba629941fE: # @_ZN3std5error5Error7type_id17h59d9d71ba629941fE
	.cfi_startproc
# %bb.0:                                # %start
	movabsq	$-2214285999057668664, %rax # imm = 0xE145469D9B0BF5C8
	retq
.Lfunc_end3:
	.size	_ZN3std5error5Error7type_id17h59d9d71ba629941fE, .Lfunc_end3-_ZN3std5error5Error7type_id17h59d9d71ba629941fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN3std5error5Error9backtrace17he692434e154190d0E
	.type	_ZN3std5error5Error9backtrace17he692434e154190d0E,@function
_ZN3std5error5Error9backtrace17he692434e154190d0E: # @_ZN3std5error5Error9backtrace17he692434e154190d0E
	.cfi_startproc
# %bb.0:                                # %start
	xorl	%eax, %eax
	retq
.Lfunc_end4:
	.size	_ZN3std5error5Error9backtrace17he692434e154190d0E, .Lfunc_end4-_ZN3std5error5Error9backtrace17he692434e154190d0E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN3std6future21poll_with_tls_context17h885a604c3570a4afE
	.type	_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE,@function
_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE: # @_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE
.Lfunc_begin1:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception1
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$24, %rsp
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rsi, %rbx
	movq	%rdi, %r14
	callq	*_ZN3std6future6TLS_CX7__getit17hdaabf9d2770484c0E@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB5_7
# %bb.1:                                # %"_ZN3std6thread5local17LocalKey$LT$T$GT$4with17h77edca364093b8c6E.exit"
	movq	(%rax), %rdx
	movq	$0, (%rax)
	movq	%rdx, 16(%rsp)
	testq	%rdx, %rdx
	je	.LBB5_2
# %bb.4:                                # %bb5
	movq	(%rbx), %rsi
	movq	8(%rbx), %rcx
	movq	16(%rbx), %r8
.Ltmp6:
	movq	%r14, %rdi
	callq	*_ZN88_$LT$tokio..net..tcp..split..WriteHalf$u20$as$u20$tokio..io..async_write..AsyncWrite$GT$10poll_write17h58cb5b5072f3817bE@GOTPCREL(%rip)
.Ltmp7:
# %bb.5:                                # %bb6
	leaq	16(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
	addq	$24, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB5_7:                                # %bb5.i.i
	.cfi_def_cfa_offset 48
	leaq	8(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.LBB5_2:                                # %bb2.i
.Ltmp8:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.1, %edi
	movl	$100, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp9:
# %bb.3:                                # %.noexc
.LBB5_6:                                # %cleanup
.Ltmp10:
	movq	%rax, %rbx
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end5:
	.size	_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE, .Lfunc_end5-_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table5:
.Lexception1:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end1-.Lcst_begin1
.Lcst_begin1:
	.uleb128 .Lfunc_begin1-.Lfunc_begin1 # >> Call Site 1 <<
	.uleb128 .Ltmp6-.Lfunc_begin1   #   Call between .Lfunc_begin1 and .Ltmp6
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp6-.Lfunc_begin1   # >> Call Site 2 <<
	.uleb128 .Ltmp7-.Ltmp6          #   Call between .Ltmp6 and .Ltmp7
	.uleb128 .Ltmp10-.Lfunc_begin1  #     jumps to .Ltmp10
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp7-.Lfunc_begin1   # >> Call Site 3 <<
	.uleb128 .Ltmp8-.Ltmp7          #   Call between .Ltmp7 and .Ltmp8
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp8-.Lfunc_begin1   # >> Call Site 4 <<
	.uleb128 .Ltmp9-.Ltmp8          #   Call between .Ltmp8 and .Ltmp9
	.uleb128 .Ltmp10-.Lfunc_begin1  #     jumps to .Ltmp10
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp9-.Lfunc_begin1   # >> Call Site 5 <<
	.uleb128 .Lfunc_end5-.Ltmp9     #   Call between .Ltmp9 and .Lfunc_end5
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end1:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN3std9panicking11begin_panic17hebd941bf54afcd90E
	.type	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E,@function
_ZN3std9panicking11begin_panic17hebd941bf54afcd90E: # @_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
	.cfi_startproc
# %bb.0:                                # %bb2
	subq	$24, %rsp
	.cfi_def_cfa_offset 32
	movq	%rdx, %rcx
	movq	%rdi, 8(%rsp)
	movq	%rsi, 16(%rsp)
	leaq	8(%rsp), %rdi
	movl	$.Lvtable.2, %esi
	xorl	%edx, %edx
	callq	*_ZN3std9panicking20rust_panic_with_hook17h787d7f532b084b9aE@GOTPCREL(%rip)
.Lfunc_end6:
	.size	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E, .Lfunc_end6-_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN3std9panicking3try7do_call17h0828aa63555b211dE
	.type	_ZN3std9panicking3try7do_call17h0828aa63555b211dE,@function
_ZN3std9panicking3try7do_call17h0828aa63555b211dE: # @_ZN3std9panicking3try7do_call17h0828aa63555b211dE
.Lfunc_begin2:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception2
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$88, %rsp
	.cfi_def_cfa_offset 112
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	(%rdi), %rcx
	movq	8(%rdi), %rax
	movq	(%rcx), %rbx
	movq	%rbx, 24(%rsp)
	movb	$0, 32(%rsp)
	cmpq	$0, (%rbx)
	jne	.LBB7_1
# %bb.3:                                # %bb15.i.i.i.i
	movq	%rdi, %r14
	movq	(%rax), %rdi
.Ltmp13:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.35, %esi
	callq	*_ZN4core4task4wake8RawWaker3new17h3348ef682dfa8f58E@GOTPCREL(%rip)
.Ltmp14:
# %bb.4:                                # %.noexc5.i.i.i
	addq	$8, %rbx
	movq	%rax, 40(%rsp)
	movq	%rdx, 48(%rsp)
	leaq	40(%rsp), %rax
	movq	%rax, (%rsp)
.Ltmp15:
	movq	%rsp, %rsi
	movq	%rbx, %rdi
	callq	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E
.Ltmp16:
# %bb.5:                                # %"_ZN101_$LT$std..panic..AssertUnwindSafe$LT$F$GT$$u20$as$u20$core..ops..function..FnOnce$LT$$LP$$RP$$GT$$GT$9call_once17h84a6fee52bda7451E.exit"
	movb	$1, (%r14)
	addq	$88, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB7_1:                                # %bb2.i.i.i.i
	.cfi_def_cfa_offset 112
	movl	$_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE, %eax
	movq	%rax, %xmm0
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.27, %eax
	movq	%rax, %xmm1
	punpcklqdq	%xmm0, %xmm1    # xmm1 = xmm1[0],xmm0[0]
	movdqa	%xmm1, (%rsp)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.21, 40(%rsp)
	movq	$1, 48(%rsp)
	movq	$0, 56(%rsp)
	movq	%rsp, %rax
	movq	%rax, 72(%rsp)
	movq	$1, 80(%rsp)
.Ltmp11:
	leaq	40(%rsp), %rdi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.28, %esi
	callq	*_ZN3std9panicking15begin_panic_fmt17h8df736026eee128cE@GOTPCREL(%rip)
.Ltmp12:
# %bb.2:                                # %.noexc.i.i.i
.LBB7_6:                                # %cleanup.i.i.i
.Ltmp17:
	movq	%rax, %rbx
	leaq	24(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end7:
	.size	_ZN3std9panicking3try7do_call17h0828aa63555b211dE, .Lfunc_end7-_ZN3std9panicking3try7do_call17h0828aa63555b211dE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table7:
.Lexception2:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end2-.Lcst_begin2
.Lcst_begin2:
	.uleb128 .Ltmp13-.Lfunc_begin2  # >> Call Site 1 <<
	.uleb128 .Ltmp12-.Ltmp13        #   Call between .Ltmp13 and .Ltmp12
	.uleb128 .Ltmp17-.Lfunc_begin2  #     jumps to .Ltmp17
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp12-.Lfunc_begin2  # >> Call Site 2 <<
	.uleb128 .Lfunc_end7-.Ltmp12    #   Call between .Ltmp12 and .Lfunc_end7
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end2:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN3std9panicking3try7do_call17h356bce4e10637fc0E
	.type	_ZN3std9panicking3try7do_call17h356bce4e10637fc0E,@function
_ZN3std9panicking3try7do_call17h356bce4e10637fc0E: # @_ZN3std9panicking3try7do_call17h356bce4e10637fc0E
.Lfunc_begin3:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception3
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$184, %rsp
	.cfi_def_cfa_offset 208
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	(%rdi), %rax
	movq	(%rax), %rbx
.Ltmp18:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp19:
# %bb.1:                                # %"_ZN101_$LT$std..panic..AssertUnwindSafe$LT$F$GT$$u20$as$u20$core..ops..function..FnOnce$LT$$LP$$RP$$GT$$GT$9call_once17h2c469918848a0364E.exit"
	movq	$2, (%rbx)
	addq	$8, %rbx
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%rbx, %rdi
	callq	*memcpy@GOTPCREL(%rip)
	addq	$184, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB8_2:                                # %cleanup.i.i.i.i
	.cfi_def_cfa_offset 208
.Ltmp20:
	movq	%rax, %r14
	movq	$2, (%rbx)
	addq	$8, %rbx
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%rbx, %rdi
	callq	*memcpy@GOTPCREL(%rip)
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end8:
	.size	_ZN3std9panicking3try7do_call17h356bce4e10637fc0E, .Lfunc_end8-_ZN3std9panicking3try7do_call17h356bce4e10637fc0E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table8:
.Lexception3:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end3-.Lcst_begin3
.Lcst_begin3:
	.uleb128 .Ltmp18-.Lfunc_begin3  # >> Call Site 1 <<
	.uleb128 .Ltmp19-.Ltmp18        #   Call between .Ltmp18 and .Ltmp19
	.uleb128 .Ltmp20-.Lfunc_begin3  #     jumps to .Ltmp20
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp19-.Lfunc_begin3  # >> Call Site 2 <<
	.uleb128 .Lfunc_end8-.Ltmp19    #   Call between .Ltmp19 and .Lfunc_end8
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end3:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E
	.type	_ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E,@function
_ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E: # @_ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E
.Lfunc_begin4:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception4
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$88, %rsp
	.cfi_def_cfa_offset 112
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	(%rdi), %rcx
	movq	8(%rdi), %rax
	movq	(%rcx), %rbx
	movq	%rbx, 24(%rsp)
	movb	$0, 32(%rsp)
	cmpq	$0, (%rbx)
	jne	.LBB9_1
# %bb.3:                                # %bb15.i.i.i.i
	movq	%rdi, %r14
	movq	(%rax), %rdi
.Ltmp23:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.34, %esi
	callq	*_ZN4core4task4wake8RawWaker3new17h3348ef682dfa8f58E@GOTPCREL(%rip)
.Ltmp24:
# %bb.4:                                # %.noexc5.i.i.i
	addq	$8, %rbx
	movq	%rax, 40(%rsp)
	movq	%rdx, 48(%rsp)
	leaq	40(%rsp), %rax
	movq	%rax, (%rsp)
.Ltmp25:
	movq	%rsp, %rsi
	movq	%rbx, %rdi
	callq	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E
.Ltmp26:
# %bb.5:                                # %"_ZN101_$LT$std..panic..AssertUnwindSafe$LT$F$GT$$u20$as$u20$core..ops..function..FnOnce$LT$$LP$$RP$$GT$$GT$9call_once17h482a14af1638a4b9E.exit"
	movb	$1, (%r14)
	addq	$88, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB9_1:                                # %bb2.i.i.i.i
	.cfi_def_cfa_offset 112
	movl	$_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE, %eax
	movq	%rax, %xmm0
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.27, %eax
	movq	%rax, %xmm1
	punpcklqdq	%xmm0, %xmm1    # xmm1 = xmm1[0],xmm0[0]
	movdqa	%xmm1, (%rsp)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.21, 40(%rsp)
	movq	$1, 48(%rsp)
	movq	$0, 56(%rsp)
	movq	%rsp, %rax
	movq	%rax, 72(%rsp)
	movq	$1, 80(%rsp)
.Ltmp21:
	leaq	40(%rsp), %rdi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.28, %esi
	callq	*_ZN3std9panicking15begin_panic_fmt17h8df736026eee128cE@GOTPCREL(%rip)
.Ltmp22:
# %bb.2:                                # %.noexc.i.i.i
.LBB9_6:                                # %cleanup.i.i.i
.Ltmp27:
	movq	%rax, %rbx
	leaq	24(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end9:
	.size	_ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E, .Lfunc_end9-_ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table9:
.Lexception4:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end4-.Lcst_begin4
.Lcst_begin4:
	.uleb128 .Ltmp23-.Lfunc_begin4  # >> Call Site 1 <<
	.uleb128 .Ltmp22-.Ltmp23        #   Call between .Ltmp23 and .Ltmp22
	.uleb128 .Ltmp27-.Lfunc_begin4  #     jumps to .Ltmp27
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp22-.Lfunc_begin4  # >> Call Site 2 <<
	.uleb128 .Lfunc_end9-.Ltmp22    #   Call between .Ltmp22 and .Lfunc_end9
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end4:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE
	.type	_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE,@function
_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE: # @"_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	%rsi, %rdx
	movq	(%rdi), %rax
	movq	8(%rdi), %rsi
	movq	%rax, %rdi
	jmpq	*_ZN42_$LT$str$u20$as$u20$core..fmt..Display$GT$3fmt17hc19f19c00f549debE@GOTPCREL(%rip) # TAILCALL
.Lfunc_end10:
	.size	_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE, .Lfunc_end10-_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE
	.type	_ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE,@function
_ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE: # @"_ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	%rsi, %rdi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.3, %esi
	movl	$2, %edx
	jmpq	*_ZN4core3fmt9Formatter3pad17hb5b5664cd7ca8060E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end11:
	.size	_ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE, .Lfunc_end11-_ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E
	.type	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E,@function
_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E: # @"_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	(%rdi), %rax
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	callq	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end12:
	.size	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E, .Lfunc_end12-_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E
	.type	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E,@function
_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E: # @"_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E"
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	movq	(%rax), %rax
	movq	(%rax), %rax
	movq	(%rax), %rax
	retq
.Lfunc_end13:
	.size	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E, .Lfunc_end13-_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE
	.type	_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE,@function
_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE: # @_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE
.Lfunc_begin5:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception5
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	cmpq	$0, (%rdi)
	je	.LBB14_6
# %bb.1:                                # %bb2
	movq	%rdi, %rbx
	cmpb	$2, 8(%rdi)
	jae	.LBB14_2
.LBB14_6:                               # %bb1
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB14_2:                               # %bb2.i.i
	.cfi_def_cfa_offset 32
	movq	16(%rbx), %r15
	movq	(%r15), %rdi
	movq	8(%r15), %rax
.Ltmp28:
	callq	*(%rax)
.Ltmp29:
# %bb.3:                                # %bb3.i.i.i.i.i
	movq	8(%r15), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB14_5
# %bb.4:                                # %bb4.i.i.i.i.i.i
	movq	(%r15), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB14_5:                               # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i
	movq	16(%rbx), %rdi
	movl	$24, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB14_7:                               # %cleanup.i.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp30:
	movq	%rax, %r14
	movq	(%r15), %rdi
	movq	8(%r15), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	16(%rbx), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end14:
	.size	_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE, .Lfunc_end14-_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table14:
.Lexception5:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end5-.Lcst_begin5
.Lcst_begin5:
	.uleb128 .Ltmp28-.Lfunc_begin5  # >> Call Site 1 <<
	.uleb128 .Ltmp29-.Ltmp28        #   Call between .Ltmp28 and .Ltmp29
	.uleb128 .Ltmp30-.Lfunc_begin5  #     jumps to .Ltmp30
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp29-.Lfunc_begin5  # >> Call Site 2 <<
	.uleb128 .Lfunc_end14-.Ltmp29   #   Call between .Ltmp29 and .Lfunc_end14
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end5:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E
	.type	_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E,@function
_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E: # @_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rdi
	movl	$64, %esi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end15:
	.size	_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E, .Lfunc_end15-_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	.type	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E,@function
_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E: # @_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip) # TAILCALL
.Lfunc_end16:
	.size	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E, .Lfunc_end16-_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
	.type	_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E,@function
_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E: # @_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
	.cfi_startproc
# %bb.0:                                # %start
	cmpq	$0, (%rdi)
	je	.LBB17_1
# %bb.2:                                # %bb2
	addq	$16, %rdi
	jmpq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip) # TAILCALL
.LBB17_1:                               # %bb1
	retq
.Lfunc_end17:
	.size	_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E, .Lfunc_end17-_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E
	.type	_ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E,@function
_ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E: # @_ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	leaq	1(%rax), %rcx
	cmpq	$1, %rcx
	jbe	.LBB18_2
# %bb.1:                                # %bb3.i.i.i
	lock		subq	$1, 8(%rax)
	jne	.LBB18_2
# %bb.3:                                # %bb6.i.i.i
	#MEMBARRIER
	movq	(%rdi), %rdi
	movl	$144, %esi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB18_2:                               # %bb1
	retq
.Lfunc_end18:
	.size	_ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E, .Lfunc_end18-_ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE
	.type	_ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE,@function
_ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE: # @_ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB19_1
# %bb.2:                                # %bb3.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E # TAILCALL
.LBB19_1:                               # %_ZN4core3ptr18real_drop_in_place17hc21f2067eaf38c08E.exit
	retq
.Lfunc_end19:
	.size	_ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE, .Lfunc_end19-_ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E
	.type	_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E,@function
_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E: # @_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	testq	%rax, %rax
	je	.LBB20_2
# %bb.1:                                # %bb2
	lock		subq	$1, (%rax)
	jne	.LBB20_2
# %bb.3:                                # %bb3.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E # TAILCALL
.LBB20_2:                               # %bb1
	retq
.Lfunc_end20:
	.size	_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E, .Lfunc_end20-_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E
	.type	_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E,@function
_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E: # @_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E
.Lfunc_begin6:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception6
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	pushq	%rax
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	(%rdi), %r15
	movq	8(%rdi), %r12
	shlq	$3, %r12
	xorl	%ebx, %ebx
	movq	_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip), %r14
	.p2align	4, 0x90
.LBB21_5:                               # %bb11.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbx, %r12
	je	.LBB21_6
# %bb.4:                                # %bb10.i.i.i
                                        #   in Loop: Header=BB21_5 Depth=1
	movq	(%r15,%rbx), %rdi
	addq	$8, %rbx
.Ltmp31:
	callq	*%r14
.Ltmp32:
	jmp	.LBB21_5
.LBB21_6:                               # %"_ZN155_$LT$$LT$alloc..collections..vec_deque..VecDeque$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$..drop..Dropper$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17hbb33cffebb787837E.exit"
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB21_7:                               # %cleanup.i.i.i
	.cfi_def_cfa_offset 48
.Ltmp33:
	movq	%rax, %r14
	cmpq	%rbx, %r12
	je	.LBB21_3
.LBB21_1:                               # %bb8.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	movq	(%r15,%rbx), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	addq	$8, %rbx
	cmpq	%rbx, %r12
	jne	.LBB21_1
.LBB21_3:                               # %bb2.i.i.i
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end21:
	.size	_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E, .Lfunc_end21-_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table21:
.Lexception6:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end6-.Lcst_begin6
.Lcst_begin6:
	.uleb128 .Ltmp31-.Lfunc_begin6  # >> Call Site 1 <<
	.uleb128 .Ltmp32-.Ltmp31        #   Call between .Ltmp31 and .Ltmp32
	.uleb128 .Ltmp33-.Lfunc_begin6  #     jumps to .Ltmp33
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp32-.Lfunc_begin6  # >> Call Site 2 <<
	.uleb128 .Lfunc_end21-.Ltmp32   #   Call between .Ltmp32 and .Lfunc_end21
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end6:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE
	.type	_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE,@function
_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE: # @_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE
.Lfunc_begin7:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception7
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	(%rdi), %rbx
	testq	%rbx, %rbx
	je	.LBB22_11
# %bb.1:                                # %bb2.i.i
	movq	%rdi, %r14
	leaq	16(%rbx), %rdi
.Ltmp34:
	callq	*_ZN5tokio4sync7oneshot5State10set_closed17h1245aa12b7db01aeE@GOTPCREL(%rip)
.Ltmp35:
# %bb.2:                                # %_7.i.i.noexc.i
	movq	%rax, %r15
.Ltmp36:
	movq	%rax, %rdi
	callq	*_ZN5tokio4sync7oneshot5State14is_tx_task_set17h1483fb4bbe76be02E@GOTPCREL(%rip)
.Ltmp37:
# %bb.3:                                # %.noexc.i
	testb	%al, %al
	je	.LBB22_7
# %bb.4:                                # %bb4.i.i.i
.Ltmp38:
	movq	%r15, %rdi
	callq	*_ZN5tokio4sync7oneshot5State11is_complete17h783483c417cbb1fbE@GOTPCREL(%rip)
.Ltmp39:
# %bb.5:                                # %.noexc5.i
	testb	%al, %al
	jne	.LBB22_7
# %bb.6:                                # %bb8.i.i.i
	movq	24(%rbx), %rdi
	movq	32(%rbx), %rax
.Ltmp40:
	callq	*16(%rax)
.Ltmp41:
.LBB22_7:                               # %bb4.i
	movq	(%r14), %rax
	testq	%rax, %rax
	je	.LBB22_11
# %bb.8:                                # %bb2.i7.i
	lock		subq	$1, (%rax)
	jne	.LBB22_11
# %bb.9:                                # %bb3.i.i.i.i
	#MEMBARRIER
	movq	%r14, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E # TAILCALL
.LBB22_11:                              # %_ZN4core3ptr18real_drop_in_place17he4e9ce7ec2951332E.exit
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB22_10:                              # %cleanup.i
	.cfi_def_cfa_offset 32
.Ltmp42:
	movq	%rax, %rbx
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end22:
	.size	_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE, .Lfunc_end22-_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table22:
.Lexception7:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end7-.Lcst_begin7
.Lcst_begin7:
	.uleb128 .Ltmp34-.Lfunc_begin7  # >> Call Site 1 <<
	.uleb128 .Ltmp41-.Ltmp34        #   Call between .Ltmp34 and .Ltmp41
	.uleb128 .Ltmp42-.Lfunc_begin7  #     jumps to .Ltmp42
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp41-.Lfunc_begin7  # >> Call Site 2 <<
	.uleb128 .Lfunc_end22-.Ltmp41   #   Call between .Ltmp41 and .Lfunc_end22
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end7:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E
	.type	_ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E,@function
_ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E: # @_ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	cmpq	$2, %rax
	jne	.LBB23_1
# %bb.3:                                # %bb1
	retq
.LBB23_1:                               # %bb2
	addq	$8, %rdi
	testq	%rax, %rax
	je	.LBB23_4
# %bb.2:                                # %bb3.i
	jmp	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E # TAILCALL
.LBB23_4:                               # %bb2.i
	jmp	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E # TAILCALL
.Lfunc_end23:
	.size	_ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E, .Lfunc_end23-_ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE
	.type	_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE,@function
_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE: # @_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	cmpb	$0, 8(%rdi)
	jne	.LBB24_3
# %bb.1:                                # %bb3.i.i
	movq	(%rbx), %r14
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB24_3
# %bb.2:                                # %bb6.i.i
	movb	$1, 8(%r14)
.LBB24_3:                               # %"_ZN79_$LT$std..sync..mutex..MutexGuard$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h0174f6e69d564c90E.exit"
	movq	(%rbx), %rax
	movq	(%rax), %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*pthread_mutex_unlock@GOTPCREL(%rip) # TAILCALL
.Lfunc_end24:
	.size	_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE, .Lfunc_end24-_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE
	.type	_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE,@function
_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE: # @_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE
	.cfi_startproc
# %bb.0:                                # %start
	retq
.Lfunc_end25:
	.size	_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE, .Lfunc_end25-_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE
	.type	_ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE,@function
_ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE: # @_ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE
	.cfi_startproc
# %bb.0:                                # %start
	cmpq	$0, (%rdi)
	leaq	8(%rdi), %rdi
	je	.LBB26_1
# %bb.2:                                # %bb3
	jmp	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E # TAILCALL
.LBB26_1:                               # %bb2
	jmp	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE # TAILCALL
.Lfunc_end26:
	.size	_ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE, .Lfunc_end26-_ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E
	.type	_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E,@function
_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E: # @_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E
.Lfunc_begin8:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception8
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
.Ltmp43:
	callq	*_ZN83_$LT$tokio..runtime..context..enter..DropGuard$u20$as$u20$core..ops..drop..Drop$GT$4drop17hfc81e99be70e3074E@GOTPCREL(%rip)
.Ltmp44:
# %bb.1:                                # %bb4
	cmpl	$3, (%rbx)
	jne	.LBB27_4
# %bb.2:                                # %_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E.exit
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB27_4:                               # %bb2.i
	.cfi_def_cfa_offset 32
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE # TAILCALL
.LBB27_3:                               # %cleanup
	.cfi_def_cfa_offset 32
.Ltmp45:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end27:
	.size	_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E, .Lfunc_end27-_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table27:
.Lexception8:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end8-.Lcst_begin8
.Lcst_begin8:
	.uleb128 .Ltmp43-.Lfunc_begin8  # >> Call Site 1 <<
	.uleb128 .Ltmp44-.Ltmp43        #   Call between .Ltmp43 and .Ltmp44
	.uleb128 .Ltmp45-.Lfunc_begin8  #     jumps to .Ltmp45
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp44-.Lfunc_begin8  # >> Call Site 2 <<
	.uleb128 .Lfunc_end27-.Ltmp44   #   Call between .Ltmp44 and .Lfunc_end27
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end8:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
	.type	_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E,@function
_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E: # @_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
	.cfi_startproc
# %bb.0:                                # %start
	addq	$8, %rdi
	jmpq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end28:
	.size	_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E, .Lfunc_end28-_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE
	.type	_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE,@function
_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE: # @_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB29_1
# %bb.2:                                # %bb3.i.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E # TAILCALL
.LBB29_1:                               # %_ZN4core3ptr18real_drop_in_place17hb6066f68c21f383eE.exit
	retq
.Lfunc_end29:
	.size	_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE, .Lfunc_end29-_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E
	.type	_ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E,@function
_ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E: # @_ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E
	.cfi_startproc
# %bb.0:                                # %start
	cmpq	$0, (%rdi)
	leaq	8(%rdi), %rdi
	je	.LBB30_1
# %bb.4:                                # %bb3
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB30_5
# %bb.6:                                # %bb3.i.i.i1
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E # TAILCALL
.LBB30_1:                               # %bb2
	movq	(%rdi), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jae	.LBB30_2
.LBB30_5:                               # %bb1
	retq
.LBB30_2:                               # %bb3.i.i.i
	lock		subq	$1, 8(%rax)
	jne	.LBB30_5
# %bb.3:                                # %bb6.i.i.i
	#MEMBARRIER
	movq	(%rdi), %rdi
	movl	$144, %esi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end30:
	.size	_ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E, .Lfunc_end30-_ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h29f155998742d087E
	.type	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E,@function
_ZN4core3ptr18real_drop_in_place17h29f155998742d087E: # @_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end31:
	.size	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E, .Lfunc_end31-_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE
	.type	_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE,@function
_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE: # @_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end32:
	.size	_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE, .Lfunc_end32-_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E
	.type	_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E,@function
_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E: # @_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E
	.cfi_startproc
# %bb.0:                                # %start
	retq
.Lfunc_end33:
	.size	_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E, .Lfunc_end33-_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E
	.type	_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E,@function
_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E: # @_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	cmpq	$0, (%rdi)
	movq	8(%rdi), %r14
	movb	16(%rdi), %al
	testb	%al, %al
	jne	.LBB34_3
# %bb.1:                                # %bb3.i.i.i.i
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB34_3
# %bb.2:                                # %bb6.i.i.i.i
	movb	$1, 8(%r14)
.LBB34_3:                               # %bb1
	movq	8(%rbx), %rax
	movq	(%rax), %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*pthread_mutex_unlock@GOTPCREL(%rip) # TAILCALL
.Lfunc_end34:
	.size	_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E, .Lfunc_end34-_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
	.type	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E,@function
_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E: # @_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rdi
	testq	%rdi, %rdi
	je	.LBB35_1
# %bb.2:                                # %bb2
	jmpq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip) # TAILCALL
.LBB35_1:                               # %bb1
	retq
.Lfunc_end35:
	.size	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E, .Lfunc_end35-_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
	.type	_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E,@function
_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E: # @_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
	.cfi_startproc
# %bb.0:                                # %bb4
	movq	8(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB36_1
# %bb.2:                                # %bb4.i.i.i
	movq	(%rdi), %rdi
	movl	$1, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB36_1:                               # %_ZN4core3ptr18real_drop_in_place17hfd3237406509f55eE.exit
	retq
.Lfunc_end36:
	.size	_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E, .Lfunc_end36-_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E
	.type	_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E,@function
_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E: # @_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E
.Lfunc_begin9:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception9
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	8(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB37_2
# %bb.1:                                # %bb3.i.i.i.i.i
	leaq	8(%rbx), %rdi
	#MEMBARRIER
.Ltmp46:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E
.Ltmp47:
.LBB37_2:                               # %bb4.i.i.i
	movq	16(%rbx), %rdi
	addq	$8, %rsp
	testq	%rdi, %rdi
	je	.LBB37_5
# %bb.3:                                # %bb2.i.i.i.i.i.i
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip) # TAILCALL
.LBB37_5:                               # %_ZN4core3ptr18real_drop_in_place17ha510dadaf4fb1602E.exit
	.cfi_def_cfa_offset 32
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB37_4:                               # %cleanup.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp48:
	movq	%rax, %r14
	addq	$16, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end37:
	.size	_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E, .Lfunc_end37-_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table37:
.Lexception9:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end9-.Lcst_begin9
.Lcst_begin9:
	.uleb128 .Ltmp46-.Lfunc_begin9  # >> Call Site 1 <<
	.uleb128 .Ltmp47-.Ltmp46        #   Call between .Ltmp46 and .Ltmp47
	.uleb128 .Ltmp48-.Lfunc_begin9  #     jumps to .Ltmp48
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp47-.Lfunc_begin9  # >> Call Site 2 <<
	.uleb128 .Lfunc_end37-.Ltmp47   #   Call between .Ltmp47 and .Lfunc_end37
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end9:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE
	.type	_ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE,@function
_ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE: # @_ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	testq	%rax, %rax
	je	.LBB38_2
# %bb.1:                                # %bb2
	lock		subq	$1, (%rax)
	jne	.LBB38_2
# %bb.3:                                # %bb3.i.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE # TAILCALL
.LBB38_2:                               # %bb1
	retq
.Lfunc_end38:
	.size	_ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE, .Lfunc_end38-_ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE
	.type	_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE,@function
_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE: # @_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE
	.cfi_startproc
# %bb.0:                                # %bb4
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end39:
	.size	_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE, .Lfunc_end39-_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE
	.type	_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE,@function
_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE: # @_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE
.Lfunc_begin10:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception10
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	cmpq	$0, (%rdi)
	je	.LBB40_6
# %bb.1:                                # %bb2
	movq	%rdi, %rbx
	movq	8(%rdi), %rdi
	testq	%rdi, %rdi
	je	.LBB40_6
# %bb.2:                                # %bb2.i.i
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	8(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	24(%rbx), %rdi
	movq	32(%rbx), %rax
.Ltmp49:
	callq	*(%rax)
.Ltmp50:
# %bb.3:                                # %bb3.i.i.i.i.i
	movq	32(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB40_6
# %bb.4:                                # %bb4.i.i.i.i.i.i
	movq	24(%rbx), %rdi
	movq	16(%rax), %rdx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB40_6:                               # %bb1
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB40_5:                               # %cleanup.i.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp51:
	movq	%rax, %r14
	movq	24(%rbx), %rdi
	movq	32(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end40:
	.size	_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE, .Lfunc_end40-_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table40:
.Lexception10:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end10-.Lcst_begin10
.Lcst_begin10:
	.uleb128 .Ltmp49-.Lfunc_begin10 # >> Call Site 1 <<
	.uleb128 .Ltmp50-.Ltmp49        #   Call between .Ltmp49 and .Ltmp50
	.uleb128 .Ltmp51-.Lfunc_begin10 #     jumps to .Ltmp51
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp50-.Lfunc_begin10 # >> Call Site 2 <<
	.uleb128 .Lfunc_end40-.Ltmp50   #   Call between .Ltmp50 and .Lfunc_end40
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end10:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E
	.type	_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E,@function
_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E: # @_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E
.Lfunc_begin11:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception11
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %r15
	movq	(%rdi), %rbp
	movq	8(%rdi), %rdi
	movq	16(%r15), %r14
	movq	24(%r15), %r12
	cmpq	%rbp, %rdi
	jae	.LBB41_4
# %bb.1:                                # %bb2.i.i.i
	movq	%rdi, %r13
	cmpq	%rbp, %r12
	jae	.LBB41_6
# %bb.2:                                # %bb4.i.i.i.i.i
.Ltmp68:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.7, %edi
	movl	$28, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.6, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp69:
# %bb.3:                                # %.noexc
.LBB41_4:                               # %bb1.i.i.i.i.i.i
	cmpq	%rdi, %r12
	jb	.LBB41_7
# %bb.5:
	xorl	%r13d, %r13d
	movq	%rdi, %r12
.LBB41_6:                               # %"_ZN5alloc11collections9vec_deque17VecDeque$LT$T$GT$13as_mut_slices17hde81b29a20c22104E.exit.i"
	movq	%r14, 8(%rsp)
	movq	%r13, 16(%rsp)
	shlq	$3, %rbp
	shlq	$3, %r12
	movq	_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip), %rbx
	.p2align	4, 0x90
.LBB41_13:                              # %bb11.i.i6.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r12
	je	.LBB41_14
# %bb.12:                               # %bb10.i.i.i
                                        #   in Loop: Header=BB41_13 Depth=1
	movq	(%r14,%rbp), %rdi
	addq	$8, %rbp
.Ltmp54:
	callq	*%rbx
.Ltmp55:
	jmp	.LBB41_13
.LBB41_14:                              # %bb3.i
	shlq	$3, %r13
	xorl	%ebp, %ebp
	.p2align	4, 0x90
.LBB41_20:                              # %bb11.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r13
	je	.LBB41_21
# %bb.19:                               # %bb10.i.i.i.i.i
                                        #   in Loop: Header=BB41_20 Depth=1
	movq	(%r14,%rbp), %rdi
	addq	$8, %rbp
.Ltmp62:
	callq	*%rbx
.Ltmp63:
	jmp	.LBB41_20
.LBB41_21:                              # %bb4
	movq	24(%r15), %rsi
	testq	%rsi, %rsi
	je	.LBB41_26
# %bb.22:                               # %bb4.i.i.i
	movq	16(%r15), %rdi
	shlq	$3, %rsi
	movl	$8, %edx
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB41_26:                              # %_ZN4core3ptr18real_drop_in_place17haac8888775c883d4E.exit
	.cfi_def_cfa_offset 80
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB41_7:                               # %bb5.i.i.i.i.i.i
	.cfi_def_cfa_offset 80
.Ltmp52:
	movq	%r12, %rsi
	callq	*_ZN4core5slice20slice_index_len_fail17ha58ce2526532f1e6E@GOTPCREL(%rip)
.Ltmp53:
# %bb.8:                                # %.noexc7
.LBB41_23:                              # %cleanup.i.i.i.i.i
.Ltmp64:
	movq	%rax, %rbx
.LBB41_18:                              # %.noexc8
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r13
	je	.LBB41_30
# %bb.16:                               # %bb8.i.i.i.i.i
                                        #   in Loop: Header=BB41_18 Depth=1
	movq	(%r14,%rbp), %rdi
.Ltmp65:
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp66:
# %bb.17:                               # %.noexc8
                                        #   in Loop: Header=BB41_18 Depth=1
	addq	$8, %rbp
	jmp	.LBB41_18
.LBB41_27:                              # %cleanup.loopexit
.Ltmp67:
	jmp	.LBB41_29
.LBB41_15:                              # %cleanup.i.i.i
.Ltmp56:
	movq	%rax, %rbx
.LBB41_11:                              # %.noexc.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r12
	je	.LBB41_25
# %bb.9:                                # %bb8.i.i.i
                                        #   in Loop: Header=BB41_11 Depth=1
	movq	(%r14,%rbp), %rdi
.Ltmp57:
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp58:
# %bb.10:                               # %.noexc.i
                                        #   in Loop: Header=BB41_11 Depth=1
	addq	$8, %rbp
	jmp	.LBB41_11
.LBB41_24:                              # %cleanup.i
.Ltmp59:
	movq	%rax, %rbx
.LBB41_25:                              # %cleanup.body.i
.Ltmp60:
	leaq	8(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E
.Ltmp61:
.LBB41_30:                              # %cleanup.body
	movq	16(%r15), %rdi
	movq	24(%r15), %rsi
	callq	_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.LBB41_28:                              # %cleanup.loopexit.split-lp
.Ltmp70:
.LBB41_29:                              # %cleanup.body
	movq	%rax, %rbx
	jmp	.LBB41_30
.Lfunc_end41:
	.size	_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E, .Lfunc_end41-_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table41:
.Lexception11:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end11-.Lcst_begin11
.Lcst_begin11:
	.uleb128 .Ltmp68-.Lfunc_begin11 # >> Call Site 1 <<
	.uleb128 .Ltmp69-.Ltmp68        #   Call between .Ltmp68 and .Ltmp69
	.uleb128 .Ltmp70-.Lfunc_begin11 #     jumps to .Ltmp70
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp54-.Lfunc_begin11 # >> Call Site 2 <<
	.uleb128 .Ltmp55-.Ltmp54        #   Call between .Ltmp54 and .Ltmp55
	.uleb128 .Ltmp56-.Lfunc_begin11 #     jumps to .Ltmp56
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp62-.Lfunc_begin11 # >> Call Site 3 <<
	.uleb128 .Ltmp63-.Ltmp62        #   Call between .Ltmp62 and .Ltmp63
	.uleb128 .Ltmp64-.Lfunc_begin11 #     jumps to .Ltmp64
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp52-.Lfunc_begin11 # >> Call Site 4 <<
	.uleb128 .Ltmp53-.Ltmp52        #   Call between .Ltmp52 and .Ltmp53
	.uleb128 .Ltmp70-.Lfunc_begin11 #     jumps to .Ltmp70
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp65-.Lfunc_begin11 # >> Call Site 5 <<
	.uleb128 .Ltmp66-.Ltmp65        #   Call between .Ltmp65 and .Ltmp66
	.uleb128 .Ltmp67-.Lfunc_begin11 #     jumps to .Ltmp67
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp57-.Lfunc_begin11 # >> Call Site 6 <<
	.uleb128 .Ltmp58-.Ltmp57        #   Call between .Ltmp57 and .Ltmp58
	.uleb128 .Ltmp59-.Lfunc_begin11 #     jumps to .Ltmp59
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp60-.Lfunc_begin11 # >> Call Site 7 <<
	.uleb128 .Ltmp61-.Ltmp60        #   Call between .Ltmp60 and .Ltmp61
	.uleb128 .Ltmp70-.Lfunc_begin11 #     jumps to .Ltmp70
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp61-.Lfunc_begin11 # >> Call Site 8 <<
	.uleb128 .Lfunc_end41-.Ltmp61   #   Call between .Ltmp61 and .Lfunc_end41
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end11:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE
	.type	_ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE,@function
_ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE: # @_ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE
	.cfi_startproc
# %bb.0:                                # %start
	movq	24(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB42_1
# %bb.2:                                # %bb4.i.i.i.i
	movq	16(%rdi), %rdi
	movl	$1, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB42_1:                               # %_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E.exit
	retq
.Lfunc_end42:
	.size	_ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE, .Lfunc_end42-_ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE
	.type	_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE,@function
_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE: # @_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	testq	%rax, %rax
	je	.LBB43_2
# %bb.1:                                # %bb2
	lock		subq	$1, (%rax)
	jne	.LBB43_2
# %bb.3:                                # %bb3.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E # TAILCALL
.LBB43_2:                               # %bb1
	retq
.Lfunc_end43:
	.size	_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE, .Lfunc_end43-_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E
	.type	_ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E,@function
_ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E: # @_ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E
.Lfunc_begin12:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception12
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	cmpq	$0, (%rdi)
	je	.LBB44_6
# %bb.1:                                # %bb2
	movq	%rdi, %rbx
	movq	8(%rdi), %rdi
	testq	%rdi, %rdi
	je	.LBB44_6
# %bb.2:                                # %bb2.i
	movq	16(%rbx), %rax
.Ltmp71:
	callq	*(%rax)
.Ltmp72:
# %bb.3:                                # %bb3.i.i
	movq	16(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB44_6
# %bb.4:                                # %bb4.i.i.i
	movq	8(%rbx), %rdi
	movq	16(%rax), %rdx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB44_6:                               # %bb1
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB44_5:                               # %cleanup.i.i
	.cfi_def_cfa_offset 32
.Ltmp73:
	movq	%rax, %r14
	movq	8(%rbx), %rdi
	movq	16(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end44:
	.size	_ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E, .Lfunc_end44-_ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table44:
.Lexception12:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end12-.Lcst_begin12
.Lcst_begin12:
	.uleb128 .Ltmp71-.Lfunc_begin12 # >> Call Site 1 <<
	.uleb128 .Ltmp72-.Ltmp71        #   Call between .Ltmp71 and .Ltmp72
	.uleb128 .Ltmp73-.Lfunc_begin12 #     jumps to .Ltmp73
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp72-.Lfunc_begin12 # >> Call Site 2 <<
	.uleb128 .Lfunc_end44-.Ltmp72   #   Call between .Ltmp72 and .Lfunc_end44
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end12:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE
	.type	_ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE,@function
_ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE: # @_ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE
	.cfi_startproc
# %bb.0:                                # %bb5
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	addq	$16, %rbx
	movq	%rbx, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmp	_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E # TAILCALL
.Lfunc_end45:
	.size	_ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE, .Lfunc_end45-_ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h47f721620558509eE
	.type	_ZN4core3ptr18real_drop_in_place17h47f721620558509eE,@function
_ZN4core3ptr18real_drop_in_place17h47f721620558509eE: # @_ZN4core3ptr18real_drop_in_place17h47f721620558509eE
.Lfunc_begin13:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception13
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
.Ltmp74:
	callq	*_ZN79_$LT$tokio..io..registration..Registration$u20$as$u20$core..ops..drop..Drop$GT$4drop17he0fe257dfb231b17E@GOTPCREL(%rip)
.Ltmp75:
# %bb.1:                                # %bb4.i
	movq	(%rbx), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jae	.LBB46_2
.LBB46_5:                               # %_ZN4core3ptr18real_drop_in_place17h1bb71f698366d10fE.exit
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB46_2:                               # %bb3.i.i.i.i
	.cfi_def_cfa_offset 32
	lock		subq	$1, 8(%rax)
	jne	.LBB46_5
# %bb.3:                                # %bb6.i.i.i.i
	#MEMBARRIER
	movq	(%rbx), %rdi
	movl	$144, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB46_4:                               # %cleanup.i
	.cfi_def_cfa_offset 32
.Ltmp76:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end46:
	.size	_ZN4core3ptr18real_drop_in_place17h47f721620558509eE, .Lfunc_end46-_ZN4core3ptr18real_drop_in_place17h47f721620558509eE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table46:
.Lexception13:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end13-.Lcst_begin13
.Lcst_begin13:
	.uleb128 .Ltmp74-.Lfunc_begin13 # >> Call Site 1 <<
	.uleb128 .Ltmp75-.Ltmp74        #   Call between .Ltmp74 and .Ltmp75
	.uleb128 .Ltmp76-.Lfunc_begin13 #     jumps to .Ltmp76
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp75-.Lfunc_begin13 # >> Call Site 2 <<
	.uleb128 .Lfunc_end46-.Ltmp75   #   Call between .Ltmp75 and .Lfunc_end46
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end13:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
	.type	_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E,@function
_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E: # @_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
	.cfi_startproc
# %bb.0:                                # %start
	movq	16(%rdi), %rax
	testq	%rax, %rax
	je	.LBB47_1
# %bb.2:                                # %bb2.i.i.i
	movq	8(%rdi), %rdi
	jmpq	*24(%rax)               # TAILCALL
.LBB47_1:                               # %_ZN4core3ptr18real_drop_in_place17ha637d94ffbd9b2f6E.exit
	retq
.Lfunc_end47:
	.size	_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E, .Lfunc_end47-_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E
	.type	_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E,@function
_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E: # @_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN115_$LT$tokio..runtime..basic_scheduler..BasicScheduler$LT$P$GT$..block_on..Guard$u20$as$u20$core..ops..drop..Drop$GT$4drop17hbbd208e653d590c4E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end48:
	.size	_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E, .Lfunc_end48-_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E
	.type	_ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E,@function
_ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E: # @_ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	cmpl	$0, (%rdi)
	je	.LBB49_4
# %bb.1:                                # %bb2
	movq	8(%rdi), %rax
	movq	$0, 8(%rdi)
	testq	%rax, %rax
	je	.LBB49_4
# %bb.2:                                # %bb2.i.i
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB49_4
# %bb.3:                                # %bb5.i.i
	movq	(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.LBB49_4:                               # %bb1
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end49:
	.size	_ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E, .Lfunc_end49-_ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE
	.type	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE,@function
_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE: # @_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE
.Lfunc_begin14:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception14
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	subq	$80, %rsp
	.cfi_def_cfa_offset 128
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r13
	movq	(%rdi), %rax
	movq	$0, (%rdi)
	movq	%rax, 56(%rsp)
	movups	8(%rdi), %xmm0
	movups	%xmm0, 64(%rsp)
	cmpq	$1, %rax
	jne	.LBB50_18
# %bb.1:                                # %bb3.i.i
	leaq	64(%rsp), %rax
	movups	(%rax), %xmm0
	movaps	%xmm0, 16(%rsp)
	leaq	24(%r13), %r14
.Ltmp77:
	movq	%r14, %rdi
	callq	*_ZN5tokio2io6driver6Handle5inner17heb68f52174073405E@GOTPCREL(%rip)
.Ltmp78:
# %bb.2:                                # %.noexc.i.i
	movq	%rax, %rbx
	movq	%rax, 48(%rsp)
	testq	%rax, %rax
	je	.LBB50_3
# %bb.6:                                # %bb5.i.i.i
	movq	%rbx, (%rsp)
	movq	%rbx, %rsi
	addq	$16, %rsi
.Ltmp79:
	leaq	32(%rsp), %rdi
	leaq	16(%rsp), %rdx
	movl	$.Lvtable.b, %ecx
	callq	*_ZN5tokio2io6driver5Inner17deregister_source17h6390581a88aedb6eE@GOTPCREL(%rip)
.Ltmp80:
# %bb.7:                                # %bb12.i.i.i
	lock		subq	$1, (%rbx)
	jne	.LBB50_9
# %bb.8:                                # %bb3.i.i.i.i.i
	#MEMBARRIER
.Ltmp84:
	movq	%rsp, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E
.Ltmp85:
	jmp	.LBB50_9
.LBB50_3:                               # %bb3.i.i.i
.Ltmp86:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.13, %edi
	movl	$12, %esi
	callq	*_ZN3std5error161_$LT$impl$u20$core..convert..From$LT$$RF$str$GT$$u20$for$u20$alloc..boxed..Box$LT$dyn$u20$std..error..Error$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$4from17h3380ca6fb4be57d1E@GOTPCREL(%rip)
.Ltmp87:
# %bb.4:                                # %.noexc.i.i.i
	movq	%rdx, %rcx
.Ltmp88:
	movq	%rsp, %rdi
	movl	$16, %esi
	movq	%rax, %rdx
	callq	*_ZN3std2io5error5Error4_new17h9d3cc36308b63b32E@GOTPCREL(%rip)
.Ltmp89:
# %bb.5:                                # %_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E.exit.i.i.i
	movups	(%rsp), %xmm0
	movaps	%xmm0, 32(%rsp)
.LBB50_9:                               # %bb4.i.i
	movb	32(%rsp), %al
	cmpb	$3, %al
	ja	.LBB50_11
# %bb.10:                               # %bb4.i.i
	cmpb	$2, %al
	jne	.LBB50_15
.LBB50_11:                              # %bb2.i.i.i.i.i
	movq	40(%rsp), %r12
	movq	(%r12), %rdi
	movq	8(%r12), %rax
.Ltmp94:
	callq	*(%rax)
.Ltmp95:
# %bb.12:                               # %bb3.i.i.i.i.i.i.i.i
	movq	8(%r12), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB50_14
# %bb.13:                               # %bb4.i.i.i.i.i.i.i.i.i
	movq	(%r12), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB50_14:                              # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i
	movl	$24, %esi
	movl	$8, %edx
	movq	%r12, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB50_15:                              # %bb7.i.i
	leaq	24(%rsp), %rdi
.Ltmp99:
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp100:
# %bb.16:                               # %bb6.i
	cmpq	$0, (%r13)
	je	.LBB50_18
# %bb.17:                               # %bb2.i.i
	leaq	16(%r13), %rdi
.Ltmp105:
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp106:
.LBB50_18:                              # %bb5.i
	addq	$24, %r13
.Ltmp108:
	movq	%r13, %rdi
	callq	*_ZN79_$LT$tokio..io..registration..Registration$u20$as$u20$core..ops..drop..Drop$GT$4drop17he0fe257dfb231b17E@GOTPCREL(%rip)
.Ltmp109:
# %bb.19:                               # %bb4.i.i.i
	movq	(%r13), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jae	.LBB50_20
.LBB50_22:                              # %_ZN4core3ptr18real_drop_in_place17h2ff7e69193ffba22E.exit
	addq	$80, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB50_20:                              # %bb3.i.i.i.i.i.i
	.cfi_def_cfa_offset 128
	lock		subq	$1, 8(%rax)
	jne	.LBB50_22
# %bb.21:                               # %bb6.i.i.i.i.i.i
	#MEMBARRIER
	movq	(%r13), %rdi
	movl	$144, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB50_22
.LBB50_25:                              # %cleanup.i.i.i.i.i.i.i.i
.Ltmp96:
	movq	%rax, %r15
                                        # kill: killed $rdx
	movq	(%r12), %rdi
	movq	8(%r12), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r12, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB50_27
.LBB50_34:                              # %cleanup1.i
.Ltmp107:
	movq	%rax, %r15
	jmp	.LBB50_33
.LBB50_23:                              # %cleanup.i.i.i
.Ltmp81:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp82:
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E
.Ltmp83:
	jmp	.LBB50_27
.LBB50_24:                              # %cleanup2.i.i.i
.Ltmp90:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp91:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E
.Ltmp92:
	jmp	.LBB50_27
.LBB50_30:                              # %cleanup1.i.i
.Ltmp101:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB50_28
.LBB50_26:                              # %cleanup.i.i
.Ltmp93:
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB50_27:                              # %cleanup.body.i.i
.Ltmp97:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
.Ltmp98:
.LBB50_28:                              # %bb5.i.i
	cmpl	$1, 56(%rsp)
	je	.LBB50_32
# %bb.29:                               # %bb9.i.i
.Ltmp102:
	leaq	56(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
.Ltmp103:
.LBB50_32:                              # %cleanup.body.i
	movq	%r13, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
.LBB50_33:                              # %bb3.i
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h47f721620558509eE
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB50_31:                              # %cleanup.i
.Ltmp104:
	movq	%rax, %r15
	jmp	.LBB50_32
.LBB50_35:                              # %cleanup.i.i9.i
.Ltmp110:
	movq	%rax, %r15
	movq	%r13, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E
	movq	%r15, %rdi
	callq	_Unwind_Resume
.Lfunc_end50:
	.size	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE, .Lfunc_end50-_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table50:
.Lexception14:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end14-.Lcst_begin14
.Lcst_begin14:
	.uleb128 .Ltmp77-.Lfunc_begin14 # >> Call Site 1 <<
	.uleb128 .Ltmp78-.Ltmp77        #   Call between .Ltmp77 and .Ltmp78
	.uleb128 .Ltmp93-.Lfunc_begin14 #     jumps to .Ltmp93
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp79-.Lfunc_begin14 # >> Call Site 2 <<
	.uleb128 .Ltmp80-.Ltmp79        #   Call between .Ltmp79 and .Ltmp80
	.uleb128 .Ltmp81-.Lfunc_begin14 #     jumps to .Ltmp81
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp84-.Lfunc_begin14 # >> Call Site 3 <<
	.uleb128 .Ltmp85-.Ltmp84        #   Call between .Ltmp84 and .Ltmp85
	.uleb128 .Ltmp93-.Lfunc_begin14 #     jumps to .Ltmp93
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp86-.Lfunc_begin14 # >> Call Site 4 <<
	.uleb128 .Ltmp89-.Ltmp86        #   Call between .Ltmp86 and .Ltmp89
	.uleb128 .Ltmp90-.Lfunc_begin14 #     jumps to .Ltmp90
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp94-.Lfunc_begin14 # >> Call Site 5 <<
	.uleb128 .Ltmp95-.Ltmp94        #   Call between .Ltmp94 and .Ltmp95
	.uleb128 .Ltmp96-.Lfunc_begin14 #     jumps to .Ltmp96
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp99-.Lfunc_begin14 # >> Call Site 6 <<
	.uleb128 .Ltmp100-.Ltmp99       #   Call between .Ltmp99 and .Ltmp100
	.uleb128 .Ltmp101-.Lfunc_begin14 #     jumps to .Ltmp101
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp105-.Lfunc_begin14 # >> Call Site 7 <<
	.uleb128 .Ltmp106-.Ltmp105      #   Call between .Ltmp105 and .Ltmp106
	.uleb128 .Ltmp107-.Lfunc_begin14 #     jumps to .Ltmp107
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp108-.Lfunc_begin14 # >> Call Site 8 <<
	.uleb128 .Ltmp109-.Ltmp108      #   Call between .Ltmp108 and .Ltmp109
	.uleb128 .Ltmp110-.Lfunc_begin14 #     jumps to .Ltmp110
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp82-.Lfunc_begin14 # >> Call Site 9 <<
	.uleb128 .Ltmp92-.Ltmp82        #   Call between .Ltmp82 and .Ltmp92
	.uleb128 .Ltmp93-.Lfunc_begin14 #     jumps to .Ltmp93
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp97-.Lfunc_begin14 # >> Call Site 10 <<
	.uleb128 .Ltmp103-.Ltmp97       #   Call between .Ltmp97 and .Ltmp103
	.uleb128 .Ltmp104-.Lfunc_begin14 #     jumps to .Ltmp104
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp103-.Lfunc_begin14 # >> Call Site 11 <<
	.uleb128 .Lfunc_end50-.Ltmp103  #   Call between .Ltmp103 and .Lfunc_end50
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end14:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E
	.type	_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E,@function
_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E: # @_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E
.Lfunc_begin15:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception15
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
.Ltmp111:
	callq	*_ZN69_$LT$std..sync..condvar..Condvar$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4eee38946b40573cE@GOTPCREL(%rip)
.Ltmp112:
# %bb.1:                                # %bb4
	movq	(%rbx), %rdi
	movl	$48, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB51_2:                               # %cleanup
	.cfi_def_cfa_offset 32
.Ltmp113:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end51:
	.size	_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E, .Lfunc_end51-_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table51:
.Lexception15:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end15-.Lcst_begin15
.Lcst_begin15:
	.uleb128 .Ltmp111-.Lfunc_begin15 # >> Call Site 1 <<
	.uleb128 .Ltmp112-.Ltmp111      #   Call between .Ltmp111 and .Ltmp112
	.uleb128 .Ltmp113-.Lfunc_begin15 #     jumps to .Ltmp113
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp112-.Lfunc_begin15 # >> Call Site 2 <<
	.uleb128 .Lfunc_end51-.Ltmp112  #   Call between .Ltmp112 and .Lfunc_end51
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end15:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE
	.type	_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE,@function
_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE: # @_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN70_$LT$mio..poll..RegistrationInner$u20$as$u20$core..ops..drop..Drop$GT$4drop17h45090a25a224e339E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end52:
	.size	_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE, .Lfunc_end52-_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
	.type	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E,@function
_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E: # @_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Lfunc_begin16:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception16
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	cmpb	$2, (%rdi)
	jae	.LBB53_1
# %bb.5:                                # %_ZN4core3ptr18real_drop_in_place17h84d8a3b4c84014e2E.exit
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB53_1:                               # %bb2.i
	.cfi_def_cfa_offset 32
	movq	%rdi, %r15
	movq	8(%rdi), %rbx
	movq	(%rbx), %rdi
	movq	8(%rbx), %rax
.Ltmp114:
	callq	*(%rax)
.Ltmp115:
# %bb.2:                                # %bb3.i.i.i.i
	movq	8(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB53_4
# %bb.3:                                # %bb4.i.i.i.i.i
	movq	(%rbx), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB53_4:                               # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i
	movq	8(%r15), %rdi
	movl	$24, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB53_6:                               # %cleanup.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp116:
	movq	%rax, %r14
	movq	(%rbx), %rdi
	movq	8(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	8(%r15), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end53:
	.size	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E, .Lfunc_end53-_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table53:
.Lexception16:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end16-.Lcst_begin16
.Lcst_begin16:
	.uleb128 .Ltmp114-.Lfunc_begin16 # >> Call Site 1 <<
	.uleb128 .Ltmp115-.Ltmp114      #   Call between .Ltmp114 and .Ltmp115
	.uleb128 .Ltmp116-.Lfunc_begin16 #     jumps to .Ltmp116
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp115-.Lfunc_begin16 # >> Call Site 2 <<
	.uleb128 .Lfunc_end53-.Ltmp115  #   Call between .Ltmp115 and .Lfunc_end53
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end16:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E
	.type	_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E,@function
_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E: # @_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	cmpb	$0, 8(%rdi)
	jne	.LBB54_3
# %bb.1:                                # %bb3.i.i.i
	movq	(%rbx), %r14
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB54_3
# %bb.2:                                # %bb6.i.i.i
	movb	$1, 8(%r14)
.LBB54_3:                               # %_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE.exit
	movq	(%rbx), %rax
	movq	(%rax), %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*pthread_mutex_unlock@GOTPCREL(%rip) # TAILCALL
.Lfunc_end54:
	.size	_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E, .Lfunc_end54-_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE
	.type	_ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE,@function
_ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE: # @_ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE
.Lfunc_begin17:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception17
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rdi
	testq	%rdi, %rdi
	je	.LBB55_5
# %bb.1:                                # %bb2
	movq	8(%rbx), %rax
.Ltmp117:
	callq	*(%rax)
.Ltmp118:
# %bb.2:                                # %bb3.i
	movq	8(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB55_5
# %bb.3:                                # %bb4.i.i
	movq	(%rbx), %rdi
	movq	16(%rax), %rdx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB55_5:                               # %bb1
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB55_4:                               # %cleanup.i
	.cfi_def_cfa_offset 32
.Ltmp119:
	movq	%rax, %r14
	movq	(%rbx), %rdi
	movq	8(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end55:
	.size	_ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE, .Lfunc_end55-_ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table55:
.Lexception17:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end17-.Lcst_begin17
.Lcst_begin17:
	.uleb128 .Ltmp117-.Lfunc_begin17 # >> Call Site 1 <<
	.uleb128 .Ltmp118-.Ltmp117      #   Call between .Ltmp117 and .Ltmp118
	.uleb128 .Ltmp119-.Lfunc_begin17 #     jumps to .Ltmp119
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp118-.Lfunc_begin17 # >> Call Site 2 <<
	.uleb128 .Lfunc_end55-.Ltmp118  #   Call between .Ltmp118 and .Lfunc_end55
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end17:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h691669770397616fE
	.type	_ZN4core3ptr18real_drop_in_place17h691669770397616fE,@function
_ZN4core3ptr18real_drop_in_place17h691669770397616fE: # @_ZN4core3ptr18real_drop_in_place17h691669770397616fE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	cmpq	$1, %rax
	je	.LBB56_3
# %bb.1:                                # %start
	testq	%rax, %rax
	je	.LBB56_2
# %bb.5:                                # %bb3
	movq	8(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB56_2
# %bb.6:                                # %bb3.i.i.i4
	addq	$8, %rdi
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE # TAILCALL
.LBB56_3:                               # %bb2
	movq	8(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB56_2
# %bb.4:                                # %bb3.i.i.i
	addq	$8, %rdi
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E # TAILCALL
.LBB56_2:                               # %bb1
	retq
.Lfunc_end56:
	.size	_ZN4core3ptr18real_drop_in_place17h691669770397616fE, .Lfunc_end56-_ZN4core3ptr18real_drop_in_place17h691669770397616fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E
	.type	_ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E,@function
_ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E: # @_ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB57_1
# %bb.2:                                # %bb3.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E # TAILCALL
.LBB57_1:                               # %"_ZN67_$LT$alloc..sync..Arc$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h203bbea02d7e2a24E.exit"
	retq
.Lfunc_end57:
	.size	_ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E, .Lfunc_end57-_ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E
	.type	_ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E,@function
_ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E: # @_ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	movq	8(%rdi), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	8(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	32(%rbx), %rsi
	testq	%rsi, %rsi
	je	.LBB58_1
# %bb.2:                                # %bb4.i.i.i.i.i.i
	movq	24(%rbx), %rdi
	shlq	$3, %rsi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB58_1:                               # %_ZN4core3ptr18real_drop_in_place17hb3e81a9042209f22E.exit
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end58:
	.size	_ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E, .Lfunc_end58-_ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE
	.type	_ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE,@function
_ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE: # @_ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE
.Lfunc_begin18:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception18
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
.Ltmp120:
	callq	*_ZN65_$LT$mio..poll..Registration$u20$as$u20$core..ops..drop..Drop$GT$4drop17hbe158bb9c1ab5543E@GOTPCREL(%rip)
.Ltmp121:
# %bb.1:                                # %bb4
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN70_$LT$mio..poll..RegistrationInner$u20$as$u20$core..ops..drop..Drop$GT$4drop17h45090a25a224e339E@GOTPCREL(%rip) # TAILCALL
.LBB59_2:                               # %cleanup
	.cfi_def_cfa_offset 32
.Ltmp122:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end59:
	.size	_ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE, .Lfunc_end59-_ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table59:
.Lexception18:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end18-.Lcst_begin18
.Lcst_begin18:
	.uleb128 .Ltmp120-.Lfunc_begin18 # >> Call Site 1 <<
	.uleb128 .Ltmp121-.Ltmp120      #   Call between .Ltmp120 and .Ltmp121
	.uleb128 .Ltmp122-.Lfunc_begin18 #     jumps to .Ltmp122
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp121-.Lfunc_begin18 # >> Call Site 2 <<
	.uleb128 .Lfunc_end59-.Ltmp121  #   Call between .Ltmp121 and .Lfunc_end59
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end18:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E
	.type	_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E,@function
_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E: # @_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E
	.cfi_startproc
# %bb.0:                                # %start
	cmpl	$3, (%rdi)
	jne	.LBB60_2
# %bb.1:                                # %bb1
	retq
.LBB60_2:                               # %bb2
	jmp	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE # TAILCALL
.Lfunc_end60:
	.size	_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E, .Lfunc_end60-_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
	.type	_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E,@function
_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E: # @_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	testq	%rax, %rax
	je	.LBB61_2
# %bb.1:                                # %bb2
	lock		subq	$1, (%rax)
	jne	.LBB61_2
# %bb.3:                                # %bb3.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE # TAILCALL
.LBB61_2:                               # %bb1
	retq
.Lfunc_end61:
	.size	_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E, .Lfunc_end61-_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h7adc16293b341271E
	.type	_ZN4core3ptr18real_drop_in_place17h7adc16293b341271E,@function
_ZN4core3ptr18real_drop_in_place17h7adc16293b341271E: # @_ZN4core3ptr18real_drop_in_place17h7adc16293b341271E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	cmpl	$3, 72(%rdi)
	jne	.LBB62_5
# %bb.1:                                # %bb12.i
	cmpl	$0, 32(%rdi)
	je	.LBB62_5
# %bb.2:                                # %bb2.i.i
	movq	40(%rdi), %rax
	movq	$0, 40(%rdi)
	testq	%rax, %rax
	je	.LBB62_5
# %bb.3:                                # %bb2.i.i.i.i
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB62_5
# %bb.4:                                # %bb5.i.i.i.i
	movq	(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.LBB62_5:                               # %_ZN4core3ptr18real_drop_in_place17hf00f322d9e323da6E.exit
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end62:
	.size	_ZN4core3ptr18real_drop_in_place17h7adc16293b341271E, .Lfunc_end62-_ZN4core3ptr18real_drop_in_place17h7adc16293b341271E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE
	.type	_ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE,@function
_ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE: # @_ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB63_1
# %bb.2:                                # %bb3.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E # TAILCALL
.LBB63_1:                               # %"_ZN67_$LT$alloc..sync..Arc$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17hd4a462d8c71cf916E.exit"
	retq
.Lfunc_end63:
	.size	_ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE, .Lfunc_end63-_ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE
	.type	_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE,@function
_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE: # @_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE
.Lfunc_begin19:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception19
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	24(%rdi), %r15
	testq	%r15, %r15
	je	.LBB64_23
# %bb.1:                                # %bb2.i.i.i
	movq	%rdi, %r12
	movq	32(%rdi), %r13
	testq	%r13, %r13
	je	.LBB64_23
# %bb.2:                                # %bb10.preheader.i.i.i.i.i
	shlq	$6, %r13
	xorl	%ebx, %ebx
	movq	_ZN86_$LT$tokio..io..driver..scheduled_io..ScheduledIo$u20$as$u20$core..ops..drop..Drop$GT$4drop17h0f6da5c3897a82caE@GOTPCREL(%rip), %r14
	jmp	.LBB64_3
	.p2align	4, 0x90
.LBB64_8:                               # %_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE.exit.i.i.i.i.i
                                        #   in Loop: Header=BB64_3 Depth=1
	addq	$64, %rbx
	cmpq	%rbx, %r13
	je	.LBB64_9
.LBB64_3:                               # %bb10.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	leaq	(%r15,%rbx), %rdi
	addq	$8, %rdi
.Ltmp123:
	callq	*%r14
.Ltmp124:
# %bb.4:                                # %bb6.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB64_3 Depth=1
	movq	32(%r15,%rbx), %rax
	testq	%rax, %rax
	je	.LBB64_6
# %bb.5:                                # %bb2.i.i.i.i10.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB64_3 Depth=1
	movq	24(%r15,%rbx), %rdi
.Ltmp128:
	callq	*24(%rax)
.Ltmp129:
.LBB64_6:                               # %bb5.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB64_3 Depth=1
	movq	56(%r15,%rbx), %rax
	testq	%rax, %rax
	je	.LBB64_8
# %bb.7:                                # %bb2.i.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB64_3 Depth=1
	movq	48(%r15,%rbx), %rdi
.Ltmp134:
	callq	*24(%rax)
.Ltmp135:
	jmp	.LBB64_8
.LBB64_9:                               # %bb3.i.i.i.i
	movq	32(%r12), %rsi
	shlq	$6, %rsi
	je	.LBB64_23
# %bb.10:                               # %bb4.i.i.i.i.i
	movq	24(%r12), %rdi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB64_23:                              # %_ZN4core3ptr18real_drop_in_place17hb27fb0c9e6fe59a4E.exit
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB64_16:                              # %cleanup.loopexit.i.i.i.i.i
	.cfi_def_cfa_offset 48
.Ltmp136:
.LBB64_18:                              # %cleanup.body.i.i.i.i.i
	movq	%rax, %r14
	jmp	.LBB64_19
.LBB64_13:                              # %cleanup1.i.i.i.i.i.i.i
.Ltmp130:
	movq	%rax, %r14
	jmp	.LBB64_14
.LBB64_15:                              # %cleanup.i.i.i.i.i.i.i
.Ltmp125:
	movq	%rax, %r14
	leaq	(%r15,%rbx), %rdi
	addq	$16, %rdi
.Ltmp126:
	callq	_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
.Ltmp127:
.LBB64_14:                              # %bb3.i.i.i.i.i.i.i
	leaq	(%r15,%rbx), %rdi
	addq	$40, %rdi
.Ltmp131:
	callq	_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
.Ltmp132:
.LBB64_19:                              # %cleanup.body.i.i.i.i.i
	leaq	-64(%r13), %rax
	cmpq	%rbx, %rax
	je	.LBB64_22
# %bb.20:
	subq	%rbx, %r13
	addq	$-64, %r13
	addq	%rbx, %r15
	addq	$64, %r15
.LBB64_11:                              # %bb8.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp137:
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE
.Ltmp138:
# %bb.12:                               # %.noexc.i.i.i.i
                                        #   in Loop: Header=BB64_11 Depth=1
	addq	$64, %r15
	addq	$-64, %r13
	jne	.LBB64_11
.LBB64_22:                              # %cleanup.body.i.i.i.i
	movq	24(%r12), %rdi
	movq	32(%r12), %rsi
	callq	_ZN5alloc5alloc8box_free17h98ac21c208ff1c57E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB64_21:                              # %cleanup.i.i.i.i
.Ltmp139:
	movq	%rax, %r14
	jmp	.LBB64_22
.LBB64_17:                              # %cleanup.loopexit.split-lp.i.i.i.i.i
.Ltmp133:
	jmp	.LBB64_18
.Lfunc_end64:
	.size	_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE, .Lfunc_end64-_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table64:
.Lexception19:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end19-.Lcst_begin19
.Lcst_begin19:
	.uleb128 .Ltmp123-.Lfunc_begin19 # >> Call Site 1 <<
	.uleb128 .Ltmp124-.Ltmp123      #   Call between .Ltmp123 and .Ltmp124
	.uleb128 .Ltmp125-.Lfunc_begin19 #     jumps to .Ltmp125
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp128-.Lfunc_begin19 # >> Call Site 2 <<
	.uleb128 .Ltmp129-.Ltmp128      #   Call between .Ltmp128 and .Ltmp129
	.uleb128 .Ltmp130-.Lfunc_begin19 #     jumps to .Ltmp130
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp134-.Lfunc_begin19 # >> Call Site 3 <<
	.uleb128 .Ltmp135-.Ltmp134      #   Call between .Ltmp134 and .Ltmp135
	.uleb128 .Ltmp136-.Lfunc_begin19 #     jumps to .Ltmp136
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp126-.Lfunc_begin19 # >> Call Site 4 <<
	.uleb128 .Ltmp132-.Ltmp126      #   Call between .Ltmp126 and .Ltmp132
	.uleb128 .Ltmp133-.Lfunc_begin19 #     jumps to .Ltmp133
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp137-.Lfunc_begin19 # >> Call Site 5 <<
	.uleb128 .Ltmp138-.Ltmp137      #   Call between .Ltmp137 and .Ltmp138
	.uleb128 .Ltmp139-.Lfunc_begin19 #     jumps to .Ltmp139
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp138-.Lfunc_begin19 # >> Call Site 6 <<
	.uleb128 .Lfunc_end64-.Ltmp138  #   Call between .Ltmp138 and .Lfunc_end64
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end19:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.type	_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E,@function
_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E: # @_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.cfi_startproc
# %bb.0:                                # %start
	retq
.Lfunc_end65:
	.size	_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E, .Lfunc_end65-_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE
	.type	_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE,@function
_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE: # @_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE
.Lfunc_begin20:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception20
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	addq	$8, %rdi
	cmpq	$0, (%rbx)
	je	.LBB66_1
# %bb.7:                                # %bb3
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB66_11
# %bb.8:                                # %bb3.i.i.i4
	#MEMBARRIER
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E # TAILCALL
.LBB66_1:                               # %bb2
	.cfi_def_cfa_offset 32
	movq	16(%rbx), %rax
	testq	%rax, %rax
	je	.LBB66_3
# %bb.2:                                # %bb4.i.i.i.i.i.i.i
	movq	(%rdi), %rdi
	shlq	$2, %rax
	leaq	(%rax,%rax,2), %rsi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB66_3:                               # %bb6.i
	movq	32(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB66_5
# %bb.4:                                # %bb3.i.i.i
	leaq	32(%rbx), %rdi
	#MEMBARRIER
.Ltmp140:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E
.Ltmp141:
.LBB66_5:                               # %bb5.i
	addq	$40, %rbx
.Ltmp143:
	movq	%rbx, %rdi
	callq	*_ZN65_$LT$mio..poll..Registration$u20$as$u20$core..ops..drop..Drop$GT$4drop17hbe158bb9c1ab5543E@GOTPCREL(%rip)
.Ltmp144:
# %bb.6:                                # %_ZN4core3ptr18real_drop_in_place17ha3f35c9d9cd9d3ecE.exit
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN70_$LT$mio..poll..RegistrationInner$u20$as$u20$core..ops..drop..Drop$GT$4drop17h45090a25a224e339E@GOTPCREL(%rip) # TAILCALL
.LBB66_11:                              # %bb1
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB66_9:                               # %bb3.i
	.cfi_def_cfa_offset 32
.Ltmp142:
	movq	%rax, %r14
	addq	$40, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6ac5afa1bd86ed5cE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB66_12:                              # %cleanup.i.i
.Ltmp145:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end66:
	.size	_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE, .Lfunc_end66-_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table66:
.Lexception20:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end20-.Lcst_begin20
.Lcst_begin20:
	.uleb128 .Lfunc_begin20-.Lfunc_begin20 # >> Call Site 1 <<
	.uleb128 .Ltmp140-.Lfunc_begin20 #   Call between .Lfunc_begin20 and .Ltmp140
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp140-.Lfunc_begin20 # >> Call Site 2 <<
	.uleb128 .Ltmp141-.Ltmp140      #   Call between .Ltmp140 and .Ltmp141
	.uleb128 .Ltmp142-.Lfunc_begin20 #     jumps to .Ltmp142
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp143-.Lfunc_begin20 # >> Call Site 3 <<
	.uleb128 .Ltmp144-.Ltmp143      #   Call between .Ltmp143 and .Ltmp144
	.uleb128 .Ltmp145-.Lfunc_begin20 #     jumps to .Ltmp145
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp144-.Lfunc_begin20 # >> Call Site 4 <<
	.uleb128 .Lfunc_end66-.Ltmp144  #   Call between .Ltmp144 and .Lfunc_end66
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end20:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E
	.type	_ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E,@function
_ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E: # @_ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	cmpq	$3, %rax
	je	.LBB67_3
# %bb.1:                                # %start
	cmpl	$1, %eax
	je	.LBB67_4
# %bb.2:                                # %start
	testq	%rax, %rax
	je	.LBB67_3
# %bb.6:                                # %bb3.i
	movq	8(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB67_3
# %bb.7:                                # %bb3.i.i.i4.i
	addq	$8, %rdi
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE # TAILCALL
.LBB67_4:                               # %bb2.i
	movq	8(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB67_3
# %bb.5:                                # %bb3.i.i.i.i
	addq	$8, %rdi
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E # TAILCALL
.LBB67_3:                               # %bb1
	retq
.Lfunc_end67:
	.size	_ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E, .Lfunc_end67-_ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
	.type	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE,@function
_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE: # @_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movl	128(%rdi), %eax
	cmpq	$5, %rax
	ja	.LBB68_5
# %bb.1:                                # %start
	movq	%rdi, %rbx
	jmpq	*.LJTI68_0(,%rax,8)
.LBB68_8:                               # %bb28.i
	movq	160(%rbx), %rsi
	testq	%rsi, %rsi
	je	.LBB68_6
# %bb.9:                                # %bb4.i.i.i.i.i38.i
	movq	152(%rbx), %rdi
	jmp	.LBB68_10
.LBB68_11:                              # %bb29.i
	movq	144(%rbx), %rsi
	testq	%rsi, %rsi
	je	.LBB68_6
# %bb.12:                               # %bb4.i.i.i.i.i43.i
	movq	136(%rbx), %rdi
.LBB68_10:                              # %bb12.i
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB68_6:                               # %bb12.i
	movq	112(%rbx), %rsi
	testq	%rsi, %rsi
	je	.LBB68_2
# %bb.7:                                # %bb4.i.i.i.i.i.i
	movq	104(%rbx), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB68_2:                               # %bb4.i
	movq	80(%rbx), %rsi
	testq	%rsi, %rsi
	je	.LBB68_4
# %bb.3:                                # %bb4.i.i.i.i
	movq	72(%rbx), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB68_4:                               # %bb26.i
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE
.LBB68_5:                               # %_ZN4core3ptr18real_drop_in_place17h97839a405d040727E.exit
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end68:
	.size	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE, .Lfunc_end68-_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
	.cfi_endproc
	.section	.rodata,"a",@progbits
	.p2align	3
.LJTI68_0:
	.quad	.LBB68_4
	.quad	.LBB68_5
	.quad	.LBB68_5
	.quad	.LBB68_2
	.quad	.LBB68_8
	.quad	.LBB68_11
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h90d8552239534afaE
	.type	_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE,@function
_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE: # @_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE
	.cfi_startproc
# %bb.0:                                # %start
	testq	%rsi, %rsi
	je	.LBB69_1
# %bb.2:                                # %bb4.i.i
	shlq	$3, %rsi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB69_1:                               # %"_ZN77_$LT$alloc..raw_vec..RawVec$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h8ff23a8caf48dd54E.exit"
	retq
.Lfunc_end69:
	.size	_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE, .Lfunc_end69-_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E
	.type	_ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E,@function
_ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E: # @_ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	cmpq	$2, %rax
	jne	.LBB70_1
# %bb.3:                                # %bb1
	retq
.LBB70_1:                               # %bb2
	addq	$8, %rdi
	testq	%rax, %rax
	je	.LBB70_4
# %bb.2:                                # %bb3.i
	jmp	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E # TAILCALL
.LBB70_4:                               # %bb2.i
	jmp	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE # TAILCALL
.Lfunc_end70:
	.size	_ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E, .Lfunc_end70-_ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E
	.type	_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E,@function
_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E: # @_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E
.Lfunc_begin21:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception21
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	8(%rdi), %r13
	testq	%r13, %r13
	je	.LBB71_17
# %bb.1:                                # %bb10.preheader.i
	movq	%rdi, %r12
	movq	(%rdi), %r15
	shlq	$7, %r13
	xorl	%ebx, %ebx
	movq	_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip), %r14
	jmp	.LBB71_2
	.p2align	4, 0x90
.LBB71_6:                               # %_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E.exit.i
                                        #   in Loop: Header=BB71_2 Depth=1
	subq	$-128, %rbx
	cmpq	%rbx, %r13
	je	.LBB71_7
.LBB71_2:                               # %bb10.i
                                        # =>This Inner Loop Header: Depth=1
	movq	8(%r15,%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB71_4
# %bb.3:                                # %bb3.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB71_2 Depth=1
	leaq	(%r15,%rbx), %rdi
	addq	$8, %rdi
	#MEMBARRIER
.Ltmp146:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E
.Ltmp147:
.LBB71_4:                               # %bb4.i.i.i.i.i
                                        #   in Loop: Header=BB71_2 Depth=1
	movq	16(%r15,%rbx), %rdi
	testq	%rdi, %rdi
	je	.LBB71_6
# %bb.5:                                # %bb2.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB71_2 Depth=1
.Ltmp152:
	callq	*%r14
.Ltmp153:
	jmp	.LBB71_6
.LBB71_7:                               # %bb3
	movq	8(%r12), %rsi
	shlq	$7, %rsi
	je	.LBB71_17
# %bb.8:                                # %bb4.i
	movq	(%r12), %rdi
	movl	$128, %edx
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB71_17:                              # %_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE.exit
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB71_11:                              # %cleanup.i.i.i.i.i
	.cfi_def_cfa_offset 48
.Ltmp148:
	movq	%rax, %r14
	leaq	(%r15,%rbx), %rdi
	addq	$16, %rdi
.Ltmp149:
	callq	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
.Ltmp150:
	jmp	.LBB71_15
.LBB71_13:                              # %cleanup.loopexit.split-lp.i
.Ltmp151:
	jmp	.LBB71_14
.LBB71_12:                              # %cleanup.loopexit.i
.Ltmp154:
.LBB71_14:                              # %cleanup.body.i
	movq	%rax, %r14
.LBB71_15:                              # %cleanup.body.i
	leaq	-128(%r13), %rax
	cmpq	%rbx, %rax
	je	.LBB71_19
# %bb.16:
	subq	%rbx, %r13
	addq	$-128, %r13
	addq	%rbx, %r15
	addq	$128, %r15
.LBB71_9:                               # %bb8.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp155:
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h31612d391bc71c78E
.Ltmp156:
# %bb.10:                               # %.noexc
                                        #   in Loop: Header=BB71_9 Depth=1
	subq	$-128, %r15
	addq	$-128, %r13
	jne	.LBB71_9
.LBB71_19:                              # %cleanup.body
	movq	(%r12), %rdi
	movq	8(%r12), %rsi
	callq	_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB71_18:                              # %cleanup
.Ltmp157:
	movq	%rax, %r14
	jmp	.LBB71_19
.Lfunc_end71:
	.size	_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E, .Lfunc_end71-_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table71:
.Lexception21:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end21-.Lcst_begin21
.Lcst_begin21:
	.uleb128 .Ltmp146-.Lfunc_begin21 # >> Call Site 1 <<
	.uleb128 .Ltmp147-.Ltmp146      #   Call between .Ltmp146 and .Ltmp147
	.uleb128 .Ltmp148-.Lfunc_begin21 #     jumps to .Ltmp148
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp152-.Lfunc_begin21 # >> Call Site 2 <<
	.uleb128 .Ltmp153-.Ltmp152      #   Call between .Ltmp152 and .Ltmp153
	.uleb128 .Ltmp154-.Lfunc_begin21 #     jumps to .Ltmp154
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp149-.Lfunc_begin21 # >> Call Site 3 <<
	.uleb128 .Ltmp150-.Ltmp149      #   Call between .Ltmp149 and .Ltmp150
	.uleb128 .Ltmp151-.Lfunc_begin21 #     jumps to .Ltmp151
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp155-.Lfunc_begin21 # >> Call Site 4 <<
	.uleb128 .Ltmp156-.Ltmp155      #   Call between .Ltmp155 and .Ltmp156
	.uleb128 .Ltmp157-.Lfunc_begin21 #     jumps to .Ltmp157
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp156-.Lfunc_begin21 # >> Call Site 5 <<
	.uleb128 .Lfunc_end71-.Ltmp156  #   Call between .Ltmp156 and .Lfunc_end71
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end21:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E
	.type	_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E,@function
_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E: # @_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN56_$LT$std..io..Guard$u20$as$u20$core..ops..drop..Drop$GT$4drop17h9d646c2a3ad901faE@GOTPCREL(%rip) # TAILCALL
.Lfunc_end72:
	.size	_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E, .Lfunc_end72-_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
	.type	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E,@function
_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E: # @_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Lfunc_begin22:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception22
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	subq	$80, %rsp
	.cfi_def_cfa_offset 128
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r13
	movq	(%rdi), %rax
	movq	$0, (%rdi)
	movq	%rax, 56(%rsp)
	movups	8(%rdi), %xmm0
	movups	%xmm0, 64(%rsp)
	cmpq	$1, %rax
	jne	.LBB73_18
# %bb.1:                                # %bb3.i.i
	leaq	64(%rsp), %rax
	movups	(%rax), %xmm0
	movaps	%xmm0, 16(%rsp)
	leaq	24(%r13), %r14
.Ltmp158:
	movq	%r14, %rdi
	callq	*_ZN5tokio2io6driver6Handle5inner17heb68f52174073405E@GOTPCREL(%rip)
.Ltmp159:
# %bb.2:                                # %.noexc.i.i
	movq	%rax, %rbx
	movq	%rax, 48(%rsp)
	testq	%rax, %rax
	je	.LBB73_3
# %bb.6:                                # %bb5.i.i.i
	movq	%rbx, (%rsp)
	movq	%rbx, %rsi
	addq	$16, %rsi
.Ltmp160:
	leaq	32(%rsp), %rdi
	leaq	16(%rsp), %rdx
	movl	$.Lvtable.a, %ecx
	callq	*_ZN5tokio2io6driver5Inner17deregister_source17h6390581a88aedb6eE@GOTPCREL(%rip)
.Ltmp161:
# %bb.7:                                # %bb12.i.i.i
	lock		subq	$1, (%rbx)
	jne	.LBB73_9
# %bb.8:                                # %bb3.i.i.i.i.i
	#MEMBARRIER
.Ltmp165:
	movq	%rsp, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E
.Ltmp166:
	jmp	.LBB73_9
.LBB73_3:                               # %bb3.i.i.i
.Ltmp167:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.13, %edi
	movl	$12, %esi
	callq	*_ZN3std5error161_$LT$impl$u20$core..convert..From$LT$$RF$str$GT$$u20$for$u20$alloc..boxed..Box$LT$dyn$u20$std..error..Error$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$4from17h3380ca6fb4be57d1E@GOTPCREL(%rip)
.Ltmp168:
# %bb.4:                                # %.noexc.i.i.i
	movq	%rdx, %rcx
.Ltmp169:
	movq	%rsp, %rdi
	movl	$16, %esi
	movq	%rax, %rdx
	callq	*_ZN3std2io5error5Error4_new17h9d3cc36308b63b32E@GOTPCREL(%rip)
.Ltmp170:
# %bb.5:                                # %_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E.exit.i.i.i
	movups	(%rsp), %xmm0
	movaps	%xmm0, 32(%rsp)
.LBB73_9:                               # %bb4.i.i
	movb	32(%rsp), %al
	cmpb	$3, %al
	ja	.LBB73_11
# %bb.10:                               # %bb4.i.i
	cmpb	$2, %al
	jne	.LBB73_15
.LBB73_11:                              # %bb2.i.i.i.i.i
	movq	40(%rsp), %r12
	movq	(%r12), %rdi
	movq	8(%r12), %rax
.Ltmp175:
	callq	*(%rax)
.Ltmp176:
# %bb.12:                               # %bb3.i.i.i.i.i.i.i.i
	movq	8(%r12), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB73_14
# %bb.13:                               # %bb4.i.i.i.i.i.i.i.i.i
	movq	(%r12), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB73_14:                              # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i
	movl	$24, %esi
	movl	$8, %edx
	movq	%r12, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB73_15:                              # %bb7.i.i
	leaq	24(%rsp), %rdi
.Ltmp180:
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp181:
# %bb.16:                               # %bb6.i
	cmpq	$0, (%r13)
	je	.LBB73_18
# %bb.17:                               # %bb2.i.i
	leaq	16(%r13), %rdi
.Ltmp186:
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp187:
.LBB73_18:                              # %bb5.i
	addq	$24, %r13
.Ltmp189:
	movq	%r13, %rdi
	callq	*_ZN79_$LT$tokio..io..registration..Registration$u20$as$u20$core..ops..drop..Drop$GT$4drop17he0fe257dfb231b17E@GOTPCREL(%rip)
.Ltmp190:
# %bb.19:                               # %bb4.i.i.i
	movq	(%r13), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jae	.LBB73_20
.LBB73_22:                              # %_ZN4core3ptr18real_drop_in_place17ha34840c2cd7fe1c3E.exit
	addq	$80, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB73_20:                              # %bb3.i.i.i.i.i.i
	.cfi_def_cfa_offset 128
	lock		subq	$1, 8(%rax)
	jne	.LBB73_22
# %bb.21:                               # %bb6.i.i.i.i.i.i
	#MEMBARRIER
	movq	(%r13), %rdi
	movl	$144, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB73_22
.LBB73_25:                              # %cleanup.i.i.i.i.i.i.i.i
.Ltmp177:
	movq	%rax, %r15
                                        # kill: killed $rdx
	movq	(%r12), %rdi
	movq	8(%r12), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r12, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB73_27
.LBB73_34:                              # %cleanup1.i
.Ltmp188:
	movq	%rax, %r15
	jmp	.LBB73_33
.LBB73_23:                              # %cleanup.i.i.i
.Ltmp162:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp163:
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E
.Ltmp164:
	jmp	.LBB73_27
.LBB73_24:                              # %cleanup2.i.i.i
.Ltmp171:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp172:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0b30e8d9d34d5f31E
.Ltmp173:
	jmp	.LBB73_27
.LBB73_30:                              # %cleanup1.i.i
.Ltmp182:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB73_28
.LBB73_26:                              # %cleanup.i.i
.Ltmp174:
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB73_27:                              # %cleanup.body.i.i
.Ltmp178:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
.Ltmp179:
.LBB73_28:                              # %bb5.i.i
	cmpl	$1, 56(%rsp)
	je	.LBB73_32
# %bb.29:                               # %bb9.i.i
.Ltmp183:
	leaq	56(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
.Ltmp184:
.LBB73_32:                              # %cleanup.body.i
	movq	%r13, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h039a5de4cf8b2434E
.LBB73_33:                              # %bb3.i
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h47f721620558509eE
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB73_31:                              # %cleanup.i
.Ltmp185:
	movq	%rax, %r15
	jmp	.LBB73_32
.LBB73_35:                              # %cleanup.i.i9.i
.Ltmp191:
	movq	%rax, %r15
	movq	%r13, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E
	movq	%r15, %rdi
	callq	_Unwind_Resume
.Lfunc_end73:
	.size	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E, .Lfunc_end73-_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table73:
.Lexception22:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end22-.Lcst_begin22
.Lcst_begin22:
	.uleb128 .Ltmp158-.Lfunc_begin22 # >> Call Site 1 <<
	.uleb128 .Ltmp159-.Ltmp158      #   Call between .Ltmp158 and .Ltmp159
	.uleb128 .Ltmp174-.Lfunc_begin22 #     jumps to .Ltmp174
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp160-.Lfunc_begin22 # >> Call Site 2 <<
	.uleb128 .Ltmp161-.Ltmp160      #   Call between .Ltmp160 and .Ltmp161
	.uleb128 .Ltmp162-.Lfunc_begin22 #     jumps to .Ltmp162
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp165-.Lfunc_begin22 # >> Call Site 3 <<
	.uleb128 .Ltmp166-.Ltmp165      #   Call between .Ltmp165 and .Ltmp166
	.uleb128 .Ltmp174-.Lfunc_begin22 #     jumps to .Ltmp174
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp167-.Lfunc_begin22 # >> Call Site 4 <<
	.uleb128 .Ltmp170-.Ltmp167      #   Call between .Ltmp167 and .Ltmp170
	.uleb128 .Ltmp171-.Lfunc_begin22 #     jumps to .Ltmp171
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp175-.Lfunc_begin22 # >> Call Site 5 <<
	.uleb128 .Ltmp176-.Ltmp175      #   Call between .Ltmp175 and .Ltmp176
	.uleb128 .Ltmp177-.Lfunc_begin22 #     jumps to .Ltmp177
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp180-.Lfunc_begin22 # >> Call Site 6 <<
	.uleb128 .Ltmp181-.Ltmp180      #   Call between .Ltmp180 and .Ltmp181
	.uleb128 .Ltmp182-.Lfunc_begin22 #     jumps to .Ltmp182
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp186-.Lfunc_begin22 # >> Call Site 7 <<
	.uleb128 .Ltmp187-.Ltmp186      #   Call between .Ltmp186 and .Ltmp187
	.uleb128 .Ltmp188-.Lfunc_begin22 #     jumps to .Ltmp188
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp189-.Lfunc_begin22 # >> Call Site 8 <<
	.uleb128 .Ltmp190-.Ltmp189      #   Call between .Ltmp189 and .Ltmp190
	.uleb128 .Ltmp191-.Lfunc_begin22 #     jumps to .Ltmp191
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp163-.Lfunc_begin22 # >> Call Site 9 <<
	.uleb128 .Ltmp173-.Ltmp163      #   Call between .Ltmp163 and .Ltmp173
	.uleb128 .Ltmp174-.Lfunc_begin22 #     jumps to .Ltmp174
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp178-.Lfunc_begin22 # >> Call Site 10 <<
	.uleb128 .Ltmp184-.Ltmp178      #   Call between .Ltmp178 and .Ltmp184
	.uleb128 .Ltmp185-.Lfunc_begin22 #     jumps to .Ltmp185
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp184-.Lfunc_begin22 # >> Call Site 11 <<
	.uleb128 .Lfunc_end73-.Ltmp184  #   Call between .Ltmp184 and .Lfunc_end73
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end22:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE
	.type	_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE,@function
_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE: # @_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE
.Lfunc_begin23:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception23
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %rbx
	movb	(%rdi), %al
	cmpb	$3, %al
	ja	.LBB74_2
# %bb.1:                                # %start
	cmpb	$2, %al
	je	.LBB74_2
# %bb.6:                                # %bb1
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB74_2:                               # %bb2.i.i
	.cfi_def_cfa_offset 32
	movq	8(%rbx), %r15
	movq	(%r15), %rdi
	movq	8(%r15), %rax
.Ltmp192:
	callq	*(%rax)
.Ltmp193:
# %bb.3:                                # %bb3.i.i.i.i.i
	movq	8(%r15), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB74_5
# %bb.4:                                # %bb4.i.i.i.i.i.i
	movq	(%r15), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB74_5:                               # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i
	movq	8(%rbx), %rdi
	movl	$24, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB74_7:                               # %cleanup.i.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp194:
	movq	%rax, %r14
	movq	(%r15), %rdi
	movq	8(%r15), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	8(%rbx), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end74:
	.size	_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE, .Lfunc_end74-_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table74:
.Lexception23:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end23-.Lcst_begin23
.Lcst_begin23:
	.uleb128 .Ltmp192-.Lfunc_begin23 # >> Call Site 1 <<
	.uleb128 .Ltmp193-.Ltmp192      #   Call between .Ltmp192 and .Ltmp193
	.uleb128 .Ltmp194-.Lfunc_begin23 #     jumps to .Ltmp194
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp193-.Lfunc_begin23 # >> Call Site 2 <<
	.uleb128 .Lfunc_end74-.Ltmp193  #   Call between .Ltmp193 and .Lfunc_end74
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end23:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	.type	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E,@function
_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E: # @_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rdi
	movl	$48, %esi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end75:
	.size	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E, .Lfunc_end75-_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE
	.type	_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE,@function
_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE: # @_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB76_1
# %bb.2:                                # %bb3.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E # TAILCALL
.LBB76_1:                               # %"_ZN67_$LT$alloc..sync..Arc$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h448c850d582154a2E.exit"
	retq
.Lfunc_end76:
	.size	_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE, .Lfunc_end76-_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E
	.type	_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E,@function
_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E: # @_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	(%rdi), %rax
	movq	$0, (%rdi)
	testq	%rax, %rax
	je	.LBB77_3
# %bb.1:                                # %bb2.i
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB77_3
# %bb.2:                                # %bb5.i
	movq	(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.LBB77_3:                               # %"_ZN80_$LT$tokio..task..join..JoinHandle$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h9841e7d565479b6eE.exit"
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end77:
	.size	_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E, .Lfunc_end77-_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb03804ef44432157E
	.type	_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E,@function
_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E: # @_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E
.Lfunc_begin24:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception24
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	32(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB78_2
# %bb.1:                                # %bb4.i.i.i.i.i
	movq	24(%rbx), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB78_2:                               # %bb6
	movq	64(%rbx), %rax
	testq	%rax, %rax
	je	.LBB78_5
# %bb.3:                                # %bb2.i10
	lock		subq	$1, (%rax)
	jne	.LBB78_5
# %bb.4:                                # %bb3.i.i.i11
	leaq	64(%rbx), %rdi
	#MEMBARRIER
.Ltmp195:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
.Ltmp196:
.LBB78_5:                               # %bb5
	movq	80(%rbx), %rax
	testq	%rax, %rax
	je	.LBB78_9
# %bb.6:                                # %bb2.i
	lock		subq	$1, (%rax)
	jne	.LBB78_9
# %bb.7:                                # %bb3.i.i.i
	addq	$80, %rbx
	#MEMBARRIER
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE # TAILCALL
.LBB78_9:                               # %_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E.exit
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB78_8:                               # %bb3
	.cfi_def_cfa_offset 32
.Ltmp197:
	movq	%rax, %r14
	addq	$80, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end78:
	.size	_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E, .Lfunc_end78-_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table78:
.Lexception24:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end24-.Lcst_begin24
.Lcst_begin24:
	.uleb128 .Ltmp195-.Lfunc_begin24 # >> Call Site 1 <<
	.uleb128 .Ltmp196-.Ltmp195      #   Call between .Ltmp195 and .Ltmp196
	.uleb128 .Ltmp197-.Lfunc_begin24 #     jumps to .Ltmp197
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp196-.Lfunc_begin24 # >> Call Site 2 <<
	.uleb128 .Lfunc_end78-.Ltmp196  #   Call between .Ltmp196 and .Lfunc_end78
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end24:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E
	.type	_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E,@function
_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E: # @_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	movq	8(%rdi), %rcx
	movq	%rax, %rdi
	jmpq	*24(%rcx)               # TAILCALL
.Lfunc_end79:
	.size	_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E, .Lfunc_end79-_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE
	.type	_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE,@function
_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE: # @_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE
.Lfunc_begin25:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception25
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %rbx
	movb	(%rdi), %al
	cmpb	$3, %al
	ja	.LBB80_2
# %bb.1:                                # %start
	cmpb	$2, %al
	je	.LBB80_2
# %bb.6:                                # %bb1
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB80_2:                               # %bb2.i.i
	.cfi_def_cfa_offset 32
	movq	8(%rbx), %r15
	movq	(%r15), %rdi
	movq	8(%r15), %rax
.Ltmp198:
	callq	*(%rax)
.Ltmp199:
# %bb.3:                                # %bb3.i.i.i.i.i
	movq	8(%r15), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB80_5
# %bb.4:                                # %bb4.i.i.i.i.i.i
	movq	(%r15), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB80_5:                               # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i
	movq	8(%rbx), %rdi
	movl	$24, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB80_7:                               # %cleanup.i.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp200:
	movq	%rax, %r14
	movq	(%r15), %rdi
	movq	8(%r15), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	8(%rbx), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end80:
	.size	_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE, .Lfunc_end80-_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table80:
.Lexception25:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end25-.Lcst_begin25
.Lcst_begin25:
	.uleb128 .Ltmp198-.Lfunc_begin25 # >> Call Site 1 <<
	.uleb128 .Ltmp199-.Ltmp198      #   Call between .Ltmp198 and .Ltmp199
	.uleb128 .Ltmp200-.Lfunc_begin25 #     jumps to .Ltmp200
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp199-.Lfunc_begin25 # >> Call Site 2 <<
	.uleb128 .Lfunc_end80-.Ltmp199  #   Call between .Ltmp199 and .Lfunc_end80
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end25:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE
	.type	_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE,@function
_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE: # @_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE
	.cfi_startproc
# %bb.0:                                # %start
	jmpq	*_ZN70_$LT$tokio..runtime..enter..Enter$u20$as$u20$core..ops..drop..Drop$GT$4drop17h8c0022eb2aaec068E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end81:
	.size	_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE, .Lfunc_end81-_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E
	.type	_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E,@function
_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E: # @_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB82_1
# %bb.2:                                # %bb3.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E # TAILCALL
.LBB82_1:                               # %"_ZN67_$LT$alloc..sync..Arc$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17hdc502d8bdc90bc79E.exit"
	retq
.Lfunc_end82:
	.size	_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E, .Lfunc_end82-_ZN4core3ptr18real_drop_in_place17hb67afcbcf1d2d5b8E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE
	.type	_ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE,@function
_ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE: # @_ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end83:
	.size	_ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE, .Lfunc_end83-_ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE
	.type	_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE,@function
_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE: # @_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE
.Lfunc_begin26:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception26
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rdi
	movq	8(%rbx), %rax
.Ltmp201:
	callq	*(%rax)
.Ltmp202:
# %bb.1:                                # %bb3
	movq	8(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB84_2
# %bb.4:                                # %bb4.i
	movq	(%rbx), %rdi
	movq	16(%rax), %rdx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB84_2:                               # %_ZN5alloc5alloc8box_free17h39766183111e1fbdE.exit
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB84_3:                               # %cleanup
	.cfi_def_cfa_offset 32
.Ltmp203:
	movq	%rax, %r14
	movq	(%rbx), %rdi
	movq	8(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end84:
	.size	_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE, .Lfunc_end84-_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table84:
.Lexception26:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end26-.Lcst_begin26
.Lcst_begin26:
	.uleb128 .Ltmp201-.Lfunc_begin26 # >> Call Site 1 <<
	.uleb128 .Ltmp202-.Ltmp201      #   Call between .Ltmp201 and .Ltmp202
	.uleb128 .Ltmp203-.Lfunc_begin26 #     jumps to .Ltmp203
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp202-.Lfunc_begin26 # >> Call Site 2 <<
	.uleb128 .Lfunc_end84-.Ltmp202  #   Call between .Ltmp202 and .Lfunc_end84
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end26:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
	.type	_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E,@function
_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E: # @_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	movl	(%rdi), %eax
	cmpl	$3, %eax
	je	.LBB85_3
# %bb.1:                                # %start
	cmpl	$4, %eax
	jne	.LBB85_8
# %bb.2:                                # %bb11.i
	addq	$8, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.LBB85_3:                               # %bb18.i
	.cfi_def_cfa_offset 16
	cmpl	$3, 80(%rdi)
	jne	.LBB85_8
# %bb.4:                                # %bb12.i.i.i
	cmpl	$0, 40(%rdi)
	je	.LBB85_8
# %bb.5:                                # %bb2.i.i.i.i
	movq	48(%rdi), %rax
	movq	$0, 48(%rdi)
	testq	%rax, %rax
	je	.LBB85_8
# %bb.6:                                # %bb2.i.i.i.i.i.i
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB85_8
# %bb.7:                                # %bb5.i.i.i.i.i.i
	movq	(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.LBB85_8:                               # %_ZN4core3ptr18real_drop_in_place17h061fc84a36f8b5adE.exit
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end85:
	.size	_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E, .Lfunc_end85-_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE
	.type	_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE,@function
_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE: # @_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE
.Lfunc_begin27:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception27
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$184, %rsp
	.cfi_def_cfa_offset 208
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	cmpb	$0, 8(%rdi)
	jne	.LBB86_3
# %bb.1:                                # %bb1.i
	movq	(%rdi), %rbx
.Ltmp204:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp205:
# %bb.2:                                # %"_ZN5tokio4task4core13Core$LT$T$GT$22transition_to_consumed17h35d3eb56e13b55baE.exit.i"
	movq	$2, (%rbx)
	addq	$8, %rbx
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%rbx, %rdi
	callq	*memcpy@GOTPCREL(%rip)
.LBB86_3:                               # %"_ZN164_$LT$tokio..task..harness..Harness$LT$T$C$S$GT$..poll..$u7b$$u7b$closure$u7d$$u7d$..$u7b$$u7b$closure$u7d$$u7d$..Guard$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h51dc05b8c0e6ee9dE.exit"
	addq	$184, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB86_4:                               # %cleanup.i.i
	.cfi_def_cfa_offset 208
.Ltmp206:
	movq	%rax, %r14
	movq	$2, (%rbx)
	addq	$8, %rbx
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%rbx, %rdi
	callq	*memcpy@GOTPCREL(%rip)
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end86:
	.size	_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE, .Lfunc_end86-_ZN4core3ptr18real_drop_in_place17hbe25490c23878e8eE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table86:
.Lexception27:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end27-.Lcst_begin27
.Lcst_begin27:
	.uleb128 .Ltmp204-.Lfunc_begin27 # >> Call Site 1 <<
	.uleb128 .Ltmp205-.Ltmp204      #   Call between .Ltmp204 and .Ltmp205
	.uleb128 .Ltmp206-.Lfunc_begin27 #     jumps to .Ltmp206
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp205-.Lfunc_begin27 # >> Call Site 2 <<
	.uleb128 .Lfunc_end86-.Ltmp205  #   Call between .Ltmp205 and .Lfunc_end86
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end27:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E
	.type	_ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E,@function
_ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E: # @_ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E
	.cfi_startproc
# %bb.0:                                # %start
	jmp	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE # TAILCALL
.Lfunc_end87:
	.size	_ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E, .Lfunc_end87-_ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E
	.type	_ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E,@function
_ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E: # @_ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	8(%rdi), %rax
	testq	%rax, %rax
	je	.LBB88_6
# %bb.1:                                # %bb10.preheader.i
	movq	%rdi, %r14
	movq	(%rdi), %r12
	shlq	$3, %rax
	leaq	(%rax,%rax,2), %r15
	xorl	%ebx, %ebx
	movq	__rust_dealloc@GOTPCREL(%rip), %r13
	jmp	.LBB88_2
	.p2align	4, 0x90
.LBB88_4:                               # %_ZN4core3ptr18real_drop_in_place17h86790422b7020667E.exit.i
                                        #   in Loop: Header=BB88_2 Depth=1
	addq	$24, %rbx
	cmpq	%rbx, %r15
	je	.LBB88_5
.LBB88_2:                               # %bb10.i
                                        # =>This Inner Loop Header: Depth=1
	movq	8(%r12,%rbx), %rsi
	shlq	$3, %rsi
	testq	%rsi, %rsi
	je	.LBB88_4
# %bb.3:                                # %bb4.i.i.i.i
                                        #   in Loop: Header=BB88_2 Depth=1
	movq	(%r12,%rbx), %rdi
	movl	$8, %edx
	callq	*%r13
	jmp	.LBB88_4
.LBB88_5:                               # %bb3
	movq	8(%r14), %rax
	shlq	$3, %rax
	leaq	(%rax,%rax,2), %rsi
	testq	%rsi, %rsi
	je	.LBB88_6
# %bb.7:                                # %bb4.i
	movq	(%r14), %rdi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB88_6:                               # %_ZN5alloc5alloc8box_free17hea529c1206ebdd10E.exit
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end88:
	.size	_ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E, .Lfunc_end88-_ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE
	.type	_ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE,@function
_ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE: # @_ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE
.Lfunc_begin28:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception28
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
.Ltmp207:
	callq	*_ZN67_$LT$mio..poll..ReadinessQueue$u20$as$u20$core..ops..drop..Drop$GT$4drop17hd5e3d1166226f4d7E@GOTPCREL(%rip)
.Ltmp208:
# %bb.1:                                # %bb4
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB89_2
# %bb.4:                                # %bb3.i.i
	#MEMBARRIER
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E # TAILCALL
.LBB89_2:                               # %_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE.exit
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB89_3:                               # %cleanup
	.cfi_def_cfa_offset 32
.Ltmp209:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end89:
	.size	_ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE, .Lfunc_end89-_ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table89:
.Lexception28:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end28-.Lcst_begin28
.Lcst_begin28:
	.uleb128 .Ltmp207-.Lfunc_begin28 # >> Call Site 1 <<
	.uleb128 .Ltmp208-.Ltmp207      #   Call between .Ltmp207 and .Ltmp208
	.uleb128 .Ltmp209-.Lfunc_begin28 #     jumps to .Ltmp209
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp208-.Lfunc_begin28 # >> Call Site 2 <<
	.uleb128 .Lfunc_end89-.Ltmp208  #   Call between .Ltmp208 and .Lfunc_end89
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end28:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E
	.type	_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E,@function
_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E: # @_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB90_1
# %bb.2:                                # %bb3.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E # TAILCALL
.LBB90_1:                               # %_ZN4core3ptr18real_drop_in_place17h83449461cd471b50E.exit
	retq
.Lfunc_end90:
	.size	_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E, .Lfunc_end90-_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E
	.type	_ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E,@function
_ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E: # @_ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E
	.cfi_startproc
# %bb.0:                                # %start
	cmpq	$0, (%rdi)
	leaq	8(%rdi), %rdi
	je	.LBB91_1
# %bb.2:                                # %bb3
	jmp	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E # TAILCALL
.LBB91_1:                               # %bb2
	jmp	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E # TAILCALL
.Lfunc_end91:
	.size	_ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E, .Lfunc_end91-_ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
	.type	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE,@function
_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE: # @_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Lfunc_begin29:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception29
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rax
	testq	%rax, %rax
	je	.LBB92_3
# %bb.1:                                # %start
	cmpl	$1, %eax
	jne	.LBB92_2
# %bb.4:                                # %bb3
	cmpq	$0, 8(%rbx)
	je	.LBB92_2
# %bb.5:                                # %bb2.i.i
	movq	16(%rbx), %rdi
	testq	%rdi, %rdi
	je	.LBB92_2
# %bb.6:                                # %bb2.i.i.i.i
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	16(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	32(%rbx), %rdi
	movq	40(%rbx), %rax
.Ltmp210:
	callq	*(%rax)
.Ltmp211:
# %bb.7:                                # %bb3.i.i.i.i.i.i.i
	movq	40(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB92_2
# %bb.8:                                # %bb4.i.i.i.i.i.i.i.i
	movq	32(%rbx), %rdi
	movq	16(%rax), %rdx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB92_2:                               # %bb1
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB92_3:                               # %bb2
	.cfi_def_cfa_offset 32
	addq	$8, %rbx
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE # TAILCALL
.LBB92_9:                               # %cleanup.i.i.i.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp212:
	movq	%rax, %r14
	movq	32(%rbx), %rdi
	movq	40(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end92:
	.size	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE, .Lfunc_end92-_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table92:
.Lexception29:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end29-.Lcst_begin29
.Lcst_begin29:
	.uleb128 .Ltmp210-.Lfunc_begin29 # >> Call Site 1 <<
	.uleb128 .Ltmp211-.Ltmp210      #   Call between .Ltmp210 and .Ltmp211
	.uleb128 .Ltmp212-.Lfunc_begin29 #     jumps to .Ltmp212
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp211-.Lfunc_begin29 # >> Call Site 2 <<
	.uleb128 .Lfunc_end92-.Ltmp211  #   Call between .Ltmp211 and .Lfunc_end92
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end29:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E
	.type	_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E,@function
_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E: # @_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E
.Lfunc_begin30:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception30
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, (%rsp)            # 8-byte Spill
	movq	(%rdi), %rax
	cmpq	$1, %rax
	je	.LBB93_5
# %bb.1:                                # %start
	testq	%rax, %rax
	jne	.LBB93_63
# %bb.2:                                # %bb2.i
	movq	(%rsp), %rbx            # 8-byte Reload
	leaq	8(%rbx), %rdi
.Ltmp254:
	callq	_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE
.Ltmp255:
# %bb.3:                                # %_ZN4core3ptr18real_drop_in_place17hf8834e0b188dc823E.exit.i
	movq	56(%rbx), %rdi
	movq	64(%rbx), %rax
.Ltmp259:
	callq	*24(%rax)
.Ltmp260:
	jmp	.LBB93_44
.LBB93_5:                               # %bb3.i
	movq	(%rsp), %rax            # 8-byte Reload
	leaq	8(%rax), %r15
	movq	8(%rax), %rbx
	leaq	16(%rbx), %r14
.Ltmp213:
	movq	%r14, %rdi
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E
.Ltmp214:
# %bb.6:                                # %.noexc.i.i
	movq	24(%rbx), %rax
	cmpq	32(%rbx), %rax
	je	.LBB93_11
# %bb.7:                                # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$15next_local_task17h66b868d50e0e3c09E.exit.lr.ph.i.i.i.i.i"
	movq	_ZN5tokio4task3raw7RawTask17cancel_from_queue17hbd4722693dab0a63E@GOTPCREL(%rip), %r12
	.p2align	4, 0x90
.LBB93_8:                               # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$15next_local_task17h66b868d50e0e3c09E.exit.i.i.i.i.i"
                                        # =>This Inner Loop Header: Depth=1
	movq	40(%rbx), %rcx
	movq	48(%rbx), %rdx
	leaq	1(%rax), %rsi
	addq	$-1, %rdx
	andq	%rsi, %rdx
	movq	%rdx, 24(%rbx)
	movq	(%rcx,%rax,8), %rbp
	testq	%rbp, %rbp
	je	.LBB93_11
# %bb.9:                                # %bb4.i.i.i.i.i
                                        #   in Loop: Header=BB93_8 Depth=1
.Ltmp215:
	movq	%rbp, %rdi
	callq	*%r12
.Ltmp216:
# %bb.10:                               # %bb9.i.i.i.i.i
                                        #   in Loop: Header=BB93_8 Depth=1
	movq	24(%rbx), %rax
	cmpq	32(%rbx), %rax
	jne	.LBB93_8
.LBB93_11:                              # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$11close_local17h9ec770a750c931a7E.exit.i.i.i.i"
	movq	(%r14), %rbp
	testq	%rbp, %rbp
	je	.LBB93_15
	.p2align	4, 0x90
.LBB93_13:                              # %bb3.i.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	movq	40(%rbp), %rax
.Ltmp220:
	movq	%rbp, %rdi
	xorl	%esi, %esi
	callq	*48(%rax)
.Ltmp221:
# %bb.14:                               # %.noexc9.i.i
                                        #   in Loop: Header=BB93_13 Depth=1
	movq	24(%rbp), %rbp
	testq	%rbp, %rbp
	jne	.LBB93_13
.LBB93_15:                              # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$8shutdown17h625e177790819e81E.exit.i.i.i"
.Ltmp223:
	movq	%r14, %rdi
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE
.Ltmp224:
# %bb.16:                               # %.noexc10.i.i
	movq	(%rsp), %rax            # 8-byte Reload
	leaq	16(%rax), %rbx
	leaq	24(%rax), %r12
	movq	_ZN5tokio4task3raw7RawTask17cancel_from_queue17hbd4722693dab0a63E@GOTPCREL(%rip), %r13
	.p2align	4, 0x90
.LBB93_17:                              # %bb3.i.i.i
                                        # =>This Loop Header: Depth=1
                                        #     Child Loop BB93_19 Depth 2
	movq	(%r15), %rdi
	addq	$16, %rdi
.Ltmp225:
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE
.Ltmp226:
# %bb.18:                               # %.noexc11.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
	movq	(%r15), %rbp
	.p2align	4, 0x90
.LBB93_19:                              # %.noexc11.i.i
                                        #   Parent Loop BB93_17 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
	movq	24(%rbp), %rax
	cmpq	32(%rbp), %rax
	je	.LBB93_22
# %bb.20:                               # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$15next_local_task17h66b868d50e0e3c09E.exit.i.i15.i.i.i"
                                        #   in Loop: Header=BB93_19 Depth=2
	movq	40(%rbp), %rcx
	movq	48(%rbp), %rdx
	leaq	1(%rax), %rsi
	addq	$-1, %rdx
	andq	%rsi, %rdx
	movq	%rdx, 24(%rbp)
	movq	(%rcx,%rax,8), %r14
	testq	%r14, %r14
	je	.LBB93_22
# %bb.21:                               # %bb4.i.i16.i.i.i
                                        #   in Loop: Header=BB93_19 Depth=2
.Ltmp227:
	movq	%r14, %rdi
	callq	*%r13
.Ltmp228:
	jmp	.LBB93_19
	.p2align	4, 0x90
.LBB93_22:                              # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12drain_queues17h274389cac057f87bE.exit.i.i.i"
                                        #   in Loop: Header=BB93_17 Depth=1
	addq	$16, %rbp
.Ltmp232:
	movq	%rbp, %rdi
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E
.Ltmp233:
# %bb.23:                               # %.noexc13.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
	movq	(%r15), %rax
	cmpq	$0, 16(%rax)
	je	.LBB93_41
# %bb.24:                               # %bb10.i.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
	cmpl	$1, (%rbx)
	jne	.LBB93_25
# %bb.35:                               # %bb5.i.i.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
.Ltmp239:
	movq	%r12, %rdi
	callq	*_ZN69_$LT$tokio..park..thread..ParkThread$u20$as$u20$tokio..park..Park$GT$4park17he4f05110cc421267E@GOTPCREL(%rip)
.Ltmp240:
# %bb.36:                               # %.noexc15.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
	testb	%al, %al
	je	.LBB93_17
	jmp	.LBB93_32
	.p2align	4, 0x90
.LBB93_25:                              # %bb2.i24.i.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
.Ltmp234:
	leaq	8(%rsp), %rdi
	movq	%r12, %rsi
	callq	*_ZN63_$LT$tokio..io..driver..Driver$u20$as$u20$tokio..park..Park$GT$4park17hdb7d962184c1111eE@GOTPCREL(%rip)
.Ltmp235:
# %bb.26:                               # %.noexc14.i.i
                                        #   in Loop: Header=BB93_17 Depth=1
	movb	8(%rsp), %al
	cmpb	$3, %al
	je	.LBB93_17
# %bb.27:                               # %bb7.i.i.i.i
	cmpb	$2, %al
	jb	.LBB93_32
# %bb.28:                               # %bb2.i.i.i.i.i.i.i.i
	movq	16(%rsp), %r12
	movq	(%r12), %rdi
	movq	8(%r12), %rax
.Ltmp236:
	callq	*(%rax)
.Ltmp237:
# %bb.29:                               # %bb3.i.i.i.i.i.i.i.i.i.i.i
	movq	8(%r12), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB93_31
# %bb.30:                               # %bb4.i.i.i.i.i.i.i.i.i.i.i.i
	movq	(%r12), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB93_31:                              # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i.i.i.i
	movl	$24, %esi
	movl	$8, %edx
	movq	%r12, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB93_32:                              # %bb2.i.i.i.i
.Ltmp242:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.60, %edi
	movl	$11, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp243:
# %bb.38:                               # %.noexc16.i.i
.LBB93_63:                              # %bb4.i
	movq	(%rsp), %rax            # 8-byte Reload
	leaq	8(%rax), %rbx
.Ltmp261:
	movq	%rbx, %rdi
	callq	*_ZN81_$LT$tokio..runtime..thread_pool..ThreadPool$u20$as$u20$core..ops..drop..Drop$GT$4drop17h6d6012278c1f3cebE@GOTPCREL(%rip)
.Ltmp262:
# %bb.64:                               # %bb4.i.i
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB93_44
# %bb.65:                               # %bb3.i.i.i.i.i
	#MEMBARRIER
.Ltmp266:
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE
.Ltmp267:
	jmp	.LBB93_44
.LBB93_41:                              # %bb6.i.i
	lock		subq	$1, (%rax)
	jne	.LBB93_43
# %bb.42:                               # %bb3.i.i.i.i
	#MEMBARRIER
.Ltmp247:
	movq	%r15, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E
.Ltmp248:
.LBB93_43:                              # %_ZN4core3ptr18real_drop_in_place17h92b7e42b9b0e393eE.exit.i
.Ltmp252:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE
.Ltmp253:
.LBB93_44:                              # %bb6
	movq	(%rsp), %rbx            # 8-byte Reload
	leaq	72(%rbx), %rdi
.Ltmp269:
	callq	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
.Ltmp270:
# %bb.45:                               # %bb5
	addq	$104, %rbx
.Ltmp272:
	movq	%rbx, %rdi
	callq	*_ZN86_$LT$tokio..runtime..blocking..pool..BlockingPool$u20$as$u20$core..ops..drop..Drop$GT$4drop17h10138d17d10c68f9E@GOTPCREL(%rip)
.Ltmp273:
# %bb.46:                               # %bb6.i
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB93_48
# %bb.47:                               # %bb3.i.i.i.i17
	#MEMBARRIER
.Ltmp275:
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E
.Ltmp276:
.LBB93_48:                              # %_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E.exit
	movq	(%rsp), %r14            # 8-byte Reload
	movq	112(%r14), %rbp
	testq	%rbp, %rbp
	je	.LBB93_70
# %bb.49:                               # %bb2.i.i.i
	addq	$112, %r14
	leaq	16(%rbp), %rdi
.Ltmp278:
	callq	*_ZN5tokio4sync7oneshot5State10set_closed17h1245aa12b7db01aeE@GOTPCREL(%rip)
.Ltmp279:
# %bb.50:                               # %_7.i.i.noexc.i.i
	movq	%rax, %rbx
.Ltmp280:
	movq	%rax, %rdi
	callq	*_ZN5tokio4sync7oneshot5State14is_tx_task_set17h1483fb4bbe76be02E@GOTPCREL(%rip)
.Ltmp281:
# %bb.51:                               # %.noexc.i.i20
	testb	%al, %al
	je	.LBB93_55
# %bb.52:                               # %bb4.i.i.i.i
.Ltmp282:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4sync7oneshot5State11is_complete17h783483c417cbb1fbE@GOTPCREL(%rip)
.Ltmp283:
# %bb.53:                               # %.noexc5.i.i
	testb	%al, %al
	jne	.LBB93_55
# %bb.54:                               # %bb8.i.i.i.i
	movq	24(%rbp), %rdi
	movq	32(%rbp), %rax
.Ltmp284:
	callq	*16(%rax)
.Ltmp285:
.LBB93_55:                              # %bb4.i.i21
	movq	(%r14), %rax
	testq	%rax, %rax
	je	.LBB93_70
# %bb.56:                               # %bb2.i7.i.i
	lock		subq	$1, (%rax)
	jne	.LBB93_70
# %bb.57:                               # %bb3.i.i.i.i.i24
	#MEMBARRIER
	movq	%r14, %rdi
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E # TAILCALL
.LBB93_70:                              # %_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE.exit
	.cfi_def_cfa_offset 80
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB93_37:                              # %cleanup.i.i.i.i.i.i.i.i.i.i.i
	.cfi_def_cfa_offset 80
.Ltmp238:
	movq	%rax, %r13
	movq	(%r12), %rdi
	movq	8(%r12), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r12, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB93_62
.LBB93_39:                              # %cleanup1.i.i
.Ltmp249:
	movq	%rax, %r13
	jmp	.LBB93_40
.LBB93_66:                              # %cleanup.i2.i
.Ltmp263:
	movq	%rax, %r13
.Ltmp264:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE
.Ltmp265:
	jmp	.LBB93_72
.LBB93_4:                               # %cleanup.i.i
.Ltmp256:
	movq	%rax, %r13
	leaq	56(%rbx), %rdi
.Ltmp257:
	callq	_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E
.Ltmp258:
	jmp	.LBB93_72
.LBB93_69:                              # %cleanup1.i
.Ltmp277:
	movq	%rax, %r13
	jmp	.LBB93_68
.LBB93_67:                              # %cleanup.i
.Ltmp274:
	movq	%rax, %r13
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E
.LBB93_68:                              # %bb3.i14
	movq	(%rsp), %rdi            # 8-byte Reload
	addq	$112, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE
	movq	%r13, %rdi
	callq	_Unwind_Resume
.LBB93_74:                              # %cleanup1
.Ltmp271:
	movq	%rax, %r13
	jmp	.LBB93_73
.LBB93_75:                              # %cleanup.i.i25
.Ltmp286:
	movq	%rax, %r13
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE
	movq	%r13, %rdi
	callq	_Unwind_Resume
.LBB93_33:                              # %bb1.i.i.i.i.i.i
.Ltmp217:
	movq	%rax, %r13
.Ltmp218:
	movq	%rbp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp219:
	jmp	.LBB93_62
.LBB93_59:                              # %cleanup.loopexit.split-lp.loopexit.i.i
.Ltmp222:
	jmp	.LBB93_61
.LBB93_58:                              # %cleanup.loopexit.i.i
.Ltmp241:
.LBB93_61:                              # %cleanup.body.i.i
	movq	%rax, %r13
	jmp	.LBB93_62
.LBB93_34:                              # %bb1.i.i.i17.i.i.i
.Ltmp229:
	movq	%rax, %r13
.Ltmp230:
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp231:
.LBB93_62:                              # %cleanup.body.i.i
.Ltmp245:
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h7d623c73fcbe815dE
.Ltmp246:
.LBB93_40:                              # %bb3.i.i
	movq	(%rsp), %rax            # 8-byte Reload
	leaq	16(%rax), %rdi
.Ltmp250:
	callq	_ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE
.Ltmp251:
.LBB93_72:                              # %cleanup.body
	movq	(%rsp), %rbx            # 8-byte Reload
	leaq	72(%rbx), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
.LBB93_73:                              # %bb3
	addq	$104, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E
	movq	%r13, %rdi
	callq	_Unwind_Resume
.LBB93_60:                              # %cleanup.loopexit.split-lp.loopexit.split-lp.i.i
.Ltmp244:
	jmp	.LBB93_61
.LBB93_71:                              # %cleanup
.Ltmp268:
	movq	%rax, %r13
	jmp	.LBB93_72
.Lfunc_end93:
	.size	_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E, .Lfunc_end93-_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table93:
.Lexception30:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end30-.Lcst_begin30
.Lcst_begin30:
	.uleb128 .Ltmp254-.Lfunc_begin30 # >> Call Site 1 <<
	.uleb128 .Ltmp255-.Ltmp254      #   Call between .Ltmp254 and .Ltmp255
	.uleb128 .Ltmp256-.Lfunc_begin30 #     jumps to .Ltmp256
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp259-.Lfunc_begin30 # >> Call Site 2 <<
	.uleb128 .Ltmp260-.Ltmp259      #   Call between .Ltmp259 and .Ltmp260
	.uleb128 .Ltmp268-.Lfunc_begin30 #     jumps to .Ltmp268
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp213-.Lfunc_begin30 # >> Call Site 3 <<
	.uleb128 .Ltmp214-.Ltmp213      #   Call between .Ltmp213 and .Ltmp214
	.uleb128 .Ltmp244-.Lfunc_begin30 #     jumps to .Ltmp244
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp215-.Lfunc_begin30 # >> Call Site 4 <<
	.uleb128 .Ltmp216-.Ltmp215      #   Call between .Ltmp215 and .Ltmp216
	.uleb128 .Ltmp217-.Lfunc_begin30 #     jumps to .Ltmp217
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp220-.Lfunc_begin30 # >> Call Site 5 <<
	.uleb128 .Ltmp221-.Ltmp220      #   Call between .Ltmp220 and .Ltmp221
	.uleb128 .Ltmp222-.Lfunc_begin30 #     jumps to .Ltmp222
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp223-.Lfunc_begin30 # >> Call Site 6 <<
	.uleb128 .Ltmp224-.Ltmp223      #   Call between .Ltmp223 and .Ltmp224
	.uleb128 .Ltmp244-.Lfunc_begin30 #     jumps to .Ltmp244
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp225-.Lfunc_begin30 # >> Call Site 7 <<
	.uleb128 .Ltmp226-.Ltmp225      #   Call between .Ltmp225 and .Ltmp226
	.uleb128 .Ltmp241-.Lfunc_begin30 #     jumps to .Ltmp241
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp227-.Lfunc_begin30 # >> Call Site 8 <<
	.uleb128 .Ltmp228-.Ltmp227      #   Call between .Ltmp227 and .Ltmp228
	.uleb128 .Ltmp229-.Lfunc_begin30 #     jumps to .Ltmp229
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp232-.Lfunc_begin30 # >> Call Site 9 <<
	.uleb128 .Ltmp235-.Ltmp232      #   Call between .Ltmp232 and .Ltmp235
	.uleb128 .Ltmp241-.Lfunc_begin30 #     jumps to .Ltmp241
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp236-.Lfunc_begin30 # >> Call Site 10 <<
	.uleb128 .Ltmp237-.Ltmp236      #   Call between .Ltmp236 and .Ltmp237
	.uleb128 .Ltmp238-.Lfunc_begin30 #     jumps to .Ltmp238
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp242-.Lfunc_begin30 # >> Call Site 11 <<
	.uleb128 .Ltmp243-.Ltmp242      #   Call between .Ltmp242 and .Ltmp243
	.uleb128 .Ltmp244-.Lfunc_begin30 #     jumps to .Ltmp244
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp261-.Lfunc_begin30 # >> Call Site 12 <<
	.uleb128 .Ltmp262-.Ltmp261      #   Call between .Ltmp261 and .Ltmp262
	.uleb128 .Ltmp263-.Lfunc_begin30 #     jumps to .Ltmp263
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp266-.Lfunc_begin30 # >> Call Site 13 <<
	.uleb128 .Ltmp267-.Ltmp266      #   Call between .Ltmp266 and .Ltmp267
	.uleb128 .Ltmp268-.Lfunc_begin30 #     jumps to .Ltmp268
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp247-.Lfunc_begin30 # >> Call Site 14 <<
	.uleb128 .Ltmp248-.Ltmp247      #   Call between .Ltmp247 and .Ltmp248
	.uleb128 .Ltmp249-.Lfunc_begin30 #     jumps to .Ltmp249
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp252-.Lfunc_begin30 # >> Call Site 15 <<
	.uleb128 .Ltmp253-.Ltmp252      #   Call between .Ltmp252 and .Ltmp253
	.uleb128 .Ltmp268-.Lfunc_begin30 #     jumps to .Ltmp268
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp269-.Lfunc_begin30 # >> Call Site 16 <<
	.uleb128 .Ltmp270-.Ltmp269      #   Call between .Ltmp269 and .Ltmp270
	.uleb128 .Ltmp271-.Lfunc_begin30 #     jumps to .Ltmp271
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp272-.Lfunc_begin30 # >> Call Site 17 <<
	.uleb128 .Ltmp273-.Ltmp272      #   Call between .Ltmp272 and .Ltmp273
	.uleb128 .Ltmp274-.Lfunc_begin30 #     jumps to .Ltmp274
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp275-.Lfunc_begin30 # >> Call Site 18 <<
	.uleb128 .Ltmp276-.Ltmp275      #   Call between .Ltmp275 and .Ltmp276
	.uleb128 .Ltmp277-.Lfunc_begin30 #     jumps to .Ltmp277
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp278-.Lfunc_begin30 # >> Call Site 19 <<
	.uleb128 .Ltmp285-.Ltmp278      #   Call between .Ltmp278 and .Ltmp285
	.uleb128 .Ltmp286-.Lfunc_begin30 #     jumps to .Ltmp286
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp285-.Lfunc_begin30 # >> Call Site 20 <<
	.uleb128 .Ltmp264-.Ltmp285      #   Call between .Ltmp285 and .Ltmp264
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp264-.Lfunc_begin30 # >> Call Site 21 <<
	.uleb128 .Ltmp258-.Ltmp264      #   Call between .Ltmp264 and .Ltmp258
	.uleb128 .Ltmp268-.Lfunc_begin30 #     jumps to .Ltmp268
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp258-.Lfunc_begin30 # >> Call Site 22 <<
	.uleb128 .Ltmp218-.Ltmp258      #   Call between .Ltmp258 and .Ltmp218
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp218-.Lfunc_begin30 # >> Call Site 23 <<
	.uleb128 .Ltmp231-.Ltmp218      #   Call between .Ltmp218 and .Ltmp231
	.uleb128 .Ltmp244-.Lfunc_begin30 #     jumps to .Ltmp244
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp245-.Lfunc_begin30 # >> Call Site 24 <<
	.uleb128 .Ltmp251-.Ltmp245      #   Call between .Ltmp245 and .Ltmp251
	.uleb128 .Ltmp268-.Lfunc_begin30 #     jumps to .Ltmp268
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp251-.Lfunc_begin30 # >> Call Site 25 <<
	.uleb128 .Lfunc_end93-.Ltmp251  #   Call between .Ltmp251 and .Lfunc_end93
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end30:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E
	.type	_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E,@function
_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E: # @_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E
.Lfunc_begin31:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception31
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
.Ltmp287:
	callq	*_ZN86_$LT$tokio..runtime..blocking..pool..BlockingPool$u20$as$u20$core..ops..drop..Drop$GT$4drop17h10138d17d10c68f9E@GOTPCREL(%rip)
.Ltmp288:
# %bb.1:                                # %bb6
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB94_3
# %bb.2:                                # %bb3.i.i.i
	#MEMBARRIER
.Ltmp290:
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E
.Ltmp291:
.LBB94_3:                               # %bb5
	addq	$8, %rbx
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE # TAILCALL
.LBB94_6:                               # %cleanup1
	.cfi_def_cfa_offset 32
.Ltmp292:
	movq	%rax, %r14
	jmp	.LBB94_5
.LBB94_4:                               # %cleanup
.Ltmp289:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E
.LBB94_5:                               # %bb3
	addq	$8, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0e7bfccaa03490aaE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end94:
	.size	_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E, .Lfunc_end94-_ZN4core3ptr18real_drop_in_place17hd05fa7a969137952E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table94:
.Lexception31:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end31-.Lcst_begin31
.Lcst_begin31:
	.uleb128 .Ltmp287-.Lfunc_begin31 # >> Call Site 1 <<
	.uleb128 .Ltmp288-.Ltmp287      #   Call between .Ltmp287 and .Ltmp288
	.uleb128 .Ltmp289-.Lfunc_begin31 #     jumps to .Ltmp289
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp290-.Lfunc_begin31 # >> Call Site 2 <<
	.uleb128 .Ltmp291-.Ltmp290      #   Call between .Ltmp290 and .Ltmp291
	.uleb128 .Ltmp292-.Lfunc_begin31 #     jumps to .Ltmp292
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp291-.Lfunc_begin31 # >> Call Site 3 <<
	.uleb128 .Lfunc_end94-.Ltmp291  #   Call between .Ltmp291 and .Lfunc_end94
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end31:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE
	.type	_ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE,@function
_ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE: # @_ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE
	.cfi_startproc
# %bb.0:                                # %start
	movq	16(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB95_1
# %bb.2:                                # %bb4.i.i
	movq	8(%rdi), %rdi
	movl	$1, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB95_1:                               # %_ZN4core3ptr18real_drop_in_place17h4f94441d06411884E.exit
	retq
.Lfunc_end95:
	.size	_ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE, .Lfunc_end95-_ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE
	.type	_ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE,@function
_ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE: # @_ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB96_1
# %bb.2:                                # %bb3.i.i
	#MEMBARRIER
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE # TAILCALL
.LBB96_1:                               # %_ZN4core3ptr18real_drop_in_place17h49f6b6a2e267827aE.exit
	retq
.Lfunc_end96:
	.size	_ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE, .Lfunc_end96-_ZN4core3ptr18real_drop_in_place17hd3a88f295e85c32eE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE
	.type	_ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE,@function
_ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE: # @_ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	movl	8(%rdi), %eax
	cmpl	$3, %eax
	je	.LBB97_3
# %bb.1:                                # %start
	cmpl	$4, %eax
	jne	.LBB97_8
# %bb.2:                                # %bb11.i.i
	addq	$16, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.LBB97_3:                               # %bb18.i.i
	.cfi_def_cfa_offset 16
	cmpl	$3, 88(%rdi)
	jne	.LBB97_8
# %bb.4:                                # %bb12.i.i.i.i
	cmpl	$0, 48(%rdi)
	je	.LBB97_8
# %bb.5:                                # %bb2.i.i.i.i.i
	movq	56(%rdi), %rax
	movq	$0, 56(%rdi)
	testq	%rax, %rax
	je	.LBB97_8
# %bb.6:                                # %bb2.i.i.i.i.i.i.i
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB97_8
# %bb.7:                                # %bb5.i.i.i.i.i.i.i
	movq	(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.LBB97_8:                               # %_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E.exit
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end97:
	.size	_ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE, .Lfunc_end97-_ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E
	.type	_ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E,@function
_ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E: # @_ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E
	.cfi_startproc
# %bb.0:                                # %start
	cmpl	$0, (%rdi)
	je	.LBB98_5
# %bb.1:                                # %bb2
	movq	24(%rdi), %rcx
	movq	32(%rdi), %rax
	subq	%rcx, %rax
	.p2align	4, 0x90
.LBB98_2:                               # %bb4.i.i
                                        # =>This Inner Loop Header: Depth=1
	testq	%rax, %rax
	je	.LBB98_4
# %bb.3:                                # %"_ZN72_$LT$$RF$mut$u20$I$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hbfa7904ad84011c1E.exit.i.i"
                                        #   in Loop: Header=BB98_2 Depth=1
	leaq	32(%rcx), %rdx
	movq	%rdx, 24(%rdi)
	addq	$-32, %rax
	cmpl	$2, (%rcx)
	movq	%rdx, %rcx
	jne	.LBB98_2
.LBB98_4:                               # %bb9.i.i
	movq	16(%rdi), %rsi
	testq	%rsi, %rsi
	je	.LBB98_5
# %bb.6:                                # %bb4.i.i.i.i.i
	movq	8(%rdi), %rdi
	shlq	$5, %rsi
	movl	$4, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB98_5:                               # %bb1
	retq
.Lfunc_end98:
	.size	_ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E, .Lfunc_end98-_ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
	.type	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE,@function
_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE: # @_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
.Lfunc_begin32:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception32
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	(%rdi), %rax
	testq	%rax, %rax
	je	.LBB99_4
# %bb.1:                                # %start
	cmpl	$1, %eax
	jne	.LBB99_9
# %bb.2:                                # %bb2.i
	movq	8(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB99_4
# %bb.3:                                # %bb3.i.i.i.i
	leaq	8(%rbx), %rdi
	#MEMBARRIER
.Ltmp293:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E
.Ltmp294:
	jmp	.LBB99_4
.LBB99_9:                               # %bb3.i
	movq	8(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB99_4
# %bb.10:                               # %bb3.i.i.i4.i
	leaq	8(%rbx), %rdi
	#MEMBARRIER
.Ltmp295:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE
.Ltmp296:
.LBB99_4:                               # %bb6
	movq	16(%rbx), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jae	.LBB99_5
.LBB99_7:                               # %bb5
	movq	24(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB99_8
# %bb.12:                               # %bb3.i.i.i
	addq	$24, %rbx
	#MEMBARRIER
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmp	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E # TAILCALL
.LBB99_8:                               # %_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E.exit
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB99_5:                               # %bb3.i.i.i.i9
	.cfi_def_cfa_offset 32
	lock		subq	$1, 8(%rax)
	jne	.LBB99_7
# %bb.6:                                # %bb6.i.i.i.i
	#MEMBARRIER
	movq	16(%rbx), %rdi
	movl	$144, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB99_7
.LBB99_11:                              # %bb3
.Ltmp297:
	movq	%rax, %r14
	leaq	16(%rbx), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0805755c54a7a761E
	addq	$24, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hc55e0a9d2dbc8282E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end99:
	.size	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE, .Lfunc_end99-_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table99:
.Lexception32:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end32-.Lcst_begin32
.Lcst_begin32:
	.uleb128 .Ltmp293-.Lfunc_begin32 # >> Call Site 1 <<
	.uleb128 .Ltmp296-.Ltmp293      #   Call between .Ltmp293 and .Ltmp296
	.uleb128 .Ltmp297-.Lfunc_begin32 #     jumps to .Ltmp297
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp296-.Lfunc_begin32 # >> Call Site 2 <<
	.uleb128 .Lfunc_end99-.Ltmp296  #   Call between .Ltmp296 and .Lfunc_end99
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end32:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE
	.type	_ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE,@function
_ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE: # @_ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE
	.cfi_startproc
# %bb.0:                                # %start
	jmp	_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE # TAILCALL
.Lfunc_end100:
	.size	_ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE, .Lfunc_end100-_ZN4core3ptr18real_drop_in_place17he20b4888eb52bdffE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E
	.type	_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E,@function
_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E: # @_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	cmpq	$0, (%rdi)
	jne	.LBB101_2
# %bb.1:                                # %"_ZN106_$LT$tokio..task..stack..TransferStack$LT$T$GT$..drain..Iter$LT$T$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17he59faf58257e1315E.exit"
	popq	%rax
	.cfi_def_cfa_offset 8
	retq
.LBB101_2:                              # %bb3.i
	.cfi_def_cfa_offset 16
	callq	*_ZN3std7process5abort17hda23989dd14b7a85E@GOTPCREL(%rip)
.Lfunc_end101:
	.size	_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E, .Lfunc_end101-_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hec17986a815092ecE
	.type	_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE,@function
_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE: # @_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE
.Lfunc_begin33:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception33
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	addq	$8, %rdi
.Ltmp298:
	callq	*_ZN86_$LT$tokio..io..driver..scheduled_io..ScheduledIo$u20$as$u20$core..ops..drop..Drop$GT$4drop17h0f6da5c3897a82caE@GOTPCREL(%rip)
.Ltmp299:
# %bb.1:                                # %bb6.i
	movq	32(%rbx), %rax
	testq	%rax, %rax
	je	.LBB102_2
# %bb.4:                                # %bb2.i.i.i.i10.i
	movq	24(%rbx), %rdi
.Ltmp301:
	callq	*24(%rax)
.Ltmp302:
.LBB102_2:                              # %bb5.i
	movq	56(%rbx), %rax
	testq	%rax, %rax
	je	.LBB102_8
# %bb.3:                                # %bb2.i.i.i.i.i
	movq	48(%rbx), %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*24(%rax)               # TAILCALL
.LBB102_8:                              # %_ZN4core3ptr18real_drop_in_place17h6b371b15e0ffe1c1E.exit
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB102_7:                              # %cleanup1.i
	.cfi_def_cfa_offset 32
.Ltmp303:
	movq	%rax, %r14
	jmp	.LBB102_6
.LBB102_5:                              # %cleanup.i
.Ltmp300:
	movq	%rax, %r14
	leaq	16(%rbx), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
.LBB102_6:                              # %bb3.i
	addq	$40, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h4b8193e59cd485a1E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end102:
	.size	_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE, .Lfunc_end102-_ZN4core3ptr18real_drop_in_place17hec17986a815092ecE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table102:
.Lexception33:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end33-.Lcst_begin33
.Lcst_begin33:
	.uleb128 .Ltmp298-.Lfunc_begin33 # >> Call Site 1 <<
	.uleb128 .Ltmp299-.Ltmp298      #   Call between .Ltmp298 and .Ltmp299
	.uleb128 .Ltmp300-.Lfunc_begin33 #     jumps to .Ltmp300
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp301-.Lfunc_begin33 # >> Call Site 2 <<
	.uleb128 .Ltmp302-.Ltmp301      #   Call between .Ltmp301 and .Ltmp302
	.uleb128 .Ltmp303-.Lfunc_begin33 #     jumps to .Ltmp303
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp302-.Lfunc_begin33 # >> Call Site 3 <<
	.uleb128 .Lfunc_end102-.Ltmp302 #   Call between .Ltmp302 and .Lfunc_end102
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end33:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE
	.type	_ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE,@function
_ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE: # @_ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE
.Lfunc_begin34:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception34
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	pushq	%rax
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	8(%rdi), %rax
	testq	%rax, %rax
	je	.LBB103_11
# %bb.1:                                # %bb10.preheader.i
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	leaq	(%rax,%rax,2), %rax
	leaq	-24(,%rax,8), %r12
	jmp	.LBB103_2
	.p2align	4, 0x90
.LBB103_4:                              # %_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE.exit.i
                                        #   in Loop: Header=BB103_2 Depth=1
	addq	$24, %rbx
	addq	$-24, %r12
	cmpq	$-24, %r12
	je	.LBB103_5
.LBB103_2:                              # %bb10.i
                                        # =>This Inner Loop Header: Depth=1
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB103_4
# %bb.3:                                # %bb3.i.i.i.i.i
                                        #   in Loop: Header=BB103_2 Depth=1
	#MEMBARRIER
.Ltmp304:
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E
.Ltmp305:
	jmp	.LBB103_4
.LBB103_5:                              # %bb3
	movq	8(%r14), %rax
	shlq	$3, %rax
	leaq	(%rax,%rax,2), %rsi
	testq	%rsi, %rsi
	je	.LBB103_11
# %bb.6:                                # %bb4.i
	movq	(%r14), %rdi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB103_11:                             # %_ZN5alloc5alloc8box_free17hc2af688206b9dacdE.exit
	.cfi_def_cfa_offset 48
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB103_9:                              # %cleanup.i
	.cfi_def_cfa_offset 48
.Ltmp306:
	movq	%rax, %r15
	testq	%r12, %r12
	je	.LBB103_13
# %bb.10:
	addq	$24, %rbx
.LBB103_7:                              # %bb8.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp307:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE
.Ltmp308:
# %bb.8:                                # %.noexc
                                        #   in Loop: Header=BB103_7 Depth=1
	addq	$24, %rbx
	addq	$-24, %r12
	jne	.LBB103_7
.LBB103_13:                             # %cleanup.body
	movq	(%r14), %rdi
	movq	8(%r14), %rsi
	callq	_ZN5alloc5alloc8box_free17hc2af688206b9dacdE
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB103_12:                             # %cleanup
.Ltmp309:
	movq	%rax, %r15
	jmp	.LBB103_13
.Lfunc_end103:
	.size	_ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE, .Lfunc_end103-_ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table103:
.Lexception34:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end34-.Lcst_begin34
.Lcst_begin34:
	.uleb128 .Ltmp304-.Lfunc_begin34 # >> Call Site 1 <<
	.uleb128 .Ltmp305-.Ltmp304      #   Call between .Ltmp304 and .Ltmp305
	.uleb128 .Ltmp306-.Lfunc_begin34 #     jumps to .Ltmp306
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp307-.Lfunc_begin34 # >> Call Site 2 <<
	.uleb128 .Ltmp308-.Ltmp307      #   Call between .Ltmp307 and .Ltmp308
	.uleb128 .Ltmp309-.Lfunc_begin34 #     jumps to .Ltmp309
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp308-.Lfunc_begin34 # >> Call Site 3 <<
	.uleb128 .Lfunc_end103-.Ltmp308 #   Call between .Ltmp308 and .Lfunc_end103
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end34:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E
	.type	_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E,@function
_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E: # @_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E
.Lfunc_begin35:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception35
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	pushq	%rax
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	8(%rdi), %rsi
	shlq	$3, %rsi
	testq	%rsi, %rsi
	je	.LBB104_2
# %bb.1:                                # %bb4.i.i.i
	movq	(%r14), %rdi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB104_2:                              # %bb4.i
	movq	16(%r14), %r12
	movq	24(%r14), %rax
	shlq	$3, %rax
	leaq	(%rax,%rax,4), %rbx
	.p2align	4, 0x90
.LBB104_7:                              # %bb11.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	testq	%rbx, %rbx
	je	.LBB104_8
# %bb.6:                                # %bb10.i.i.i
                                        #   in Loop: Header=BB104_7 Depth=1
	addq	$-40, %rbx
.Ltmp310:
	movq	%r12, %rdi
	addq	$40, %r12
	callq	_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE
.Ltmp311:
	jmp	.LBB104_7
.LBB104_8:                              # %bb3.i.i
	movq	24(%r14), %rax
	shlq	$3, %rax
	leaq	(%rax,%rax,4), %rsi
	testq	%rsi, %rsi
	je	.LBB104_10
# %bb.9:                                # %bb4.i.i5.i
	movq	16(%r14), %rdi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB104_10:                             # %bb4
	movq	32(%r14), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	32(%r14), %rdi
	movl	$40, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB104_3:                              # %cleanup.i.i.i
	.cfi_def_cfa_offset 48
.Ltmp312:
	movq	%rax, %r15
	testq	%rbx, %rbx
	je	.LBB104_12
.LBB104_4:                              # %bb8.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp313:
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h7fdbf070a286670aE
.Ltmp314:
# %bb.5:                                # %.noexc.i.i
                                        #   in Loop: Header=BB104_4 Depth=1
	addq	$40, %r12
	addq	$-40, %rbx
	jne	.LBB104_4
.LBB104_12:                             # %cleanup.body.i.i
	movq	16(%r14), %rdi
	movq	24(%r14), %rsi
	callq	_ZN5alloc5alloc8box_free17hcfad119380109afaE
	addq	$32, %r14
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB104_11:                             # %cleanup.i.i
.Ltmp315:
	movq	%rax, %r15
	jmp	.LBB104_12
.Lfunc_end104:
	.size	_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E, .Lfunc_end104-_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table104:
.Lexception35:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end35-.Lcst_begin35
.Lcst_begin35:
	.uleb128 .Ltmp310-.Lfunc_begin35 # >> Call Site 1 <<
	.uleb128 .Ltmp311-.Ltmp310      #   Call between .Ltmp310 and .Ltmp311
	.uleb128 .Ltmp312-.Lfunc_begin35 #     jumps to .Ltmp312
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp313-.Lfunc_begin35 # >> Call Site 2 <<
	.uleb128 .Ltmp314-.Ltmp313      #   Call between .Ltmp313 and .Ltmp314
	.uleb128 .Ltmp315-.Lfunc_begin35 #     jumps to .Ltmp315
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp314-.Lfunc_begin35 # >> Call Site 3 <<
	.uleb128 .Lfunc_end104-.Ltmp314 #   Call between .Ltmp314 and .Lfunc_end104
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end35:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E
	.type	_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E,@function
_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E: # @_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jb	.LBB105_2
# %bb.1:                                # %bb3.i.i
	lock		subq	$1, 8(%rax)
	jne	.LBB105_2
# %bb.3:                                # %bb6.i.i
	#MEMBARRIER
	movq	(%rdi), %rdi
	movl	$144, %esi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB105_2:                              # %_ZN4core3ptr18real_drop_in_place17hf622eec4bf4c77bdE.exit
	retq
.Lfunc_end105:
	.size	_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E, .Lfunc_end105-_ZN4core3ptr18real_drop_in_place17hf72921a7bb3322d2E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE
	.type	_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE,@function
_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE: # @"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	testq	%rsi, %rsi
	je	.LBB106_2
# %bb.1:                                # %bb3
	movq	%rsi, %rdx
	movq	%rdi, %rax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.LBB106_2:                              # %bb5
	.cfi_def_cfa_offset 16
	movq	%rsp, %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.9, %edi
	movl	$43, %esi
	movl	$.Lvtable.9, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Lfunc_end106:
	.size	_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE, .Lfunc_end106-_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E"
.Lfunc_begin36:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception36
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	movq	24(%rbx), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	24(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	leaq	40(%rbx), %r15
.Ltmp316:
	movq	%r15, %rdi
	callq	*_ZN69_$LT$std..sync..condvar..Condvar$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4eee38946b40573cE@GOTPCREL(%rip)
.Ltmp317:
# %bb.1:                                # %bb5.i.i
	movq	40(%rbx), %rdi
	movl	$48, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	56(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB107_3
# %bb.2:                                # %bb3.i.i.i.i
	addq	$56, %rbx
	#MEMBARRIER
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E
.LBB107_3:                              # %_ZN4core3ptr13drop_in_place17h61e7a69d715aee9dE.exit
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB107_4
# %bb.6:                                # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$64, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB107_4:                              # %bb11
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB107_5:                              # %cleanup.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp318:
	movq	%rax, %r14
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	addq	$56, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6a1b919391b771b5E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end107:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E, .Lfunc_end107-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table107:
.Lexception36:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end36-.Lcst_begin36
.Lcst_begin36:
	.uleb128 .Ltmp316-.Lfunc_begin36 # >> Call Site 1 <<
	.uleb128 .Ltmp317-.Ltmp316      #   Call between .Ltmp316 and .Ltmp317
	.uleb128 .Ltmp318-.Lfunc_begin36 #     jumps to .Ltmp318
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp317-.Lfunc_begin36 # >> Call Site 2 <<
	.uleb128 .Lfunc_end107-.Ltmp317 #   Call between .Ltmp317 and .Lfunc_end107
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end36:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E"
.Lfunc_begin37:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception37
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, (%rsp)            # 8-byte Spill
	movq	(%rdi), %r15
	movq	16(%r15), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	16(%r15), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	32(%r15), %rbp
	movq	40(%r15), %rdi
	movq	48(%r15), %rbx
	movq	56(%r15), %r12
	cmpq	%rbp, %rdi
	jae	.LBB108_4
# %bb.1:                                # %bb2.i.i.i.i.i.i.i.i
	movq	%rdi, %r13
	cmpq	%rbp, %r12
	jae	.LBB108_6
# %bb.2:                                # %bb4.i.i.i.i.i.i.i.i.i.i
.Ltmp343:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.7, %edi
	movl	$28, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.6, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp344:
# %bb.3:                                # %.noexc.i.i.i.i.i
.LBB108_4:                              # %bb1.i.i.i.i.i.i.i.i.i.i.i
	cmpq	%rdi, %r12
	jb	.LBB108_7
# %bb.5:
	xorl	%r13d, %r13d
	movq	%rdi, %r12
.LBB108_6:                              # %"_ZN5alloc11collections9vec_deque17VecDeque$LT$T$GT$13as_mut_slices17h735216223c3ac28eE.exit.i.i.i.i.i.i"
	movq	%rbx, 8(%rsp)
	movq	%r13, 16(%rsp)
	shlq	$3, %rbp
	shlq	$3, %r12
	movq	_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip), %r14
	.p2align	4, 0x90
.LBB108_13:                             # %bb11.i.i6.i.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r12
	je	.LBB108_14
# %bb.12:                               # %bb10.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB108_13 Depth=1
	movq	(%rbx,%rbp), %rdi
	addq	$8, %rbp
.Ltmp321:
	callq	*%r14
.Ltmp322:
	jmp	.LBB108_13
.LBB108_14:                             # %bb3.i.i.i.i.i.i
	shlq	$3, %r13
	xorl	%ebp, %ebp
	.p2align	4, 0x90
.LBB108_20:                             # %bb11.i.i.i.i.i.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r13
	je	.LBB108_21
# %bb.19:                               # %bb10.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB108_20 Depth=1
	movq	(%rbx,%rbp), %rdi
	addq	$8, %rbp
.Ltmp329:
	callq	*%r14
.Ltmp330:
	jmp	.LBB108_20
.LBB108_21:                             # %bb4.i.i.i.i.i
	movq	56(%r15), %rsi
	testq	%rsi, %rsi
	je	.LBB108_23
# %bb.22:                               # %bb4.i.i.i.i.i.i.i.i
	movq	48(%r15), %rdi
	shlq	$3, %rsi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB108_23:                             # %bb4.i.i.i.i
	movq	72(%r15), %rax
	testq	%rax, %rax
	je	.LBB108_26
# %bb.24:                               # %bb2.i.i.i.i.i
	lock		subq	$1, (%rax)
	jne	.LBB108_26
# %bb.25:                               # %bb3.i.i.i.i.i.i.i.i
	leaq	72(%r15), %rdi
	#MEMBARRIER
.Ltmp335:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE
.Ltmp336:
.LBB108_26:                             # %bb10.i.i
	leaq	96(%r15), %rbx
.Ltmp337:
	movq	%rbx, %rdi
	callq	*_ZN69_$LT$std..sync..condvar..Condvar$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4eee38946b40573cE@GOTPCREL(%rip)
.Ltmp338:
# %bb.27:                               # %bb9.i.i
	movq	96(%r15), %rdi
	movl	$48, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	120(%r15), %rsi
	testq	%rsi, %rsi
	je	.LBB108_29
# %bb.28:                               # %bb4.i.i.i.i.i.i.i
	movq	112(%r15), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB108_29:                             # %bb8.i.i
	movq	152(%r15), %rax
	testq	%rax, %rax
	je	.LBB108_32
# %bb.30:                               # %bb2.i19.i.i
	lock		subq	$1, (%rax)
	jne	.LBB108_32
# %bb.31:                               # %bb3.i.i.i20.i.i
	leaq	152(%r15), %rdi
	#MEMBARRIER
.Ltmp340:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
.Ltmp341:
.LBB108_32:                             # %bb7.i.i
	movq	168(%r15), %rax
	testq	%rax, %rax
	je	.LBB108_35
# %bb.33:                               # %bb2.i.i.i
	lock		subq	$1, (%rax)
	jne	.LBB108_35
# %bb.34:                               # %bb3.i.i.i.i.i
	addq	$168, %r15
	#MEMBARRIER
	movq	%r15, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
.LBB108_35:                             # %_ZN4core3ptr13drop_in_place17h273fd82c967e3b2fE.exit
	movq	(%rsp), %rcx            # 8-byte Reload
	movq	(%rcx), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB108_50
# %bb.36:                               # %bb5
	#MEMBARRIER
	movq	(%rcx), %rdi
	movl	$192, %esi
	movl	$8, %edx
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB108_50:                             # %bb11
	.cfi_def_cfa_offset 80
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB108_7:                              # %bb5.i.i.i.i.i.i.i.i.i.i.i
	.cfi_def_cfa_offset 80
.Ltmp319:
	movq	%r12, %rsi
	callq	*_ZN4core5slice20slice_index_len_fail17ha58ce2526532f1e6E@GOTPCREL(%rip)
.Ltmp320:
# %bb.8:                                # %.noexc7.i.i.i.i.i
.LBB108_48:                             # %cleanup3.i.i
.Ltmp342:
	movq	%rax, %r14
	jmp	.LBB108_49
.LBB108_44:                             # %cleanup.i.i.i
.Ltmp339:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	jmp	.LBB108_45
.LBB108_37:                             # %cleanup.i.i.i.i.i.i.i.i.i.i
.Ltmp331:
	movq	%rax, %r14
.LBB108_18:                             # %.noexc8.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r13
	je	.LBB108_43
# %bb.16:                               # %bb8.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB108_18 Depth=1
	movq	(%rbx,%rbp), %rdi
.Ltmp332:
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp333:
# %bb.17:                               # %.noexc8.i.i.i.i.i
                                        #   in Loop: Header=BB108_18 Depth=1
	addq	$8, %rbp
	jmp	.LBB108_18
.LBB108_40:                             # %cleanup.loopexit.i.i.i.i.i
.Ltmp334:
	jmp	.LBB108_42
.LBB108_15:                             # %cleanup.i.i.i.i.i.i.i.i
.Ltmp323:
	movq	%rax, %r14
.LBB108_11:                             # %.noexc.i.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbp, %r12
	je	.LBB108_39
# %bb.9:                                # %bb8.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB108_11 Depth=1
	movq	(%rbx,%rbp), %rdi
.Ltmp324:
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp325:
# %bb.10:                               # %.noexc.i.i.i.i.i.i
                                        #   in Loop: Header=BB108_11 Depth=1
	addq	$8, %rbp
	jmp	.LBB108_11
.LBB108_38:                             # %cleanup.i.i.i.i.i.i
.Ltmp326:
	movq	%rax, %r14
.LBB108_39:                             # %cleanup.body.i.i.i.i.i.i
.Ltmp327:
	leaq	8(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0c5e93ad2f336c64E
.Ltmp328:
.LBB108_43:                             # %cleanup.body.i.i.i.i.i
	movq	48(%r15), %rdi
	movq	56(%r15), %rsi
	callq	_ZN4core3ptr18real_drop_in_place17h90d8552239534afaE
	leaq	72(%r15), %rdi
.Ltmp346:
	callq	_ZN4core3ptr18real_drop_in_place17h34cd177c93b7022dE
.Ltmp347:
.LBB108_47:                             # %cleanup.body.i.i
	leaq	96(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E
.LBB108_45:                             # %bb4.i.i
	leaq	112(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
	leaq	152(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
.LBB108_49:                             # %bb3.i.i
	addq	$168, %r15
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB108_41:                             # %cleanup.loopexit.split-lp.i.i.i.i.i
.Ltmp345:
.LBB108_42:                             # %cleanup.body.i.i.i.i.i
	movq	%rax, %r14
	jmp	.LBB108_43
.LBB108_46:                             # %cleanup.i.i
.Ltmp348:
	movq	%rax, %r14
	jmp	.LBB108_47
.Lfunc_end108:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E, .Lfunc_end108-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0b7738850a39f860E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table108:
.Lexception37:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end37-.Lcst_begin37
.Lcst_begin37:
	.uleb128 .Ltmp343-.Lfunc_begin37 # >> Call Site 1 <<
	.uleb128 .Ltmp344-.Ltmp343      #   Call between .Ltmp343 and .Ltmp344
	.uleb128 .Ltmp345-.Lfunc_begin37 #     jumps to .Ltmp345
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp321-.Lfunc_begin37 # >> Call Site 2 <<
	.uleb128 .Ltmp322-.Ltmp321      #   Call between .Ltmp321 and .Ltmp322
	.uleb128 .Ltmp323-.Lfunc_begin37 #     jumps to .Ltmp323
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp329-.Lfunc_begin37 # >> Call Site 3 <<
	.uleb128 .Ltmp330-.Ltmp329      #   Call between .Ltmp329 and .Ltmp330
	.uleb128 .Ltmp331-.Lfunc_begin37 #     jumps to .Ltmp331
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp335-.Lfunc_begin37 # >> Call Site 4 <<
	.uleb128 .Ltmp336-.Ltmp335      #   Call between .Ltmp335 and .Ltmp336
	.uleb128 .Ltmp348-.Lfunc_begin37 #     jumps to .Ltmp348
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp337-.Lfunc_begin37 # >> Call Site 5 <<
	.uleb128 .Ltmp338-.Ltmp337      #   Call between .Ltmp337 and .Ltmp338
	.uleb128 .Ltmp339-.Lfunc_begin37 #     jumps to .Ltmp339
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp340-.Lfunc_begin37 # >> Call Site 6 <<
	.uleb128 .Ltmp341-.Ltmp340      #   Call between .Ltmp340 and .Ltmp341
	.uleb128 .Ltmp342-.Lfunc_begin37 #     jumps to .Ltmp342
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp341-.Lfunc_begin37 # >> Call Site 7 <<
	.uleb128 .Ltmp319-.Ltmp341      #   Call between .Ltmp341 and .Ltmp319
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp319-.Lfunc_begin37 # >> Call Site 8 <<
	.uleb128 .Ltmp320-.Ltmp319      #   Call between .Ltmp319 and .Ltmp320
	.uleb128 .Ltmp345-.Lfunc_begin37 #     jumps to .Ltmp345
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp332-.Lfunc_begin37 # >> Call Site 9 <<
	.uleb128 .Ltmp333-.Ltmp332      #   Call between .Ltmp332 and .Ltmp333
	.uleb128 .Ltmp334-.Lfunc_begin37 #     jumps to .Ltmp334
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp324-.Lfunc_begin37 # >> Call Site 10 <<
	.uleb128 .Ltmp325-.Ltmp324      #   Call between .Ltmp324 and .Ltmp325
	.uleb128 .Ltmp326-.Lfunc_begin37 #     jumps to .Ltmp326
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp327-.Lfunc_begin37 # >> Call Site 11 <<
	.uleb128 .Ltmp328-.Ltmp327      #   Call between .Ltmp327 and .Ltmp328
	.uleb128 .Ltmp345-.Lfunc_begin37 #     jumps to .Ltmp345
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp346-.Lfunc_begin37 # >> Call Site 12 <<
	.uleb128 .Ltmp347-.Ltmp346      #   Call between .Ltmp346 and .Ltmp347
	.uleb128 .Ltmp348-.Lfunc_begin37 #     jumps to .Ltmp348
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp347-.Lfunc_begin37 # >> Call Site 13 <<
	.uleb128 .Lfunc_end108-.Ltmp347 #   Call between .Ltmp347 and .Lfunc_end108
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end37:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E"
.Lfunc_begin38:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception38
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	movq	24(%rbx), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	24(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	addq	$40, %rbx
.Ltmp349:
	movq	%rbx, %rdi
	callq	*_ZN69_$LT$std..sync..condvar..Condvar$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4eee38946b40573cE@GOTPCREL(%rip)
.Ltmp350:
# %bb.1:                                # %_ZN4core3ptr13drop_in_place17h18737bd901e0313aE.exit
	movq	(%rbx), %rdi
	movl	$48, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB109_2
# %bb.4:                                # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$56, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB109_2:                              # %bb11
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB109_3:                              # %cleanup.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp351:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end109:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E, .Lfunc_end109-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table109:
.Lexception38:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end38-.Lcst_begin38
.Lcst_begin38:
	.uleb128 .Ltmp349-.Lfunc_begin38 # >> Call Site 1 <<
	.uleb128 .Ltmp350-.Ltmp349      #   Call between .Ltmp349 and .Ltmp350
	.uleb128 .Ltmp351-.Lfunc_begin38 #     jumps to .Ltmp351
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp350-.Lfunc_begin38 # >> Call Site 2 <<
	.uleb128 .Lfunc_end109-.Ltmp350 #   Call between .Ltmp350 and .Lfunc_end109
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end38:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E"
.Lfunc_begin39:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception39
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$72, %rsp
	.cfi_def_cfa_offset 128
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, 32(%rsp)          # 8-byte Spill
	movq	(%rdi), %rcx
	leaq	16(%rcx), %rax
	movq	%rax, 8(%rsp)           # 8-byte Spill
	movq	%rcx, (%rsp)            # 8-byte Spill
	movq	24(%rcx), %rax
	testq	%rax, %rax
	je	.LBB110_7
# %bb.1:                                # %"_ZN85_$LT$core..slice..Iter$LT$T$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hff7c58754b4d39fcE.exit.preheader.i.i.i"
	movq	(%rsp), %rcx            # 8-byte Reload
	movq	16(%rcx), %r15
	leaq	(%rax,%rax,2), %rax
	leaq	(%r15,%rax,8), %rax
	movq	%rax, 40(%rsp)          # 8-byte Spill
	movq	_ZN83_$LT$tokio..loom..std..atomic_u32..AtomicU32$u20$as$u20$core..ops..deref..Deref$GT$5deref17h413be14b30362907E@GOTPCREL(%rip), %r12
	jmp	.LBB110_2
	.p2align	4, 0x90
.LBB110_6:                              # %bb3.loopexit.i.i.i
                                        #   in Loop: Header=BB110_2 Depth=1
	movq	48(%rsp), %r15          # 8-byte Reload
	cmpq	40(%rsp), %r15          # 8-byte Folded Reload
	je	.LBB110_7
.LBB110_2:                              # %"_ZN85_$LT$core..slice..Iter$LT$T$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hff7c58754b4d39fcE.exit.i.i.i"
                                        # =>This Loop Header: Depth=1
                                        #     Child Loop BB110_3 Depth 2
                                        #       Child Loop BB110_5 Depth 3
	leaq	24(%r15), %rax
	movq	%rax, 48(%rsp)          # 8-byte Spill
	leaq	16(%r15), %rbx
	leaq	20(%r15), %r13
.LBB110_3:                              # %bb8.i.i.i
                                        #   Parent Loop BB110_2 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB110_5 Depth 3
.Ltmp352:
	movq	%rbx, %rdi
	callq	*%r12
.Ltmp353:
# %bb.4:                                # %_32.i.i.noexc.i.i
                                        #   in Loop: Header=BB110_3 Depth=2
	movl	(%rax), %ebp
.Ltmp354:
	movq	%r13, %rdi
	callq	*_ZN5tokio4loom3std10atomic_u329AtomicU3211unsync_load17h136f72c9a15700c3E@GOTPCREL(%rip)
.Ltmp355:
	.p2align	4, 0x90
.LBB110_5:                              # %_114.i.i.noexc.i.i
                                        #   Parent Loop BB110_2 Depth=1
                                        #     Parent Loop BB110_3 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
	cmpl	%eax, %ebp
	je	.LBB110_6
# %bb.13:                               # %bb5.i.i.i.i
                                        #   in Loop: Header=BB110_5 Depth=3
	movzbl	%bpl, %esi
	movq	8(%r15), %rdx
	cmpq	%rsi, %rdx
	jbe	.LBB110_18
# %bb.14:                               # %bb8.i7.i.i.i
                                        #   in Loop: Header=BB110_5 Depth=3
	movq	(%r15), %rax
	movq	(%rax,%rsi,8), %r14
.Ltmp358:
	movq	%rbx, %rdi
	callq	*%r12
.Ltmp359:
# %bb.15:                               # %_22.i.i.noexc.i.i
                                        #   in Loop: Header=BB110_5 Depth=3
	movq	%rax, %rcx
	leal	1(%rbp), %edx
	movl	%ebp, %eax
	lock		cmpxchgl	%edx, (%rcx)
	je	.LBB110_20
# %bb.16:                               # %bb13.i.i.i.i
                                        #   in Loop: Header=BB110_5 Depth=3
	pause
.Ltmp360:
	movq	%rbx, %rdi
	callq	*%r12
.Ltmp361:
# %bb.17:                               # %_3.i.i.noexc.i.i
                                        #   in Loop: Header=BB110_5 Depth=3
	movl	(%rax), %ebp
.Ltmp362:
	movq	%r13, %rdi
	callq	*_ZN5tokio4loom3std10atomic_u329AtomicU3211unsync_load17h136f72c9a15700c3E@GOTPCREL(%rip)
.Ltmp363:
	jmp	.LBB110_5
	.p2align	4, 0x90
.LBB110_20:                             # %"_ZN5tokio7runtime11thread_pool5queue5local14Queue$LT$T$GT$3pop17h76a98b4988aef1ffE.exit.i.i.i"
                                        #   in Loop: Header=BB110_3 Depth=2
	testq	%r14, %r14
	je	.LBB110_6
# %bb.21:                               # %bb2.i9.i.i.i
                                        #   in Loop: Header=BB110_3 Depth=2
.Ltmp365:
	movq	%r14, %rdi
	callq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip)
.Ltmp366:
	jmp	.LBB110_3
.LBB110_7:                              # %bb14.preheader.i.i.i
	movq	(%rsp), %r12            # 8-byte Reload
	leaq	32(%r12), %r14
	leaq	64(%r12), %r13
	movq	_ZN87_$LT$tokio..loom..std..atomic_usize..AtomicUsize$u20$as$u20$core..ops..deref..Deref$GT$5deref17hbaf43d7bebd8d6d8E@GOTPCREL(%rip), %r15
	.p2align	4, 0x90
.LBB110_8:                              # %bb14.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp368:
	movq	%r13, %rdi
	callq	*%r15
.Ltmp369:
# %bb.9:                                # %_3.i.i.i.i.noexc.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	(%rax), %rax
	cmpq	$2, %rax
	jb	.LBB110_30
# %bb.10:                               # %bb3.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	(%r14), %rdi
	callq	*pthread_mutex_lock@GOTPCREL(%rip)
.Ltmp370:
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
.Ltmp371:
# %bb.11:                               # %.noexc15.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movzbl	40(%r12), %ecx
	testb	%cl, %cl
	jne	.LBB110_12
# %bb.24:                               # %bb10.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	%r14, 16(%rsp)
	movb	%al, 24(%rsp)
	movq	48(%r12), %rbx
	testq	%rbx, %rbx
	je	.LBB110_25
# %bb.39:                               # %bb16.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
.Ltmp377:
	movq	%rbx, %rdi
	callq	*_ZN5tokio7runtime11thread_pool5queue6global8get_next17haf015d9603c07a33E@GOTPCREL(%rip)
.Ltmp378:
# %bb.40:                               # %bb20.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	%rax, 48(%r12)
	testq	%rax, %rax
	jne	.LBB110_42
# %bb.41:                               # %bb23.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	$0, 56(%r12)
.LBB110_42:                             # %bb25.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
.Ltmp379:
	movq	%rbx, %rdi
	xorl	%esi, %esi
	callq	*_ZN5tokio7runtime11thread_pool5queue6global8set_next17hf22f40b83bbe18f7E@GOTPCREL(%rip)
.Ltmp380:
# %bb.43:                               # %bb26.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
.Ltmp381:
	movq	%r13, %rdi
	callq	*%r15
.Ltmp382:
# %bb.44:                               # %bb27.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	%rax, %rbp
.Ltmp383:
	movq	%r13, %rdi
	callq	*_ZN5tokio4loom3std12atomic_usize11AtomicUsize11unsync_load17h73b132dc0500d3d9E@GOTPCREL(%rip)
.Ltmp384:
# %bb.45:                               # %bb29.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	addq	$-2, %rax
	movq	%rax, (%rbp)
	movq	16(%rsp), %rbp
	cmpb	$0, 24(%rsp)
	jne	.LBB110_49
# %bb.46:                               # %bb3.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
.Ltmp388:
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
.Ltmp389:
# %bb.47:                               # %.noexc18.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	testb	%al, %al
	je	.LBB110_49
# %bb.48:                               # %bb6.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movb	$1, 8(%rbp)
	.p2align	4, 0x90
.LBB110_49:                             # %bb2.i.i.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
	movq	(%rbp), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
.Ltmp390:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
.Ltmp391:
# %bb.50:                               # %.noexc20.i.i
                                        #   in Loop: Header=BB110_8 Depth=1
.Ltmp392:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip)
.Ltmp393:
	jmp	.LBB110_8
.LBB110_25:                             # %bb14.i.i.i.i
	testb	%al, %al
	jne	.LBB110_29
# %bb.26:                               # %bb3.i.i.i.i.i.i.i
.Ltmp395:
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
.Ltmp396:
# %bb.27:                               # %.noexc17.i.i
	testb	%al, %al
	je	.LBB110_29
# %bb.28:                               # %bb6.i.i.i.i.i.i.i
	movb	$1, 40(%r12)
.LBB110_29:                             # %_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE.exit.i.i.i.i
	movq	(%r14), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
.LBB110_30:                             # %bb6.i.i
	movq	24(%r12), %rax
	testq	%rax, %rax
	je	.LBB110_37
# %bb.31:                               # %bb10.preheader.i.i.i.i
	movq	16(%r12), %rbx
	shlq	$3, %rax
	leaq	(%rax,%rax,2), %r15
	xorl	%ebp, %ebp
	movq	__rust_dealloc@GOTPCREL(%rip), %r12
	jmp	.LBB110_32
	.p2align	4, 0x90
.LBB110_34:                             # %_ZN4core3ptr18real_drop_in_place17h86790422b7020667E.exit.i.i.i.i
                                        #   in Loop: Header=BB110_32 Depth=1
	addq	$24, %rbp
	cmpq	%rbp, %r15
	je	.LBB110_35
.LBB110_32:                             # %bb10.i.i22.i.i
                                        # =>This Inner Loop Header: Depth=1
	movq	8(%rbx,%rbp), %rsi
	shlq	$3, %rsi
	testq	%rsi, %rsi
	je	.LBB110_34
# %bb.33:                               # %bb4.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB110_32 Depth=1
	movq	(%rbx,%rbp), %rdi
	movl	$8, %edx
	callq	*%r12
	jmp	.LBB110_34
.LBB110_35:                             # %bb3.i.i.i
	movq	(%rsp), %rax            # 8-byte Reload
	movq	24(%rax), %rax
	shlq	$3, %rax
	leaq	(%rax,%rax,2), %rsi
	testq	%rsi, %rsi
	je	.LBB110_37
# %bb.36:                               # %bb4.i.i.i.i
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB110_37:                             # %_ZN4core3ptr13drop_in_place17hbd8e4f49258c270cE.exit
	movq	(%r14), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	(%r14), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	32(%rsp), %rcx          # 8-byte Reload
	movq	(%rcx), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB110_59
# %bb.38:                               # %bb5
	#MEMBARRIER
	movq	(%rcx), %rdi
	movl	$72, %esi
	movl	$8, %edx
	addq	$72, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB110_59:                             # %bb11
	.cfi_def_cfa_offset 128
	addq	$72, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB110_18:                             # %panic.i.i.i.i
	.cfi_def_cfa_offset 128
.Ltmp356:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.50, %edi
	movq	(%rsp), %r12            # 8-byte Reload
	callq	*_ZN4core9panicking18panic_bounds_check17hdf3f3ae37b439756E@GOTPCREL(%rip)
.Ltmp357:
# %bb.19:                               # %.noexc.i.i
.LBB110_12:                             # %bb5.i.i.i.i.i
	movq	%r14, 56(%rsp)
	movb	%al, 64(%rsp)
.Ltmp372:
	leaq	56(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.9, %edi
	movl	$43, %esi
	movl	$.Lvtable.7, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp373:
# %bb.23:                               # %unreachable.i.i.i.i.i
.LBB110_22:                             # %bb1.i.i.i.i.i
.Ltmp374:
	movq	%rax, %rbx
.Ltmp375:
	leaq	56(%rsp), %rdi
	movq	(%rsp), %r12            # 8-byte Reload
	callq	_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E
.Ltmp376:
	jmp	.LBB110_58
.LBB110_51:                             # %bb32.i.i.i.i
.Ltmp385:
	movq	%rax, %rbx
.Ltmp386:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h17386eb751d7fc4eE
.Ltmp387:
	jmp	.LBB110_58
.LBB110_56:                             # %cleanup.loopexit.split-lp.loopexit.split-lp.loopexit.split-lp.i.i
.Ltmp397:
	jmp	.LBB110_57
.LBB110_52:                             # %cleanup.loopexit.i.i
.Ltmp394:
.LBB110_57:                             # %cleanup.body.i.i
	movq	%rax, %rbx
	jmp	.LBB110_58
.LBB110_55:                             # %cleanup.loopexit.split-lp.loopexit.split-lp.loopexit.i.i
.Ltmp367:
	jmp	.LBB110_54
.LBB110_53:                             # %cleanup.loopexit.split-lp.loopexit.i.i
.Ltmp364:
.LBB110_54:                             # %cleanup.body.i.i
	movq	%rax, %rbx
	movq	(%rsp), %r12            # 8-byte Reload
.LBB110_58:                             # %cleanup.body.i.i
	movq	8(%rsp), %rdi           # 8-byte Reload
	callq	_ZN4core3ptr18real_drop_in_place17hc186ceffa195d583E
	addq	$32, %r12
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb84cac86afc837feE
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end110:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E, .Lfunc_end110-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table110:
.Lexception39:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end39-.Lcst_begin39
.Lcst_begin39:
	.uleb128 .Ltmp352-.Lfunc_begin39 # >> Call Site 1 <<
	.uleb128 .Ltmp355-.Ltmp352      #   Call between .Ltmp352 and .Ltmp355
	.uleb128 .Ltmp367-.Lfunc_begin39 #     jumps to .Ltmp367
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp358-.Lfunc_begin39 # >> Call Site 2 <<
	.uleb128 .Ltmp363-.Ltmp358      #   Call between .Ltmp358 and .Ltmp363
	.uleb128 .Ltmp364-.Lfunc_begin39 #     jumps to .Ltmp364
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp365-.Lfunc_begin39 # >> Call Site 3 <<
	.uleb128 .Ltmp366-.Ltmp365      #   Call between .Ltmp365 and .Ltmp366
	.uleb128 .Ltmp367-.Lfunc_begin39 #     jumps to .Ltmp367
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp368-.Lfunc_begin39 # >> Call Site 4 <<
	.uleb128 .Ltmp371-.Ltmp368      #   Call between .Ltmp368 and .Ltmp371
	.uleb128 .Ltmp394-.Lfunc_begin39 #     jumps to .Ltmp394
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp377-.Lfunc_begin39 # >> Call Site 5 <<
	.uleb128 .Ltmp384-.Ltmp377      #   Call between .Ltmp377 and .Ltmp384
	.uleb128 .Ltmp385-.Lfunc_begin39 #     jumps to .Ltmp385
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp388-.Lfunc_begin39 # >> Call Site 6 <<
	.uleb128 .Ltmp393-.Ltmp388      #   Call between .Ltmp388 and .Ltmp393
	.uleb128 .Ltmp394-.Lfunc_begin39 #     jumps to .Ltmp394
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp395-.Lfunc_begin39 # >> Call Site 7 <<
	.uleb128 .Ltmp396-.Ltmp395      #   Call between .Ltmp395 and .Ltmp396
	.uleb128 .Ltmp397-.Lfunc_begin39 #     jumps to .Ltmp397
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp396-.Lfunc_begin39 # >> Call Site 8 <<
	.uleb128 .Ltmp356-.Ltmp396      #   Call between .Ltmp396 and .Ltmp356
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp356-.Lfunc_begin39 # >> Call Site 9 <<
	.uleb128 .Ltmp357-.Ltmp356      #   Call between .Ltmp356 and .Ltmp357
	.uleb128 .Ltmp397-.Lfunc_begin39 #     jumps to .Ltmp397
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp372-.Lfunc_begin39 # >> Call Site 10 <<
	.uleb128 .Ltmp373-.Ltmp372      #   Call between .Ltmp372 and .Ltmp373
	.uleb128 .Ltmp374-.Lfunc_begin39 #     jumps to .Ltmp374
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp375-.Lfunc_begin39 # >> Call Site 11 <<
	.uleb128 .Ltmp387-.Ltmp375      #   Call between .Ltmp375 and .Ltmp387
	.uleb128 .Ltmp397-.Lfunc_begin39 #     jumps to .Ltmp397
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp387-.Lfunc_begin39 # >> Call Site 12 <<
	.uleb128 .Lfunc_end110-.Ltmp387 #   Call between .Ltmp387 and .Lfunc_end110
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end39:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E"
.Lfunc_begin40:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception40
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	leaq	56(%rbx), %rdi
.Ltmp398:
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp399:
# %bb.1:                                # %bb4.i.i.i
	leaq	60(%rbx), %rdi
.Ltmp403:
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp404:
# %bb.2:                                # %_ZN4core3ptr13drop_in_place17hbf3466463a2ab6e6E.exit
	movq	32(%rbx), %rdi
	movq	__rust_dealloc@GOTPCREL(%rip), %r15
	movl	$64, %esi
	movl	$8, %edx
	callq	*%r15
	movq	40(%rbx), %rdi
	movl	$64, %esi
	movl	$8, %edx
	callq	*%r15
	movq	48(%rbx), %rdi
	movl	$64, %esi
	movl	$8, %edx
	callq	*%r15
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB111_7
# %bb.3:                                # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$64, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB111_7:                              # %bb11
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB111_4:                              # %cleanup.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp400:
	movq	%rax, %r14
	leaq	60(%rbx), %rdi
.Ltmp401:
	callq	_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE
.Ltmp402:
	jmp	.LBB111_5
.LBB111_6:                              # %cleanup.i.i
.Ltmp405:
	movq	%rax, %r14
.LBB111_5:                              # %bb3.i.i
	leaq	32(%rbx), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E
	leaq	40(%rbx), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E
	addq	$48, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h02e96a77055b26b7E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end111:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E, .Lfunc_end111-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table111:
.Lexception40:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end40-.Lcst_begin40
.Lcst_begin40:
	.uleb128 .Ltmp398-.Lfunc_begin40 # >> Call Site 1 <<
	.uleb128 .Ltmp399-.Ltmp398      #   Call between .Ltmp398 and .Ltmp399
	.uleb128 .Ltmp400-.Lfunc_begin40 #     jumps to .Ltmp400
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp403-.Lfunc_begin40 # >> Call Site 2 <<
	.uleb128 .Ltmp404-.Ltmp403      #   Call between .Ltmp403 and .Ltmp404
	.uleb128 .Ltmp405-.Lfunc_begin40 #     jumps to .Ltmp405
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp404-.Lfunc_begin40 # >> Call Site 3 <<
	.uleb128 .Ltmp401-.Ltmp404      #   Call between .Ltmp404 and .Ltmp401
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp401-.Lfunc_begin40 # >> Call Site 4 <<
	.uleb128 .Ltmp402-.Ltmp401      #   Call between .Ltmp401 and .Ltmp402
	.uleb128 .Ltmp405-.Lfunc_begin40 #     jumps to .Ltmp405
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp402-.Lfunc_begin40 # >> Call Site 5 <<
	.uleb128 .Lfunc_end111-.Ltmp402 #   Call between .Ltmp402 and .Lfunc_end111
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end40:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E"
.Lfunc_begin41:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception41
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	(%rdi), %r15
	leaq	16(%r15), %rdi
.Ltmp406:
	callq	*_ZN73_$LT$mio..sys..unix..epoll..Selector$u20$as$u20$core..ops..drop..Drop$GT$4drop17h788c62d502c77cc3E@GOTPCREL(%rip)
.Ltmp407:
# %bb.1:                                # %bb8.i.i.i
	leaq	32(%r15), %rbx
.Ltmp411:
	movq	%rbx, %rdi
	callq	*_ZN67_$LT$mio..poll..ReadinessQueue$u20$as$u20$core..ops..drop..Drop$GT$4drop17hd5e3d1166226f4d7E@GOTPCREL(%rip)
.Ltmp412:
# %bb.2:                                # %bb4.i.i.i.i
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB112_4
# %bb.3:                                # %bb3.i.i.i.i.i.i
	#MEMBARRIER
.Ltmp416:
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h2b4004cb1a3842a7E
.Ltmp417:
.LBB112_4:                              # %bb6.i.i.i
	movq	48(%r15), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	48(%r15), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	leaq	64(%r15), %rbx
.Ltmp422:
	movq	%rbx, %rdi
	callq	*_ZN69_$LT$std..sync..condvar..Condvar$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4eee38946b40573cE@GOTPCREL(%rip)
.Ltmp423:
# %bb.5:                                # %bb6.i.i
	movq	64(%r15), %rdi
	movl	$48, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	leaq	80(%r15), %rdi
.Ltmp425:
	callq	_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E
.Ltmp426:
# %bb.6:                                # %_ZN4core3ptr13drop_in_place17hc40e711a86409f6fE.exit
	addq	$136, %r15
	movq	%r15, %rdi
	callq	*_ZN70_$LT$mio..poll..RegistrationInner$u20$as$u20$core..ops..drop..Drop$GT$4drop17h45090a25a224e339E@GOTPCREL(%rip)
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB112_17
# %bb.7:                                # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$144, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB112_17:                             # %bb11
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB112_16:                             # %cleanup1.i.i
	.cfi_def_cfa_offset 32
.Ltmp427:
	movq	%rax, %r14
	jmp	.LBB112_15
.LBB112_8:                              # %cleanup.i.i.i.i
.Ltmp424:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha6fa1980cd7ce6c6E
	jmp	.LBB112_14
.LBB112_9:                              # %cleanup.i12.i.i.i
.Ltmp413:
	movq	%rax, %r14
.Ltmp414:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17habc6c8abb5f5d03aE
.Ltmp415:
	jmp	.LBB112_11
.LBB112_12:                             # %cleanup1.i.i.i
.Ltmp418:
	movq	%rax, %r14
	jmp	.LBB112_11
.LBB112_10:                             # %cleanup.i.i.i
.Ltmp408:
	movq	%rax, %r14
	leaq	32(%r15), %rdi
.Ltmp409:
	callq	_ZN4core3ptr18real_drop_in_place17hc545d43790ffecbeE
.Ltmp410:
.LBB112_11:                             # %bb3.i.i.i
	leaq	48(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h34e8b2af0c545c8bE
	leaq	64(%r15), %rdi
.Ltmp419:
	callq	_ZN4core3ptr18real_drop_in_place17h57c7b716786d5f27E
.Ltmp420:
.LBB112_14:                             # %cleanup.body.i.i
	leaq	80(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hf06429378fe5ad37E
.LBB112_15:                             # %bb3.i.i
	addq	$136, %r15
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h5caf02987c84db7fE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB112_13:                             # %cleanup.i.i
.Ltmp421:
	movq	%rax, %r14
	jmp	.LBB112_14
.Lfunc_end112:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E, .Lfunc_end112-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h5d84505ff6cb1dc8E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table112:
.Lexception41:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end41-.Lcst_begin41
.Lcst_begin41:
	.uleb128 .Ltmp406-.Lfunc_begin41 # >> Call Site 1 <<
	.uleb128 .Ltmp407-.Ltmp406      #   Call between .Ltmp406 and .Ltmp407
	.uleb128 .Ltmp408-.Lfunc_begin41 #     jumps to .Ltmp408
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp411-.Lfunc_begin41 # >> Call Site 2 <<
	.uleb128 .Ltmp412-.Ltmp411      #   Call between .Ltmp411 and .Ltmp412
	.uleb128 .Ltmp413-.Lfunc_begin41 #     jumps to .Ltmp413
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp416-.Lfunc_begin41 # >> Call Site 3 <<
	.uleb128 .Ltmp417-.Ltmp416      #   Call between .Ltmp416 and .Ltmp417
	.uleb128 .Ltmp418-.Lfunc_begin41 #     jumps to .Ltmp418
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp422-.Lfunc_begin41 # >> Call Site 4 <<
	.uleb128 .Ltmp423-.Ltmp422      #   Call between .Ltmp422 and .Ltmp423
	.uleb128 .Ltmp424-.Lfunc_begin41 #     jumps to .Ltmp424
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp425-.Lfunc_begin41 # >> Call Site 5 <<
	.uleb128 .Ltmp426-.Ltmp425      #   Call between .Ltmp425 and .Ltmp426
	.uleb128 .Ltmp427-.Lfunc_begin41 #     jumps to .Ltmp427
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp426-.Lfunc_begin41 # >> Call Site 6 <<
	.uleb128 .Ltmp414-.Ltmp426      #   Call between .Ltmp426 and .Ltmp414
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp414-.Lfunc_begin41 # >> Call Site 7 <<
	.uleb128 .Ltmp415-.Ltmp414      #   Call between .Ltmp414 and .Ltmp415
	.uleb128 .Ltmp418-.Lfunc_begin41 #     jumps to .Ltmp418
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp409-.Lfunc_begin41 # >> Call Site 8 <<
	.uleb128 .Ltmp420-.Ltmp409      #   Call between .Ltmp409 and .Ltmp420
	.uleb128 .Ltmp421-.Lfunc_begin41 #     jumps to .Ltmp421
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp420-.Lfunc_begin41 # >> Call Site 9 <<
	.uleb128 .Lfunc_end112-.Ltmp420 #   Call between .Ltmp420 and .Lfunc_end112
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end41:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E"
.Lfunc_begin42:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception42
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	leaq	24(%rbx), %rdi
.Ltmp428:
	callq	_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E
.Ltmp429:
# %bb.1:                                # %bb4.i.i.i
	movq	56(%rbx), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	56(%rbx), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	leaq	72(%rbx), %rdi
.Ltmp433:
	callq	_ZN4core3ptr18real_drop_in_place17h3fc5e9ef977b7cf0E
.Ltmp434:
# %bb.2:                                # %bb4.i.i
	movq	120(%rbx), %rdi
	movq	128(%rbx), %rax
.Ltmp436:
	callq	*(%rax)
.Ltmp437:
# %bb.3:                                # %bb3.i.i.i
	movq	128(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB113_5
# %bb.4:                                # %bb4.i.i.i.i
	movq	120(%rbx), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB113_5:                              # %_ZN4core3ptr13drop_in_place17hbcb394e4be98b822E.exit
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB113_10
# %bb.6:                                # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$136, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB113_10:                             # %bb11
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB113_11:                             # %cleanup.i5.i.i
	.cfi_def_cfa_offset 32
.Ltmp438:
	movq	%rax, %r14
	movq	120(%rbx), %rdi
	movq	128(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB113_7:                              # %cleanup.i.i.i
.Ltmp430:
	movq	%rax, %r14
	leaq	56(%rbx), %rdi
.Ltmp431:
	callq	_ZN4core3ptr18real_drop_in_place17h466fb76dfe79443cE
.Ltmp432:
	jmp	.LBB113_9
.LBB113_8:                              # %cleanup.i.i
.Ltmp435:
	movq	%rax, %r14
.LBB113_9:                              # %cleanup.body.i.i
	addq	$120, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb9548981e85bfaaeE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end113:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E, .Lfunc_end113-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table113:
.Lexception42:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end42-.Lcst_begin42
.Lcst_begin42:
	.uleb128 .Ltmp428-.Lfunc_begin42 # >> Call Site 1 <<
	.uleb128 .Ltmp429-.Ltmp428      #   Call between .Ltmp428 and .Ltmp429
	.uleb128 .Ltmp430-.Lfunc_begin42 #     jumps to .Ltmp430
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp433-.Lfunc_begin42 # >> Call Site 2 <<
	.uleb128 .Ltmp434-.Ltmp433      #   Call between .Ltmp433 and .Ltmp434
	.uleb128 .Ltmp435-.Lfunc_begin42 #     jumps to .Ltmp435
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp436-.Lfunc_begin42 # >> Call Site 3 <<
	.uleb128 .Ltmp437-.Ltmp436      #   Call between .Ltmp436 and .Ltmp437
	.uleb128 .Ltmp438-.Lfunc_begin42 #     jumps to .Ltmp438
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp437-.Lfunc_begin42 # >> Call Site 4 <<
	.uleb128 .Ltmp431-.Ltmp437      #   Call between .Ltmp437 and .Ltmp431
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp431-.Lfunc_begin42 # >> Call Site 5 <<
	.uleb128 .Ltmp432-.Ltmp431      #   Call between .Ltmp431 and .Ltmp432
	.uleb128 .Ltmp435-.Lfunc_begin42 #     jumps to .Ltmp435
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp432-.Lfunc_begin42 # >> Call Site 6 <<
	.uleb128 .Lfunc_end113-.Ltmp432 #   Call between .Ltmp432 and .Lfunc_end113
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end42:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E"
.Lfunc_begin43:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception43
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	leaq	16(%rbx), %rdi
.Ltmp439:
	callq	_ZN4core3ptr18real_drop_in_place17h81ef323e0c51fdcbE
.Ltmp440:
# %bb.1:                                # %bb4.i.i
	leaq	80(%rbx), %rdi
	cmpq	$0, 72(%rbx)
	je	.LBB114_2
# %bb.5:                                # %bb3.i.i.i
	movq	(%rdi), %rax
	lock		subq	$1, (%rax)
	jne	.LBB114_7
# %bb.6:                                # %bb3.i.i.i1.i.i.i
	#MEMBARRIER
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h11947988d5165e69E
	jmp	.LBB114_7
.LBB114_2:                              # %bb2.i.i.i
	movq	(%rdi), %rax
	leaq	1(%rax), %rcx
	cmpq	$2, %rcx
	jae	.LBB114_3
.LBB114_7:                              # %_ZN4core3ptr13drop_in_place17h9669b46bc9cb170aE.exit
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB114_8
# %bb.10:                               # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$88, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB114_8:                              # %bb11
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB114_3:                              # %bb3.i.i.i.i.i.i
	.cfi_def_cfa_offset 32
	lock		subq	$1, 8(%rax)
	jne	.LBB114_7
# %bb.4:                                # %bb6.i.i.i.i.i.i
	#MEMBARRIER
	movq	(%rdi), %rdi
	movl	$144, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB114_7
.LBB114_9:                              # %cleanup.i.i
.Ltmp441:
	movq	%rax, %r14
	addq	$72, %rbx
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h26bbc049ccc22ec4E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end114:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E, .Lfunc_end114-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9da3ed3bbf13a0f5E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table114:
.Lexception43:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end43-.Lcst_begin43
.Lcst_begin43:
	.uleb128 .Ltmp439-.Lfunc_begin43 # >> Call Site 1 <<
	.uleb128 .Ltmp440-.Ltmp439      #   Call between .Ltmp439 and .Ltmp440
	.uleb128 .Ltmp441-.Lfunc_begin43 #     jumps to .Ltmp441
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp440-.Lfunc_begin43 # >> Call Site 2 <<
	.uleb128 .Lfunc_end114-.Ltmp440 #   Call between .Ltmp440 and .Lfunc_end114
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end43:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE"
.Lfunc_begin44:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception44
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	(%rdi), %r15
	leaq	16(%r15), %r12
.Ltmp442:
	movq	%r12, %rdi
	callq	*_ZN81_$LT$tokio..runtime..thread_pool..slice..Set$u20$as$u20$core..ops..drop..Drop$GT$4drop17he4cb7fb60aab743cE@GOTPCREL(%rip)
.Ltmp443:
# %bb.1:                                # %bb10.i.i
	movq	24(%r15), %rax
	testq	%rax, %rax
	je	.LBB115_8
# %bb.2:                                # %bb10.preheader.i.i.i.i
	movq	16(%r15), %rbx
	leaq	(%rax,%rax,2), %rax
	leaq	-24(,%rax,8), %r13
	jmp	.LBB115_3
	.p2align	4, 0x90
.LBB115_5:                              # %_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE.exit.i.i.i.i
                                        #   in Loop: Header=BB115_3 Depth=1
	addq	$24, %rbx
	addq	$-24, %r13
	cmpq	$-24, %r13
	je	.LBB115_6
.LBB115_3:                              # %bb10.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	movq	(%rbx), %rax
	lock		subq	$1, (%rax)
	jne	.LBB115_5
# %bb.4:                                # %bb3.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB115_3 Depth=1
	#MEMBARRIER
.Ltmp445:
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h0a7fbfec7b3b8de4E
.Ltmp446:
	jmp	.LBB115_5
.LBB115_6:                              # %bb3.i.i.i
	movq	24(%r15), %rax
	shlq	$3, %rax
	leaq	(%rax,%rax,2), %rsi
	testq	%rsi, %rsi
	je	.LBB115_8
# %bb.7:                                # %bb4.i.i.i.i
	movq	(%r12), %rdi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB115_8:                              # %bb9.i.i
	leaq	32(%r15), %rdi
.Ltmp451:
	callq	_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E
.Ltmp452:
# %bb.9:                                # %bb8.i.i
	movq	48(%r15), %rax
	lock		subq	$1, (%rax)
	jne	.LBB115_11
# %bb.10:                               # %bb3.i.i.i.i.i
	leaq	48(%r15), %rdi
	#MEMBARRIER
.Ltmp454:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h27122a2f92d5b3e1E
.Ltmp455:
.LBB115_11:                             # %bb7.i.i
	movq	64(%r15), %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movq	64(%r15), %rdi
	movl	$40, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	88(%r15), %rsi
	testq	%rsi, %rsi
	je	.LBB115_13
# %bb.12:                               # %bb4.i.i.i.i.i.i.i.i.i
	movq	80(%r15), %rdi
	shlq	$3, %rsi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB115_13:                             # %_ZN4core3ptr13drop_in_place17h47fb34901932a24fE.exit
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB115_27
# %bb.14:                               # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$112, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB115_27:                             # %bb11
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB115_26:                             # %cleanup3.i.i
	.cfi_def_cfa_offset 48
.Ltmp456:
	movq	%rax, %r14
	jmp	.LBB115_17
.LBB115_15:                             # %cleanup2.i.i
.Ltmp453:
	movq	%rax, %r14
	jmp	.LBB115_16
.LBB115_24:                             # %cleanup.i.i
.Ltmp444:
	movq	%rax, %r14
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hf03004b4cf0d299fE
	jmp	.LBB115_25
.LBB115_20:                             # %cleanup.i.i.i.i
.Ltmp447:
	movq	%rax, %r14
	testq	%r13, %r13
	je	.LBB115_23
# %bb.21:
	addq	$24, %rbx
.LBB115_18:                             # %bb8.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp448:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1e17b893d760546dE
.Ltmp449:
# %bb.19:                               # %.noexc.i.i.i
                                        #   in Loop: Header=BB115_18 Depth=1
	addq	$24, %rbx
	addq	$-24, %r13
	jne	.LBB115_18
.LBB115_23:                             # %cleanup.body.i.i.i
	movq	16(%r15), %rdi
	movq	24(%r15), %rsi
	callq	_ZN5alloc5alloc8box_free17hc2af688206b9dacdE
.LBB115_25:                             # %bb5.i.i
	leaq	32(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha34e7f3e5c4d81c1E
.LBB115_16:                             # %bb4.i.i
	leaq	48(%r15), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0a3379bb6d3dc22fE
.LBB115_17:                             # %bb3.i.i
	addq	$56, %r15
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6aa61a8176e62ef4E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB115_22:                             # %cleanup.i.i.i
.Ltmp450:
	movq	%rax, %r14
	jmp	.LBB115_23
.Lfunc_end115:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE, .Lfunc_end115-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table115:
.Lexception44:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end44-.Lcst_begin44
.Lcst_begin44:
	.uleb128 .Ltmp442-.Lfunc_begin44 # >> Call Site 1 <<
	.uleb128 .Ltmp443-.Ltmp442      #   Call between .Ltmp442 and .Ltmp443
	.uleb128 .Ltmp444-.Lfunc_begin44 #     jumps to .Ltmp444
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp445-.Lfunc_begin44 # >> Call Site 2 <<
	.uleb128 .Ltmp446-.Ltmp445      #   Call between .Ltmp445 and .Ltmp446
	.uleb128 .Ltmp447-.Lfunc_begin44 #     jumps to .Ltmp447
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp451-.Lfunc_begin44 # >> Call Site 3 <<
	.uleb128 .Ltmp452-.Ltmp451      #   Call between .Ltmp451 and .Ltmp452
	.uleb128 .Ltmp453-.Lfunc_begin44 #     jumps to .Ltmp453
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp454-.Lfunc_begin44 # >> Call Site 4 <<
	.uleb128 .Ltmp455-.Ltmp454      #   Call between .Ltmp454 and .Ltmp455
	.uleb128 .Ltmp456-.Lfunc_begin44 #     jumps to .Ltmp456
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp455-.Lfunc_begin44 # >> Call Site 5 <<
	.uleb128 .Ltmp448-.Ltmp455      #   Call between .Ltmp455 and .Ltmp448
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp448-.Lfunc_begin44 # >> Call Site 6 <<
	.uleb128 .Ltmp449-.Ltmp448      #   Call between .Ltmp448 and .Ltmp449
	.uleb128 .Ltmp450-.Lfunc_begin44 #     jumps to .Ltmp450
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp449-.Lfunc_begin44 # >> Call Site 7 <<
	.uleb128 .Lfunc_end115-.Ltmp449 #   Call between .Ltmp449 and .Lfunc_end115
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end44:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	movq	8(%rdi), %rax
	movq	16(%rax), %rcx
	leaq	15(%rcx), %rdi
	negq	%rcx
	andq	%rcx, %rdi
	addq	(%rbx), %rdi
	callq	*(%rax)
	movq	(%rbx), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB116_1
# %bb.2:                                # %bb5
	#MEMBARRIER
	movq	(%rbx), %rdi
	movq	8(%rbx), %rax
	movq	16(%rax), %rcx
	cmpq	$8, %rcx
	movl	$8, %edx
	cmovaq	%rcx, %rdx
	movq	8(%rax), %rax
	addq	%rdx, %rax
	addq	$15, %rax
	movq	%rdx, %rsi
	negq	%rsi
	andq	%rax, %rsi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB116_1:                              # %bb11
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end116:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE, .Lfunc_end116-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	(%rdi), %r15
	leaq	16(%r15), %rdi
	callq	*_ZN90_$LT$tokio..loom..std..atomic_usize..AtomicUsize$u20$as$u20$core..ops..deref..DerefMut$GT$9deref_mut17h10cfc10a31d682beE@GOTPCREL(%rip)
	movq	(%rax), %rbx
	movq	%rbx, %rdi
	callq	*_ZN5tokio4sync7oneshot5State14is_rx_task_set17hf17667a651d30d00E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB117_2
# %bb.1:                                # %bb4.i.i.i
	movq	40(%r15), %rdi
	movq	48(%r15), %rax
	callq	*24(%rax)
.LBB117_2:                              # %bb6.i.i.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4sync7oneshot5State14is_tx_task_set17h1483fb4bbe76be02E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB117_4
# %bb.3:                                # %bb8.i.i.i
	movq	24(%r15), %rdi
	movq	32(%r15), %rax
	callq	*24(%rax)
.LBB117_4:                              # %_ZN4core3ptr13drop_in_place17h2e23b474068f43b0E.exit
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB117_5
# %bb.6:                                # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$64, %esi
	movl	$8, %edx
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB117_5:                              # %bb11
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end117:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E, .Lfunc_end117-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE
	.type	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE,@function
_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE: # @"_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE"
.Lfunc_begin45:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception45
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	pushq	%rax
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	(%rdi), %rbx
	movq	16(%rbx), %r12
	testq	%r12, %r12
	je	.LBB118_10
# %bb.1:                                # %bb2.i.i.i
	addq	$16, %rbx
	leaq	16(%r12), %rdi
.Ltmp457:
	callq	*_ZN5tokio4sync7oneshot5State12set_complete17h9f887ac06cc82a2cE@GOTPCREL(%rip)
.Ltmp458:
# %bb.2:                                # %_6.i.i.noexc.i.i
	movq	%rax, %r15
.Ltmp459:
	movq	%rax, %rdi
	callq	*_ZN5tokio4sync7oneshot5State9is_closed17h11a4ace625e3d0f5E@GOTPCREL(%rip)
.Ltmp460:
# %bb.3:                                # %.noexc.i.i
	testb	%al, %al
	jne	.LBB118_7
# %bb.4:                                # %bb3.i.i.i.i
.Ltmp461:
	movq	%r15, %rdi
	callq	*_ZN5tokio4sync7oneshot5State14is_rx_task_set17hf17667a651d30d00E@GOTPCREL(%rip)
.Ltmp462:
# %bb.5:                                # %.noexc5.i.i
	testb	%al, %al
	je	.LBB118_7
# %bb.6:                                # %bb7.i.i.i.i
	movq	40(%r12), %rdi
	movq	48(%r12), %rax
.Ltmp463:
	callq	*16(%rax)
.Ltmp464:
.LBB118_7:                              # %bb4.i.i
	movq	(%rbx), %rax
	testq	%rax, %rax
	je	.LBB118_10
# %bb.8:                                # %bb2.i7.i.i
	lock		subq	$1, (%rax)
	jne	.LBB118_10
# %bb.9:                                # %bb3.i.i.i.i.i
	#MEMBARRIER
	movq	%rbx, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hdf925423c13282e1E
.LBB118_10:                             # %_ZN4core3ptr13drop_in_place17h66cd8985e312a10fE.exit
	movq	(%r14), %rax
	lock		subq	$1, 8(%rax)
	jne	.LBB118_11
# %bb.13:                               # %bb5
	#MEMBARRIER
	movq	(%r14), %rdi
	movl	$24, %esi
	movl	$8, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB118_11:                             # %bb11
	.cfi_def_cfa_offset 48
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB118_12:                             # %cleanup.i.i
	.cfi_def_cfa_offset 48
.Ltmp465:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h42c5a505e750659bE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end118:
	.size	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE, .Lfunc_end118-_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17he590ba7b80be8f2aE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table118:
.Lexception45:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end45-.Lcst_begin45
.Lcst_begin45:
	.uleb128 .Ltmp457-.Lfunc_begin45 # >> Call Site 1 <<
	.uleb128 .Ltmp464-.Ltmp457      #   Call between .Ltmp457 and .Ltmp464
	.uleb128 .Ltmp465-.Lfunc_begin45 #     jumps to .Ltmp465
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp464-.Lfunc_begin45 # >> Call Site 2 <<
	.uleb128 .Lfunc_end118-.Ltmp464 #   Call between .Ltmp464 and .Lfunc_end118
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end45:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17h39766183111e1fbdE
	.type	_ZN5alloc5alloc8box_free17h39766183111e1fbdE,@function
_ZN5alloc5alloc8box_free17h39766183111e1fbdE: # @_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	.cfi_startproc
# %bb.0:                                # %start
	movq	%rsi, %rax
	movq	8(%rsi), %rsi
	testq	%rsi, %rsi
	je	.LBB119_1
# %bb.2:                                # %bb4
	movq	16(%rax), %rdx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB119_1:                              # %bb7
	retq
.Lfunc_end119:
	.size	_ZN5alloc5alloc8box_free17h39766183111e1fbdE, .Lfunc_end119-_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17h75f7638681be2462E
	.type	_ZN5alloc5alloc8box_free17h75f7638681be2462E,@function
_ZN5alloc5alloc8box_free17h75f7638681be2462E: # @_ZN5alloc5alloc8box_free17h75f7638681be2462E
	.cfi_startproc
# %bb.0:                                # %start
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end120:
	.size	_ZN5alloc5alloc8box_free17h75f7638681be2462E, .Lfunc_end120-_ZN5alloc5alloc8box_free17h75f7638681be2462E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17h98ac21c208ff1c57E
	.type	_ZN5alloc5alloc8box_free17h98ac21c208ff1c57E,@function
_ZN5alloc5alloc8box_free17h98ac21c208ff1c57E: # @_ZN5alloc5alloc8box_free17h98ac21c208ff1c57E
	.cfi_startproc
# %bb.0:                                # %start
	shlq	$6, %rsi
	je	.LBB121_1
# %bb.2:                                # %bb4
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB121_1:                              # %bb7
	retq
.Lfunc_end121:
	.size	_ZN5alloc5alloc8box_free17h98ac21c208ff1c57E, .Lfunc_end121-_ZN5alloc5alloc8box_free17h98ac21c208ff1c57E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	.type	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE,@function
_ZN5alloc5alloc8box_free17ha829dafaf86a282fE: # @_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	.cfi_startproc
# %bb.0:                                # %start
	movl	$24, %esi
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.Lfunc_end122:
	.size	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE, .Lfunc_end122-_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17hb071a4daabbfbecaE
	.type	_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE,@function
_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE: # @_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE
	.cfi_startproc
# %bb.0:                                # %start
	shlq	$7, %rsi
	je	.LBB123_1
# %bb.2:                                # %bb4
	movl	$128, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB123_1:                              # %bb7
	retq
.Lfunc_end123:
	.size	_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE, .Lfunc_end123-_ZN5alloc5alloc8box_free17hb071a4daabbfbecaE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17hc2af688206b9dacdE
	.type	_ZN5alloc5alloc8box_free17hc2af688206b9dacdE,@function
_ZN5alloc5alloc8box_free17hc2af688206b9dacdE: # @_ZN5alloc5alloc8box_free17hc2af688206b9dacdE
	.cfi_startproc
# %bb.0:                                # %start
	shlq	$3, %rsi
	leaq	(%rsi,%rsi,2), %rsi
	testq	%rsi, %rsi
	je	.LBB124_1
# %bb.2:                                # %bb4
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB124_1:                              # %bb7
	retq
.Lfunc_end124:
	.size	_ZN5alloc5alloc8box_free17hc2af688206b9dacdE, .Lfunc_end124-_ZN5alloc5alloc8box_free17hc2af688206b9dacdE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc5alloc8box_free17hcfad119380109afaE
	.type	_ZN5alloc5alloc8box_free17hcfad119380109afaE,@function
_ZN5alloc5alloc8box_free17hcfad119380109afaE: # @_ZN5alloc5alloc8box_free17hcfad119380109afaE
	.cfi_startproc
# %bb.0:                                # %start
	shlq	$3, %rsi
	leaq	(%rsi,%rsi,4), %rsi
	testq	%rsi, %rsi
	je	.LBB125_1
# %bb.2:                                # %bb4
	movl	$8, %edx
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB125_1:                              # %bb7
	retq
.Lfunc_end125:
	.size	_ZN5alloc5alloc8box_free17hcfad119380109afaE, .Lfunc_end125-_ZN5alloc5alloc8box_free17hcfad119380109afaE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE
	.type	_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE,@function
_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE: # @"_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	pushq	%rax
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r14
	movq	8(%rdi), %rbx
	xorl	%r12d, %r12d
	testq	%rbx, %rbx
	setne	%al
	testq	%rbx, %rbx
	je	.LBB126_3
# %bb.1:                                # %"_ZN4core6result19Result$LT$T$C$E$GT$14unwrap_or_else17h84b39e1212184ee4E.exit"
	movb	%al, %r12b
	shlq	$3, %r12
	leaq	(,%rbx,8), %rsi
	movq	%rbx, %r15
	shlq	$4, %r15
	movq	(%r14), %rdi
	movq	%r12, %rdx
	movq	%r15, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB126_6
# %bb.2:                                # %bb16
	addq	%rbx, %rbx
	jmp	.LBB126_5
.LBB126_3:                              # %bb23
	movl	$32, %edi
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB126_7
# %bb.4:                                # %bb23.bb31_crit_edge
	movl	$4, %ebx
.LBB126_5:                              # %bb31
	movq	%rax, (%r14)
	movq	%rbx, 8(%r14)
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB126_6:                              # %bb14
	.cfi_def_cfa_offset 48
	movq	%r15, %rdi
	movq	%r12, %rsi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.LBB126_7:                              # %bb25
	movl	$32, %edi
	movl	$8, %esi
	callq	_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h85e7125661f2df3bE
	movq	%rax, %rdi
	movq	%rdx, %rsi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.Lfunc_end126:
	.size	_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE, .Lfunc_end126-_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE
	.type	_ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE,@function
_ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE: # @"_ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	movq	(%rax), %rax
	movq	(%rax), %rax
	movq	(%rax), %rax
	retq
.Lfunc_end127:
	.size	_ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE, .Lfunc_end127-_ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E
	.type	_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E,@function
_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E: # @_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E
.Lfunc_begin46:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception46
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	subq	$264, %rsp              # imm = 0x108
	.cfi_def_cfa_offset 304
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rsi, %r14
	movq	%rdi, %rbx
	movq	%rdx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB128_1
# %bb.7:                                # %bb3.i
	leaq	72(%rsp), %rdi
	callq	*_ZN5tokio4task5error9JoinError10cancelled217h1d6355458d07eb67E@GOTPCREL(%rip)
	movq	$1, (%r14)
	movups	72(%rsp), %xmm0
	movups	88(%rsp), %xmm1
	movups	%xmm0, 8(%r14)
	movups	%xmm1, 24(%r14)
	jmp	.LBB128_8
.LBB128_1:                              # %bb2.i
	movl	$2, %eax
	movq	%rax, %xmm0
	movdqu	48(%rbx), %xmm1
	movups	64(%rbx), %xmm2
	movups	80(%rbx), %xmm11
	movups	96(%rbx), %xmm4
	movdqu	%xmm0, 48(%rbx)
	movups	128(%rbx), %xmm9
	movups	112(%rbx), %xmm5
	movups	160(%rbx), %xmm6
	movups	144(%rbx), %xmm7
	movups	192(%rbx), %xmm8
	movups	176(%rbx), %xmm0
	movups	224(%rbx), %xmm10
	movups	208(%rbx), %xmm3
	movups	%xmm2, 88(%rsp)
	movdqu	%xmm1, 72(%rsp)
	movups	%xmm11, 104(%rsp)
	movups	%xmm4, 120(%rsp)
	movups	%xmm5, 136(%rsp)
	movups	%xmm9, 152(%rsp)
	movups	%xmm7, 168(%rsp)
	movups	%xmm6, 184(%rsp)
	movups	%xmm0, 200(%rsp)
	movups	%xmm8, 216(%rsp)
	movups	%xmm3, 232(%rsp)
	movups	%xmm10, 248(%rsp)
	movq	%xmm1, %rax
	cmpq	$1, %rax
	jne	.LBB128_2
# %bb.6:                                # %"_ZN5tokio4task4core13Core$LT$T$GT$11read_output17hf565d9c93be0b629E.exit.i"
	movq	112(%rsp), %rax
	movq	%rax, 32(%r14)
	movups	80(%rsp), %xmm0
	movups	96(%rsp), %xmm1
	movups	%xmm1, 16(%r14)
	movups	%xmm0, (%r14)
.LBB128_8:                              # %bb9.i
	movq	240(%rbx), %r14
	movq	248(%rbx), %r12
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State20complete_join_handle17h328e1451ce68f6f3E@GOTPCREL(%rip)
	movq	%rax, %r15
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_released17hb98c4cec87a92420E@GOTPCREL(%rip)
	testq	%r12, %r12
	je	.LBB128_11
# %bb.9:                                # %bb9.i
	testb	%al, %al
	je	.LBB128_11
# %bb.10:                               # %bb2.i.i.i
	movq	%r14, %rdi
	callq	*24(%r12)
.LBB128_11:                             # %bb17.i
	movq	%r15, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB128_14
# %bb.12:                               # %bb19.i
	leaq	48(%rbx), %rdi
.Ltmp469:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp470:
# %bb.13:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17hd857a2847326da88E.exit.i"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%rbx, %rdi
	addq	$264, %rsp              # imm = 0x108
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB128_14:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11read_output17h9008b46f2ceda23bE.exit"
	.cfi_def_cfa_offset 304
	addq	$264, %rsp              # imm = 0x108
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB128_2:                              # %bb7.i.i
	.cfi_def_cfa_offset 304
	movl	$_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h568fe60fa079166bE, %eax
	movq	%rax, %xmm0
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.23, %eax
	movq	%rax, %xmm1
	punpcklqdq	%xmm0, %xmm1    # xmm1 = xmm1[0],xmm0[0]
	movdqa	%xmm1, (%rsp)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.21, 24(%rsp)
	movq	$1, 32(%rsp)
	movq	$0, 40(%rsp)
	movq	%rsp, %rax
	movq	%rax, 56(%rsp)
	movq	$1, 64(%rsp)
.Ltmp466:
	leaq	24(%rsp), %rdi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.25, %esi
	callq	*_ZN3std9panicking15begin_panic_fmt17h8df736026eee128cE@GOTPCREL(%rip)
.Ltmp467:
# %bb.5:                                # %unreachable.i.i
.LBB128_3:                              # %cleanup.i.i
.Ltmp468:
	movq	%rax, %r14
	cmpl	$1, 72(%rsp)
	jne	.LBB128_15
# %bb.4:                                # %bb10.i.i
	leaq	80(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB128_15:                             # %bb11.i.i
	leaq	72(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB128_17:                             # %cleanup.i.i.i.i
.Ltmp471:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end128:
	.size	_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E, .Lfunc_end128-_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table128:
.Lexception46:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end46-.Lcst_begin46
.Lcst_begin46:
	.uleb128 .Lfunc_begin46-.Lfunc_begin46 # >> Call Site 1 <<
	.uleb128 .Ltmp469-.Lfunc_begin46 #   Call between .Lfunc_begin46 and .Ltmp469
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp469-.Lfunc_begin46 # >> Call Site 2 <<
	.uleb128 .Ltmp470-.Ltmp469      #   Call between .Ltmp469 and .Ltmp470
	.uleb128 .Ltmp471-.Lfunc_begin46 #     jumps to .Ltmp471
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp466-.Lfunc_begin46 # >> Call Site 3 <<
	.uleb128 .Ltmp467-.Ltmp466      #   Call between .Ltmp466 and .Ltmp467
	.uleb128 .Ltmp468-.Lfunc_begin46 #     jumps to .Ltmp468
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp467-.Lfunc_begin46 # >> Call Site 4 <<
	.uleb128 .Lfunc_end128-.Ltmp467 #   Call between .Ltmp467 and .Lfunc_end128
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end46:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E
	.type	_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E,@function
_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E: # @_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E
.Lfunc_begin47:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception47
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	248(%rdi), %rax
	testq	%rax, %rax
	je	.LBB129_15
# %bb.1:                                # %"_ZN4core6option15Option$LT$T$GT$6unwrap17h3beba3607e555013E.exit.i.i.i"
	movq	%rsi, %r15
	movq	%rdi, %rbx
	leaq	240(%rdi), %r13
	movq	(%rsi), %r12
	cmpq	%r12, (%r13)
	jne	.LBB129_6
# %bb.2:                                # %bb3.i.i.i.i.i
	movq	%rdx, %r14
	movq	8(%r15), %rcx
	movq	(%rax), %rdx
	cmpq	(%rcx), %rdx
	jne	.LBB129_6
# %bb.3:                                # %bb11.i.i.i.i.i.i.i
	movq	8(%rax), %rdx
	cmpq	8(%rcx), %rdx
	jne	.LBB129_6
# %bb.4:                                # %bb7.i.i.i.i.i.i.i
	movq	16(%rax), %rdx
	cmpq	16(%rcx), %rdx
	jne	.LBB129_6
# %bb.5:                                # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$4with17h533b9a3dde94afb8E.exit.i"
	movq	24(%rax), %rax
	cmpq	24(%rcx), %rax
	je	.LBB129_14
.LBB129_6:                              # %bb3.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State11unset_waker17hf201a95db4a2bd90E@GOTPCREL(%rip)
	movq	%rax, %r14
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot9is_active17h8a9442eacb7d6b71E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB129_14
# %bb.7:                                # %bb11.i
	movq	8(%r15), %rax
	movq	%r12, %rdi
	callq	*(%rax)
	movq	240(%rbx), %rdi
	movq	248(%rbx), %rcx
	movq	%rax, 240(%rbx)
	movq	%rdx, 248(%rbx)
	testq	%rcx, %rcx
	je	.LBB129_9
# %bb.8:                                # %bb2.i.i.i5.i.i
	callq	*24(%rcx)
.LBB129_9:                              # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$8with_mut17h021044601bfe2552E.exit.i.i"
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State16store_join_waker17heeb2fa26bdf4151bE@GOTPCREL(%rip)
	movq	%rax, %r14
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_complete17hc01045b854402218E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB129_11
# %bb.10:                               # %bb7.i.i
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB129_14
.LBB129_11:                             # %bb11.i.i
	movq	248(%rbx), %rax
	testq	%rax, %rax
	je	.LBB129_13
# %bb.12:                               # %bb2.i.i.i.i.i
	movq	(%r13), %rdi
.Ltmp472:
	callq	*24(%rax)
.Ltmp473:
.LBB129_13:                             # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$8with_mut17h3b345ae44c5d25baE.exit.i.i"
	xorps	%xmm0, %xmm0
	movups	%xmm0, (%r13)
.LBB129_14:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$15swap_join_waker17h64ab4329ab5f0a55E.exit"
	movq	%r14, %rax
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB129_15:                             # %bb2.i.i.i.i
	.cfi_def_cfa_offset 48
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.8, %edi
	movl	$43, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.6, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.LBB129_16:                             # %bb1.i.i.i.i
.Ltmp474:
	xorps	%xmm0, %xmm0
	movups	%xmm0, (%r13)
	movq	%rax, %rdi
	callq	_Unwind_Resume
.Lfunc_end129:
	.size	_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E, .Lfunc_end129-_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table129:
.Lexception47:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end47-.Lcst_begin47
.Lcst_begin47:
	.uleb128 .Lfunc_begin47-.Lfunc_begin47 # >> Call Site 1 <<
	.uleb128 .Ltmp472-.Lfunc_begin47 #   Call between .Lfunc_begin47 and .Ltmp472
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp472-.Lfunc_begin47 # >> Call Site 2 <<
	.uleb128 .Ltmp473-.Ltmp472      #   Call between .Ltmp472 and .Ltmp473
	.uleb128 .Ltmp474-.Lfunc_begin47 #     jumps to .Ltmp474
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp473-.Lfunc_begin47 # >> Call Site 3 <<
	.uleb128 .Lfunc_end129-.Ltmp473 #   Call between .Ltmp473 and .Lfunc_end129
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end47:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E
	.type	_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E,@function
_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E: # @_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E
.Lfunc_begin48:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception48
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	movq	(%rsi), %rdi
	movq	8(%rsi), %rax
	callq	*(%rax)
	movq	240(%rbx), %rdi
	movq	248(%rbx), %rcx
	movq	%rax, 240(%rbx)
	movq	%rdx, 248(%rbx)
	testq	%rcx, %rcx
	je	.LBB130_2
# %bb.1:                                # %bb2.i.i.i5.i
	callq	*24(%rcx)
.LBB130_2:                              # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$8with_mut17h021044601bfe2552E.exit.i"
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State16store_join_waker17heeb2fa26bdf4151bE@GOTPCREL(%rip)
	movq	%rax, %r14
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_complete17hc01045b854402218E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB130_4
# %bb.3:                                # %bb7.i
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB130_7
.LBB130_4:                              # %bb11.i
	movq	248(%rbx), %rax
	addq	$240, %rbx
	testq	%rax, %rax
	je	.LBB130_6
# %bb.5:                                # %bb2.i.i.i.i
	movq	(%rbx), %rdi
.Ltmp475:
	callq	*24(%rax)
.Ltmp476:
.LBB130_6:                              # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$8with_mut17h3b345ae44c5d25baE.exit.i"
	xorps	%xmm0, %xmm0
	movups	%xmm0, (%rbx)
.LBB130_7:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$16store_join_waker17h2a55a7ce3e7d546dE.exit"
	movq	%r14, %rax
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB130_8:                              # %bb1.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp477:
	xorps	%xmm0, %xmm0
	movups	%xmm0, (%rbx)
	movq	%rax, %rdi
	callq	_Unwind_Resume
.Lfunc_end130:
	.size	_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E, .Lfunc_end130-_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table130:
.Lexception48:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end48-.Lcst_begin48
.Lcst_begin48:
	.uleb128 .Lfunc_begin48-.Lfunc_begin48 # >> Call Site 1 <<
	.uleb128 .Ltmp475-.Lfunc_begin48 #   Call between .Lfunc_begin48 and .Ltmp475
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp475-.Lfunc_begin48 # >> Call Site 2 <<
	.uleb128 .Ltmp476-.Ltmp475      #   Call between .Ltmp475 and .Ltmp476
	.uleb128 .Ltmp477-.Lfunc_begin48 #     jumps to .Ltmp477
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp476-.Lfunc_begin48 # >> Call Site 3 <<
	.uleb128 .Lfunc_end130-.Ltmp476 #   Call between .Ltmp476 and .Lfunc_end130
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end48:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E
	.type	_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E,@function
_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E: # @_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E
.Lfunc_begin49:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception49
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	subq	$192, %rsp
	.cfi_def_cfa_offset 240
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %r15
	movq	240(%rdi), %r14
	movq	248(%rdi), %r12
	callq	*_ZN5tokio4task5state5State21drop_join_handle_slow17h4aa376c2ba7fd89aE@GOTPCREL(%rip)
	movq	%rdx, %rbx
	testq	%rax, %rax
	je	.LBB131_5
# %bb.1:                                # %bb6.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_complete17hc01045b854402218E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB131_4
# %bb.2:                                # %bb8.i
	leaq	48(%r15), %rdi
.Ltmp478:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp479:
# %bb.3:                                # %"_ZN5tokio4task4core13Core$LT$T$GT$22transition_to_consumed17h35d3eb56e13b55baE.exit.i"
	movq	$2, 48(%r15)
	leaq	56(%r15), %rdi
	leaq	8(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
.LBB131_4:                              # %bb11.i
	movq	%r15, %rdi
	callq	*_ZN5tokio4task5state5State20complete_join_handle17h328e1451ce68f6f3E@GOTPCREL(%rip)
	movq	%rax, %rbx
.LBB131_5:                              # %bb14.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_complete17hc01045b854402218E@GOTPCREL(%rip)
	movl	%eax, %ebp
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%bpl, %bpl
	jne	.LBB131_7
# %bb.6:                                # %bb14.i
	testb	%al, %al
	jne	.LBB131_7
# %bb.9:                                # %bb22.i
	testq	%r12, %r12
	jne	.LBB131_10
	jmp	.LBB131_11
.LBB131_7:                              # %bb17.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_released17hb98c4cec87a92420E@GOTPCREL(%rip)
	testq	%r12, %r12
	je	.LBB131_11
# %bb.8:                                # %bb17.i
	testb	%al, %al
	je	.LBB131_11
.LBB131_10:                             # %bb2.i.i.i
	movq	%r14, %rdi
	callq	*24(%r12)
.LBB131_11:                             # %bb25.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB131_14
# %bb.12:                               # %bb27.i
	leaq	48(%r15), %rdi
.Ltmp481:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp482:
# %bb.13:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17hd857a2847326da88E.exit.i"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%r15, %rdi
	addq	$192, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB131_14:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$21drop_join_handle_slow17hf0cfb4106c19084aE.exit"
	.cfi_def_cfa_offset 240
	addq	$192, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB131_15:                             # %cleanup.i.i
	.cfi_def_cfa_offset 240
.Ltmp480:
	movq	%rax, %rbx
	movq	$2, 48(%r15)
	addq	$56, %r15
	leaq	8(%rsp), %rsi
	movl	$184, %edx
	movq	%r15, %rdi
	callq	*memcpy@GOTPCREL(%rip)
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.LBB131_17:                             # %cleanup.i.i.i.i
.Ltmp483:
	movq	%rax, %rbx
	movq	%r15, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end131:
	.size	_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E, .Lfunc_end131-_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table131:
.Lexception49:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end49-.Lcst_begin49
.Lcst_begin49:
	.uleb128 .Lfunc_begin49-.Lfunc_begin49 # >> Call Site 1 <<
	.uleb128 .Ltmp478-.Lfunc_begin49 #   Call between .Lfunc_begin49 and .Ltmp478
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp478-.Lfunc_begin49 # >> Call Site 2 <<
	.uleb128 .Ltmp479-.Ltmp478      #   Call between .Ltmp478 and .Ltmp479
	.uleb128 .Ltmp480-.Lfunc_begin49 #     jumps to .Ltmp480
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp479-.Lfunc_begin49 # >> Call Site 3 <<
	.uleb128 .Ltmp481-.Ltmp479      #   Call between .Ltmp479 and .Ltmp481
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp481-.Lfunc_begin49 # >> Call Site 4 <<
	.uleb128 .Ltmp482-.Ltmp481      #   Call between .Ltmp481 and .Ltmp482
	.uleb128 .Ltmp483-.Lfunc_begin49 #     jumps to .Ltmp483
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp482-.Lfunc_begin49 # >> Call Site 5 <<
	.uleb128 .Lfunc_end131-.Ltmp482 #   Call between .Ltmp482 and .Lfunc_end131
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end49:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw4poll17h03fbca31b17747c9E
	.type	_ZN5tokio4task3raw4poll17h03fbca31b17747c9E,@function
_ZN5tokio4task3raw4poll17h03fbca31b17747c9E: # @_ZN5tokio4task3raw4poll17h03fbca31b17747c9E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	subq	$96, %rsp
	.cfi_def_cfa_offset 144
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdx, %r14
	movq	%rsi, %r15
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State21transition_to_running17h240d042632310ea1E@GOTPCREL(%rip)
	movq	%rax, %rbp
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB132_1
.LBB132_12:                             # %bb36.i
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E
	jmp	.LBB132_10
.LBB132_1:                              # %bb5.i
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
	movl	%eax, %r12d
	movq	%rbx, (%rsp)
	leaq	48(%rbx), %rax
	movq	%rax, 56(%rsp)
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task4core6Header8executor17h840bc5db85041688E@GOTPCREL(%rip)
	testq	%rax, %rax
	jne	.LBB132_4
# %bb.2:                                # %bb13.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	movq	%rax, 16(%rsp)
	movq	%r15, %rdi
	callq	*24(%r14)
	testq	%rax, %rax
	je	.LBB132_13
# %bb.3:                                # %"_ZN4core6option15Option$LT$T$GT$6expect17hba434563f4529786E.exit.i"
	movq	%rax, %rbp
	leaq	16(%rsp), %rsi
	movq	%rax, %rdi
	callq	*_ZN85_$LT$tokio..runtime..thread_pool..shared..Shared$u20$as$u20$tokio..task..Schedule$GT$4bind17h4b80950e4e0d248bE@GOTPCREL(%rip)
	movq	(%rsp), %rax
	movq	%rbp, 8(%rax)
.LBB132_4:                              # %bb24.i
	movq	$0, 8(%rsp)
	movq	$0, 64(%rsp)
	leaq	56(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	%rsp, %rax
	movq	%rax, 24(%rsp)
	leaq	16(%rsp), %rsi
	leaq	8(%rsp), %rdx
	leaq	64(%rsp), %rcx
	movl	$_ZN3std9panicking3try7do_call17h0828aa63555b211dE, %edi
	callq	*__rust_maybe_catch_panic@GOTPCREL(%rip)
	testl	%eax, %eax
	je	.LBB132_5
# %bb.8:                                # %bb40.i
	movq	$-1, %rdi
	callq	*_ZN3std9panicking18update_panic_count17h122a47c81179092bE@GOTPCREL(%rip)
	movq	8(%rsp), %rsi
	movq	64(%rsp), %rdx
	leaq	64(%rsp), %rdi
	callq	*_ZN5tokio4task5error9JoinError6panic217h69bdfc93c60ff130E@GOTPCREL(%rip)
	movups	64(%rsp), %xmm0
	movups	80(%rsp), %xmm1
	movups	%xmm1, 40(%rsp)
	movups	%xmm0, 24(%rsp)
	movq	$1, 16(%rsp)
	jmp	.LBB132_9
.LBB132_5:                              # %bb28.i
	cmpb	$1, 16(%rsp)
	jne	.LBB132_14
# %bb.6:                                # %bb32.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State18transition_to_idle17h3ce1c3ea98916d56E@GOTPCREL(%rip)
	movq	%rax, %rbp
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB132_12
# %bb.7:                                # %bb35.i
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_notified17h1a85ed82a6fc1f2bE@GOTPCREL(%rip)
                                        # kill: def $al killed $al def $eax
	jmp	.LBB132_11
.LBB132_14:                             # %bb26.i
	movq	$0, 16(%rsp)
.LBB132_9:                              # %bb50.i
	movzbl	%r12b, %ecx
	leaq	16(%rsp), %r8
	movq	%rbx, %rdi
	movq	%r15, %rsi
	movq	%r14, %rdx
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E
.LBB132_10:                             # %bb50.i
	xorl	%eax, %eax
.LBB132_11:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$4poll17h4b611eb06a169192E.exit"
                                        # kill: def $al killed $al killed $eax
	addq	$96, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB132_13:                             # %bb2.i.i
	.cfi_def_cfa_offset 144
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.39, %edi
	movl	$39, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Lfunc_end132:
	.size	_ZN5tokio4task3raw4poll17h03fbca31b17747c9E, .Lfunc_end132-_ZN5tokio4task3raw4poll17h03fbca31b17747c9E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw4poll17h8ae230134c718f4fE
	.type	_ZN5tokio4task3raw4poll17h8ae230134c718f4fE,@function
_ZN5tokio4task3raw4poll17h8ae230134c718f4fE: # @_ZN5tokio4task3raw4poll17h8ae230134c718f4fE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	subq	$96, %rsp
	.cfi_def_cfa_offset 144
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdx, %r14
	movq	%rsi, %r15
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State21transition_to_running17h240d042632310ea1E@GOTPCREL(%rip)
	movq	%rax, %rbp
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB133_1
.LBB133_12:                             # %bb36.i
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E
	jmp	.LBB133_10
.LBB133_1:                              # %bb5.i
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
	movl	%eax, %r12d
	movq	%rbx, (%rsp)
	leaq	48(%rbx), %rax
	movq	%rax, 56(%rsp)
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task4core6Header8executor17h840bc5db85041688E@GOTPCREL(%rip)
	testq	%rax, %rax
	jne	.LBB133_4
# %bb.2:                                # %bb13.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	movq	%rax, 16(%rsp)
	movq	%r15, %rdi
	callq	*24(%r14)
	testq	%rax, %rax
	je	.LBB133_13
# %bb.3:                                # %"_ZN4core6option15Option$LT$T$GT$6expect17hba434563f4529786E.exit.i"
	movq	%rax, %rbp
	leaq	16(%rsp), %rsi
	movq	%rax, %rdi
	callq	*_ZN88_$LT$tokio..runtime..basic_scheduler..SchedulerPriv$u20$as$u20$tokio..task..Schedule$GT$4bind17h257780439e14a7cbE@GOTPCREL(%rip)
	movq	(%rsp), %rax
	movq	%rbp, 8(%rax)
.LBB133_4:                              # %bb24.i
	movq	$0, 8(%rsp)
	movq	$0, 64(%rsp)
	leaq	56(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	%rsp, %rax
	movq	%rax, 24(%rsp)
	leaq	16(%rsp), %rsi
	leaq	8(%rsp), %rdx
	leaq	64(%rsp), %rcx
	movl	$_ZN3std9panicking3try7do_call17hcc1357f0800e2dd6E, %edi
	callq	*__rust_maybe_catch_panic@GOTPCREL(%rip)
	testl	%eax, %eax
	je	.LBB133_5
# %bb.8:                                # %bb40.i
	movq	$-1, %rdi
	callq	*_ZN3std9panicking18update_panic_count17h122a47c81179092bE@GOTPCREL(%rip)
	movq	8(%rsp), %rsi
	movq	64(%rsp), %rdx
	leaq	64(%rsp), %rdi
	callq	*_ZN5tokio4task5error9JoinError6panic217h69bdfc93c60ff130E@GOTPCREL(%rip)
	movups	64(%rsp), %xmm0
	movups	80(%rsp), %xmm1
	movups	%xmm1, 40(%rsp)
	movups	%xmm0, 24(%rsp)
	movq	$1, 16(%rsp)
	jmp	.LBB133_9
.LBB133_5:                              # %bb28.i
	cmpb	$1, 16(%rsp)
	jne	.LBB133_14
# %bb.6:                                # %bb32.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State18transition_to_idle17h3ce1c3ea98916d56E@GOTPCREL(%rip)
	movq	%rax, %rbp
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB133_12
# %bb.7:                                # %bb35.i
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_notified17h1a85ed82a6fc1f2bE@GOTPCREL(%rip)
                                        # kill: def $al killed $al def $eax
	jmp	.LBB133_11
.LBB133_14:                             # %bb26.i
	movq	$0, 16(%rsp)
.LBB133_9:                              # %bb50.i
	movzbl	%r12b, %ecx
	leaq	16(%rsp), %r8
	movq	%rbx, %rdi
	movq	%r15, %rsi
	movq	%r14, %rdx
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE
.LBB133_10:                             # %bb50.i
	xorl	%eax, %eax
.LBB133_11:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$4poll17hb7313f175dca7a15E.exit"
                                        # kill: def $al killed $al killed $eax
	addq	$96, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB133_13:                             # %bb2.i.i
	.cfi_def_cfa_offset 144
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.39, %edi
	movl	$39, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Lfunc_end133:
	.size	_ZN5tokio4task3raw4poll17h8ae230134c718f4fE, .Lfunc_end133-_ZN5tokio4task3raw4poll17h8ae230134c718f4fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw6cancel17h1c94218425a95fb3E
	.type	_ZN5tokio4task3raw6cancel17h1c94218425a95fb3E,@function
_ZN5tokio4task3raw6cancel17h1c94218425a95fb3E: # @_ZN5tokio4task3raw6cancel17h1c94218425a95fb3E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	testl	%esi, %esi
	je	.LBB134_1
# %bb.5:                                # %bb2.i
	callq	*_ZN5tokio4task5state5State33transition_to_canceled_from_queue17hb5d5795681ed1a93E@GOTPCREL(%rip)
	movq	%rax, %rsi
	jmp	.LBB134_3
.LBB134_1:                              # %bb1.i
	callq	*_ZN5tokio4task5state5State32transition_to_canceled_from_list17h09b04c8d7355e0daE@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB134_4
# %bb.2:                                # %bb9.i
	movq	%rdx, %rsi
.LBB134_3:                              # %bb11.i
	movq	%rbx, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmp	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E # TAILCALL
.LBB134_4:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$6cancel17hf6716bd3985d82fdE.exit"
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end134:
	.size	_ZN5tokio4task3raw6cancel17h1c94218425a95fb3E, .Lfunc_end134-_ZN5tokio4task3raw6cancel17h1c94218425a95fb3E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw6cancel17h440673ff578b8afaE
	.type	_ZN5tokio4task3raw6cancel17h440673ff578b8afaE,@function
_ZN5tokio4task3raw6cancel17h440673ff578b8afaE: # @_ZN5tokio4task3raw6cancel17h440673ff578b8afaE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	testl	%esi, %esi
	je	.LBB135_1
# %bb.5:                                # %bb2.i
	callq	*_ZN5tokio4task5state5State33transition_to_canceled_from_queue17hb5d5795681ed1a93E@GOTPCREL(%rip)
	movq	%rax, %rsi
	jmp	.LBB135_3
.LBB135_1:                              # %bb1.i
	callq	*_ZN5tokio4task5state5State32transition_to_canceled_from_list17h09b04c8d7355e0daE@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB135_4
# %bb.2:                                # %bb9.i
	movq	%rdx, %rsi
.LBB135_3:                              # %bb11.i
	movq	%rbx, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmp	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E # TAILCALL
.LBB135_4:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$6cancel17he6cad07c7c16263bE.exit"
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end135:
	.size	_ZN5tokio4task3raw6cancel17h440673ff578b8afaE, .Lfunc_end135-_ZN5tokio4task3raw6cancel17h440673ff578b8afaE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E
	.type	_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E,@function
_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E: # @_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E
.Lfunc_begin50:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception50
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	subq	$80, %rsp
	.cfi_def_cfa_offset 128
	.cfi_offset %rbx, -48
	.cfi_offset %r12, -40
	.cfi_offset %r13, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rdi, %r15
	movq	16(%rdi), %r13
	testb	$1, %r13b
	je	.LBB136_1
# %bb.2:                                # %bb3.i
	movq	240(%r15), %r14
	movq	248(%r15), %r12
	jmp	.LBB136_3
.LBB136_1:
                                        # implicit-def: $r12
                                        # implicit-def: $r14
.LBB136_3:                              # %bb5.i
	movq	%r15, %rdi
	callq	*_ZN5tokio4task5state5State12release_task17h72ffa2965b00db4eE@GOTPCREL(%rip)
	movq	%rax, %rbx
	movq	%rax, 8(%rsp)
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_terminal17h28728993e3c2dc04E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB136_12
# %bb.4:                                # %bb9.i
	testb	$1, %r13b
	je	.LBB136_8
# %bb.5:                                # %bb15.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
	testq	%r12, %r12
	je	.LBB136_8
# %bb.6:                                # %bb15.i
	testb	%al, %al
	jne	.LBB136_8
# %bb.7:                                # %bb2.i.i
	movq	%r14, %rdi
	callq	*24(%r12)
.LBB136_8:                              # %bb21.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB136_11
# %bb.9:                                # %bb23.i
	leaq	48(%r15), %rdi
.Ltmp484:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp485:
# %bb.10:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17hd857a2847326da88E.exit.i"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%r15, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB136_11:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9drop_task17h69235921ff58c701E.exit"
	addq	$80, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB136_12:                             # %bb10.i
	.cfi_def_cfa_offset 128
	leaq	8(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	_ZN65_$LT$tokio..task..state..Snapshot$u20$as$u20$core..fmt..Debug$GT$3fmt17h6f4aad22a2ea6cbcE@GOTPCREL(%rip), %rax
	movq	%rax, 24(%rsp)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.45, 32(%rsp)
	movq	$1, 40(%rsp)
	movq	$0, 48(%rsp)
	leaq	16(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	$1, 72(%rsp)
	leaq	32(%rsp), %rdi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.46, %esi
	callq	*_ZN3std9panicking15begin_panic_fmt17h8df736026eee128cE@GOTPCREL(%rip)
.LBB136_13:                             # %cleanup.i.i.i.i
.Ltmp486:
	movq	%rax, %rbx
	movq	%r15, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end136:
	.size	_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E, .Lfunc_end136-_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table136:
.Lexception50:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end50-.Lcst_begin50
.Lcst_begin50:
	.uleb128 .Lfunc_begin50-.Lfunc_begin50 # >> Call Site 1 <<
	.uleb128 .Ltmp484-.Lfunc_begin50 #   Call between .Lfunc_begin50 and .Ltmp484
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp484-.Lfunc_begin50 # >> Call Site 2 <<
	.uleb128 .Ltmp485-.Ltmp484      #   Call between .Ltmp484 and .Ltmp485
	.uleb128 .Ltmp486-.Lfunc_begin50 #     jumps to .Ltmp486
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp485-.Lfunc_begin50 # >> Call Site 3 <<
	.uleb128 .Lfunc_end136-.Ltmp485 #   Call between .Ltmp485 and .Lfunc_end136
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end50:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E
	.type	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E,@function
_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E: # @"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E"
.Lfunc_begin51:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception51
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %r14
	leaq	40(%rdi), %r15
	movq	40(%rdi), %rdi
	callq	*pthread_mutex_lock@GOTPCREL(%rip)
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	movl	%eax, %ebp
	movb	48(%r14), %al
	xorl	%ecx, %ecx
	testb	%al, %al
	setne	%cl
	movq	%r15, 8(%rsp)
	movb	%bpl, 16(%rsp)
	movq	%rcx, (%rsp)
	je	.LBB137_1
.LBB137_4:                              # %bb5
.Ltmp499:
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
.Ltmp500:
# %bb.5:                                # %bb6
	testb	%al, %al
	je	.LBB137_33
# %bb.6:                                # %bb3.i
	testb	%bpl, %bpl
	jne	.LBB137_9
# %bb.7:                                # %bb3.i.i.i.i.i
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB137_9
# %bb.8:                                # %bb6.i.i.i.i.i
	movb	$1, 48(%r14)
.LBB137_9:                              # %_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E.exit
	movq	(%r15), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
.LBB137_10:                             # %bb11
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB137_1:
	.cfi_def_cfa_offset 80
	movq	_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip), %r12
	movq	pthread_mutex_lock@GOTPCREL(%rip), %r13
	.p2align	4, 0x90
.LBB137_2:                              # %bb15
                                        # =>This Inner Loop Header: Depth=1
	movb	$0, 88(%r14)
	movq	56(%r14), %rax
	cmpq	64(%r14), %rax
	je	.LBB137_3
# %bb.11:                               # %bb16
                                        #   in Loop: Header=BB137_2 Depth=1
	movq	72(%r14), %rcx
	movq	80(%r14), %rdx
	leaq	1(%rax), %rsi
	addq	$-1, %rdx
	andq	%rsi, %rdx
	movq	%rdx, 56(%r14)
	movq	(%rcx,%rax,8), %rbx
	movq	%rbx, (%rsp)
	testq	%rbx, %rbx
	je	.LBB137_12
# %bb.18:                               # %bb18
                                        #   in Loop: Header=BB137_2 Depth=1
	testb	%bpl, %bpl
	jne	.LBB137_22
# %bb.19:                               # %bb3.i.i.i.i21
                                        #   in Loop: Header=BB137_2 Depth=1
.Ltmp487:
	callq	*%r12
.Ltmp488:
# %bb.20:                               # %.noexc26
                                        #   in Loop: Header=BB137_2 Depth=1
	testb	%al, %al
	je	.LBB137_22
# %bb.21:                               # %bb6.i.i.i.i23
                                        #   in Loop: Header=BB137_2 Depth=1
	movb	$1, 48(%r14)
	.p2align	4, 0x90
.LBB137_22:                             # %bb19
                                        #   in Loop: Header=BB137_2 Depth=1
	movq	(%r15), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
.Ltmp490:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask17cancel_from_queue17hbd4722693dab0a63E@GOTPCREL(%rip)
.Ltmp491:
# %bb.23:                               # %bb20
                                        #   in Loop: Header=BB137_2 Depth=1
	movq	40(%r14), %rdi
	callq	*%r13
	callq	*%r12
	movl	%eax, %ebp
	movzbl	48(%r14), %eax
	xorl	%ecx, %ecx
	testb	%al, %al
	setne	%cl
	movq	%r15, 8(%rsp)
	movb	%bpl, 16(%rsp)
	movq	%rcx, (%rsp)
	je	.LBB137_2
	jmp	.LBB137_4
.LBB137_3:                              # %bb16.thread
	movq	$0, (%rsp)
.LBB137_12:                             # %bb17
	testb	%bpl, %bpl
	jne	.LBB137_16
# %bb.13:                               # %bb3.i.i.i
.Ltmp496:
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
.Ltmp497:
# %bb.14:                               # %.noexc
	testb	%al, %al
	je	.LBB137_16
# %bb.15:                               # %bb6.i.i.i
	movb	$1, 48(%r14)
.LBB137_16:                             # %bb21
	movq	(%r15), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
	movq	(%rsp), %rdi
	testq	%rdi, %rdi
	je	.LBB137_10
# %bb.17:                               # %bb2.i30
	callq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip)
	jmp	.LBB137_10
.LBB137_33:                             # %bb9
.Ltmp501:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.31, %edi
	movl	$14, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.30, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp502:
# %bb.34:                               # %unreachable
.LBB137_35:                             # %cleanup2
.Ltmp498:
	movq	%rax, %rbp
	movb	$1, %cl
	jmp	.LBB137_26
.LBB137_32:                             # %cleanup
.Ltmp503:
	movq	%rax, %rbp
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E
	movq	%rbp, %rdi
	callq	_Unwind_Resume
.LBB137_31:                             # %bb29
.Ltmp489:
	movq	%rax, %rbp
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	jmp	.LBB137_25
.LBB137_24:                             # %bb1.i
.Ltmp492:
	movq	%rax, %rbp
.Ltmp493:
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp494:
.LBB137_25:                             # %cleanup3.body.thread
	xorl	%ecx, %ecx
.LBB137_26:                             # %bb28
	movq	(%rsp), %rdi
	testq	%rdi, %rdi
	jne	.LBB137_27
# %bb.30:                               # %bb27
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
	movq	%rbp, %rdi
	callq	_Unwind_Resume
.LBB137_27:                             # %bb25
	testb	%cl, %cl
	je	.LBB137_29
# %bb.28:                               # %bb26
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.LBB137_29:                             # %bb2
	movq	%rbp, %rdi
	callq	_Unwind_Resume
.LBB137_36:                             # %cleanup3.body
.Ltmp495:
	movq	%rax, %rbp
	jmp	.LBB137_25
.Lfunc_end137:
	.size	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E, .Lfunc_end137-_ZN5tokio4task5queue19MpscQueues$LT$S$GT$12close_remote17h5516dd699ff28479E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table137:
.Lexception51:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end51-.Lcst_begin51
.Lcst_begin51:
	.uleb128 .Lfunc_begin51-.Lfunc_begin51 # >> Call Site 1 <<
	.uleb128 .Ltmp499-.Lfunc_begin51 #   Call between .Lfunc_begin51 and .Ltmp499
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp499-.Lfunc_begin51 # >> Call Site 2 <<
	.uleb128 .Ltmp500-.Ltmp499      #   Call between .Ltmp499 and .Ltmp500
	.uleb128 .Ltmp503-.Lfunc_begin51 #     jumps to .Ltmp503
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp500-.Lfunc_begin51 # >> Call Site 3 <<
	.uleb128 .Ltmp487-.Ltmp500      #   Call between .Ltmp500 and .Ltmp487
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp487-.Lfunc_begin51 # >> Call Site 4 <<
	.uleb128 .Ltmp488-.Ltmp487      #   Call between .Ltmp487 and .Ltmp488
	.uleb128 .Ltmp489-.Lfunc_begin51 #     jumps to .Ltmp489
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp490-.Lfunc_begin51 # >> Call Site 5 <<
	.uleb128 .Ltmp491-.Ltmp490      #   Call between .Ltmp490 and .Ltmp491
	.uleb128 .Ltmp492-.Lfunc_begin51 #     jumps to .Ltmp492
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp491-.Lfunc_begin51 # >> Call Site 6 <<
	.uleb128 .Ltmp496-.Ltmp491      #   Call between .Ltmp491 and .Ltmp496
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp496-.Lfunc_begin51 # >> Call Site 7 <<
	.uleb128 .Ltmp497-.Ltmp496      #   Call between .Ltmp496 and .Ltmp497
	.uleb128 .Ltmp498-.Lfunc_begin51 #     jumps to .Ltmp498
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp497-.Lfunc_begin51 # >> Call Site 8 <<
	.uleb128 .Ltmp501-.Ltmp497      #   Call between .Ltmp497 and .Ltmp501
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp501-.Lfunc_begin51 # >> Call Site 9 <<
	.uleb128 .Ltmp502-.Ltmp501      #   Call between .Ltmp501 and .Ltmp502
	.uleb128 .Ltmp503-.Lfunc_begin51 #     jumps to .Ltmp503
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp502-.Lfunc_begin51 # >> Call Site 10 <<
	.uleb128 .Ltmp493-.Ltmp502      #   Call between .Ltmp502 and .Ltmp493
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp493-.Lfunc_begin51 # >> Call Site 11 <<
	.uleb128 .Ltmp494-.Ltmp493      #   Call between .Ltmp493 and .Ltmp494
	.uleb128 .Ltmp495-.Lfunc_begin51 #     jumps to .Ltmp495
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp494-.Lfunc_begin51 # >> Call Site 12 <<
	.uleb128 .Lfunc_end137-.Ltmp494 #   Call between .Ltmp494 and .Lfunc_end137
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end51:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE
	.type	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE,@function
_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE: # @"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE"
.Lfunc_begin52:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception52
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	subq	$24, %rsp
	.cfi_def_cfa_offset 64
	.cfi_offset %rbx, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %rbx
	leaq	40(%rdi), %r15
	movq	40(%rdi), %rdi
	callq	*pthread_mutex_lock@GOTPCREL(%rip)
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	movl	%eax, %ebp
	movb	48(%rbx), %al
	xorl	%ecx, %ecx
	testb	%al, %al
	setne	%cl
	movq	%r15, 8(%rsp)
	movb	%bpl, 16(%rsp)
	movq	%rcx, (%rsp)
	je	.LBB138_8
# %bb.1:                                # %bb4
.Ltmp504:
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
.Ltmp505:
# %bb.2:                                # %bb5
	testb	%al, %al
	je	.LBB138_15
# %bb.3:                                # %bb3.i
	testb	%bpl, %bpl
	jne	.LBB138_6
# %bb.4:                                # %bb3.i.i.i.i.i
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB138_6
# %bb.5:                                # %bb6.i.i.i.i.i
	movb	$1, 48(%rbx)
.LBB138_6:                              # %_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E.exit
	movq	(%r15), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
	xorl	%r14d, %r14d
	jmp	.LBB138_7
.LBB138_8:                              # %bb13
	movq	56(%rbx), %rax
	cmpq	64(%rbx), %rax
	jne	.LBB138_10
# %bb.9:
	xorl	%r14d, %r14d
	testb	%bpl, %bpl
	je	.LBB138_12
	jmp	.LBB138_14
.LBB138_10:                             # %bb2.i11
	movq	72(%rbx), %rcx
	movq	80(%rbx), %rdx
	leaq	1(%rax), %rsi
	addq	$-1, %rdx
	andq	%rsi, %rdx
	movq	%rdx, 56(%rbx)
	movq	(%rcx,%rax,8), %r14
	testb	%bpl, %bpl
	jne	.LBB138_14
.LBB138_12:                             # %bb3.i.i.i
	callq	*_ZN3std9panicking9panicking17hb29bc5349f72a38fE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB138_14
# %bb.13:                               # %bb6.i.i.i
	movb	$1, 48(%rbx)
.LBB138_14:                             # %_ZN4core3ptr18real_drop_in_place17hd2c3e5c57c128e03E.exit
	movq	(%r15), %rdi
	callq	*pthread_mutex_unlock@GOTPCREL(%rip)
.LBB138_7:                              # %bb9
	movq	%r14, %rax
	addq	$24, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB138_15:                             # %bb8
	.cfi_def_cfa_offset 64
.Ltmp506:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.31, %edi
	movl	$14, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.32, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp507:
# %bb.16:                               # %unreachable
.LBB138_17:                             # %bb1
.Ltmp508:
	movq	%rax, %rbx
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2c6aabfae917c7e6E
	movq	%rbx, %rdi
	callq	_Unwind_Resume
.Lfunc_end138:
	.size	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE, .Lfunc_end138-_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table138:
.Lexception52:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end52-.Lcst_begin52
.Lcst_begin52:
	.uleb128 .Lfunc_begin52-.Lfunc_begin52 # >> Call Site 1 <<
	.uleb128 .Ltmp504-.Lfunc_begin52 #   Call between .Lfunc_begin52 and .Ltmp504
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp504-.Lfunc_begin52 # >> Call Site 2 <<
	.uleb128 .Ltmp505-.Ltmp504      #   Call between .Ltmp504 and .Ltmp505
	.uleb128 .Ltmp508-.Lfunc_begin52 #     jumps to .Ltmp508
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp505-.Lfunc_begin52 # >> Call Site 3 <<
	.uleb128 .Ltmp506-.Ltmp505      #   Call between .Ltmp505 and .Ltmp506
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp506-.Lfunc_begin52 # >> Call Site 4 <<
	.uleb128 .Ltmp507-.Ltmp506      #   Call between .Ltmp506 and .Ltmp507
	.uleb128 .Ltmp508-.Lfunc_begin52 #     jumps to .Ltmp508
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp507-.Lfunc_begin52 # >> Call Site 5 <<
	.uleb128 .Lfunc_end138-.Ltmp507 #   Call between .Ltmp507 and .Lfunc_end138
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end52:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE
	.type	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE,@function
_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE: # @"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE"
.Lfunc_begin53:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception53
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %rax
	xorl	%edi, %edi
	movq	%rax, 16(%rsp)          # 8-byte Spill
	xchgq	%rdi, 96(%rax)
	movq	%rdi, (%rsp)
	testq	%rdi, %rdi
	je	.LBB139_12
# %bb.1:                                # %bb8.i.lr.ph
	leaq	8(%rsp), %r15
	movq	_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip), %r13
	movq	_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip), %r12
	.p2align	4, 0x90
.LBB139_2:                              # %bb8.i
                                        # =>This Inner Loop Header: Depth=1
	movq	16(%rdi), %rbx
	andq	$-2, %rbx
.Ltmp509:
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
.Ltmp510:
# %bb.3:                                # %bb11
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	%rax, 8(%rsp)
.Ltmp512:
	movq	%r15, %rdi
	callq	*%r13
.Ltmp513:
# %bb.4:                                # %.noexc15
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	24(%rax), %r14
	testq	%r14, %r14
	je	.LBB139_7
# %bb.5:                                # %bb3.i
                                        #   in Loop: Header=BB139_2 Depth=1
.Ltmp514:
	movq	%r15, %rdi
	callq	*%r13
.Ltmp515:
# %bb.6:                                # %.noexc16
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	32(%rax), %rax
	movq	%rax, 32(%r14)
.LBB139_7:                              # %bb8.i14
                                        #   in Loop: Header=BB139_2 Depth=1
.Ltmp516:
	movq	%r15, %rdi
	callq	*%r13
.Ltmp517:
# %bb.8:                                # %.noexc17
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	32(%rax), %rbp
	testq	%rbp, %rbp
	je	.LBB139_9
# %bb.13:                               # %bb12.i
                                        #   in Loop: Header=BB139_2 Depth=1
.Ltmp518:
	movq	%r15, %rdi
	callq	*%r13
.Ltmp519:
# %bb.14:                               # %.noexc19
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	24(%rax), %rax
	movq	%rax, 24(%rbp)
	jmp	.LBB139_15
	.p2align	4, 0x90
.LBB139_9:                              # %bb11.i
                                        #   in Loop: Header=BB139_2 Depth=1
.Ltmp520:
	movq	%r15, %rdi
	callq	*%r13
.Ltmp521:
# %bb.10:                               # %.noexc18
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	24(%rax), %rax
	movq	16(%rsp), %rcx          # 8-byte Reload
	movq	%rax, (%rcx)
.LBB139_15:                             # %bb12
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	8(%rsp), %rdi
.Ltmp523:
	callq	*%r12
.Ltmp524:
# %bb.16:                               # %bb13
                                        #   in Loop: Header=BB139_2 Depth=1
	movq	%rbx, %rdi
	testq	%rbx, %rbx
	jne	.LBB139_2
# %bb.11:                               # %bb4._ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E.exit_crit_edge
	movq	%rbx, (%rsp)
.LBB139_12:                             # %_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E.exit
	addq	$24, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB139_21:                             # %cleanup1
	.cfi_def_cfa_offset 80
.Ltmp525:
	jmp	.LBB139_18
.LBB139_17:                             # %bb16.thread37
.Ltmp511:
.LBB139_18:                             # %bb5
	movq	%rax, %r14
	movq	%rbx, (%rsp)
	jmp	.LBB139_20
.LBB139_19:                             # %bb19
.Ltmp522:
	movq	%rax, %r14
	movq	%rbx, (%rsp)
	movq	8(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.LBB139_20:                             # %bb5
	movq	%rsp, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17he566ede032eb1a60E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end139:
	.size	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE, .Lfunc_end139-_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table139:
.Lexception53:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end53-.Lcst_begin53
.Lcst_begin53:
	.uleb128 .Ltmp509-.Lfunc_begin53 # >> Call Site 1 <<
	.uleb128 .Ltmp510-.Ltmp509      #   Call between .Ltmp509 and .Ltmp510
	.uleb128 .Ltmp511-.Lfunc_begin53 #     jumps to .Ltmp511
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp512-.Lfunc_begin53 # >> Call Site 2 <<
	.uleb128 .Ltmp521-.Ltmp512      #   Call between .Ltmp512 and .Ltmp521
	.uleb128 .Ltmp522-.Lfunc_begin53 #     jumps to .Ltmp522
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp523-.Lfunc_begin53 # >> Call Site 3 <<
	.uleb128 .Ltmp524-.Ltmp523      #   Call between .Ltmp523 and .Ltmp524
	.uleb128 .Ltmp525-.Lfunc_begin53 #     jumps to .Ltmp525
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp524-.Lfunc_begin53 # >> Call Site 4 <<
	.uleb128 .Lfunc_end139-.Ltmp524 #   Call between .Ltmp524 and .Lfunc_end139
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end53:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E
	.type	_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E,@function
_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E: # @_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E
.Lfunc_begin54:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception54
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State7ref_dec17h92abd8751aeaaf50E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB140_3
# %bb.1:                                # %bb3.i
	leaq	48(%rbx), %rdi
.Ltmp526:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp527:
# %bb.2:                                # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17hd857a2847326da88E.exit.i"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB140_3:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$10drop_waker17ha75d033ecedb532cE.exit"
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB140_4:                              # %cleanup.i.i.i.i
	.cfi_def_cfa_offset 32
.Ltmp528:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end140:
	.size	_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E, .Lfunc_end140-_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table140:
.Lexception54:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end54-.Lcst_begin54
.Lcst_begin54:
	.uleb128 .Lfunc_begin54-.Lfunc_begin54 # >> Call Site 1 <<
	.uleb128 .Ltmp526-.Lfunc_begin54 #   Call between .Lfunc_begin54 and .Ltmp526
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp526-.Lfunc_begin54 # >> Call Site 2 <<
	.uleb128 .Ltmp527-.Ltmp526      #   Call between .Ltmp526 and .Ltmp527
	.uleb128 .Ltmp528-.Lfunc_begin54 #     jumps to .Ltmp528
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp527-.Lfunc_begin54 # >> Call Site 3 <<
	.uleb128 .Lfunc_end140-.Ltmp527 #   Call between .Ltmp527 and .Lfunc_end140
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end54:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker11clone_waker17h801246328d671f18E
	.type	_ZN5tokio4task5waker11clone_waker17h801246328d671f18E,@function
_ZN5tokio4task5waker11clone_waker17h801246328d671f18E: # @_ZN5tokio4task5waker11clone_waker17h801246328d671f18E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State7ref_inc17h8fffc7ecfaf5121bE@GOTPCREL(%rip)
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.35, %esi
	movq	%rbx, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmpq	*_ZN4core4task4wake8RawWaker3new17h3348ef682dfa8f58E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end141:
	.size	_ZN5tokio4task5waker11clone_waker17h801246328d671f18E, .Lfunc_end141-_ZN5tokio4task5waker11clone_waker17h801246328d671f18E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE
	.type	_ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE,@function
_ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE: # @_ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State7ref_inc17h8fffc7ecfaf5121bE@GOTPCREL(%rip)
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.34, %esi
	movq	%rbx, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmpq	*_ZN4core4task4wake8RawWaker3new17h3348ef682dfa8f58E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end142:
	.size	_ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE, .Lfunc_end142-_ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE
	.type	_ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE,@function
_ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE: # @_ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State22transition_to_notified17h3b53dc092898bad1E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB143_3
# %bb.1:                                # %bb3.i
	movq	8(%rbx), %r14
	testq	%r14, %r14
	je	.LBB143_4
# %bb.2:                                # %bb8.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	movq	%r14, %rdi
	movq	%rax, %rsi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN85_$LT$tokio..runtime..thread_pool..shared..Shared$u20$as$u20$tokio..task..Schedule$GT$8schedule17hd372c1a856512277E@GOTPCREL(%rip) # TAILCALL
.LBB143_3:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11wake_by_ref17hb548b114e8c42d6cE.exit"
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB143_4:                              # %bb6.i
	.cfi_def_cfa_offset 32
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.38, %edi
	movl	$22, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.37, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Lfunc_end143:
	.size	_ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE, .Lfunc_end143-_ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E
	.type	_ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E,@function
_ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E: # @_ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State22transition_to_notified17h3b53dc092898bad1E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB144_3
# %bb.1:                                # %bb3.i
	movq	8(%rbx), %r14
	testq	%r14, %r14
	je	.LBB144_4
# %bb.2:                                # %bb8.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	movq	%r14, %rdi
	movq	%rax, %rsi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*_ZN88_$LT$tokio..runtime..basic_scheduler..SchedulerPriv$u20$as$u20$tokio..task..Schedule$GT$8schedule17h60ae70b8c21be710E@GOTPCREL(%rip) # TAILCALL
.LBB144_3:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11wake_by_ref17h30e31ea3edb9aa1cE.exit"
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB144_4:                              # %bb6.i
	.cfi_def_cfa_offset 32
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.38, %edi
	movl	$22, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.37, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Lfunc_end144:
	.size	_ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E, .Lfunc_end144-_ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E
	.type	_ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E,@function
_ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E: # @_ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E
.Lfunc_begin55:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception55
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State22transition_to_notified17h3b53dc092898bad1E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB145_3
# %bb.1:                                # %bb3.i.i
	movq	8(%rbx), %r14
	testq	%r14, %r14
	je	.LBB145_7
# %bb.2:                                # %bb8.i.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	movq	%r14, %rdi
	movq	%rax, %rsi
	callq	*_ZN88_$LT$tokio..runtime..basic_scheduler..SchedulerPriv$u20$as$u20$tokio..task..Schedule$GT$8schedule17h60ae70b8c21be710E@GOTPCREL(%rip)
.LBB145_3:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11wake_by_ref17h30e31ea3edb9aa1cE.exit.i"
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State7ref_dec17h92abd8751aeaaf50E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB145_6
# %bb.4:                                # %bb3.i2.i
	leaq	48(%rbx), %rdi
.Ltmp529:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp530:
# %bb.5:                                # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17h76ec7dada589aec1E.exit.i.i"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB145_6:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11wake_by_val17h7d5894807a28e4acE.exit"
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB145_7:                              # %bb6.i.i
	.cfi_def_cfa_offset 32
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.38, %edi
	movl	$22, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.37, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.LBB145_8:                              # %cleanup.i.i.i.i.i
.Ltmp531:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end145:
	.size	_ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E, .Lfunc_end145-_ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table145:
.Lexception55:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end55-.Lcst_begin55
.Lcst_begin55:
	.uleb128 .Lfunc_begin55-.Lfunc_begin55 # >> Call Site 1 <<
	.uleb128 .Ltmp529-.Lfunc_begin55 #   Call between .Lfunc_begin55 and .Ltmp529
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp529-.Lfunc_begin55 # >> Call Site 2 <<
	.uleb128 .Ltmp530-.Ltmp529      #   Call between .Ltmp529 and .Ltmp530
	.uleb128 .Ltmp531-.Lfunc_begin55 #     jumps to .Ltmp531
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp530-.Lfunc_begin55 # >> Call Site 3 <<
	.uleb128 .Lfunc_end145-.Ltmp530 #   Call between .Ltmp530 and .Lfunc_end145
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end55:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE
	.type	_ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE,@function
_ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE: # @_ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE
.Lfunc_begin56:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception56
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdi, %rbx
	callq	*_ZN5tokio4task5state5State22transition_to_notified17h3b53dc092898bad1E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB146_3
# %bb.1:                                # %bb3.i.i
	movq	8(%rbx), %r14
	testq	%r14, %r14
	je	.LBB146_7
# %bb.2:                                # %bb8.i.i
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	movq	%r14, %rdi
	movq	%rax, %rsi
	callq	*_ZN85_$LT$tokio..runtime..thread_pool..shared..Shared$u20$as$u20$tokio..task..Schedule$GT$8schedule17hd372c1a856512277E@GOTPCREL(%rip)
.LBB146_3:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11wake_by_ref17hb548b114e8c42d6cE.exit.i"
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state5State7ref_dec17h92abd8751aeaaf50E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB146_6
# %bb.4:                                # %bb3.i2.i
	leaq	48(%rbx), %rdi
.Ltmp532:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp533:
# %bb.5:                                # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17hd857a2847326da88E.exit.i.i"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%rbx, %rdi
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	jmpq	*__rust_dealloc@GOTPCREL(%rip) # TAILCALL
.LBB146_6:                              # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$11wake_by_val17he22fae0dd79866f8E.exit"
	.cfi_def_cfa_offset 32
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB146_7:                              # %bb6.i.i
	.cfi_def_cfa_offset 32
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.38, %edi
	movl	$22, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.37, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.LBB146_8:                              # %cleanup.i.i.i.i.i
.Ltmp534:
	movq	%rax, %r14
	movq	%rbx, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end146:
	.size	_ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE, .Lfunc_end146-_ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table146:
.Lexception56:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end56-.Lcst_begin56
.Lcst_begin56:
	.uleb128 .Lfunc_begin56-.Lfunc_begin56 # >> Call Site 1 <<
	.uleb128 .Ltmp532-.Lfunc_begin56 #   Call between .Lfunc_begin56 and .Ltmp532
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp532-.Lfunc_begin56 # >> Call Site 2 <<
	.uleb128 .Ltmp533-.Ltmp532      #   Call between .Ltmp532 and .Ltmp533
	.uleb128 .Ltmp534-.Lfunc_begin56 #     jumps to .Ltmp534
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp533-.Lfunc_begin56 # >> Call Site 3 <<
	.uleb128 .Lfunc_end146-.Ltmp533 #   Call between .Ltmp533 and .Lfunc_end146
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end56:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E
	.type	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E,@function
_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E: # @"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E"
.Lfunc_begin57:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception57
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	subq	$184, %rsp
	.cfi_def_cfa_offset 224
	.cfi_offset %rbx, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movl	%esi, %ebp
	movq	%rdi, %rbx
	movq	(%rdi), %rdi
	callq	*_ZN5tokio4task5state5State22transition_to_complete17hf67b8e736319a75cE@GOTPCREL(%rip)
	movq	%rax, %r14
	testb	%bpl, %bpl
	je	.LBB147_12
# %bb.1:                                # %bb1.i
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB147_8
# %bb.2:                                # %bb3.i
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB147_12
# %bb.3:                                # %bb8.i
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot11is_canceled17hac79fc0f8b4bfdf9E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB147_6
# %bb.4:                                # %bb10.i
	movq	(%rbx), %r15
	leaq	48(%r15), %rdi
.Ltmp538:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp539:
# %bb.5:                                # %"_ZN5tokio4task4core13Core$LT$T$GT$22transition_to_consumed17h35d3eb56e13b55baE.exit13.i"
	movq	$2, 48(%r15)
	addq	$56, %r15
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%r15, %rdi
	callq	*memcpy@GOTPCREL(%rip)
.LBB147_6:                              # %bb13.i
	movq	(%rbx), %rcx
	movq	248(%rcx), %rax
	testq	%rax, %rax
	je	.LBB147_7
# %bb.11:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9wake_join17h05ea5df4d596cd66E.exit.i"
	movq	240(%rcx), %rdi
	callq	*16(%rax)
	jmp	.LBB147_12
.LBB147_8:                              # %bb4.i
	movq	(%rbx), %rbx
	leaq	48(%rbx), %rdi
.Ltmp535:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp536:
# %bb.9:                                # %"_ZN5tokio4task4core13Core$LT$T$GT$22transition_to_consumed17h35d3eb56e13b55baE.exit.i"
	movq	$2, 48(%rbx)
	addq	$56, %rbx
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%rbx, %rdi
	callq	*memcpy@GOTPCREL(%rip)
.LBB147_12:                             # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$18notify_join_handle17h860ff3758006782eE.exit"
	movq	%r14, %rax
	addq	$184, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB147_7:                              # %bb2.i.i.i.i.i
	.cfi_def_cfa_offset 224
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.47, %edi
	movl	$13, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.LBB147_10:                             # %cleanup.i12.i
.Ltmp540:
	movq	%rax, %r14
	movq	$2, 48(%r15)
	addq	$56, %r15
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%r15, %rdi
	jmp	.LBB147_14
.LBB147_13:                             # %cleanup.i.i
.Ltmp537:
	movq	%rax, %r14
	movq	$2, 48(%rbx)
	addq	$56, %rbx
	movq	%rsp, %rsi
	movl	$184, %edx
	movq	%rbx, %rdi
.LBB147_14:                             # %unwind_resume
	callq	*memcpy@GOTPCREL(%rip)
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end147:
	.size	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E, .Lfunc_end147-_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table147:
.Lexception57:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end57-.Lcst_begin57
.Lcst_begin57:
	.uleb128 .Lfunc_begin57-.Lfunc_begin57 # >> Call Site 1 <<
	.uleb128 .Ltmp538-.Lfunc_begin57 #   Call between .Lfunc_begin57 and .Ltmp538
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp538-.Lfunc_begin57 # >> Call Site 2 <<
	.uleb128 .Ltmp539-.Ltmp538      #   Call between .Ltmp538 and .Ltmp539
	.uleb128 .Ltmp540-.Lfunc_begin57 #     jumps to .Ltmp540
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp539-.Lfunc_begin57 # >> Call Site 3 <<
	.uleb128 .Ltmp535-.Ltmp539      #   Call between .Ltmp539 and .Ltmp535
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp535-.Lfunc_begin57 # >> Call Site 4 <<
	.uleb128 .Ltmp536-.Ltmp535      #   Call between .Ltmp535 and .Ltmp536
	.uleb128 .Ltmp537-.Lfunc_begin57 #     jumps to .Ltmp537
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp536-.Lfunc_begin57 # >> Call Site 5 <<
	.uleb128 .Lfunc_end147-.Ltmp536 #   Call between .Ltmp536 and .Lfunc_end147
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end57:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E
	.type	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E,@function
_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E: # @"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E"
.Lfunc_begin58:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception58
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$200, %rsp
	.cfi_def_cfa_offset 256
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%r8, %r14
	movl	%ecx, %r15d
	movq	%rdx, %rbp
	movq	%rsi, %rbx
	movq	%rdi, %r12
	movq	%rdi, (%rsp)
	movb	$1, %r13b
	testl	%ecx, %ecx
	je	.LBB148_3
# %bb.1:                                # %bb3
	leaq	48(%r12), %rdi
	movups	(%r14), %xmm0
	movups	16(%r14), %xmm1
	movaps	%xmm0, 16(%rsp)
	movaps	%xmm1, 32(%rsp)
	movq	32(%r14), %rax
	movq	%rax, 48(%rsp)
.Ltmp541:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp542:
# %bb.2:                                # %bb4
	movq	$1, 48(%r12)
	movaps	16(%rsp), %xmm0
	movaps	32(%rsp), %xmm1
	movups	%xmm0, 56(%r12)
	movups	%xmm1, 72(%r12)
	movq	48(%rsp), %rax
	movq	%rax, 88(%r12)
	leaq	96(%r12), %rdi
	leaq	56(%rsp), %rsi
	movl	$144, %edx
	callq	*memcpy@GOTPCREL(%rip)
	xorl	%r13d, %r13d
.LBB148_3:                              # %bb5
.Ltmp544:
	movq	%rbx, %rdi
	callq	*24(%rbp)
.Ltmp545:
# %bb.4:                                # %bb13
	movq	%rax, %rbx
	movq	8(%r12), %rbp
	testq	%rax, %rax
	je	.LBB148_14
# %bb.5:                                # %bb11
	testq	%rbp, %rbp
	je	.LBB148_14
# %bb.6:                                # %bb11
	cmpq	%rbp, %rbx
	jne	.LBB148_14
# %bb.7:                                # %bb16
.Ltmp546:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
.Ltmp547:
# %bb.8:                                # %bb23
	movq	%rax, 56(%rsp)
.Ltmp548:
	leaq	56(%rsp), %rsi
	movq	%rbx, %rdi
	callq	*_ZN85_$LT$tokio..runtime..thread_pool..shared..Shared$u20$as$u20$tokio..task..Schedule$GT$13release_local17h1a9452609632d637E@GOTPCREL(%rip)
.Ltmp549:
# %bb.9:                                # %bb24
	testb	%r15b, %r15b
	je	.LBB148_30
# %bb.10:                               # %bb2.i21
.Ltmp552:
	movq	%rsp, %rdi
	movl	$1, %esi
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E
.Ltmp553:
# %bb.11:                               # %_9.i.noexc
	movq	%rax, %rbx
.Ltmp554:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
.Ltmp555:
# %bb.12:                               # %.noexc28
	testb	%al, %al
	je	.LBB148_32
# %bb.13:                               # %bb6.i
	movq	240(%r12), %rax
	movq	%rax, 8(%rsp)           # 8-byte Spill
	movq	248(%r12), %r15
	jmp	.LBB148_33
.LBB148_14:                             # %bb10
.Ltmp569:
	movzbl	%r15b, %esi
	movq	%rsp, %rdi
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E
.Ltmp570:
# %bb.15:                               # %bb30
	movq	%rax, %rbx
.Ltmp571:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
.Ltmp572:
# %bb.16:                               # %bb31
	testb	%al, %al
	jne	.LBB148_43
# %bb.17:                               # %bb32
.Ltmp573:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
.Ltmp574:
# %bb.18:                               # %bb34
	testb	%al, %al
	je	.LBB148_20
# %bb.19:                               # %bb35
	movq	$1, 16(%r12)
.LBB148_20:                             # %bb37
.Ltmp575:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
.Ltmp576:
# %bb.21:                               # %bb38
	movq	%rax, %rbx
	testq	%rbp, %rbp
	je	.LBB148_44
# %bb.22:                               # %bb43
.Ltmp577:
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	*_ZN85_$LT$tokio..runtime..thread_pool..shared..Shared$u20$as$u20$tokio..task..Schedule$GT$7release17hec23299a9eaa44c8E@GOTPCREL(%rip)
.Ltmp578:
.LBB148_23:                             # %bb45
	testb	%r13b, %r13b
	je	.LBB148_29
# %bb.24:                               # %bb51
	cmpq	$0, (%r14)
	je	.LBB148_29
# %bb.25:                               # %bb2.i
	movq	8(%r14), %rbx
	testq	%rbx, %rbx
	je	.LBB148_29
# %bb.26:                               # %bb2.i.i.i
	movq	%rbx, %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movl	$40, %esi
	movl	$8, %edx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	24(%r14), %rbx
	movq	32(%r14), %rbp
.Ltmp580:
	movq	%rbx, %rdi
	callq	*(%rbp)
.Ltmp581:
# %bb.27:                               # %bb3.i.i.i.i.i.i
	movq	8(%rbp), %rsi
	testq	%rsi, %rsi
	je	.LBB148_29
# %bb.28:                               # %bb4.i.i.i.i.i.i.i
	movq	16(%rbp), %rdx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB148_29:                             # %bb46
	addq	$200, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB148_30:                             # %bb1.i
	.cfi_def_cfa_offset 256
.Ltmp550:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task5state5State22transition_to_released17hce4ae16957754da4E@GOTPCREL(%rip)
.Ltmp551:
# %bb.31:
	movq	%rax, %rbp
	jmp	.LBB148_39
.LBB148_32:
                                        # implicit-def: $r15
                                        # implicit-def: $rax
                                        # kill: killed $rax
.LBB148_33:                             # %bb8.i
.Ltmp556:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task5state5State12release_task17h72ffa2965b00db4eE@GOTPCREL(%rip)
.Ltmp557:
# %bb.34:                               # %_20.i.noexc
	movq	%rax, %rbp
.Ltmp558:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
.Ltmp559:
# %bb.35:                               # %.noexc30
	testb	%al, %al
	je	.LBB148_39
# %bb.36:                               # %bb13.i23
.Ltmp560:
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
.Ltmp561:
# %bb.37:                               # %.noexc31
	testq	%r15, %r15
	sete	%cl
	orb	%al, %cl
	jne	.LBB148_39
# %bb.38:                               # %bb2.i.i.i24
.Ltmp562:
	movq	8(%rsp), %rdi           # 8-byte Reload
	callq	*24(%r15)
.Ltmp563:
.LBB148_39:                             # %bb25
.Ltmp564:
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
.Ltmp565:
# %bb.40:                               # %bb26
	testb	%al, %al
	je	.LBB148_23
# %bb.41:                               # %bb27
	leaq	48(%r12), %rdi
.Ltmp566:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp567:
# %bb.42:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17hd857a2847326da88E.exit"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%r12, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB148_23
.LBB148_43:                             # %bb33
.Ltmp586:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.41, %edi
	movl	$37, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.40, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp587:
	jmp	.LBB148_45
.LBB148_44:                             # %bb39
.Ltmp583:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.38, %edi
	movl	$22, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.42, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp584:
.LBB148_45:                             # %unreachable
.LBB148_46:                             # %bb49
.Ltmp585:
	movq	%rax, %r15
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	jmp	.LBB148_53
.LBB148_47:                             # %cleanup.i.i.i
.Ltmp568:
	movq	%rax, %r15
	movq	%r12, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	jmp	.LBB148_53
.LBB148_48:                             # %cleanup.i.i.i.i.i.i
.Ltmp582:
	movq	%rax, %r15
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	jmp	.LBB148_54
.LBB148_49:                             # %cleanup.i
.Ltmp543:
	movq	%rax, %r15
	movq	$1, 48(%r12)
	movaps	16(%rsp), %xmm0
	movaps	32(%rsp), %xmm1
	movups	%xmm0, 56(%r12)
	movups	%xmm1, 72(%r12)
	movq	48(%rsp), %rax
	movq	%rax, 88(%r12)
	addq	$96, %r12
	leaq	56(%rsp), %rsi
	movl	$144, %edx
	movq	%r12, %rdi
	callq	*memcpy@GOTPCREL(%rip)
	xorl	%r13d, %r13d
	jmp	.LBB148_53
.LBB148_50:                             # %cleanup3
.Ltmp579:
	jmp	.LBB148_52
.LBB148_51:                             # %cleanup
.Ltmp588:
.LBB148_52:                             # %bb48
	movq	%rax, %r15
.LBB148_53:                             # %bb48
	testb	%r13b, %r13b
	jne	.LBB148_55
.LBB148_54:                             # %unwind_resume
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB148_55:                             # %bb47
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE
	movq	%r15, %rdi
	callq	_Unwind_Resume
.Lfunc_end148:
	.size	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E, .Lfunc_end148-_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17h0891186467f2a6a4E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table148:
.Lexception58:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end58-.Lcst_begin58
.Lcst_begin58:
	.uleb128 .Ltmp541-.Lfunc_begin58 # >> Call Site 1 <<
	.uleb128 .Ltmp542-.Ltmp541      #   Call between .Ltmp541 and .Ltmp542
	.uleb128 .Ltmp543-.Lfunc_begin58 #     jumps to .Ltmp543
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp542-.Lfunc_begin58 # >> Call Site 2 <<
	.uleb128 .Ltmp544-.Ltmp542      #   Call between .Ltmp542 and .Ltmp544
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp544-.Lfunc_begin58 # >> Call Site 3 <<
	.uleb128 .Ltmp576-.Ltmp544      #   Call between .Ltmp544 and .Ltmp576
	.uleb128 .Ltmp588-.Lfunc_begin58 #     jumps to .Ltmp588
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp577-.Lfunc_begin58 # >> Call Site 4 <<
	.uleb128 .Ltmp578-.Ltmp577      #   Call between .Ltmp577 and .Ltmp578
	.uleb128 .Ltmp579-.Lfunc_begin58 #     jumps to .Ltmp579
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp580-.Lfunc_begin58 # >> Call Site 5 <<
	.uleb128 .Ltmp581-.Ltmp580      #   Call between .Ltmp580 and .Ltmp581
	.uleb128 .Ltmp582-.Lfunc_begin58 #     jumps to .Ltmp582
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp550-.Lfunc_begin58 # >> Call Site 6 <<
	.uleb128 .Ltmp565-.Ltmp550      #   Call between .Ltmp550 and .Ltmp565
	.uleb128 .Ltmp588-.Lfunc_begin58 #     jumps to .Ltmp588
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp566-.Lfunc_begin58 # >> Call Site 7 <<
	.uleb128 .Ltmp567-.Ltmp566      #   Call between .Ltmp566 and .Ltmp567
	.uleb128 .Ltmp568-.Lfunc_begin58 #     jumps to .Ltmp568
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp586-.Lfunc_begin58 # >> Call Site 8 <<
	.uleb128 .Ltmp587-.Ltmp586      #   Call between .Ltmp586 and .Ltmp587
	.uleb128 .Ltmp588-.Lfunc_begin58 #     jumps to .Ltmp588
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp583-.Lfunc_begin58 # >> Call Site 9 <<
	.uleb128 .Ltmp584-.Ltmp583      #   Call between .Ltmp583 and .Ltmp584
	.uleb128 .Ltmp585-.Lfunc_begin58 #     jumps to .Ltmp585
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp584-.Lfunc_begin58 # >> Call Site 10 <<
	.uleb128 .Lfunc_end148-.Ltmp584 #   Call between .Ltmp584 and .Lfunc_end148
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end58:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE
	.type	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE,@function
_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE: # @"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE"
.Lfunc_begin59:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception59
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$200, %rsp
	.cfi_def_cfa_offset 256
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%r8, %r14
	movl	%ecx, %r15d
	movq	%rdx, %rbp
	movq	%rsi, %rbx
	movq	%rdi, %r12
	movq	%rdi, (%rsp)
	movb	$1, %r13b
	testl	%ecx, %ecx
	je	.LBB149_3
# %bb.1:                                # %bb3
	leaq	48(%r12), %rdi
	movups	(%r14), %xmm0
	movups	16(%r14), %xmm1
	movaps	%xmm0, 16(%rsp)
	movaps	%xmm1, 32(%rsp)
	movq	32(%r14), %rax
	movq	%rax, 48(%rsp)
.Ltmp589:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp590:
# %bb.2:                                # %bb4
	movq	$1, 48(%r12)
	movaps	16(%rsp), %xmm0
	movaps	32(%rsp), %xmm1
	movups	%xmm0, 56(%r12)
	movups	%xmm1, 72(%r12)
	movq	48(%rsp), %rax
	movq	%rax, 88(%r12)
	leaq	96(%r12), %rdi
	leaq	56(%rsp), %rsi
	movl	$144, %edx
	callq	*memcpy@GOTPCREL(%rip)
	xorl	%r13d, %r13d
.LBB149_3:                              # %bb5
.Ltmp592:
	movq	%rbx, %rdi
	callq	*24(%rbp)
.Ltmp593:
# %bb.4:                                # %bb13
	movq	%rax, %rbx
	movq	8(%r12), %rbp
	testq	%rax, %rax
	je	.LBB149_14
# %bb.5:                                # %bb11
	testq	%rbp, %rbp
	je	.LBB149_14
# %bb.6:                                # %bb11
	cmpq	%rbp, %rbx
	jne	.LBB149_14
# %bb.7:                                # %bb16
.Ltmp594:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
.Ltmp595:
# %bb.8:                                # %bb23
	movq	%rax, 56(%rsp)
.Ltmp596:
	leaq	56(%rsp), %rsi
	movq	%rbx, %rdi
	callq	*_ZN88_$LT$tokio..runtime..basic_scheduler..SchedulerPriv$u20$as$u20$tokio..task..Schedule$GT$13release_local17h778cf886d5c85314E@GOTPCREL(%rip)
.Ltmp597:
# %bb.9:                                # %bb24
	testb	%r15b, %r15b
	je	.LBB149_30
# %bb.10:                               # %bb2.i21
.Ltmp600:
	movq	%rsp, %rdi
	movl	$1, %esi
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E
.Ltmp601:
# %bb.11:                               # %_9.i.noexc
	movq	%rax, %rbx
.Ltmp602:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
.Ltmp603:
# %bb.12:                               # %.noexc28
	testb	%al, %al
	je	.LBB149_32
# %bb.13:                               # %bb6.i
	movq	240(%r12), %rax
	movq	%rax, 8(%rsp)           # 8-byte Spill
	movq	248(%r12), %r15
	jmp	.LBB149_33
.LBB149_14:                             # %bb10
.Ltmp617:
	movzbl	%r15b, %esi
	movq	%rsp, %rdi
	callq	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$22transition_to_complete17h095827039dc613e9E
.Ltmp618:
# %bb.15:                               # %bb30
	movq	%rax, %rbx
.Ltmp619:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
.Ltmp620:
# %bb.16:                               # %bb31
	testb	%al, %al
	jne	.LBB149_43
# %bb.17:                               # %bb32
.Ltmp621:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
.Ltmp622:
# %bb.18:                               # %bb34
	testb	%al, %al
	je	.LBB149_20
# %bb.19:                               # %bb35
	movq	$1, 16(%r12)
.LBB149_20:                             # %bb37
.Ltmp623:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
.Ltmp624:
# %bb.21:                               # %bb38
	movq	%rax, %rbx
	testq	%rbp, %rbp
	je	.LBB149_44
# %bb.22:                               # %bb43
.Ltmp625:
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	*_ZN88_$LT$tokio..runtime..basic_scheduler..SchedulerPriv$u20$as$u20$tokio..task..Schedule$GT$7release17hbf2e890af0633d80E@GOTPCREL(%rip)
.Ltmp626:
.LBB149_23:                             # %bb45
	testb	%r13b, %r13b
	je	.LBB149_29
# %bb.24:                               # %bb51
	cmpq	$0, (%r14)
	je	.LBB149_29
# %bb.25:                               # %bb2.i
	movq	8(%r14), %rbx
	testq	%rbx, %rbx
	je	.LBB149_29
# %bb.26:                               # %bb2.i.i.i
	movq	%rbx, %rdi
	callq	*pthread_mutex_destroy@GOTPCREL(%rip)
	movl	$40, %esi
	movl	$8, %edx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
	movq	24(%r14), %rbx
	movq	32(%r14), %rbp
.Ltmp628:
	movq	%rbx, %rdi
	callq	*(%rbp)
.Ltmp629:
# %bb.27:                               # %bb3.i.i.i.i.i.i
	movq	8(%rbp), %rsi
	testq	%rsi, %rsi
	je	.LBB149_29
# %bb.28:                               # %bb4.i.i.i.i.i.i.i
	movq	16(%rbp), %rdx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB149_29:                             # %bb46
	addq	$200, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB149_30:                             # %bb1.i
	.cfi_def_cfa_offset 256
.Ltmp598:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task5state5State22transition_to_released17hce4ae16957754da4E@GOTPCREL(%rip)
.Ltmp599:
# %bb.31:
	movq	%rax, %rbp
	jmp	.LBB149_39
.LBB149_32:
                                        # implicit-def: $r15
                                        # implicit-def: $rax
                                        # kill: killed $rax
.LBB149_33:                             # %bb8.i
.Ltmp604:
	movq	%r12, %rdi
	callq	*_ZN5tokio4task5state5State12release_task17h72ffa2965b00db4eE@GOTPCREL(%rip)
.Ltmp605:
# %bb.34:                               # %_20.i.noexc
	movq	%rax, %rbp
.Ltmp606:
	movq	%rbx, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
.Ltmp607:
# %bb.35:                               # %.noexc30
	testb	%al, %al
	je	.LBB149_39
# %bb.36:                               # %bb13.i23
.Ltmp608:
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
.Ltmp609:
# %bb.37:                               # %.noexc31
	testq	%r15, %r15
	sete	%cl
	orb	%al, %cl
	jne	.LBB149_39
# %bb.38:                               # %bb2.i.i.i24
.Ltmp610:
	movq	8(%rsp), %rdi           # 8-byte Reload
	callq	*24(%r15)
.Ltmp611:
.LBB149_39:                             # %bb25
.Ltmp612:
	movq	%rbp, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
.Ltmp613:
# %bb.40:                               # %bb26
	testb	%al, %al
	je	.LBB149_23
# %bb.41:                               # %bb27
	leaq	48(%r12), %rdi
.Ltmp614:
	callq	_ZN4core3ptr18real_drop_in_place17hca145ce36531b1ceE
.Ltmp615:
# %bb.42:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$7dealloc17h76ec7dada589aec1E.exit"
	movl	$256, %esi              # imm = 0x100
	movl	$8, %edx
	movq	%r12, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB149_23
.LBB149_43:                             # %bb33
.Ltmp634:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.41, %edi
	movl	$37, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.40, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp635:
	jmp	.LBB149_45
.LBB149_44:                             # %bb39
.Ltmp631:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.38, %edi
	movl	$22, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.42, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp632:
.LBB149_45:                             # %unreachable
.LBB149_46:                             # %bb49
.Ltmp633:
	movq	%rax, %r15
	movq	%rbx, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
	jmp	.LBB149_53
.LBB149_47:                             # %cleanup.i.i.i
.Ltmp616:
	movq	%rax, %r15
	movq	%r12, %rdi
	callq	_ZN5alloc5alloc8box_free17h75f7638681be2462E
	jmp	.LBB149_53
.LBB149_48:                             # %cleanup.i.i.i.i.i.i
.Ltmp630:
	movq	%rax, %r15
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	jmp	.LBB149_54
.LBB149_49:                             # %cleanup.i
.Ltmp591:
	movq	%rax, %r15
	movq	$1, 48(%r12)
	movaps	16(%rsp), %xmm0
	movaps	32(%rsp), %xmm1
	movups	%xmm0, 56(%r12)
	movups	%xmm1, 72(%r12)
	movq	48(%rsp), %rax
	movq	%rax, 88(%r12)
	addq	$96, %r12
	leaq	56(%rsp), %rsi
	movl	$144, %edx
	movq	%r12, %rdi
	callq	*memcpy@GOTPCREL(%rip)
	xorl	%r13d, %r13d
	jmp	.LBB149_53
.LBB149_50:                             # %cleanup3
.Ltmp627:
	jmp	.LBB149_52
.LBB149_51:                             # %cleanup
.Ltmp636:
.LBB149_52:                             # %bb48
	movq	%rax, %r15
.LBB149_53:                             # %bb48
	testb	%r13b, %r13b
	jne	.LBB149_55
.LBB149_54:                             # %unwind_resume
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB149_55:                             # %bb47
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h3cd02a9edc568febE
	movq	%r15, %rdi
	callq	_Unwind_Resume
.Lfunc_end149:
	.size	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE, .Lfunc_end149-_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$8complete17hd539a115822c175dE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table149:
.Lexception59:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end59-.Lcst_begin59
.Lcst_begin59:
	.uleb128 .Ltmp589-.Lfunc_begin59 # >> Call Site 1 <<
	.uleb128 .Ltmp590-.Ltmp589      #   Call between .Ltmp589 and .Ltmp590
	.uleb128 .Ltmp591-.Lfunc_begin59 #     jumps to .Ltmp591
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp590-.Lfunc_begin59 # >> Call Site 2 <<
	.uleb128 .Ltmp592-.Ltmp590      #   Call between .Ltmp590 and .Ltmp592
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp592-.Lfunc_begin59 # >> Call Site 3 <<
	.uleb128 .Ltmp624-.Ltmp592      #   Call between .Ltmp592 and .Ltmp624
	.uleb128 .Ltmp636-.Lfunc_begin59 #     jumps to .Ltmp636
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp625-.Lfunc_begin59 # >> Call Site 4 <<
	.uleb128 .Ltmp626-.Ltmp625      #   Call between .Ltmp625 and .Ltmp626
	.uleb128 .Ltmp627-.Lfunc_begin59 #     jumps to .Ltmp627
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp628-.Lfunc_begin59 # >> Call Site 5 <<
	.uleb128 .Ltmp629-.Ltmp628      #   Call between .Ltmp628 and .Ltmp629
	.uleb128 .Ltmp630-.Lfunc_begin59 #     jumps to .Ltmp630
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp598-.Lfunc_begin59 # >> Call Site 6 <<
	.uleb128 .Ltmp613-.Ltmp598      #   Call between .Ltmp598 and .Ltmp613
	.uleb128 .Ltmp636-.Lfunc_begin59 #     jumps to .Ltmp636
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp614-.Lfunc_begin59 # >> Call Site 7 <<
	.uleb128 .Ltmp615-.Ltmp614      #   Call between .Ltmp614 and .Ltmp615
	.uleb128 .Ltmp616-.Lfunc_begin59 #     jumps to .Ltmp616
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp634-.Lfunc_begin59 # >> Call Site 8 <<
	.uleb128 .Ltmp635-.Ltmp634      #   Call between .Ltmp634 and .Ltmp635
	.uleb128 .Ltmp636-.Lfunc_begin59 #     jumps to .Ltmp636
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp631-.Lfunc_begin59 # >> Call Site 9 <<
	.uleb128 .Ltmp632-.Ltmp631      #   Call between .Ltmp631 and .Ltmp632
	.uleb128 .Ltmp633-.Lfunc_begin59 #     jumps to .Ltmp633
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp632-.Lfunc_begin59 # >> Call Site 10 <<
	.uleb128 .Lfunc_end149-.Ltmp632 #   Call between .Ltmp632 and .Lfunc_end149
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end59:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E
	.type	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E,@function
_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E: # @"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E"
.Lfunc_begin60:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception60
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	subq	$40, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rsi, %r14
	movq	%rdi, %r15
	leaq	48(%rdi), %rax
	movq	%rax, 24(%rsp)
	movq	$0, 8(%rsp)
	movq	$0, 16(%rsp)
	leaq	24(%rsp), %rax
	movq	%rax, 32(%rsp)
	leaq	32(%rsp), %rsi
	leaq	8(%rsp), %rdx
	leaq	16(%rsp), %rcx
	movl	$_ZN3std9panicking3try7do_call17h356bce4e10637fc0E, %edi
	callq	*__rust_maybe_catch_panic@GOTPCREL(%rip)
	testl	%eax, %eax
	je	.LBB150_1
# %bb.2:                                # %bb3.i.i.i.i
	movq	$-1, %rdi
	callq	*_ZN3std9panicking18update_panic_count17h122a47c81179092bE@GOTPCREL(%rip)
	movq	8(%rsp), %rbx
	movq	16(%rsp), %r12
	testq	%rbx, %rbx
	jne	.LBB150_4
	jmp	.LBB150_7
.LBB150_1:
	xorl	%ebx, %ebx
                                        # implicit-def: $r12
	testq	%rbx, %rbx
	je	.LBB150_7
.LBB150_4:                              # %bb2.i.i.i
.Ltmp637:
	movq	%rbx, %rdi
	callq	*(%r12)
.Ltmp638:
# %bb.5:                                # %bb3.i.i1.i.i
	movq	8(%r12), %rsi
	testq	%rsi, %rsi
	je	.LBB150_7
# %bb.6:                                # %bb4.i.i.i.i.i
	movq	16(%r12), %rdx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB150_7:                              # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$8with_mut17hfe91e850d678a42bE.exit"
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB150_11
# %bb.8:                                # %bb6
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB150_11
# %bb.9:                                # %bb10
	movq	248(%r15), %rax
	testq	%rax, %rax
	je	.LBB150_17
# %bb.10:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9wake_join17he980aef68612f175E.exit"
	movq	240(%r15), %rdi
	callq	*16(%rax)
	movq	$1, 16(%r15)
.LBB150_11:                             # %bb13
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB150_18
# %bb.12:                               # %bb15
	movq	8(%r15), %rbx
	movq	%r15, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	testq	%rbx, %rbx
	je	.LBB150_13
# %bb.14:                               # %bb23
	movq	%rbx, %rdi
	movq	%rax, %rsi
	callq	*_ZN85_$LT$tokio..runtime..thread_pool..shared..Shared$u20$as$u20$tokio..task..Schedule$GT$7release17hec23299a9eaa44c8E@GOTPCREL(%rip)
	jmp	.LBB150_15
.LBB150_13:                             # %bb20
	movq	%rax, %rdi
	callq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip)
.LBB150_15:                             # %bb26
	addq	$40, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB150_18:                             # %bb16
	.cfi_def_cfa_offset 80
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.41, %edi
	movl	$37, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.43, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.LBB150_17:                             # %bb2.i.i.i.i
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.47, %edi
	movl	$13, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.LBB150_16:                             # %cleanup.i.i.i.i
.Ltmp639:
	movq	%rax, %r14
	movq	%rbx, %rdi
	movq	%r12, %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end150:
	.size	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E, .Lfunc_end150-_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h0a68882be263aa15E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table150:
.Lexception60:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end60-.Lcst_begin60
.Lcst_begin60:
	.uleb128 .Lfunc_begin60-.Lfunc_begin60 # >> Call Site 1 <<
	.uleb128 .Ltmp637-.Lfunc_begin60 #   Call between .Lfunc_begin60 and .Ltmp637
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp637-.Lfunc_begin60 # >> Call Site 2 <<
	.uleb128 .Ltmp638-.Ltmp637      #   Call between .Ltmp637 and .Ltmp638
	.uleb128 .Ltmp639-.Lfunc_begin60 #     jumps to .Ltmp639
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp638-.Lfunc_begin60 # >> Call Site 3 <<
	.uleb128 .Lfunc_end150-.Ltmp638 #   Call between .Ltmp638 and .Lfunc_end150
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end60:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E
	.type	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E,@function
_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E: # @"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E"
.Lfunc_begin61:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception61
# %bb.0:                                # %start
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	subq	$40, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	movq	%rsi, %r14
	movq	%rdi, %r15
	leaq	48(%rdi), %rax
	movq	%rax, 24(%rsp)
	movq	$0, 8(%rsp)
	movq	$0, 16(%rsp)
	leaq	24(%rsp), %rax
	movq	%rax, 32(%rsp)
	leaq	32(%rsp), %rsi
	leaq	8(%rsp), %rdx
	leaq	16(%rsp), %rcx
	movl	$_ZN3std9panicking3try7do_call17h356bce4e10637fc0E, %edi
	callq	*__rust_maybe_catch_panic@GOTPCREL(%rip)
	testl	%eax, %eax
	je	.LBB151_1
# %bb.2:                                # %bb3.i.i.i.i
	movq	$-1, %rdi
	callq	*_ZN3std9panicking18update_panic_count17h122a47c81179092bE@GOTPCREL(%rip)
	movq	8(%rsp), %rbx
	movq	16(%rsp), %r12
	testq	%rbx, %rbx
	jne	.LBB151_4
	jmp	.LBB151_7
.LBB151_1:
	xorl	%ebx, %ebx
                                        # implicit-def: $r12
	testq	%rbx, %rbx
	je	.LBB151_7
.LBB151_4:                              # %bb2.i.i.i
.Ltmp640:
	movq	%rbx, %rdi
	callq	*(%r12)
.Ltmp641:
# %bb.5:                                # %bb3.i.i1.i.i
	movq	8(%r12), %rsi
	testq	%rsi, %rsi
	je	.LBB151_7
# %bb.6:                                # %bb4.i.i.i.i.i
	movq	16(%r12), %rdx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB151_7:                              # %"_ZN5tokio4loom3std11causal_cell19CausalCell$LT$T$GT$8with_mut17h3833c63ef8fa26d6E.exit"
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot18is_join_interested17h6391d7c60b3ab58cE@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB151_11
# %bb.8:                                # %bb6
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot14has_join_waker17hfddc3cc9b59112a4E@GOTPCREL(%rip)
	testb	%al, %al
	je	.LBB151_11
# %bb.9:                                # %bb10
	movq	248(%r15), %rax
	testq	%rax, %rax
	je	.LBB151_17
# %bb.10:                               # %"_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9wake_join17h05ea5df4d596cd66E.exit"
	movq	240(%r15), %rdi
	callq	*16(%rax)
	movq	$1, 16(%r15)
.LBB151_11:                             # %bb13
	movq	%r14, %rdi
	callq	*_ZN5tokio4task5state8Snapshot12is_final_ref17hdb7e1977785e1112E@GOTPCREL(%rip)
	testb	%al, %al
	jne	.LBB151_18
# %bb.12:                               # %bb15
	movq	8(%r15), %rbx
	movq	%r15, %rdi
	callq	*_ZN5tokio4task3raw7RawTask8from_raw17h3f6c8e0de647a2b0E@GOTPCREL(%rip)
	testq	%rbx, %rbx
	je	.LBB151_13
# %bb.14:                               # %bb23
	movq	%rbx, %rdi
	movq	%rax, %rsi
	callq	*_ZN88_$LT$tokio..runtime..basic_scheduler..SchedulerPriv$u20$as$u20$tokio..task..Schedule$GT$7release17hbf2e890af0633d80E@GOTPCREL(%rip)
	jmp	.LBB151_15
.LBB151_13:                             # %bb20
	movq	%rax, %rdi
	callq	*_ZN5tokio4task3raw7RawTask9drop_task17h698abef7adc201bbE@GOTPCREL(%rip)
.LBB151_15:                             # %bb26
	addq	$40, %rsp
	.cfi_def_cfa_offset 40
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	retq
.LBB151_18:                             # %bb16
	.cfi_def_cfa_offset 80
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.41, %edi
	movl	$37, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.43, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.LBB151_17:                             # %bb2.i.i.i.i
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.47, %edi
	movl	$13, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.LBB151_16:                             # %cleanup.i.i.i.i
.Ltmp642:
	movq	%rax, %r14
	movq	%rbx, %rdi
	movq	%r12, %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.Lfunc_end151:
	.size	_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E, .Lfunc_end151-_ZN5tokio4task7harness20Harness$LT$T$C$S$GT$9do_cancel17h35beb3e2432acf85E
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table151:
.Lexception61:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end61-.Lcst_begin61
.Lcst_begin61:
	.uleb128 .Lfunc_begin61-.Lfunc_begin61 # >> Call Site 1 <<
	.uleb128 .Ltmp640-.Lfunc_begin61 #   Call between .Lfunc_begin61 and .Ltmp640
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp640-.Lfunc_begin61 # >> Call Site 2 <<
	.uleb128 .Ltmp641-.Ltmp640      #   Call between .Ltmp640 and .Ltmp641
	.uleb128 .Ltmp642-.Lfunc_begin61 #     jumps to .Ltmp642
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp641-.Lfunc_begin61 # >> Call Site 3 <<
	.uleb128 .Lfunc_end151-.Ltmp641 #   Call between .Ltmp641 and .Lfunc_end151
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end61:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE
	.type	_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE,@function
_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE: # @"_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	%rsi, %rdx
	movq	(%rdi), %rax
	movq	16(%rdi), %rsi
	movq	%rax, %rdi
	jmpq	*_ZN42_$LT$str$u20$as$u20$core..fmt..Display$GT$3fmt17hc19f19c00f549debE@GOTPCREL(%rip) # TAILCALL
.Lfunc_end152:
	.size	_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE, .Lfunc_end152-_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE
	.type	_ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE,@function
_ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE: # @"_ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	(%rdi), %rax
	movq	8(%rdi), %rcx
	movq	72(%rcx), %rcx
	movq	%rax, %rdi
	jmpq	*%rcx                   # TAILCALL
.Lfunc_end153:
	.size	_ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE, .Lfunc_end153-_ZN63_$LT$alloc..boxed..Box$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h5f6b5d1a7f049ffaE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE
	.type	_ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE,@function
_ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE: # @"_ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	%rsi, %rax
	cmpb	$3, (%rdi)
	jne	.LBB154_1
# %bb.2:                                # %bb4
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.3, %esi
	movl	$2, %edx
	movq	%rax, %rdi
	jmpq	*_ZN4core3fmt9Formatter3pad17hb5b5664cd7ca8060E@GOTPCREL(%rip) # TAILCALL
.LBB154_1:                              # %bb2
	movq	%rax, %rsi
	jmpq	*_ZN58_$LT$std..io..error..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h80d51771597be04eE@GOTPCREL(%rip) # TAILCALL
.Lfunc_end154:
	.size	_ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE, .Lfunc_end154-_ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E
	.type	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E,@function
_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E: # @"_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E"
.Lfunc_begin62:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception62
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$1304, %rsp             # imm = 0x518
	.cfi_def_cfa_offset 1360
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rsi, %r13
	movq	%rdi, 40(%rsp)          # 8-byte Spill
	movq	%rdx, %rdi
	callq	*_ZN3std6future16set_task_context17hd1bc3d998532dcddE@GOTPCREL(%rip)
	movq	%rax, 240(%rsp)
	movl	(%r13), %eax
	jmpq	*.LJTI155_0(,%rax,8)
.LBB155_1:                              # %bb2.i
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.74, 8(%r13)
	movq	$12, 16(%r13)
	movl	$0, 80(%r13)
.LBB155_2:                              # %bb9.i
	leaq	8(%r13), %r15
.Ltmp647:
	callq	*_ZN3std6future6TLS_CX7__getit17hdaabf9d2770484c0E@GOTPCREL(%rip)
.Ltmp648:
# %bb.3:                                # %.noexc.i
	testq	%rax, %rax
	je	.LBB155_91
# %bb.4:                                # %"_ZN3std6thread5local17LocalKey$LT$T$GT$4with17h431b85d9219b6670E.exit.i.i"
	movq	(%rax), %rdi
	movq	$0, (%rax)
	movq	%rdi, 32(%rsp)
	testq	%rdi, %rdi
	je	.LBB155_93
# %bb.5:                                # %bb5.i.i
.Ltmp649:
	callq	*_ZN3std6future16set_task_context17hd1bc3d998532dcddE@GOTPCREL(%rip)
.Ltmp650:
# %bb.6:                                # %.noexc5.i.i
	movq	%rax, 848(%rsp)
	movl	80(%r13), %eax
	jmpq	*.LJTI155_1(,%rax,8)
.LBB155_7:                              # %bb1.i.i.i.i
	movq	8(%r13), %rsi
	movq	16(%r13), %rdx
	movq	%rsi, 24(%r13)
	movq	%rdx, 32(%r13)
.Ltmp655:
	leaq	256(%rsp), %rdi
	callq	*_ZN5tokio3net4addr77_$LT$impl$u20$tokio..net..addr..sealed..ToSocketAddrsPriv$u20$for$u20$str$GT$15to_socket_addrs17h2a94ec5e981404b1E@GOTPCREL(%rip)
.Ltmp656:
# %bb.8:                                # %bb2.i.i.i.i
	movq	288(%rsp), %rax
	movq	%rax, 72(%r13)
	movups	256(%rsp), %xmm0
	movups	272(%rsp), %xmm1
	movups	%xmm1, 56(%r13)
	movups	%xmm0, 40(%r13)
.LBB155_9:                              # %bb11.i.i.i.i
	leaq	40(%r13), %r12
.Ltmp658:
	callq	*_ZN3std6future6TLS_CX7__getit17hdaabf9d2770484c0E@GOTPCREL(%rip)
.Ltmp659:
# %bb.10:                               # %.noexc.i.i.i.i
	testq	%rax, %rax
	je	.LBB155_99
# %bb.11:                               # %"_ZN3std6thread5local17LocalKey$LT$T$GT$4with17hc3c7cc5296d3a6abE.exit.i.i.i.i.i"
	movq	(%rax), %rdx
	movq	$0, (%rax)
	movq	%rdx, 400(%rsp)
	testq	%rdx, %rdx
	je	.LBB155_101
# %bb.12:                               # %bb5.i.i.i.i.i
.Ltmp660:
	leaq	48(%rsp), %rdi
	movq	%r12, %rsi
	callq	*_ZN85_$LT$tokio..net..addr..sealed..MaybeReady$u20$as$u20$core..future..future..Future$GT$4poll17h38cc45b30186290fE@GOTPCREL(%rip)
.Ltmp661:
# %bb.13:                               # %bb6.i.i.i.i.i
.Ltmp662:
	leaq	400(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp663:
# %bb.14:                               # %bb14.i.i.i.i
	cmpl	$2, 48(%rsp)
	jne	.LBB155_16
# %bb.15:                               # %bb7.i.i.i
	movq	$2, 48(%rsp)
	movl	$3, 80(%r13)
	movb	$1, %bpl
	movl	$2, %r14d
	jmp	.LBB155_63
.LBB155_16:                             # %bb60.i.i.i.i
	movups	48(%rsp), %xmm0
	movups	64(%rsp), %xmm1
	movups	80(%rsp), %xmm2
	movaps	%xmm2, 784(%rsp)
	movaps	%xmm1, 768(%rsp)
	movaps	%xmm0, 752(%rsp)
	cmpl	$0, (%r12)
	je	.LBB155_22
# %bb.17:                               # %bb2.i148.i.i.i.i
	movq	48(%r13), %rax
	movq	$0, 48(%r13)
	testq	%rax, %rax
	je	.LBB155_22
# %bb.18:                               # %bb2.i.i.i149.i.i.i.i
	movq	%rax, 48(%rsp)
.Ltmp664:
	leaq	48(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
.Ltmp665:
# %bb.19:                               # %.noexc151.i.i.i.i
.Ltmp666:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
.Ltmp667:
# %bb.20:                               # %.noexc152.i.i.i.i
	testb	%al, %al
	jne	.LBB155_22
# %bb.21:                               # %bb5.i.i.i150.i.i.i.i
	movq	48(%rsp), %rdi
.Ltmp668:
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.Ltmp669:
.LBB155_22:                             # %bb21.i.i.i.i
	movq	752(%rsp), %rax
	movups	760(%rsp), %xmm0
	movaps	%xmm0, 800(%rsp)
	movups	776(%rsp), %xmm0
	movaps	%xmm0, 816(%rsp)
	movq	792(%rsp), %rcx
	movq	%rcx, 832(%rsp)
	cmpq	$1, %rax
	jne	.LBB155_24
# %bb.23:                               # %bb63.i.i.i.i
	movaps	800(%rsp), %xmm0
	jmp	.LBB155_61
.LBB155_24:                             # %bb35.i.i.i.i
	movq	%r12, 232(%rsp)         # 8-byte Spill
	movq	%r15, 16(%rsp)          # 8-byte Spill
	movq	832(%rsp), %rax
	movq	%rax, 1296(%rsp)
	movaps	800(%rsp), %xmm0
	movaps	816(%rsp), %xmm1
	movaps	%xmm1, 1280(%rsp)
	movaps	%xmm0, 1264(%rsp)
	movb	$3, 256(%rsp)
	movq	%rax, 432(%rsp)
	movaps	%xmm1, 416(%rsp)
	movaps	%xmm0, 400(%rsp)
	leaq	56(%rsp), %r12
	leaq	48(%rsp), %rbx
	leaq	400(%rsp), %r14
	movq	_ZN94_$LT$tokio..net..addr..sealed..OneOrMore$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17h948ec1524f3fe5c5E@GOTPCREL(%rip), %rbp
	leaq	496(%rsp), %r15
	movq	%r13, 24(%rsp)          # 8-byte Spill
	jmp	.LBB155_26
	.p2align	4, 0x90
.LBB155_25:                             # %bb74.thread.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movaps	496(%rsp), %xmm0
	movaps	%xmm0, 256(%rsp)
.LBB155_26:                             # %bb40.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp671:
	movq	%rbx, %rdi
	movq	%r14, %rsi
	callq	*%rbp
.Ltmp672:
# %bb.27:                               # %bb42.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	cmpl	$2, 48(%rsp)
	je	.LBB155_37
# %bb.28:                               # %bb47.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movups	48(%rsp), %xmm0
	movups	64(%rsp), %xmm1
	movaps	%xmm1, 768(%rsp)
	movaps	%xmm0, 752(%rsp)
	movaps	%xmm1, 512(%rsp)
	movaps	%xmm0, 496(%rsp)
.Ltmp674:
	movq	%rbx, %rdi
	movq	%r15, %rsi
	callq	*_ZN5tokio3net3tcp8listener11TcpListener9bind_addr17hc1cb4b5e90c4957eE@GOTPCREL(%rip)
.Ltmp675:
# %bb.29:                               # %bb48.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	cmpl	$1, 48(%rsp)
	jne	.LBB155_46
# %bb.30:                               # %bb56.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movups	(%r12), %xmm0
	movaps	%xmm0, 496(%rsp)
	movzbl	256(%rsp), %eax
	cmpb	$3, %al
	ja	.LBB155_32
# %bb.31:                               # %bb56.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	cmpb	$2, %al
	jne	.LBB155_25
.LBB155_32:                             # %bb2.i.i.i135.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movq	%r15, %r13
	movq	%r14, %r15
	movq	264(%rsp), %r12
	movq	(%r12), %rdi
	movq	8(%r12), %rax
.Ltmp680:
	callq	*(%rax)
.Ltmp681:
# %bb.33:                               # %bb3.i.i.i.i.i.i137.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movq	8(%r12), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	movq	__rust_dealloc@GOTPCREL(%rip), %r14
	je	.LBB155_35
# %bb.34:                               # %bb4.i.i.i.i.i.i.i138.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movq	(%r12), %rdi
	movq	16(%rax), %rdx
	callq	*%r14
.LBB155_35:                             # %bb74.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
	movl	$24, %esi
	movl	$8, %edx
	movq	%r12, %rdi
	callq	*%r14
	movaps	496(%rsp), %xmm0
	movaps	%xmm0, 256(%rsp)
	cmpq	$0, 48(%rsp)
	leaq	56(%rsp), %r12
	movq	%r15, %r14
	movq	%r13, %r15
	movq	24(%rsp), %r13          # 8-byte Reload
	jne	.LBB155_26
# %bb.36:                               # %bb76.i.i.i.i
                                        #   in Loop: Header=BB155_26 Depth=1
.Ltmp685:
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp686:
	jmp	.LBB155_26
.LBB155_37:                             # %bb45.i.i.i.i
	cmpl	$0, 400(%rsp)
	movq	16(%rsp), %r15          # 8-byte Reload
	movq	232(%rsp), %r12         # 8-byte Reload
	je	.LBB155_43
# %bb.38:                               # %bb2.i.i.i.i.i
	movq	424(%rsp), %rcx
	movq	432(%rsp), %rax
	subq	%rcx, %rax
	.p2align	4, 0x90
.LBB155_39:                             # %bb4.i.i.i.i.i.i140.i
                                        # =>This Inner Loop Header: Depth=1
	testq	%rax, %rax
	je	.LBB155_41
# %bb.40:                               # %"_ZN72_$LT$$RF$mut$u20$I$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hbfa7904ad84011c1E.exit.i.i.i.i.i.i.i"
                                        #   in Loop: Header=BB155_39 Depth=1
	leaq	32(%rcx), %rdx
	movq	%rdx, 424(%rsp)
	addq	$-32, %rax
	cmpl	$2, (%rcx)
	movq	%rdx, %rcx
	jne	.LBB155_39
.LBB155_41:                             # %bb9.i.i.i.i.i.i.i
	movq	416(%rsp), %rsi
	testq	%rsi, %rsi
	je	.LBB155_43
# %bb.42:                               # %bb4.i.i.i.i.i.i.i.i.i.i
	movq	408(%rsp), %rdi
	shlq	$5, %rsi
	movl	$4, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_43:                             # %bb57.i.i.i.i
	movaps	256(%rsp), %xmm0
	movaps	%xmm0, 48(%rsp)
	cmpb	$3, 48(%rsp)
	jne	.LBB155_59
# %bb.44:                               # %bb2.i143.i.i.i.i
.Ltmp690:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.16, %edi
	movl	$32, %esi
	callq	*_ZN3std5error161_$LT$impl$u20$core..convert..From$LT$$RF$str$GT$$u20$for$u20$alloc..boxed..Box$LT$dyn$u20$std..error..Error$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$4from17h3380ca6fb4be57d1E@GOTPCREL(%rip)
.Ltmp691:
# %bb.45:                               # %.noexc.i144.i.i.i.i
	movq	%rdx, %rcx
.Ltmp692:
	leaq	400(%rsp), %rdi
	movl	$11, %esi
	movq	%rax, %rdx
	callq	*_ZN3std2io5error5Error4_new17h9d3cc36308b63b32E@GOTPCREL(%rip)
.Ltmp693:
	jmp	.LBB155_60
.LBB155_46:                             # %bb71.i.i.i.i
	movq	48(%r12), %rax
	movq	%rax, 928(%rsp)
	movups	(%r12), %xmm0
	movups	16(%r12), %xmm1
	movups	32(%r12), %xmm2
	movaps	%xmm2, 912(%rsp)
	movaps	%xmm1, 896(%rsp)
	movaps	%xmm0, 880(%rsp)
	cmpl	$0, 400(%rsp)
	movq	16(%rsp), %r15          # 8-byte Reload
	movq	232(%rsp), %r12         # 8-byte Reload
	je	.LBB155_52
# %bb.47:                               # %bb2.i177.i.i.i.i
	movq	424(%rsp), %rcx
	movq	432(%rsp), %rax
	subq	%rcx, %rax
	.p2align	4, 0x90
.LBB155_48:                             # %bb4.i.i.i180.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	testq	%rax, %rax
	je	.LBB155_50
# %bb.49:                               # %"_ZN72_$LT$$RF$mut$u20$I$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hbfa7904ad84011c1E.exit.i.i.i183.i.i.i.i"
                                        #   in Loop: Header=BB155_48 Depth=1
	leaq	32(%rcx), %rdx
	movq	%rdx, 424(%rsp)
	addq	$-32, %rax
	cmpl	$2, (%rcx)
	movq	%rdx, %rcx
	jne	.LBB155_48
.LBB155_50:                             # %bb9.i.i.i186.i.i.i.i
	movq	416(%rsp), %rsi
	testq	%rsi, %rsi
	je	.LBB155_52
# %bb.51:                               # %bb4.i.i.i.i.i.i189.i.i.i.i
	movq	408(%rsp), %rdi
	shlq	$5, %rsi
	movl	$4, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_52:                             # %bb54.i.i.i.i
	movb	256(%rsp), %al
	cmpb	$3, %al
	ja	.LBB155_54
# %bb.53:                               # %bb54.i.i.i.i
	cmpb	$2, %al
	jne	.LBB155_58
.LBB155_54:                             # %bb2.i.i.i.i.i.i.i
	movq	264(%rsp), %rbx
	movq	(%rbx), %rdi
	movq	8(%rbx), %rax
.Ltmp677:
	callq	*(%rax)
.Ltmp678:
# %bb.55:                               # %bb3.i.i.i.i.i.i.i.i.i.i
	movq	8(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB155_57
# %bb.56:                               # %bb4.i.i.i.i.i.i.i.i.i.i.i
	movq	(%rbx), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_57:                             # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i.i.i
	movl	$24, %esi
	movl	$8, %edx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_58:                             # %bb55.i.i.i.i
	xorl	%r14d, %r14d
	jmp	.LBB155_62
.LBB155_59:                             # %bb14.i.i.i.i.i
	movaps	48(%rsp), %xmm0
	movaps	%xmm0, 400(%rsp)
.LBB155_60:                             # %bb58.i.i.i.i
	movaps	400(%rsp), %xmm0
.LBB155_61:                             # %bb8.i.i.i
	movaps	%xmm0, 880(%rsp)
	movl	$1, %r14d
.LBB155_62:                             # %bb8.i.i.i
	movq	%r14, 48(%rsp)
	movaps	880(%rsp), %xmm0
	movaps	896(%rsp), %xmm1
	movaps	912(%rsp), %xmm2
	movups	%xmm0, 56(%rsp)
	movups	%xmm1, 72(%rsp)
	movups	%xmm2, 88(%rsp)
	movq	928(%rsp), %rax
	movq	%rax, 104(%rsp)
	movl	$1, 80(%r13)
	movups	56(%rsp), %xmm0
	movups	72(%rsp), %xmm1
	movups	88(%rsp), %xmm2
	movaps	%xmm0, 1072(%rsp)
	movaps	%xmm1, 1088(%rsp)
	movaps	%xmm2, 1104(%rsp)
	movq	104(%rsp), %rax
	movq	%rax, 1120(%rsp)
	xorl	%ebp, %ebp
.LBB155_63:                             # %bb10.i.i.i
.Ltmp698:
	leaq	848(%rsp), %rbx
	movq	%rbx, %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp699:
# %bb.64:                               # %bb11.i.i.i
	movq	48(%rsp), %rax
	cmpq	$2, %rax
	je	.LBB155_73
# %bb.65:                               # %bb11.i.i.i
	xorb	$1, %bpl
	jne	.LBB155_73
# %bb.66:                               # %bb17.i.i.i
	testq	%rax, %rax
	je	.LBB155_72
# %bb.67:                               # %bb3.i.i.i.i
	cmpb	$2, 56(%rsp)
	jb	.LBB155_73
# %bb.68:                               # %bb2.i.i18.i.i.i
	movq	64(%rsp), %rbp
	movq	(%rbp), %rdi
	movq	8(%rbp), %rax
.Ltmp705:
	callq	*(%rax)
.Ltmp706:
# %bb.69:                               # %bb3.i.i.i.i.i.i.i.i
	movq	8(%rbp), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB155_71
# %bb.70:                               # %bb4.i.i.i.i.i.i.i.i.i
	movq	(%rbp), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_71:                             # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i
	movq	64(%rsp), %rdi
	movl	$24, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB155_73
.LBB155_72:                             # %bb2.i17.i.i.i
	leaq	56(%rsp), %rdi
.Ltmp708:
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp709:
.LBB155_73:                             # %bb6.i.i
.Ltmp710:
	leaq	32(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp711:
# %bb.74:                               # %bb12.i
	cmpl	$2, %r14d
	jne	.LBB155_76
# %bb.75:                               # %bb17.i
	movq	$0, 48(%rsp)
	movl	$3, (%r13)
	jmp	.LBB155_134
.LBB155_76:                             # %bb69.i
	movq	%r14, 560(%rsp)
	movaps	1072(%rsp), %xmm0
	movaps	1088(%rsp), %xmm1
	movaps	1104(%rsp), %xmm2
	movups	%xmm0, 568(%rsp)
	movups	%xmm1, 584(%rsp)
	movups	%xmm2, 600(%rsp)
	movq	1120(%rsp), %rax
	movq	%rax, 616(%rsp)
	cmpl	$3, 80(%r13)
	jne	.LBB155_83
# %bb.77:                               # %bb12.i.i256.i
	cmpl	$0, (%r12)
	je	.LBB155_83
# %bb.78:                               # %bb2.i.i.i257.i
	movq	48(%r13), %rax
	movq	$0, 48(%r13)
	testq	%rax, %rax
	je	.LBB155_83
# %bb.79:                               # %bb2.i.i.i.i.i258.i
	movq	%rax, 48(%rsp)
.Ltmp712:
	leaq	48(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
.Ltmp713:
# %bb.80:                               # %.noexc259.i
.Ltmp714:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
.Ltmp715:
# %bb.81:                               # %.noexc260.i
	testb	%al, %al
	jne	.LBB155_83
# %bb.82:                               # %bb5.i.i.i.i.i.i
	movq	48(%rsp), %rdi
.Ltmp716:
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.Ltmp717:
.LBB155_83:                             # %bb19.i
	leaq	568(%rsp), %rax
	movq	48(%rax), %rcx
	movq	%rcx, 352(%rsp)
	movups	(%rax), %xmm0
	movups	16(%rax), %xmm1
	movups	32(%rax), %xmm2
	movaps	%xmm2, 336(%rsp)
	movaps	%xmm1, 320(%rsp)
	movaps	%xmm0, 304(%rsp)
	cmpl	$1, %r14d
	jne	.LBB155_86
# %bb.84:                               # %bb22.i
	movaps	304(%rsp), %xmm0
	movaps	%xmm0, 48(%rsp)
	movl	$16, %edi
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB155_135
# %bb.85:                               # %bb72.i
	movq	%rax, %rbx
	movaps	48(%rsp), %xmm0
	movups	%xmm0, (%rax)
	jmp	.LBB155_190
.LBB155_86:                             # %bb74.i
	movq	352(%rsp), %rax
	movq	%rax, 48(%r15)
	movaps	304(%rsp), %xmm0
	movaps	320(%rsp), %xmm1
	movaps	336(%rsp), %xmm2
	movups	%xmm2, 32(%r15)
	movups	%xmm1, 16(%r15)
	movups	%xmm0, (%r15)
	jmp	.LBB155_136
.LBB155_87:                             # %panic4.i
.Ltmp645:
	movl	$str.d, %edi
	movl	$35, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.73, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp646:
# %bb.88:                               # %.noexc13
.LBB155_89:                             # %panic.i
.Ltmp643:
	movl	$str.c, %edi
	movl	$34, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.73, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp644:
# %bb.90:                               # %.noexc12
.LBB155_91:                             # %bb5.i.i.i.i
.Ltmp849:
	leaq	8(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp850:
# %bb.92:                               # %.noexc141.i
.LBB155_93:                             # %bb2.i.i139.i
.Ltmp844:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.1, %edi
	movl	$100, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp845:
# %bb.94:                               # %.noexc.i.i
.LBB155_95:                             # %panic2.i.i.i.i
.Ltmp653:
	movq	%r13, 24(%rsp)          # 8-byte Spill
	movq	%r15, 16(%rsp)          # 8-byte Spill
	movl	$str.d, %edi
	movl	$35, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.15, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp654:
# %bb.96:                               # %.noexc14.i.i.i
.LBB155_97:                             # %panic.i.i.i.i
.Ltmp651:
	movq	%r13, 24(%rsp)          # 8-byte Spill
	movq	%r15, 16(%rsp)          # 8-byte Spill
	movl	$str.c, %edi
	movl	$34, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.15, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp652:
# %bb.98:                               # %.noexc13.i.i.i
.LBB155_99:                             # %bb5.i.i.i.i.i.i.i
.Ltmp836:
	leaq	8(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp837:
# %bb.100:                              # %.noexc131.i.i.i.i
.LBB155_101:                            # %bb2.i.i.i.i.i.i
.Ltmp831:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.1, %edi
	movl	$100, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp832:
# %bb.102:                              # %.noexc.i.i.i.i.i
.LBB155_103:                            # %cleanup.i.i.i.i.i.i.i.i.i.i
.Ltmp679:
	movq	%rax, %r14
                                        # kill: killed $rdx
	movq	(%rbx), %rdi
	movq	8(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%rbx, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB155_127
.LBB155_104:                            # %bb1.i.i.i.i.i
.Ltmp694:
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp695:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE
.Ltmp696:
	jmp	.LBB155_127
.LBB155_105:                            # %cleanup19.i.i.i.i
.Ltmp697:
	jmp	.LBB155_112
.LBB155_106:                            # %cleanup.i.i.i.i.i.i.i.i
.Ltmp707:
	movq	%rax, %r14
                                        # kill: killed $rdx
	movq	(%rbp), %rdi
	movq	8(%rbp), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	64(%rsp), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB155_129
.LBB155_107:                            # %cleanup8.i
.Ltmp718:
	jmp	.LBB155_219
.LBB155_108:                            # %cleanup16.body.i.i.i.i
.Ltmp687:
	jmp	.LBB155_125
.LBB155_109:                            # %cleanup6.i.i.i.i
.Ltmp670:
	jmp	.LBB155_111
.LBB155_110:                            # %cleanup.i.i.i.i
.Ltmp657:
.LBB155_111:                            # %bb4.i.i.i.i
	movq	%r13, 24(%rsp)          # 8-byte Spill
	movq	%r15, 16(%rsp)          # 8-byte Spill
.LBB155_112:                            # %bb4.i.i.i.i
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_127
.LBB155_113:                            # %cleanup.i.i.i.i.i.i139.i.i.i.i
.Ltmp682:
	movq	%rax, %r14
                                        # kill: killed $rdx
	movq	(%r12), %rdi
	movq	8(%r12), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r12, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	movaps	496(%rsp), %xmm0
	movaps	%xmm0, 256(%rsp)
	cmpq	$0, 48(%rsp)
	jne	.LBB155_126
# %bb.114:                              # %bb70.i.i.i.i
.Ltmp683:
	leaq	56(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp684:
	jmp	.LBB155_126
.LBB155_115:                            # %cleanup1.i.i.i
.Ltmp700:
	movq	%rax, %r14
                                        # kill: killed $rdx
	cmpl	$2, 48(%rsp)
	jne	.LBB155_117
# %bb.116:                              # %bb14.i.i.i
.Ltmp703:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h0fa96f10805463b4E
.Ltmp704:
	jmp	.LBB155_129
.LBB155_117:                            # %bb12.i.i.i
	testb	%bpl, %bpl
	je	.LBB155_129
# %bb.118:                              # %bb13.i.i.i
.Ltmp701:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hc95f04c95d6546b6E
.Ltmp702:
	jmp	.LBB155_129
.LBB155_119:                            # %cleanup.i.i.i.i.i
.Ltmp833:
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp834:
	leaq	400(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp835:
# %bb.120:
	movq	%r13, 24(%rsp)          # 8-byte Spill
	movq	%r15, 16(%rsp)          # 8-byte Spill
	jmp	.LBB155_122
.LBB155_121:                            # %cleanup4.i.i.i.i
.Ltmp838:
	movq	%r13, 24(%rsp)          # 8-byte Spill
	movq	%r15, 16(%rsp)          # 8-byte Spill
	movq	%rax, %r14
                                        # kill: killed $rdx
.LBB155_122:                            # %bb10.i.i.i.i
.Ltmp839:
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h5154e662f80429f9E
.Ltmp840:
	jmp	.LBB155_127
.LBB155_123:                            # %cleanup14.i.i.i.i
.Ltmp676:
	jmp	.LBB155_125
.LBB155_124:                            # %cleanup13.i.i.i.i
.Ltmp673:
.LBB155_125:                            # %bb69.i.i.i.i
	movq	%rax, %r14
                                        # kill: killed $rdx
.LBB155_126:                            # %bb69.i.i.i.i
	leaq	400(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hdfcb5327f06b8e36E
.Ltmp688:
	leaq	256(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha528f2a6a17be11cE
.Ltmp689:
.LBB155_127:                            # %bb4.i.i.i.i
	movq	24(%rsp), %rax          # 8-byte Reload
	movl	$2, 80(%rax)
.LBB155_128:                            # %cleanup.body.i.i.i
.Ltmp842:
	leaq	848(%rsp), %rdi
	movq	16(%rsp), %r15          # 8-byte Reload
	movq	24(%rsp), %r13          # 8-byte Reload
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp843:
.LBB155_129:                            # %cleanup.body.i.i
.Ltmp847:
	leaq	32(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp848:
.LBB155_130:                            # %bb8.i
.Ltmp852:
	movq	%r15, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h7adc16293b341271E
.Ltmp853:
	jmp	.LBB155_254
.LBB155_131:                            # %cleanup.i.i.i
.Ltmp841:
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_128
.LBB155_132:                            # %cleanup.i.i
.Ltmp846:
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_129
.LBB155_133:                            # %cleanup6.i
.Ltmp851:
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_130
.LBB155_134:                            # %bb10
	movb	$1, %bl
	movl	$1, %eax
	xorl	%ebp, %ebp
	movq	40(%rsp), %rcx          # 8-byte Reload
	jmp	.LBB155_191
.LBB155_135:                            # %bb6.i.i.i.i
	movl	$16, %edi
	movl	$8, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.LBB155_136:                            # %bb31.i
	leaq	8(%r13), %rsi
.Ltmp719:
	leaq	848(%rsp), %rdi
	callq	*_ZN5tokio3net3tcp8listener11TcpListener6accept17hd0d7c5be65ee690aE@GOTPCREL(%rip)
.Ltmp720:
# %bb.137:                              # %bb33.i
	movups	(%rbx), %xmm0
	movups	16(%rbx), %xmm1
	movups	%xmm1, 80(%r13)
	movups	%xmm0, 64(%r13)
.LBB155_138:                            # %bb40.i
.Ltmp722:
	callq	*_ZN3std6future6TLS_CX7__getit17hdaabf9d2770484c0E@GOTPCREL(%rip)
.Ltmp723:
# %bb.139:                              # %.noexc211.i
	testq	%rax, %rax
	je	.LBB155_200
# %bb.140:                              # %"_ZN3std6thread5local17LocalKey$LT$T$GT$4with17ha8d9291b1d7f1d45E.exit.i.i"
	movq	(%rax), %rdi
	movq	$0, (%rax)
	movq	%rdi, 248(%rsp)
	testq	%rdi, %rdi
	je	.LBB155_204
# %bb.141:                              # %bb5.i168.i
.Ltmp724:
	callq	*_ZN3std6future16set_task_context17hd1bc3d998532dcddE@GOTPCREL(%rip)
.Ltmp725:
# %bb.142:                              # %.noexc4.i.i
	movq	%rax, 32(%rsp)
	movl	88(%r13), %eax
	jmpq	*.LJTI155_2(,%rax,8)
.LBB155_143:                            # %bb2.i.i.i169.i
	leaq	72(%r13), %rax
	movq	64(%r13), %rcx
	movq	%rcx, 72(%r13)
	movq	%rax, 80(%r13)
.LBB155_144:                            # %bb6.i.i.i171.i
.Ltmp731:
	callq	*_ZN3std6future6TLS_CX7__getit17hdaabf9d2770484c0E@GOTPCREL(%rip)
.Ltmp732:
# %bb.145:                              # %.noexc23.i.i.i.i
	testq	%rax, %rax
	je	.LBB155_202
# %bb.146:                              # %"_ZN3std6thread5local17LocalKey$LT$T$GT$4with17h59c28499e06e97abE.exit.i.i.i.i.i"
	movq	(%rax), %rdx
	movq	$0, (%rax)
	movq	%rdx, 560(%rsp)
	testq	%rdx, %rdx
	je	.LBB155_206
# %bb.147:                              # %bb5.i.i.i.i176.i
	movq	80(%r13), %rax
	movq	(%rax), %rsi
.Ltmp733:
	leaq	48(%rsp), %rdi
	callq	*_ZN5tokio3net3tcp8listener11TcpListener11poll_accept17hcaa4193c927f0e71E@GOTPCREL(%rip)
.Ltmp734:
# %bb.148:                              # %bb6.i.i.i.i177.i
.Ltmp735:
	leaq	560(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp736:
# %bb.149:                              # %bb9.i.i.i179.i
	cmpl	$2, 48(%rsp)
	jne	.LBB155_151
# %bb.150:                              # %bb4.thread.i.i.i
	movq	$2, 560(%rsp)
	movl	$3, 88(%r13)
	jmp	.LBB155_152
.LBB155_151:                            # %bb4.i.i.i
	movups	128(%rsp), %xmm0
	movaps	%xmm0, 640(%rsp)
	movups	112(%rsp), %xmm0
	movaps	%xmm0, 624(%rsp)
	movups	48(%rsp), %xmm0
	movups	64(%rsp), %xmm1
	movups	80(%rsp), %xmm2
	movups	96(%rsp), %xmm3
	movaps	%xmm3, 608(%rsp)
	movaps	%xmm2, 592(%rsp)
	movaps	%xmm1, 576(%rsp)
	movaps	%xmm0, 560(%rsp)
	movq	560(%rsp), %rbx
	movl	$1, 88(%r13)
	cmpq	$2, %rbx
	jne	.LBB155_153
.LBB155_152:
	movb	$1, %bpl
	movl	$2, %ebx
	jmp	.LBB155_154
.LBB155_153:                            # %bb8.i.i186.i
	movq	648(%rsp), %rax
	movq	%rax, 384(%rsp)
	movups	632(%rsp), %xmm0
	movaps	%xmm0, 368(%rsp)
	movups	568(%rsp), %xmm0
	movups	584(%rsp), %xmm1
	movups	600(%rsp), %xmm2
	movups	616(%rsp), %xmm3
	movaps	%xmm3, 352(%rsp)
	movaps	%xmm2, 336(%rsp)
	movaps	%xmm1, 320(%rsp)
	movaps	%xmm0, 304(%rsp)
	xorl	%ebp, %ebp
.LBB155_154:                            # %bb10.i.i188.i
.Ltmp737:
	leaq	32(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp738:
# %bb.155:                              # %bb11.i.i191.i
	movq	560(%rsp), %rax
	cmpq	$2, %rax
	je	.LBB155_164
# %bb.156:                              # %bb11.i.i191.i
	xorb	$1, %bpl
	jne	.LBB155_164
# %bb.157:                              # %bb17.i.i195.i
	testq	%rax, %rax
	je	.LBB155_163
# %bb.158:                              # %bb3.i14.i.i.i
	cmpb	$2, 568(%rsp)
	jb	.LBB155_164
# %bb.159:                              # %bb2.i.i.i.i197.i
	movq	576(%rsp), %rbp
	movq	(%rbp), %rdi
	movq	8(%rbp), %rax
.Ltmp744:
	callq	*(%rax)
.Ltmp745:
# %bb.160:                              # %bb3.i.i.i.i.i.i.i199.i
	movq	8(%rbp), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB155_162
# %bb.161:                              # %bb4.i.i.i.i.i.i.i.i200.i
	movq	(%rbp), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_162:                            # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i202.i
	movq	576(%rsp), %rdi
	movl	$24, %esi
	movl	$8, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
	jmp	.LBB155_164
.LBB155_163:                            # %bb2.i13.i.i.i
	leaq	568(%rsp), %rdi
.Ltmp747:
	callq	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE
.Ltmp748:
.LBB155_164:                            # %bb6.i207.i
.Ltmp749:
	leaq	248(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp750:
# %bb.165:                              # %bb43.i
	cmpl	$2, %ebx
	je	.LBB155_187
# %bb.166:                              # %bb50.i
	movq	%rbx, 880(%rsp)
	movaps	304(%rsp), %xmm0
	movaps	320(%rsp), %xmm1
	movaps	336(%rsp), %xmm2
	movaps	352(%rsp), %xmm3
	movups	%xmm0, 888(%rsp)
	movq	384(%rsp), %rax
	movq	%rax, 968(%rsp)
	movaps	368(%rsp), %xmm0
	movups	%xmm0, 952(%rsp)
	movups	%xmm3, 936(%rsp)
	movups	%xmm2, 920(%rsp)
	movups	%xmm1, 904(%rsp)
	movq	880(%rsp), %rax
	movq	%rax, 1072(%rsp)
	movq	888(%rsp), %rax
	movq	%rax, 1080(%rsp)
	movups	896(%rsp), %xmm0
	movaps	%xmm0, 1088(%rsp)
	movups	912(%rsp), %xmm0
	movaps	%xmm0, 1104(%rsp)
	movups	928(%rsp), %xmm0
	movaps	%xmm0, 1120(%rsp)
	movups	944(%rsp), %xmm0
	movaps	%xmm0, 1136(%rsp)
	movups	960(%rsp), %xmm0
	movaps	%xmm0, 1152(%rsp)
	cmpl	$1, 1072(%rsp)
	leaq	1080(%rsp), %rax
	je	.LBB155_188
# %bb.167:                              # %bb62.i
	movq	48(%rax), %rcx
	movq	%rcx, 544(%rsp)
	movups	(%rax), %xmm0
	movups	16(%rax), %xmm1
	movups	32(%rax), %xmm2
	movaps	%xmm2, 528(%rsp)
	movaps	%xmm1, 512(%rsp)
	movaps	%xmm0, 496(%rsp)
	movq	%rcx, 1120(%rsp)
	movaps	%xmm2, 1104(%rsp)
	movaps	%xmm1, 1088(%rsp)
	movaps	%xmm0, 1072(%rsp)
	movl	$0, 1200(%rsp)
.Ltmp751:
	callq	*_ZN5tokio7runtime7context12spawn_handle17h566b9f86afc14ebaE@GOTPCREL(%rip)
.Ltmp752:
# %bb.168:                              # %bb2.i236.i
	movq	%rax, %rbx
	movq	%rdx, %r12
	movq	%rax, 48(%rsp)
	movq	%rdx, 56(%rsp)
	cmpq	$3, %rax
	je	.LBB155_212
# %bb.169:                              # %bb3.i.i
	movq	%rbx, 304(%rsp)
	leaq	312(%rsp), %r15
	movq	%r12, 312(%rsp)
	leaq	880(%rsp), %rdi
	leaq	1072(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
	cmpq	$1, %rbx
	je	.LBB155_176
# %bb.170:                              # %bb3.i.i
	cmpq	$2, %rbx
	jne	.LBB155_198
# %bb.171:                              # %bb6.i.i.i
	leaq	48(%rsp), %rdi
	leaq	880(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
.Ltmp753:
	callq	*_ZN5tokio4task5state5State12new_joinable17h91dbe9abe6cd8ac7E@GOTPCREL(%rip)
.Ltmp754:
# %bb.172:                              # %bb1.i.i.i.i.i.i.i
	movq	%rax, %r14
	leaq	560(%rsp), %rdi
	leaq	48(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
	movl	$256, %edi              # imm = 0x100
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB155_214
# %bb.173:                              # %_ZN5tokio4task8joinable17h86929a75c62ac110E.exit.i.i.i.i.i
	movq	%rax, %rbx
	movq	%r12, %rbp
	addq	$16, %rbp
	movq	%r14, (%rax)
	xorps	%xmm0, %xmm0
	movups	%xmm0, 8(%rax)
	movups	%xmm0, 24(%rax)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.19, 40(%rax)
	movq	$0, 48(%rax)
	movq	%rax, %rdi
	addq	$56, %rdi
	leaq	560(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
	movq	$0, 248(%rbx)
	movq	%rbx, 48(%rsp)
.Ltmp758:
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	*_ZN5tokio7runtime11thread_pool5slice3Set8schedule17h768f3bc515047910E@GOTPCREL(%rip)
.Ltmp759:
# %bb.174:                              # %bb3.i19.i.i
	lock		subq	$1, (%r12)
	jne	.LBB155_181
# %bb.175:                              # %bb3.i.i.i4.i.i.i
	#MEMBARRIER
.Ltmp763:
	movq	%r15, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hbcd17717d774df8bE
.Ltmp764:
	jmp	.LBB155_181
.LBB155_176:                            # %bb4.i.i240.i
	leaq	48(%rsp), %rdi
	leaq	880(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
.Ltmp765:
	callq	*_ZN5tokio4task5state5State12new_joinable17h91dbe9abe6cd8ac7E@GOTPCREL(%rip)
.Ltmp766:
# %bb.177:                              # %bb1.i.i.i.i.i.i
	movq	%rax, %rbp
	leaq	560(%rsp), %rdi
	leaq	48(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
	movl	$256, %edi              # imm = 0x100
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB155_214
# %bb.178:                              # %bb5.i.i.i243.i
	movq	%rax, %rbx
	movq	%rbp, (%rax)
	xorps	%xmm0, %xmm0
	movups	%xmm0, 8(%rax)
	movups	%xmm0, 24(%rax)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.18, 40(%rax)
	movq	$0, 48(%rax)
	movq	%rax, %rdi
	addq	$56, %rdi
	leaq	560(%rsp), %rsi
	movl	$184, %edx
	callq	*memcpy@GOTPCREL(%rip)
	movq	$0, 248(%rbx)
	movq	%rbx, 48(%rsp)
	movq	%r12, %rdi
	addq	$16, %rdi
.Ltmp770:
	movq	%rbx, %rsi
	movl	$1, %edx
	callq	*_ZN5tokio7runtime15basic_scheduler13SchedulerPriv8schedule17h66990a9d3e6b6ed6E@GOTPCREL(%rip)
.Ltmp771:
# %bb.179:                              # %bb2.i18.i.i
	lock		subq	$1, (%r12)
	jne	.LBB155_181
# %bb.180:                              # %bb3.i.i.i.i.i246.i
	#MEMBARRIER
.Ltmp775:
	movq	%r15, %rdi
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17h9b2e2fe3654c86e4E
.Ltmp776:
.LBB155_181:                            # %bb66.i
	testq	%rbx, %rbx
	je	.LBB155_186
# %bb.182:                              # %bb2.i.i251.i
	movq	%rbx, 48(%rsp)
.Ltmp778:
	leaq	48(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
.Ltmp779:
# %bb.183:                              # %.noexc253.i
.Ltmp780:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
.Ltmp781:
# %bb.184:                              # %.noexc254.i
	testb	%al, %al
	jne	.LBB155_186
# %bb.185:                              # %bb5.i.i.i
	movq	48(%rsp), %rdi
.Ltmp782:
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.Ltmp783:
.LBB155_186:                            # %bb68.i
	leaq	848(%rsp), %rbx
	jmp	.LBB155_136
.LBB155_187:                            # %bb48.i
	movq	$0, 48(%rsp)
	movl	$4, (%r13)
	jmp	.LBB155_134
.LBB155_188:                            # %bb53.i
	movups	(%rax), %xmm0
	movaps	%xmm0, 48(%rsp)
	movl	$16, %edi
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB155_135
# %bb.189:                              # %bb80.i
	movq	%rax, %rbx
	movaps	48(%rsp), %xmm0
	movups	%xmm0, (%rax)
	leaq	8(%r13), %rdi
.Ltmp802:
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp803:
.LBB155_190:                            # %bb8
	movq	%rbx, 56(%rsp)
	movq	$.Lvtable.1, 64(%rsp)
	movq	$1, 48(%rsp)
	movl	$1, (%r13)
	movq	56(%rsp), %rax
	movq	40(%rsp), %rcx          # 8-byte Reload
	movq	%rax, 8(%rcx)
	movq	64(%rsp), %rax
	movq	%rax, 16(%rcx)
	movb	$1, %bpl
	xorl	%eax, %eax
	xorl	%ebx, %ebx
.LBB155_191:                            # %bb10
	movq	%rax, (%rcx)
.Ltmp825:
	leaq	240(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp826:
# %bb.192:                              # %bb11
	testb	%bl, %bpl
	je	.LBB155_197
# %bb.193:                              # %bb17
	movq	56(%rsp), %rbx
	testq	%rbx, %rbx
	je	.LBB155_197
# %bb.194:                              # %bb2.i15
	movq	64(%rsp), %rbp
.Ltmp828:
	movq	%rbx, %rdi
	callq	*(%rbp)
.Ltmp829:
# %bb.195:                              # %bb3.i.i16
	movq	8(%rbp), %rsi
	testq	%rsi, %rsi
	je	.LBB155_197
# %bb.196:                              # %bb4.i.i.i17
	movq	16(%rbp), %rdx
	movq	%rbx, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB155_197:                            # %bb15
	addq	$1304, %rsp             # imm = 0x518
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB155_198:                            # %bb3.i.i239.i
	.cfi_def_cfa_offset 1360
.Ltmp785:
	movq	%r13, %rbx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.55, %edi
	movl	$32, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.54, %edx
	callq	_ZN3std9panicking11begin_panic17hebd941bf54afcd90E
.Ltmp786:
# %bb.199:                              # %unreachable.i9.i.i
.LBB155_200:                            # %bb5.i.i.i164.i
.Ltmp820:
	leaq	8(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp821:
# %bb.201:                              # %.noexc212.i
.LBB155_202:                            # %bb5.i.i.i.i.i.i173.i
.Ltmp810:
	leaq	8(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp811:
# %bb.203:                              # %.noexc24.i.i.i.i
.LBB155_204:                            # %bb2.i.i165.i
.Ltmp815:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.1, %edi
	movl	$100, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp816:
# %bb.205:                              # %.noexc.i166.i
.LBB155_206:                            # %bb2.i.i22.i.i.i.i
.Ltmp805:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.1, %edi
	movl	$100, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp806:
# %bb.207:                              # %.noexc.i.i.i.i174.i
.LBB155_208:                            # %panic1.i.i.i.i
.Ltmp728:
	movl	$str.d, %edi
	movl	$35, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.17, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp729:
# %bb.209:                              # %.noexc11.i.i.i
.LBB155_210:                            # %panic.i.i.i180.i
.Ltmp726:
	movl	$str.c, %edi
	movl	$34, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.17, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp727:
# %bb.211:                              # %.noexc.i.i181.i
.LBB155_212:                            # %bb2.i.i237.i
.Ltmp793:
	movq	%r13, %rbx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.33, %edi
	movl	$113, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp794:
# %bb.213:                              # %unreachable.i.i.i
.LBB155_214:                            # %bb6.i.i.i.i.i.i.i.i.i.i
	movl	$256, %edi              # imm = 0x100
	movl	$8, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.LBB155_215:                            # %cleanup.i.i238.i
.Ltmp795:
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp796:
	leaq	48(%rsp), %rdi
	movq	%rbx, %r13
	callq	_ZN4core3ptr18real_drop_in_place17h897c32c5c49535c6E
.Ltmp797:
	jmp	.LBB155_235
.LBB155_216:                            # %bb9.i.i.i
.Ltmp787:
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp788:
	leaq	880(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
.Ltmp789:
	jmp	.LBB155_232
.LBB155_217:                            # %cleanup.i.i203.i
.Ltmp730:
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_248
.LBB155_218:                            # %cleanup12.i
.Ltmp804:
.LBB155_219:                            # %bb3.i
	movq	%rax, %r14
	jmp	.LBB155_254
.LBB155_220:                            # %cleanup.i.i18
.Ltmp830:
	movq	%rax, %r14
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB155_221:                            # %cleanup1
.Ltmp827:
	movq	%rax, %r14
	testb	%bpl, %bpl
	je	.LBB155_224
# %bb.222:                              # %bb12
	testb	%bl, %bl
	je	.LBB155_225
# %bb.223:                              # %bb13
	leaq	56(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h66e229bae9518afeE
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB155_224:                            # %bb14
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h455108c36d4b96e1E
.LBB155_225:                            # %unwind_resume
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB155_226:                            # %cleanup.i.i.i.i.i.i.i201.i
.Ltmp746:
	movq	%rax, %r14
                                        # kill: killed $rdx
	movq	(%rbp), %rdi
	movq	8(%rbp), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	576(%rsp), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB155_250
.LBB155_227:                            # %bb8.i.i
.Ltmp777:
	movq	%r13, %rbx
.LBB155_238:                            # %bb63.i
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_236
.LBB155_228:                            # %bb1.i.i.i242.i
.Ltmp772:
	movq	%r13, %rbx
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp773:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E
.Ltmp774:
	jmp	.LBB155_232
.LBB155_229:                            # %bb2.i.i.i.i.i241.i
.Ltmp767:
	movq	%r13, %rbx
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp768:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
.Ltmp769:
	jmp	.LBB155_232
.LBB155_230:                            # %cleanup.i.i.i.i245.i
.Ltmp760:
	movq	%r13, %rbx
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp761:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hae2d1d855d95da95E
.Ltmp762:
	jmp	.LBB155_232
.LBB155_231:                            # %bb2.i.i.i.i.i.i244.i
.Ltmp755:
	movq	%r13, %rbx
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp756:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
.Ltmp757:
.LBB155_232:                            # %bb8.thread.i.i
.Ltmp791:
	leaq	304(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h691669770397616fE
.Ltmp792:
	jmp	.LBB155_236
.LBB155_233:                            # %cleanup1.i.i
.Ltmp790:
	movq	%rax, %r14
                                        # kill: killed $rdx
	jmp	.LBB155_232
.LBB155_234:                            # %bb8.thread36.i.i
.Ltmp798:
	movq	%r13, %rbx
	movq	%rax, %r14
                                        # kill: killed $rdx
.LBB155_235:                            # %bb7.i.i
.Ltmp799:
	leaq	1072(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h8d31eaf3f74d642fE
.Ltmp800:
.LBB155_236:                            # %bb63.i
	movq	%rbx, %r13
	jmp	.LBB155_253
.LBB155_237:                            # %cleanup25.i
.Ltmp801:
	jmp	.LBB155_238
.LBB155_239:                            # %cleanup1.i.i206.i
.Ltmp739:
	movq	%rax, %r14
                                        # kill: killed $rdx
	cmpl	$2, 560(%rsp)
	jne	.LBB155_241
# %bb.240:                              # %bb14.i.i194.i
.Ltmp742:
	leaq	560(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h98054c6ad867e3d0E
.Ltmp743:
	jmp	.LBB155_250
.LBB155_241:                            # %bb12.i.i192.i
	testb	%bpl, %bpl
	je	.LBB155_250
# %bb.242:                              # %bb13.i.i193.i
.Ltmp740:
	leaq	560(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1adadefef472b07aE
.Ltmp741:
	jmp	.LBB155_250
.LBB155_243:                            # %cleanup.i.i.i.i178.i
.Ltmp807:
	movq	%rax, %r14
                                        # kill: killed $rdx
.Ltmp808:
	leaq	560(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp809:
	jmp	.LBB155_247
.LBB155_244:                            # %cleanup14.i
.Ltmp721:
	jmp	.LBB155_252
.LBB155_245:                            # %cleanup26.i
.Ltmp784:
	jmp	.LBB155_252
.LBB155_246:                            # %cleanup3.i.i.i.i
.Ltmp812:
	movq	%rax, %r14
                                        # kill: killed $rdx
.LBB155_247:                            # %bb3.i.i.i170.i
	movl	$2, 88(%r13)
.LBB155_248:                            # %cleanup.body.i.i205.i
.Ltmp813:
	leaq	32(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp814:
	jmp	.LBB155_250
.LBB155_249:                            # %cleanup.i208.i
.Ltmp817:
	movq	%rax, %r14
                                        # kill: killed $rdx
.LBB155_250:                            # %cleanup.body.i210.i
.Ltmp818:
	leaq	248(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp819:
	jmp	.LBB155_253
.LBB155_251:                            # %cleanup16.i
.Ltmp822:
.LBB155_252:                            # %bb30.i
	movq	%rax, %r14
                                        # kill: killed $rdx
.LBB155_253:                            # %bb30.i
	leaq	8(%r13), %rdi
.Ltmp823:
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp824:
.LBB155_254:                            # %bb3.i
	movl	$2, (%r13)
.LBB155_255:                            # %cleanup.body
	leaq	240(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
	movq	%r14, %rdi
	callq	_Unwind_Resume
.LBB155_256:                            # %cleanup
.Ltmp854:
	movq	%rax, %r14
	jmp	.LBB155_255
.Lfunc_end155:
	.size	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E, .Lfunc_end155-_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E
	.cfi_endproc
	.section	.rodata,"a",@progbits
	.p2align	3
.LJTI155_0:
	.quad	.LBB155_1
	.quad	.LBB155_87
	.quad	.LBB155_89
	.quad	.LBB155_2
	.quad	.LBB155_138
.LJTI155_1:
	.quad	.LBB155_7
	.quad	.LBB155_95
	.quad	.LBB155_97
	.quad	.LBB155_9
.LJTI155_2:
	.quad	.LBB155_143
	.quad	.LBB155_208
	.quad	.LBB155_210
	.quad	.LBB155_144
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table155:
.Lexception62:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end62-.Lcst_begin62
.Lcst_begin62:
	.uleb128 .Lfunc_begin62-.Lfunc_begin62 # >> Call Site 1 <<
	.uleb128 .Ltmp647-.Lfunc_begin62 #   Call between .Lfunc_begin62 and .Ltmp647
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp647-.Lfunc_begin62 # >> Call Site 2 <<
	.uleb128 .Ltmp648-.Ltmp647      #   Call between .Ltmp647 and .Ltmp648
	.uleb128 .Ltmp851-.Lfunc_begin62 #     jumps to .Ltmp851
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp649-.Lfunc_begin62 # >> Call Site 3 <<
	.uleb128 .Ltmp650-.Ltmp649      #   Call between .Ltmp649 and .Ltmp650
	.uleb128 .Ltmp846-.Lfunc_begin62 #     jumps to .Ltmp846
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp655-.Lfunc_begin62 # >> Call Site 4 <<
	.uleb128 .Ltmp656-.Ltmp655      #   Call between .Ltmp655 and .Ltmp656
	.uleb128 .Ltmp657-.Lfunc_begin62 #     jumps to .Ltmp657
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp658-.Lfunc_begin62 # >> Call Site 5 <<
	.uleb128 .Ltmp659-.Ltmp658      #   Call between .Ltmp658 and .Ltmp659
	.uleb128 .Ltmp838-.Lfunc_begin62 #     jumps to .Ltmp838
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp660-.Lfunc_begin62 # >> Call Site 6 <<
	.uleb128 .Ltmp661-.Ltmp660      #   Call between .Ltmp660 and .Ltmp661
	.uleb128 .Ltmp833-.Lfunc_begin62 #     jumps to .Ltmp833
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp662-.Lfunc_begin62 # >> Call Site 7 <<
	.uleb128 .Ltmp663-.Ltmp662      #   Call between .Ltmp662 and .Ltmp663
	.uleb128 .Ltmp838-.Lfunc_begin62 #     jumps to .Ltmp838
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp664-.Lfunc_begin62 # >> Call Site 8 <<
	.uleb128 .Ltmp669-.Ltmp664      #   Call between .Ltmp664 and .Ltmp669
	.uleb128 .Ltmp670-.Lfunc_begin62 #     jumps to .Ltmp670
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp671-.Lfunc_begin62 # >> Call Site 9 <<
	.uleb128 .Ltmp672-.Ltmp671      #   Call between .Ltmp671 and .Ltmp672
	.uleb128 .Ltmp673-.Lfunc_begin62 #     jumps to .Ltmp673
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp674-.Lfunc_begin62 # >> Call Site 10 <<
	.uleb128 .Ltmp675-.Ltmp674      #   Call between .Ltmp674 and .Ltmp675
	.uleb128 .Ltmp676-.Lfunc_begin62 #     jumps to .Ltmp676
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp680-.Lfunc_begin62 # >> Call Site 11 <<
	.uleb128 .Ltmp681-.Ltmp680      #   Call between .Ltmp680 and .Ltmp681
	.uleb128 .Ltmp682-.Lfunc_begin62 #     jumps to .Ltmp682
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp681-.Lfunc_begin62 # >> Call Site 12 <<
	.uleb128 .Ltmp685-.Ltmp681      #   Call between .Ltmp681 and .Ltmp685
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp685-.Lfunc_begin62 # >> Call Site 13 <<
	.uleb128 .Ltmp686-.Ltmp685      #   Call between .Ltmp685 and .Ltmp686
	.uleb128 .Ltmp687-.Lfunc_begin62 #     jumps to .Ltmp687
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp690-.Lfunc_begin62 # >> Call Site 14 <<
	.uleb128 .Ltmp693-.Ltmp690      #   Call between .Ltmp690 and .Ltmp693
	.uleb128 .Ltmp694-.Lfunc_begin62 #     jumps to .Ltmp694
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp677-.Lfunc_begin62 # >> Call Site 15 <<
	.uleb128 .Ltmp678-.Ltmp677      #   Call between .Ltmp677 and .Ltmp678
	.uleb128 .Ltmp679-.Lfunc_begin62 #     jumps to .Ltmp679
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp698-.Lfunc_begin62 # >> Call Site 16 <<
	.uleb128 .Ltmp699-.Ltmp698      #   Call between .Ltmp698 and .Ltmp699
	.uleb128 .Ltmp700-.Lfunc_begin62 #     jumps to .Ltmp700
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp705-.Lfunc_begin62 # >> Call Site 17 <<
	.uleb128 .Ltmp706-.Ltmp705      #   Call between .Ltmp705 and .Ltmp706
	.uleb128 .Ltmp707-.Lfunc_begin62 #     jumps to .Ltmp707
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp708-.Lfunc_begin62 # >> Call Site 18 <<
	.uleb128 .Ltmp709-.Ltmp708      #   Call between .Ltmp708 and .Ltmp709
	.uleb128 .Ltmp846-.Lfunc_begin62 #     jumps to .Ltmp846
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp710-.Lfunc_begin62 # >> Call Site 19 <<
	.uleb128 .Ltmp711-.Ltmp710      #   Call between .Ltmp710 and .Ltmp711
	.uleb128 .Ltmp851-.Lfunc_begin62 #     jumps to .Ltmp851
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp712-.Lfunc_begin62 # >> Call Site 20 <<
	.uleb128 .Ltmp717-.Ltmp712      #   Call between .Ltmp712 and .Ltmp717
	.uleb128 .Ltmp718-.Lfunc_begin62 #     jumps to .Ltmp718
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp645-.Lfunc_begin62 # >> Call Site 21 <<
	.uleb128 .Ltmp644-.Ltmp645      #   Call between .Ltmp645 and .Ltmp644
	.uleb128 .Ltmp854-.Lfunc_begin62 #     jumps to .Ltmp854
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp849-.Lfunc_begin62 # >> Call Site 22 <<
	.uleb128 .Ltmp850-.Ltmp849      #   Call between .Ltmp849 and .Ltmp850
	.uleb128 .Ltmp851-.Lfunc_begin62 #     jumps to .Ltmp851
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp844-.Lfunc_begin62 # >> Call Site 23 <<
	.uleb128 .Ltmp845-.Ltmp844      #   Call between .Ltmp844 and .Ltmp845
	.uleb128 .Ltmp846-.Lfunc_begin62 #     jumps to .Ltmp846
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp653-.Lfunc_begin62 # >> Call Site 24 <<
	.uleb128 .Ltmp652-.Ltmp653      #   Call between .Ltmp653 and .Ltmp652
	.uleb128 .Ltmp841-.Lfunc_begin62 #     jumps to .Ltmp841
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp836-.Lfunc_begin62 # >> Call Site 25 <<
	.uleb128 .Ltmp837-.Ltmp836      #   Call between .Ltmp836 and .Ltmp837
	.uleb128 .Ltmp838-.Lfunc_begin62 #     jumps to .Ltmp838
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp831-.Lfunc_begin62 # >> Call Site 26 <<
	.uleb128 .Ltmp832-.Ltmp831      #   Call between .Ltmp831 and .Ltmp832
	.uleb128 .Ltmp833-.Lfunc_begin62 #     jumps to .Ltmp833
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp695-.Lfunc_begin62 # >> Call Site 27 <<
	.uleb128 .Ltmp696-.Ltmp695      #   Call between .Ltmp695 and .Ltmp696
	.uleb128 .Ltmp697-.Lfunc_begin62 #     jumps to .Ltmp697
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp683-.Lfunc_begin62 # >> Call Site 28 <<
	.uleb128 .Ltmp684-.Ltmp683      #   Call between .Ltmp683 and .Ltmp684
	.uleb128 .Ltmp841-.Lfunc_begin62 #     jumps to .Ltmp841
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp703-.Lfunc_begin62 # >> Call Site 29 <<
	.uleb128 .Ltmp702-.Ltmp703      #   Call between .Ltmp703 and .Ltmp702
	.uleb128 .Ltmp846-.Lfunc_begin62 #     jumps to .Ltmp846
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp834-.Lfunc_begin62 # >> Call Site 30 <<
	.uleb128 .Ltmp835-.Ltmp834      #   Call between .Ltmp834 and .Ltmp835
	.uleb128 .Ltmp838-.Lfunc_begin62 #     jumps to .Ltmp838
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp839-.Lfunc_begin62 # >> Call Site 31 <<
	.uleb128 .Ltmp689-.Ltmp839      #   Call between .Ltmp839 and .Ltmp689
	.uleb128 .Ltmp841-.Lfunc_begin62 #     jumps to .Ltmp841
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp842-.Lfunc_begin62 # >> Call Site 32 <<
	.uleb128 .Ltmp843-.Ltmp842      #   Call between .Ltmp842 and .Ltmp843
	.uleb128 .Ltmp846-.Lfunc_begin62 #     jumps to .Ltmp846
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp847-.Lfunc_begin62 # >> Call Site 33 <<
	.uleb128 .Ltmp848-.Ltmp847      #   Call between .Ltmp847 and .Ltmp848
	.uleb128 .Ltmp851-.Lfunc_begin62 #     jumps to .Ltmp851
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp852-.Lfunc_begin62 # >> Call Site 34 <<
	.uleb128 .Ltmp853-.Ltmp852      #   Call between .Ltmp852 and .Ltmp853
	.uleb128 .Ltmp854-.Lfunc_begin62 #     jumps to .Ltmp854
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp719-.Lfunc_begin62 # >> Call Site 35 <<
	.uleb128 .Ltmp720-.Ltmp719      #   Call between .Ltmp719 and .Ltmp720
	.uleb128 .Ltmp721-.Lfunc_begin62 #     jumps to .Ltmp721
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp722-.Lfunc_begin62 # >> Call Site 36 <<
	.uleb128 .Ltmp723-.Ltmp722      #   Call between .Ltmp722 and .Ltmp723
	.uleb128 .Ltmp822-.Lfunc_begin62 #     jumps to .Ltmp822
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp724-.Lfunc_begin62 # >> Call Site 37 <<
	.uleb128 .Ltmp725-.Ltmp724      #   Call between .Ltmp724 and .Ltmp725
	.uleb128 .Ltmp817-.Lfunc_begin62 #     jumps to .Ltmp817
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp731-.Lfunc_begin62 # >> Call Site 38 <<
	.uleb128 .Ltmp732-.Ltmp731      #   Call between .Ltmp731 and .Ltmp732
	.uleb128 .Ltmp812-.Lfunc_begin62 #     jumps to .Ltmp812
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp733-.Lfunc_begin62 # >> Call Site 39 <<
	.uleb128 .Ltmp734-.Ltmp733      #   Call between .Ltmp733 and .Ltmp734
	.uleb128 .Ltmp807-.Lfunc_begin62 #     jumps to .Ltmp807
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp735-.Lfunc_begin62 # >> Call Site 40 <<
	.uleb128 .Ltmp736-.Ltmp735      #   Call between .Ltmp735 and .Ltmp736
	.uleb128 .Ltmp812-.Lfunc_begin62 #     jumps to .Ltmp812
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp737-.Lfunc_begin62 # >> Call Site 41 <<
	.uleb128 .Ltmp738-.Ltmp737      #   Call between .Ltmp737 and .Ltmp738
	.uleb128 .Ltmp739-.Lfunc_begin62 #     jumps to .Ltmp739
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp744-.Lfunc_begin62 # >> Call Site 42 <<
	.uleb128 .Ltmp745-.Ltmp744      #   Call between .Ltmp744 and .Ltmp745
	.uleb128 .Ltmp746-.Lfunc_begin62 #     jumps to .Ltmp746
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp747-.Lfunc_begin62 # >> Call Site 43 <<
	.uleb128 .Ltmp748-.Ltmp747      #   Call between .Ltmp747 and .Ltmp748
	.uleb128 .Ltmp817-.Lfunc_begin62 #     jumps to .Ltmp817
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp749-.Lfunc_begin62 # >> Call Site 44 <<
	.uleb128 .Ltmp750-.Ltmp749      #   Call between .Ltmp749 and .Ltmp750
	.uleb128 .Ltmp822-.Lfunc_begin62 #     jumps to .Ltmp822
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp751-.Lfunc_begin62 # >> Call Site 45 <<
	.uleb128 .Ltmp752-.Ltmp751      #   Call between .Ltmp751 and .Ltmp752
	.uleb128 .Ltmp798-.Lfunc_begin62 #     jumps to .Ltmp798
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp752-.Lfunc_begin62 # >> Call Site 46 <<
	.uleb128 .Ltmp753-.Ltmp752      #   Call between .Ltmp752 and .Ltmp753
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp753-.Lfunc_begin62 # >> Call Site 47 <<
	.uleb128 .Ltmp754-.Ltmp753      #   Call between .Ltmp753 and .Ltmp754
	.uleb128 .Ltmp755-.Lfunc_begin62 #     jumps to .Ltmp755
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp754-.Lfunc_begin62 # >> Call Site 48 <<
	.uleb128 .Ltmp758-.Ltmp754      #   Call between .Ltmp754 and .Ltmp758
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp758-.Lfunc_begin62 # >> Call Site 49 <<
	.uleb128 .Ltmp759-.Ltmp758      #   Call between .Ltmp758 and .Ltmp759
	.uleb128 .Ltmp760-.Lfunc_begin62 #     jumps to .Ltmp760
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp763-.Lfunc_begin62 # >> Call Site 50 <<
	.uleb128 .Ltmp764-.Ltmp763      #   Call between .Ltmp763 and .Ltmp764
	.uleb128 .Ltmp777-.Lfunc_begin62 #     jumps to .Ltmp777
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp764-.Lfunc_begin62 # >> Call Site 51 <<
	.uleb128 .Ltmp765-.Ltmp764      #   Call between .Ltmp764 and .Ltmp765
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp765-.Lfunc_begin62 # >> Call Site 52 <<
	.uleb128 .Ltmp766-.Ltmp765      #   Call between .Ltmp765 and .Ltmp766
	.uleb128 .Ltmp767-.Lfunc_begin62 #     jumps to .Ltmp767
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp766-.Lfunc_begin62 # >> Call Site 53 <<
	.uleb128 .Ltmp770-.Ltmp766      #   Call between .Ltmp766 and .Ltmp770
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp770-.Lfunc_begin62 # >> Call Site 54 <<
	.uleb128 .Ltmp771-.Ltmp770      #   Call between .Ltmp770 and .Ltmp771
	.uleb128 .Ltmp772-.Lfunc_begin62 #     jumps to .Ltmp772
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp775-.Lfunc_begin62 # >> Call Site 55 <<
	.uleb128 .Ltmp776-.Ltmp775      #   Call between .Ltmp775 and .Ltmp776
	.uleb128 .Ltmp777-.Lfunc_begin62 #     jumps to .Ltmp777
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp778-.Lfunc_begin62 # >> Call Site 56 <<
	.uleb128 .Ltmp783-.Ltmp778      #   Call between .Ltmp778 and .Ltmp783
	.uleb128 .Ltmp784-.Lfunc_begin62 #     jumps to .Ltmp784
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp802-.Lfunc_begin62 # >> Call Site 57 <<
	.uleb128 .Ltmp803-.Ltmp802      #   Call between .Ltmp802 and .Ltmp803
	.uleb128 .Ltmp804-.Lfunc_begin62 #     jumps to .Ltmp804
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp825-.Lfunc_begin62 # >> Call Site 58 <<
	.uleb128 .Ltmp826-.Ltmp825      #   Call between .Ltmp825 and .Ltmp826
	.uleb128 .Ltmp827-.Lfunc_begin62 #     jumps to .Ltmp827
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp828-.Lfunc_begin62 # >> Call Site 59 <<
	.uleb128 .Ltmp829-.Ltmp828      #   Call between .Ltmp828 and .Ltmp829
	.uleb128 .Ltmp830-.Lfunc_begin62 #     jumps to .Ltmp830
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp785-.Lfunc_begin62 # >> Call Site 60 <<
	.uleb128 .Ltmp786-.Ltmp785      #   Call between .Ltmp785 and .Ltmp786
	.uleb128 .Ltmp787-.Lfunc_begin62 #     jumps to .Ltmp787
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp820-.Lfunc_begin62 # >> Call Site 61 <<
	.uleb128 .Ltmp821-.Ltmp820      #   Call between .Ltmp820 and .Ltmp821
	.uleb128 .Ltmp822-.Lfunc_begin62 #     jumps to .Ltmp822
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp810-.Lfunc_begin62 # >> Call Site 62 <<
	.uleb128 .Ltmp811-.Ltmp810      #   Call between .Ltmp810 and .Ltmp811
	.uleb128 .Ltmp812-.Lfunc_begin62 #     jumps to .Ltmp812
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp815-.Lfunc_begin62 # >> Call Site 63 <<
	.uleb128 .Ltmp816-.Ltmp815      #   Call between .Ltmp815 and .Ltmp816
	.uleb128 .Ltmp817-.Lfunc_begin62 #     jumps to .Ltmp817
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp805-.Lfunc_begin62 # >> Call Site 64 <<
	.uleb128 .Ltmp806-.Ltmp805      #   Call between .Ltmp805 and .Ltmp806
	.uleb128 .Ltmp807-.Lfunc_begin62 #     jumps to .Ltmp807
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp728-.Lfunc_begin62 # >> Call Site 65 <<
	.uleb128 .Ltmp727-.Ltmp728      #   Call between .Ltmp728 and .Ltmp727
	.uleb128 .Ltmp730-.Lfunc_begin62 #     jumps to .Ltmp730
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp793-.Lfunc_begin62 # >> Call Site 66 <<
	.uleb128 .Ltmp794-.Ltmp793      #   Call between .Ltmp793 and .Ltmp794
	.uleb128 .Ltmp795-.Lfunc_begin62 #     jumps to .Ltmp795
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp796-.Lfunc_begin62 # >> Call Site 67 <<
	.uleb128 .Ltmp797-.Ltmp796      #   Call between .Ltmp796 and .Ltmp797
	.uleb128 .Ltmp798-.Lfunc_begin62 #     jumps to .Ltmp798
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp788-.Lfunc_begin62 # >> Call Site 68 <<
	.uleb128 .Ltmp789-.Ltmp788      #   Call between .Ltmp788 and .Ltmp789
	.uleb128 .Ltmp790-.Lfunc_begin62 #     jumps to .Ltmp790
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp789-.Lfunc_begin62 # >> Call Site 69 <<
	.uleb128 .Ltmp773-.Ltmp789      #   Call between .Ltmp789 and .Ltmp773
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp773-.Lfunc_begin62 # >> Call Site 70 <<
	.uleb128 .Ltmp757-.Ltmp773      #   Call between .Ltmp773 and .Ltmp757
	.uleb128 .Ltmp790-.Lfunc_begin62 #     jumps to .Ltmp790
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp791-.Lfunc_begin62 # >> Call Site 71 <<
	.uleb128 .Ltmp800-.Ltmp791      #   Call between .Ltmp791 and .Ltmp800
	.uleb128 .Ltmp801-.Lfunc_begin62 #     jumps to .Ltmp801
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp742-.Lfunc_begin62 # >> Call Site 72 <<
	.uleb128 .Ltmp741-.Ltmp742      #   Call between .Ltmp742 and .Ltmp741
	.uleb128 .Ltmp817-.Lfunc_begin62 #     jumps to .Ltmp817
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp808-.Lfunc_begin62 # >> Call Site 73 <<
	.uleb128 .Ltmp809-.Ltmp808      #   Call between .Ltmp808 and .Ltmp809
	.uleb128 .Ltmp812-.Lfunc_begin62 #     jumps to .Ltmp812
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp813-.Lfunc_begin62 # >> Call Site 74 <<
	.uleb128 .Ltmp814-.Ltmp813      #   Call between .Ltmp813 and .Ltmp814
	.uleb128 .Ltmp817-.Lfunc_begin62 #     jumps to .Ltmp817
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp818-.Lfunc_begin62 # >> Call Site 75 <<
	.uleb128 .Ltmp819-.Ltmp818      #   Call between .Ltmp818 and .Ltmp819
	.uleb128 .Ltmp822-.Lfunc_begin62 #     jumps to .Ltmp822
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp823-.Lfunc_begin62 # >> Call Site 76 <<
	.uleb128 .Ltmp824-.Ltmp823      #   Call between .Ltmp823 and .Ltmp824
	.uleb128 .Ltmp854-.Lfunc_begin62 #     jumps to .Ltmp854
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp824-.Lfunc_begin62 # >> Call Site 77 <<
	.uleb128 .Lfunc_end155-.Ltmp824 #   Call between .Ltmp824 and .Lfunc_end155
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end62:
	.p2align	2
                                        # -- End function
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4               # -- Begin function _ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E
.LCPI156_0:
	.quad	8192                    # 0x2000
	.quad	8192                    # 0x2000
	.text
	.p2align	4, 0x90
	.type	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E,@function
_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E: # @"_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E"
.Lfunc_begin63:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception63
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$200, %rsp
	.cfi_def_cfa_offset 256
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdi, %r14
	movq	%rsi, %rdi
	callq	*_ZN3std6future16set_task_context17hd1bc3d998532dcddE@GOTPCREL(%rip)
	movq	%rax, 192(%rsp)
	movl	128(%r14), %eax
	jmpq	*.LJTI156_0(,%rax,8)
.LBB156_1:                              # %bb1.i
.Ltmp859:
	movq	%r14, %rdi
	callq	*_ZN5tokio3net3tcp6stream9TcpStream5split17h6a3b015777130982E@GOTPCREL(%rip)
.Ltmp860:
# %bb.2:                                # %bb2.i
	movq	%rdx, 56(%r14)
	movq	%rax, 112(%rsp)
	movl	$8192, %edi             # imm = 0x2000
	movl	$1, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB156_21
# %bb.3:                                # %bb4.i.i.i
	movq	%rax, 80(%rsp)
	movdqa	.LCPI156_0(%rip), %xmm0 # xmm0 = [8192,8192]
	movdqu	%xmm0, 88(%rsp)
.Ltmp862:
	leaq	112(%rsp), %rdi
	movl	$8192, %edx             # imm = 0x2000
	movq	%rax, %rsi
	callq	*_ZN85_$LT$tokio..net..tcp..split..ReadHalf$u20$as$u20$tokio..io..async_read..AsyncRead$GT$28prepare_uninitialized_buffer17hdd88513c72b23a70E@GOTPCREL(%rip)
.Ltmp863:
# %bb.4:                                # %bb5.i.i.i
	movq	112(%rsp), %rbp
	movdqu	80(%rsp), %xmm0
	movdqa	%xmm0, 16(%rsp)
	movq	96(%rsp), %rbx
	movq	%rbx, 32(%rsp)
	movq	24(%rsp), %rsi
	cmpq	%rbx, %rsi
	jne	.LBB156_9
# %bb.5:                                # %start.bb5_crit_edge.i.i.i.i
	movq	16(%rsp), %rcx
	jmp	.LBB156_16
.LBB156_6:                              # %bb104.i
                                        # implicit-def: $al
                                        # kill: killed $al
                                        # implicit-def: $r12
	jmp	.LBB156_33
.LBB156_7:                              # %bb103.i
                                        # implicit-def: $al
                                        # kill: killed $al
                                        # implicit-def: $r12
	jmp	.LBB156_29
.LBB156_8:                              # %bb105.i
                                        # implicit-def: $al
                                        # kill: killed $al
                                        # implicit-def: $r12
	jmp	.LBB156_176
.LBB156_9:                              # %bb2.i.i.i.i.i
	jb	.LBB156_22
# %bb.10:                               # %bb6.i.i.i.i.i.i
	testq	%rbx, %rbx
	je	.LBB156_13
# %bb.11:                               # %bb15.i.i.i.i.i.i
	movq	16(%rsp), %rdi
	movl	$1, %edx
	movq	%rbx, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB156_184
# %bb.12:                               # %bb23.i.i.i.i.i.i
	movq	%rax, %rcx
	movq	%rax, 16(%rsp)
	movq	%rbx, 24(%rsp)
	movq	%rbx, %rsi
	jmp	.LBB156_16
.LBB156_13:                             # %bb10.i.i.i.i.i.i
	testq	%rsi, %rsi
	je	.LBB156_15
# %bb.14:                               # %bb4.i.i.i.i.i.i.i
	movq	16(%rsp), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB156_15:                             # %"_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$14dealloc_buffer17h25287affd2d84adaE.exit.i.i.i.i.i.i"
	movq	$1, 16(%rsp)
	movq	$0, 24(%rsp)
	movl	$1, %ecx
	xorl	%esi, %esi
.LBB156_16:                             # %"_ZN5tokio2io4util10buf_reader18BufReader$LT$R$GT$3new17hddb40933f9d7ef87E.exit.i"
	movq	%rbp, 64(%r14)
	movq	%rcx, 72(%r14)
	movq	%rsi, 80(%r14)
	pxor	%xmm0, %xmm0
	movdqu	%xmm0, 88(%r14)
                                        # implicit-def: $al
                                        # kill: killed $al
                                        # implicit-def: $r12
	jmp	.LBB156_28
.LBB156_17:                             # %panic3.i
.Ltmp857:
	movl	$str.d, %edi
	movl	$35, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.63, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp858:
# %bb.18:                               # %.noexc3
.LBB156_19:                             # %panic.i
.Ltmp855:
	movl	$str.c, %edi
	movl	$34, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.63, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp856:
# %bb.20:                               # %.noexc2
.LBB156_21:                             # %bb18.i.i.i.i.i.i
	movl	$8192, %edi             # imm = 0x2000
	movl	$1, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.LBB156_22:                             # %bb7.i.i.i.i.i.i
.Ltmp865:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.10, %edi
	movl	$36, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.12, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp866:
# %bb.23:                               # %.noexc.i.i.i.i
.LBB156_24:                             # %bb6.i.i.i.i
.Ltmp867:
	movq	%rax, %r15
	leaq	16(%rsp), %rdi
	jmp	.LBB156_26
.LBB156_25:                             # %bb10.i.i.i
.Ltmp864:
	movq	%rax, %r15
	leaq	80(%rsp), %rdi
.LBB156_26:                             # %bb3.i
	callq	_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
	jmp	.LBB156_276
.LBB156_27:                             # %cleanup.i
.Ltmp861:
	movq	%rax, %r15
	jmp	.LBB156_276
.LBB156_33:                             # %bb33.i
	leaq	136(%r14), %rax
	movq	%rax, 72(%rsp)          # 8-byte Spill
.Ltmp871:
	callq	*_ZN3std6future6TLS_CX7__getit17hdaabf9d2770484c0E@GOTPCREL(%rip)
.Ltmp872:
	movq	%r12, 184(%rsp)         # 8-byte Spill
# %bb.34:                               # %.noexc.i
	testq	%rax, %rax
	je	.LBB156_210
# %bb.35:                               # %"_ZN3std6thread5local17LocalKey$LT$T$GT$4with17h42770fb4f9496e7bE.exit.i.i"
	movq	(%rax), %r15
	movq	$0, (%rax)
	movq	%r15, 128(%rsp)
	testq	%r15, %r15
	je	.LBB156_208
# %bb.36:                               # %bb5.i.i
	leaq	144(%r14), %rax
	movq	%rax, 168(%rsp)         # 8-byte Spill
	leaq	152(%r14), %rax
	movq	%rax, 8(%rsp)           # 8-byte Spill
	movq	144(%r14), %rax
	movq	%rax, 176(%rsp)         # 8-byte Spill
	.p2align	4, 0x90
.LBB156_37:                             # %bb1.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
	movq	72(%rsp), %rax          # 8-byte Reload
	movq	(%rax), %rbx
	movq	24(%rbx), %rax
	movq	32(%rbx), %r13
	cmpq	%r13, %rax
	jb	.LBB156_42
# %bb.38:                               # %bb3.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	8(%rbx), %rcx
	movq	16(%rbx), %r8
.Ltmp873:
	leaq	16(%rsp), %rdi
	movq	%rbx, %rsi
	movq	%r15, %rdx
	callq	*_ZN85_$LT$tokio..net..tcp..split..ReadHalf$u20$as$u20$tokio..io..async_read..AsyncRead$GT$9poll_read17h30d176be94d88147E@GOTPCREL(%rip)
.Ltmp874:
# %bb.39:                               # %.noexc4.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	16(%rsp), %rax
	cmpq	$2, %rax
	je	.LBB156_69
# %bb.40:                               # %bb12.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	24(%rsp), %r13
	cmpl	$1, %eax
	je	.LBB156_70
# %bb.41:                               # %bb19.thread.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	%r13, 32(%rbx)
	movq	$0, 24(%rbx)
	xorl	%eax, %eax
.LBB156_42:                             # %bb1.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	16(%rbx), %rsi
	cmpq	%r13, %rsi
	jb	.LBB156_188
# %bb.43:                               # %bb42.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	8(%rbx), %r12
	addq	%rax, %r12
	subq	%rax, %r13
	je	.LBB156_50
# %bb.44:                               # %_ZN6memchr6memchr17heed00860354b0018E.exit.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	_ZN6memchr3x866memchr2FN17h86b9bdb70818f9f5E(%rip), %rax
.Ltmp875:
	movl	$10, %edi
	movq	%r12, %rsi
	movq	%r13, %rdx
	callq	*%rax
.Ltmp876:
# %bb.45:                               # %.noexc10.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	cmpq	$1, %rax
	jne	.LBB156_50
# %bb.46:                               # %bb21.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	cmpq	$-1, %rdx
	je	.LBB156_196
# %bb.47:                               # %bb1.i.i.i.i12.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	leaq	1(%rdx), %rbp
	cmpq	%r13, %rdx
	jae	.LBB156_194
# %bb.48:                               # %"_ZN4core5slice74_$LT$impl$u20$core..ops..index..Index$LT$I$GT$$u20$for$u20$$u5b$T$u5d$$GT$5index17hfd9c6fcb4e28e917E.exit.i.i.i.i.i"
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	160(%r14), %rsi
	movq	168(%r14), %rbx
	movq	%rsi, %rax
	subq	%rbx, %rax
	cmpq	%rdx, %rax
	jbe	.LBB156_55
# %bb.49:                               # %"start._ZN4core5slice29_$LT$impl$u20$$u5b$T$u5d$$GT$15copy_from_slice17h4e2f8679739916b1E.exit_crit_edge.i.i19.i.i.i.i.i"
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdi
	jmp	.LBB156_65
	.p2align	4, 0x90
.LBB156_50:                             # %bb20.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	160(%r14), %rsi
	movq	168(%r14), %rbx
	movq	%rsi, %rax
	subq	%rbx, %rax
	cmpq	%r13, %rax
	jae	.LBB156_54
# %bb.51:                               # %bb6.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	addq	%r13, %rbx
	jb	.LBB156_192
# %bb.52:                               # %bb42.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	leaq	(%rsi,%rsi), %rax
	cmpq	%rbx, %rax
	cmovaq	%rax, %rbx
	testq	%rsi, %rsi
	je	.LBB156_58
# %bb.53:                               # %bb46.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdi
	movl	$1, %edx
	movq	%rbx, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	jmp	.LBB156_59
	.p2align	4, 0x90
.LBB156_54:                             # %"start._ZN4core5slice29_$LT$impl$u20$$u5b$T$u5d$$GT$15copy_from_slice17h4e2f8679739916b1E.exit_crit_edge.i.i.i.i.i.i.i"
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdi
	jmp	.LBB156_61
.LBB156_55:                             # %bb6.i.i.i.i.i20.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	addq	%rbp, %rbx
	jb	.LBB156_202
# %bb.56:                               # %bb42.i.i.i.i.i24.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	leaq	(%rsi,%rsi), %rax
	cmpq	%rbx, %rax
	cmovaq	%rax, %rbx
	testq	%rsi, %rsi
	je	.LBB156_62
# %bb.57:                               # %bb46.i.i.i.i.i27.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdi
	movl	$1, %edx
	movq	%rbx, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	jmp	.LBB156_63
.LBB156_58:                             # %bb44.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movl	$1, %esi
	movq	%rbx, %rdi
	callq	*__rust_alloc@GOTPCREL(%rip)
.LBB156_59:                             # %bb52.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	%rax, %rdi
	testq	%rax, %rax
	je	.LBB156_184
# %bb.60:                               # %bb58.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	%rdi, 152(%r14)
	movq	%rbx, 160(%r14)
	movq	168(%r14), %rbx
.LBB156_61:                             # %"_ZN5alloc3vec12Vec$LT$T$GT$17extend_from_slice17h4974f2d399e5512dE.exit.i.i.i.i.i"
                                        #   in Loop: Header=BB156_37 Depth=1
	leaq	(%rbx,%r13), %rax
	movq	%rax, 168(%r14)
	addq	%rbx, %rdi
	xorl	%ebx, %ebx
	jmp	.LBB156_66
.LBB156_62:                             # %bb44.i.i.i.i.i25.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movl	$1, %esi
	movq	%rbx, %rdi
	callq	*__rust_alloc@GOTPCREL(%rip)
.LBB156_63:                             # %bb52.i.i.i.i.i29.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	%rax, %rdi
	testq	%rax, %rax
	je	.LBB156_184
# %bb.64:                               # %bb58.i.i.i.i.i32.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	%rdi, 152(%r14)
	movq	%rbx, 160(%r14)
	movq	168(%r14), %rbx
.LBB156_65:                             # %"_ZN5alloc3vec12Vec$LT$T$GT$17extend_from_slice17h4974f2d399e5512dE.exit37.i.i.i.i.i"
                                        #   in Loop: Header=BB156_37 Depth=1
	leaq	(%rbx,%rbp), %rax
	movq	%rax, 168(%r14)
	addq	%rbx, %rdi
	movb	$1, %bl
	movq	%rbp, %r13
.LBB156_66:                             # %bb26.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	movq	%r12, %rsi
	movq	%r13, %rdx
	callq	*memcpy@GOTPCREL(%rip)
	movq	136(%r14), %rax
	movq	24(%rax), %rcx
	addq	%r13, %rcx
	movq	32(%rax), %rdx
	cmpq	%rdx, %rcx
	cmovaq	%rdx, %rcx
	movq	%rcx, 24(%rax)
	movq	176(%r14), %rbp
	addq	%r13, %rbp
	movq	%rbp, 176(%r14)
	testb	%bl, %bl
	jne	.LBB156_68
# %bb.67:                               # %bb26.i.i.i.i.i
                                        #   in Loop: Header=BB156_37 Depth=1
	testq	%r13, %r13
	jne	.LBB156_37
.LBB156_68:                             # %bb34.i.i.i.i.i
	movq	$0, 176(%r14)
	xorl	%ebx, %ebx
                                        # implicit-def: $r12
	jmp	.LBB156_71
.LBB156_69:                             # %_ZN4core3ptr18real_drop_in_place17hb016ad0a224444edE.exit.i.i.i.i
	movl	$2, %ebx
	movq	184(%rsp), %r12         # 8-byte Reload
	jmp	.LBB156_76
.LBB156_70:                             # %bb40.i.i.i.i.i
	movq	32(%rsp), %r12
	movl	$1, %ebx
	movq	%r13, %rbp
.LBB156_71:                             # %bb9.i.i.i.i
	movq	%rbx, 80(%rsp)
	movq	%rbp, 88(%rsp)
	movq	%r12, 96(%rsp)
	movq	152(%r14), %rsi
	movq	168(%r14), %rdx
.Ltmp884:
	leaq	16(%rsp), %rdi
	callq	*_ZN4core3str9from_utf817h355180e46c909e18E@GOTPCREL(%rip)
.Ltmp885:
# %bb.72:                               # %bb11.i.i.i.i
	cmpq	$1, 16(%rsp)
	jne	.LBB156_75
# %bb.73:                               # %bb13.i.i.i.i
	movdqu	88(%rsp), %xmm0
	movdqa	%xmm0, 112(%rsp)
	testq	%rbx, %rbx
	movq	168(%rsp), %r15         # 8-byte Reload
	je	.LBB156_77
# %bb.74:                               # %bb14.i.i.i.i.i
	movdqa	112(%rsp), %xmm0
	movdqa	%xmm0, 16(%rsp)
	jmp	.LBB156_79
.LBB156_75:                             # %bb16.i.i.i.i
	movq	176(%rsp), %rdx         # 8-byte Reload
	movq	16(%rdx), %rax
	movq	%rax, 32(%rsp)
	movups	(%rdx), %xmm0
	movaps	%xmm0, 16(%rsp)
	movq	8(%rsp), %rcx           # 8-byte Reload
	movq	16(%rcx), %rax
	movq	%rax, 16(%rdx)
	movups	(%rcx), %xmm0
	movups	%xmm0, (%rdx)
	movq	32(%rsp), %rax
	movq	%rax, 16(%rcx)
	movdqa	16(%rsp), %xmm0
	movdqu	%xmm0, (%rcx)
	movl	89(%rsp), %eax
	movl	92(%rsp), %ecx
	movl	%eax, 144(%rsp)
	movl	%ecx, 147(%rsp)
	movl	%ebp, %eax
	movb	%bpl, 7(%rsp)           # 1-byte Spill
.LBB156_76:                             # %bb6.i.i
	movq	168(%rsp), %r15         # 8-byte Reload
	jmp	.LBB156_80
.LBB156_77:                             # %bb3.i.i.i.i.i
.Ltmp889:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.0, %edi
	movl	$34, %esi
	callq	*_ZN3std5error161_$LT$impl$u20$core..convert..From$LT$$RF$str$GT$$u20$for$u20$alloc..boxed..Box$LT$dyn$u20$std..error..Error$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$4from17h3380ca6fb4be57d1E@GOTPCREL(%rip)
.Ltmp890:
# %bb.78:                               # %.noexc11.i.i
	movq	%rdx, %rcx
.Ltmp891:
	leaq	16(%rsp), %rdi
	movl	$12, %esi
	movq	%rax, %rdx
	callq	*_ZN3std2io5error5Error4_new17h9d3cc36308b63b32E@GOTPCREL(%rip)
.Ltmp892:
.LBB156_79:                             # %bb14.i.i.i.i
	movb	16(%rsp), %al
	movb	%al, 7(%rsp)            # 1-byte Spill
	movl	17(%rsp), %eax
	movl	%eax, 144(%rsp)
	movl	20(%rsp), %eax
	movl	%eax, 147(%rsp)
	movq	24(%rsp), %r12
	movl	$1, %ebx
.LBB156_80:                             # %bb6.i.i
.Ltmp893:
	leaq	128(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp894:
# %bb.81:                               # %bb36.i
	cmpl	$2, %ebx
	je	.LBB156_98
# %bb.82:                               # %bb98.i
	movl	144(%rsp), %eax
	movl	147(%rsp), %ecx
	movl	%ecx, 107(%rsp)
	movl	%eax, 104(%rsp)
	movq	160(%r14), %rsi
	testq	%rsi, %rsi
	je	.LBB156_84
# %bb.83:                               # %bb4.i.i.i.i.i128.i
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB156_84:                             # %bb42.i
	cmpl	$1, %ebx
	je	.LBB156_213
# %bb.85:                               # %bb43.i
	movq	120(%r14), %rax
	testq	%rax, %rax
	je	.LBB156_204
# %bb.86:                               # %bb9.i.i.i.i.i
	movq	104(%r14), %rbx
	leaq	(%rbx,%rax), %rbp
	movzbl	-1(%rbp), %edx
	movl	$1, %edi
	testb	%dl, %dl
	jns	.LBB156_106
# %bb.87:                               # %bb11.i.i.i.i.i
	leaq	-1(%rbp), %rsi
	cmpq	%rsi, %rbx
	je	.LBB156_93
# %bb.88:                               # %_ZN4core3str11unwrap_or_017h8b346d772d3fa2e4E.exit38.i.i.i.i.i
	movzbl	-2(%rbp), %esi
	movl	%esi, %ecx
	andb	$-64, %cl
	cmpb	$-128, %cl
	jne	.LBB156_94
# %bb.89:                               # %bb16.i.i.i.i.i
	leaq	-2(%rbp), %rcx
	cmpq	%rcx, %rbx
	je	.LBB156_95
# %bb.90:                               # %_ZN4core3str11unwrap_or_017h8b346d772d3fa2e4E.exit26.i.i.i.i.i
	movzbl	-3(%rbp), %r8d
	movl	%r8d, %ecx
	andb	$-64, %cl
	cmpb	$-128, %cl
	jne	.LBB156_96
# %bb.91:                               # %bb21.i.i.i.i21.i
	leaq	-3(%rbp), %rcx
	cmpq	%rcx, %rbx
	je	.LBB156_99
# %bb.92:                               # %bb3.i.i.i.i.i.i
	movzbl	-4(%rbp), %ebp
	andl	$7, %ebp
	shll	$6, %ebp
	jmp	.LBB156_100
.LBB156_93:
	xorl	%esi, %esi
	jmp	.LBB156_102
.LBB156_94:
	andl	$31, %esi
	jmp	.LBB156_102
.LBB156_95:
	xorl	%r8d, %r8d
	jmp	.LBB156_101
.LBB156_96:
	andl	$15, %r8d
	jmp	.LBB156_101
.LBB156_98:                             # %bb41.i
	movl	$4, %eax
	jmp	.LBB156_186
.LBB156_99:
	xorl	%ebp, %ebp
.LBB156_100:                            # %_ZN4core3str11unwrap_or_017h8b346d772d3fa2e4E.exit.i.i.i.i.i
	andl	$63, %r8d
	orl	%ebp, %r8d
.LBB156_101:                            # %bb26.i.i.i.i22.i
	shll	$6, %r8d
	andl	$63, %esi
	orl	%r8d, %esi
.LBB156_102:                            # %"_ZN93_$LT$core..iter..adapters..Rev$LT$I$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hd4a54ae2d5033363E.exit.i.i"
	shll	$6, %esi
	andl	$63, %edx
	orl	%esi, %edx
	cmpl	$1114112, %edx          # imm = 0x110000
	je	.LBB156_204
# %bb.103:                              # %bb11.i.i
	cmpl	$128, %edx
	jb	.LBB156_106
# %bb.104:                              # %bb1.i.i23.i
	movl	$2, %edi
	cmpl	$2048, %edx             # imm = 0x800
	jb	.LBB156_106
# %bb.105:                              # %bb3.i.i.i
	cmpl	$65536, %edx            # imm = 0x10000
	movl	$4, %edi
	sbbq	$0, %rdi
.LBB156_106:                            # %bb53.i
	leaq	104(%r14), %rcx
	subq	%rdi, %rax
	movq	%rax, 120(%r14)
	movq	%rcx, 80(%rsp)
	movq	$_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h682d6de7e17c539bE, 88(%rsp)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.68, 16(%rsp)
	movq	$2, 24(%rsp)
	movq	$0, 32(%rsp)
	leaq	80(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	$1, 56(%rsp)
.Ltmp895:
	leaq	16(%rsp), %rdi
	callq	*_ZN3std2io5stdio6_print17h74e13de89e94daa3E@GOTPCREL(%rip)
.Ltmp896:
# %bb.107:                              # %bb55.i
	movq	72(%rsp), %rax          # 8-byte Reload
	movq	$1, (%rax)
	pxor	%xmm0, %xmm0
	movdqu	%xmm0, (%r15)
	movl	$30, %edi
	movl	$1, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB156_212
# %bb.108:                              # %"_ZN47_$LT$str$u20$as$u20$alloc..string..ToString$GT$9to_string17hf47172a7da064b33E.exit.i.i"
	movups	.Lanon.112aa5216417f3e30cbfa40815f3b444.61+14(%rip), %xmm0
	movups	%xmm0, 14(%rax)
	movdqu	.Lanon.112aa5216417f3e30cbfa40815f3b444.61(%rip), %xmm0
	movdqu	%xmm0, (%rax)
	cmpq	$30, 120(%r14)
	jne	.LBB156_111
# %bb.109:                              # %bb3.i.i.i.i.i.i30.i
	movq	104(%r14), %rcx
	cmpq	%rax, %rcx
	je	.LBB156_117
# %bb.110:                              # %bb56.i
	movdqu	(%rcx), %xmm0
	movdqu	14(%rcx), %xmm1
	movdqu	(%rax), %xmm2
	pcmpeqb	%xmm0, %xmm2
	movdqu	14(%rax), %xmm0
	pcmpeqb	%xmm1, %xmm0
	pand	%xmm2, %xmm0
	pmovmskb	%xmm0, %ebx
	movl	$30, %esi
	movl	$1, %edx
	movq	%rax, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
	cmpl	$65535, %ebx            # imm = 0xFFFF
	jne	.LBB156_112
	jmp	.LBB156_118
.LBB156_111:                            # %bb56.thread362.i
	movl	$30, %esi
	movl	$1, %edx
	movq	%rax, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB156_112:                            # %bb60.i
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rbx
	movq	(%r15), %rsi
	movq	%rsi, %rax
	subq	%rbx, %rax
	cmpq	$32, %rax
	jae	.LBB156_116
# %bb.113:                              # %bb6.i.i.i.i.i.i.i.i
	addq	$32, %rbx
	jb	.LBB156_219
# %bb.114:                              # %bb42.i.i.i.i.i.i.i.i
	leaq	(%rsi,%rsi), %rax
	cmpq	%rbx, %rax
	cmovaq	%rax, %rbx
	testq	%rsi, %rsi
	je	.LBB156_158
# %bb.115:                              # %bb46.i.i.i.i.i.i.i.i
	movq	72(%rsp), %rax          # 8-byte Reload
	movq	(%rax), %rdi
	movl	$1, %edx
	movq	%rbx, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	testq	%rax, %rax
	jne	.LBB156_159
	jmp	.LBB156_184
.LBB156_116:                            # %"start._ZN4core5slice29_$LT$impl$u20$$u5b$T$u5d$$GT$15copy_from_slice17h4e2f8679739916b1E.exit_crit_edge.i.i.i.i.i"
	movq	72(%rsp), %rax          # 8-byte Reload
	movq	(%rax), %rax
	movq	8(%rsp), %rdx           # 8-byte Reload
	jmp	.LBB156_160
.LBB156_117:                            # %bb56.thread.i
	movl	$30, %esi
	movl	$1, %edx
	movq	%rax, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB156_118:                            # %bb61.i
.Ltmp901:
	leaq	80(%rsp), %rdi
	callq	*_ZN3std2fs11OpenOptions3new17h637db50ba519ceacE@GOTPCREL(%rip)
.Ltmp902:
# %bb.119:                              # %.noexc32.i
.Ltmp903:
	leaq	80(%rsp), %rdi
	movl	$1, %esi
	callq	*_ZN3std2fs11OpenOptions4read17hd7975430325f755cE@GOTPCREL(%rip)
.Ltmp904:
# %bb.120:                              # %_2.i.noexc.i
	movq	%rax, %rbx
.Ltmp905:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.69, %edi
	movl	$9, %esi
	callq	*_ZN3std4path77_$LT$impl$u20$core..convert..AsRef$LT$std..path..Path$GT$$u20$for$u20$str$GT$6as_ref17h3c5d1f03bd3cf2fcE@GOTPCREL(%rip)
.Ltmp906:
# %bb.121:                              # %.noexc34.i
.Ltmp907:
	movq	%rax, %rdi
	movq	%rdx, %rsi
	callq	*_ZN79_$LT$std..path..Path$u20$as$u20$core..convert..AsRef$LT$std..path..Path$GT$$GT$6as_ref17hfed8283f245d364dE@GOTPCREL(%rip)
.Ltmp908:
# %bb.122:                              # %.noexc35.i
	movq	%rdx, %rcx
.Ltmp909:
	leaq	16(%rsp), %rdi
	movq	%rbx, %rsi
	movq	%rax, %rdx
	callq	*_ZN3std2fs11OpenOptions5_open17hf998f871b8441183E@GOTPCREL(%rip)
.Ltmp910:
# %bb.123:                              # %bb62.i
	movq	%r12, 184(%rsp)         # 8-byte Spill
	cmpl	$1, 16(%rsp)
	je	.LBB156_225
# %bb.124:                              # %bb64.i
	movl	20(%rsp), %eax
	movl	%eax, 104(%rsp)
	movq	8(%rsp), %rax           # 8-byte Reload
	movq	(%rax), %rdx
	movq	72(%rsp), %r15          # 8-byte Reload
	movq	%r15, 128(%rsp)
	movq	%rdx, 136(%rsp)
	movq	%r15, 112(%rsp)
	movq	%rdx, 120(%rsp)
	leaq	16(%rsp), %r12
	leaq	104(%rsp), %r13
	movq	_ZN47_$LT$std..fs..File$u20$as$u20$std..io..Read$GT$4read17h1b63e27a613578d8E@GOTPCREL(%rip), %rbp
	movq	%rdx, %rbx
	movq	%rdx, 176(%rsp)         # 8-byte Spill
	jmp	.LBB156_127
	.p2align	4, 0x90
.LBB156_125:                            # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i59.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	32(%rsp), %rdi
	movl	$24, %esi
	movl	$8, %edx
	callq	*%rbp
	movq	%r15, %rbp
.LBB156_126:                            # %bb31.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	112(%rsp), %r15
	movq	120(%rsp), %rdx
	movq	16(%r15), %rbx
.LBB156_127:                            # %bb7.i.i.i.i.i50.i
                                        # =>This Inner Loop Header: Depth=1
	cmpq	%rbx, %rdx
	jne	.LBB156_132
# %bb.128:                              # %bb9.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	8(%r15), %rsi
	movq	%rsi, %rax
	subq	%rbx, %rax
	cmpq	$31, %rax
	ja	.LBB156_135
# %bb.129:                              # %bb6.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	addq	$32, %rbx
	jb	.LBB156_200
# %bb.130:                              # %bb42.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	leaq	(%rsi,%rsi), %rax
	cmpq	%rbx, %rax
	cmovaq	%rax, %rbx
	testq	%rsi, %rsi
	je	.LBB156_133
# %bb.131:                              # %bb46.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	(%r15), %rdi
	movl	$1, %edx
	movq	%rbx, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	testq	%rax, %rax
	jne	.LBB156_134
	jmp	.LBB156_184
	.p2align	4, 0x90
.LBB156_132:                            #   in Loop: Header=BB156_127 Depth=1
	movq	%rbx, %rsi
	jmp	.LBB156_137
.LBB156_133:                            # %bb44.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movl	$1, %esi
	movq	%rbx, %rdi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB156_184
.LBB156_134:                            # %bb58.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	%rax, (%r15)
	movq	%rbx, 8(%r15)
	movq	112(%rsp), %r15
	movq	120(%rsp), %rbx
	movq	8(%r15), %rsi
.LBB156_135:                            # %bb13.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	%rsi, 16(%r15)
	cmpq	%rbx, %rsi
	jb	.LBB156_198
# %bb.136:                              #   in Loop: Header=BB156_127 Depth=1
	movq	%rbx, %rdx
.LBB156_137:                            # %bb16.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	%rsi, %rcx
	subq	%rdx, %rcx
	jb	.LBB156_190
# %bb.138:                              # %bb17.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	addq	(%r15), %rdx
.Ltmp912:
	movq	%r12, %rdi
	movq	%r13, %rsi
	callq	*%rbp
.Ltmp913:
# %bb.139:                              # %bb18.i.i.i.i.i52.i
                                        #   in Loop: Header=BB156_127 Depth=1
	cmpl	$1, 16(%rsp)
	jne	.LBB156_147
# %bb.140:                              # %bb25.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
.Ltmp915:
	leaq	24(%rsp), %rdi
	callq	*_ZN3std2io5error5Error4kind17h9a10ca659fd922acE@GOTPCREL(%rip)
.Ltmp916:
# %bb.141:                              # %bb27.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	cmpb	$15, %al
	jne	.LBB156_150
# %bb.142:                              # %bb30.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	cmpq	$0, 16(%rsp)
	je	.LBB156_126
# %bb.143:                              # %bb30.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	cmpb	$2, 24(%rsp)
	jb	.LBB156_126
# %bb.144:                              # %bb2.i.i.i54.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	%rbp, %r15
	movq	32(%rsp), %rbx
	movq	(%rbx), %rdi
	movq	8(%rbx), %rax
.Ltmp959:
	callq	*(%rax)
.Ltmp960:
# %bb.145:                              # %bb3.i.i.i.i.i.i56.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	8(%rbx), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	movq	__rust_dealloc@GOTPCREL(%rip), %rbp
	je	.LBB156_125
# %bb.146:                              # %bb4.i.i.i.i.i.i.i57.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	(%rbx), %rdi
	movq	16(%rax), %rdx
	callq	*%rbp
	jmp	.LBB156_125
	.p2align	4, 0x90
.LBB156_147:                            # %bb21.i.i.i.i.i53.i
                                        #   in Loop: Header=BB156_127 Depth=1
	movq	24(%rsp), %rcx
	movq	120(%rsp), %rax
	testq	%rcx, %rcx
	je	.LBB156_149
# %bb.148:                              # %bb30.thread.i.i.i.i.i.i
                                        #   in Loop: Header=BB156_127 Depth=1
	addq	%rcx, %rax
	movq	%rax, 120(%rsp)
	jmp	.LBB156_126
.LBB156_149:                            # %bb19.i.i.i.i.i.i
	subq	176(%rsp), %rax         # 8-byte Folded Reload
	xorl	%ebx, %ebx
                                        # implicit-def: $rcx
	jmp	.LBB156_151
.LBB156_150:                            # %bb29.i.i.i.i.i.i
	movq	24(%rsp), %rax
	movq	32(%rsp), %rcx
	movl	$1, %ebx
.LBB156_151:                            # %bb36.i.i.i.i.i.i
	movq	%rbx, 80(%rsp)
	movq	%rax, 88(%rsp)
	movq	%rcx, 96(%rsp)
.Ltmp920:
	leaq	112(%rsp), %rdi
	callq	*_ZN56_$LT$std..io..Guard$u20$as$u20$core..ops..drop..Drop$GT$4drop17h9d646c2a3ad901faE@GOTPCREL(%rip)
.Ltmp921:
	movq	184(%rsp), %r12         # 8-byte Reload
	movq	168(%rsp), %r15         # 8-byte Reload
# %bb.152:                              # %bb4.i.i57.i
	movq	128(%rsp), %rcx
	movq	136(%rsp), %rsi
	movq	16(%rcx), %rax
	movq	%rax, %rdx
	subq	%rsi, %rdx
	jb	.LBB156_223
# %bb.153:                              # %bb6.i.i.i
	addq	(%rcx), %rsi
.Ltmp923:
	leaq	16(%rsp), %rdi
	callq	*_ZN4core3str9from_utf817h355180e46c909e18E@GOTPCREL(%rip)
.Ltmp924:
# %bb.154:                              # %bb8.i.i.i
	cmpq	$1, 16(%rsp)
	jne	.LBB156_157
# %bb.155:                              # %bb10.i.i63.i
	movups	88(%rsp), %xmm0
	movaps	%xmm0, 112(%rsp)
	testq	%rbx, %rbx
	je	.LBB156_161
# %bb.156:                              # %bb14.i.i.i64.i
	movaps	112(%rsp), %xmm0
	jmp	.LBB156_164
.LBB156_157:                            # %bb12.i.i.i
	movq	128(%rsp), %rax
	movq	16(%rax), %rax
	movq	%rax, 136(%rsp)
	movups	88(%rsp), %xmm0
	movaps	%xmm0, 144(%rsp)
	jmp	.LBB156_165
.LBB156_158:                            # %bb44.i.i.i.i.i.i.i.i
	movl	$1, %esi
	movq	%rbx, %rdi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB156_184
.LBB156_159:                            # %bb58.i.i.i.i.i.i.i.i
	movq	72(%rsp), %rcx          # 8-byte Reload
	movq	%rax, (%rcx)
	movq	%rbx, (%r15)
	movq	8(%rsp), %rdx           # 8-byte Reload
	movq	(%rdx), %rbx
.LBB156_160:                            # %"_ZN84_$LT$alloc..string..String$u20$as$u20$core..ops..arith..AddAssign$LT$$RF$str$GT$$GT$10add_assign17hc61c61e64f02023eE.exit.i"
	leaq	32(%rbx), %rcx
	movq	%rcx, (%rdx)
	movups	.Lanon.112aa5216417f3e30cbfa40815f3b444.72+16(%rip), %xmm0
	movups	%xmm0, 16(%rax,%rbx)
	movups	.Lanon.112aa5216417f3e30cbfa40815f3b444.72(%rip), %xmm0
	movups	%xmm0, (%rax,%rbx)
	jmp	.LBB156_169
.LBB156_161:                            # %bb3.i.i.i.i
.Ltmp925:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.0, %edi
	movl	$34, %esi
	callq	*_ZN3std5error161_$LT$impl$u20$core..convert..From$LT$$RF$str$GT$$u20$for$u20$alloc..boxed..Box$LT$dyn$u20$std..error..Error$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$4from17h3380ca6fb4be57d1E@GOTPCREL(%rip)
.Ltmp926:
# %bb.162:                              # %.noexc18.i.i.i
	movq	%rdx, %rcx
.Ltmp927:
	leaq	16(%rsp), %rdi
	movl	$12, %esi
	movq	%rax, %rdx
	callq	*_ZN3std2io5error5Error4_new17h9d3cc36308b63b32E@GOTPCREL(%rip)
.Ltmp928:
# %bb.163:                              # %.noexc19.i.i.i
	movups	16(%rsp), %xmm0
.LBB156_164:                            # %bb13.i.i.i
	movaps	%xmm0, 144(%rsp)
	movl	$1, %ebx
.LBB156_165:                            # %bb13.i.i.i
.Ltmp930:
	leaq	128(%rsp), %rdi
	callq	*_ZN56_$LT$std..io..Guard$u20$as$u20$core..ops..drop..Drop$GT$4drop17h9d646c2a3ad901faE@GOTPCREL(%rip)
.Ltmp931:
# %bb.166:                              # %bb68.i
	testq	%rbx, %rbx
	jne	.LBB156_221
# %bb.167:                              # %bb70.i
.Ltmp933:
	leaq	104(%rsp), %rdi
	callq	*_ZN70_$LT$std..sys..unix..fd..FileDesc$u20$as$u20$core..ops..drop..Drop$GT$4drop17hf2b9d188fe38bb32E@GOTPCREL(%rip)
.Ltmp934:
# %bb.168:                              # %bb72.i
	movq	8(%rsp), %rdx           # 8-byte Reload
.LBB156_169:                            # %bb75.i
	movq	(%rdx), %rsi
	cmpq	(%r15), %rsi
	jne	.LBB156_174
# %bb.170:                              # %bb6.i.i.i.i.i80.i
	movq	%rsi, %rbx
	incq	%rbx
	je	.LBB156_217
# %bb.171:                              # %bb42.i.i.i.i.i.i
	leaq	(%rsi,%rsi), %rax
	cmpq	%rbx, %rax
	cmovaq	%rax, %rbx
	testq	%rsi, %rsi
	je	.LBB156_183
# %bb.172:                              # %bb46.i.i.i.i.i.i
	movq	72(%rsp), %rax          # 8-byte Reload
	movq	(%rax), %rdi
	movl	$1, %edx
	movq	%rbx, %rcx
	callq	*__rust_realloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB156_184
.LBB156_173:                            # %bb58.i.i.i.i.i.i
	movq	72(%rsp), %rcx          # 8-byte Reload
	movq	%rax, (%rcx)
	movq	%rbx, (%r15)
	movq	8(%rsp), %rcx           # 8-byte Reload
	movq	(%rcx), %rsi
	jmp	.LBB156_175
.LBB156_174:                            # %bb3.bb8_crit_edge.i.i
	movq	72(%rsp), %rax          # 8-byte Reload
	movq	(%rax), %rax
.LBB156_175:                            # %bb82.i
	movb	$10, (%rax,%rsi)
	movq	152(%r14), %rax
	addq	$1, %rax
	movq	%rax, 152(%r14)
	movq	136(%r14), %rcx
	leaq	56(%r14), %rdx
	movq	%rdx, 160(%r14)
	movq	%rcx, 168(%r14)
	movq	%rax, 176(%r14)
.LBB156_176:                            # %bb84.i
	leaq	160(%r14), %rsi
.Ltmp936:
	leaq	16(%rsp), %rdi
	callq	_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE
.Ltmp937:
# %bb.177:                              # %bb87.i
	movq	16(%rsp), %rax
	cmpq	$2, %rax
	je	.LBB156_185
# %bb.178:                              # %bb100.i
	movdqu	24(%rsp), %xmm0
	movdqa	%xmm0, 80(%rsp)
	cmpl	$1, %eax
	je	.LBB156_206
# %bb.179:                              # %bb93.i
	movq	144(%r14), %rsi
	testq	%rsi, %rsi
	je	.LBB156_181
# %bb.180:                              # %bb4.i.i.i.i.i.i
	movq	136(%r14), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB156_181:                            # %bb95.i
	movq	112(%r14), %rsi
	testq	%rsi, %rsi
	je	.LBB156_28
# %bb.182:                              # %bb4.i.i.i.i.i100.i
	movq	104(%r14), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB156_28:                             # %bb10.i
	leaq	56(%r14), %rax
	movq	%rax, 136(%r14)
	movq	$.Lanon.112aa5216417f3e30cbfa40815f3b444.64, 144(%r14)
	movq	$10, 152(%r14)
.LBB156_29:                             # %bb14.i
	leaq	136(%r14), %rsi
.Ltmp868:
	leaq	16(%rsp), %rdi
	callq	_ZN3std6future21poll_with_tls_context17h885a604c3570a4afE
.Ltmp869:
# %bb.30:                               # %bb17.i
	movq	16(%rsp), %rax
	cmpq	$2, %rax
	je	.LBB156_97
# %bb.31:                               # %bb96.i
	movdqu	24(%rsp), %xmm0
	movdqa	%xmm0, 80(%rsp)
	cmpl	$1, %eax
	je	.LBB156_215
# %bb.32:                               # %bb26.i
	leaq	104(%r14), %rax
	leaq	64(%r14), %rcx
	movq	$1, 104(%r14)
	pxor	%xmm0, %xmm0
	movdqu	%xmm0, 112(%r14)
	movq	%rcx, 136(%r14)
	movq	%rax, 144(%r14)
	movq	$1, 152(%r14)
	movdqu	%xmm0, 160(%r14)
	movq	$0, 176(%r14)
	jmp	.LBB156_33
.LBB156_183:                            # %bb44.i.i.i.i.i.i
	movl	$1, %esi
	movq	%rbx, %rdi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	jne	.LBB156_173
.LBB156_184:                            # %bb21.i.i.i.i.i.i
	movl	$1, %esi
	movq	%rbx, %rdi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.LBB156_97:                             # %bb22.i
	movl	$3, %eax
	jmp	.LBB156_186
.LBB156_185:                            # %bb92.i
	movl	$5, %eax
.LBB156_186:                            # %bb10
	movl	%eax, 128(%r14)
.Ltmp1015:
	leaq	192(%rsp), %rdi
	callq	*_ZN64_$LT$std..future..SetOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop17h024ba6850ad4d096E@GOTPCREL(%rip)
.Ltmp1016:
# %bb.187:                              # %bb11
	addq	$200, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.LBB156_188:                            # %bb5.i.i.i.i.i.i.i.i.i
	.cfi_def_cfa_offset 256
.Ltmp996:
	movq	%r13, %rdi
	callq	*_ZN4core5slice20slice_index_len_fail17ha58ce2526532f1e6E@GOTPCREL(%rip)
.Ltmp997:
# %bb.189:                              # %.noexc5.i.i
.LBB156_190:                            # %bb2.i.i.i.i46.i.i.i.i.i.i
.Ltmp962:
	movq	%rdx, %rdi
	callq	*_ZN4core5slice22slice_index_order_fail17hc2daf093fd804659E@GOTPCREL(%rip)
.Ltmp963:
# %bb.191:                              # %.noexc49.i.i.i.i.i.i
.LBB156_192:                            # %bb2.i.i.i.i10.i.i.i.i.i
.Ltmp994:
	callq	*_ZN5alloc7raw_vec17capacity_overflow17h69b424f1d1921be0E@GOTPCREL(%rip)
.Ltmp995:
# %bb.193:                              # %.noexc6.i.i
.LBB156_194:                            # %bb5.i.i.i.i13.i.i.i.i.i
.Ltmp878:
	movq	%rbp, %rdi
	movq	%r13, %rsi
	callq	*_ZN4core5slice20slice_index_len_fail17ha58ce2526532f1e6E@GOTPCREL(%rip)
.Ltmp879:
# %bb.195:                              # %.noexc7.i.i
.LBB156_196:                            # %bb4.i.i.i.i.i.i.i.i
.Ltmp882:
	callq	*_ZN4core5slice25slice_index_overflow_fail17hade8e16d1c099b7eE@GOTPCREL(%rip)
.Ltmp883:
# %bb.197:                              # %.noexc8.i.i
.LBB156_198:                            # %bb2.i.i.i.i.i.i.i.i.i.i
.Ltmp964:
	movq	%rbx, %rdi
	callq	*_ZN4core5slice22slice_index_order_fail17hc2daf093fd804659E@GOTPCREL(%rip)
.Ltmp965:
# %bb.199:                              # %.noexc42.i.i.i.i.i.i
.LBB156_200:                            # %bb2.i.i.i.i.i.i.i.i
.Ltmp966:
	callq	*_ZN5alloc7raw_vec17capacity_overflow17h69b424f1d1921be0E@GOTPCREL(%rip)
.Ltmp967:
# %bb.201:                              # %.noexc.i.i.i.i.i.i
.LBB156_202:                            # %bb2.i.i.i.i33.i.i.i.i.i
.Ltmp880:
	callq	*_ZN5alloc7raw_vec17capacity_overflow17h69b424f1d1921be0E@GOTPCREL(%rip)
.Ltmp881:
# %bb.203:                              # %.noexc9.i.i
.LBB156_204:                            # %bb2.i.i
.Ltmp985:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.8, %edi
	movl	$43, %esi
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.6, %edx
	callq	*_ZN4core9panicking5panic17hf3b2e3f8bf85ebd1E@GOTPCREL(%rip)
.Ltmp986:
# %bb.205:                              # %.noexc24.i
.LBB156_206:                            # %bb5.i145.i
	movaps	80(%rsp), %xmm0
	movaps	%xmm0, 16(%rsp)
.Ltmp939:
	leaq	16(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.65, %edi
	movl	$30, %esi
	movl	$.Lvtable.4, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp940:
# %bb.207:                              # %unreachable.i146.i
.LBB156_208:                            # %bb2.i.i3.i
.Ltmp998:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.1, %edi
	movl	$100, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp999:
# %bb.209:                              # %.noexc.i.i
.LBB156_210:                            # %bb5.i.i.i.i
.Ltmp1003:
	leaq	16(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1004:
# %bb.211:                              # %.noexc4.i
.LBB156_212:                            # %bb18.i.i.i.i.i.i.i.i.i.i.i
	movl	$30, %edi
	movl	$1, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.LBB156_213:                            # %bb5.i18.i
	movb	7(%rsp), %al            # 1-byte Reload
	movb	%al, 16(%rsp)
	movl	104(%rsp), %eax
	movl	107(%rsp), %ecx
	movl	%eax, 17(%rsp)
	movl	%ecx, 20(%rsp)
	movq	%r12, 24(%rsp)
.Ltmp988:
	leaq	16(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.66, %edi
	movl	$31, %esi
	movl	$.Lvtable.4, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp989:
# %bb.214:                              # %unreachable.i.i
.LBB156_215:                            # %bb5.i106.i
	movdqa	80(%rsp), %xmm0
	movdqa	%xmm0, 16(%rsp)
.Ltmp1006:
	leaq	16(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.65, %edi
	movl	$30, %esi
	movl	$.Lvtable.4, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1007:
# %bb.216:                              # %unreachable.i107.i
.LBB156_217:                            # %bb2.i.i.i.i82.i
.Ltmp945:
	callq	*_ZN5alloc7raw_vec17capacity_overflow17h69b424f1d1921be0E@GOTPCREL(%rip)
.Ltmp946:
# %bb.218:                              # %.noexc83.i
.LBB156_219:                            # %bb2.i.i.i.i.i.i.i
.Ltmp898:
	callq	*_ZN5alloc7raw_vec17capacity_overflow17h69b424f1d1921be0E@GOTPCREL(%rip)
.Ltmp899:
# %bb.220:                              # %.noexc31.i
.LBB156_221:                            # %bb5.i72.i
	movaps	144(%rsp), %xmm0
	movaps	%xmm0, 16(%rsp)
.Ltmp948:
	leaq	16(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.71, %edi
	movl	$24, %esi
	movl	$.Lvtable.4, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp949:
# %bb.222:                              # %unreachable.i73.i
.LBB156_223:                            # %bb2.i.i.i.i.i.i58.i
.Ltmp954:
	movq	%rsi, %rdi
	movq	%rax, %rsi
	callq	*_ZN4core5slice22slice_index_order_fail17hc2daf093fd804659E@GOTPCREL(%rip)
.Ltmp955:
# %bb.224:                              # %.noexc16.i.i.i
.LBB156_225:                            # %bb5.i40.i
	movdqu	24(%rsp), %xmm0
	movdqa	%xmm0, 80(%rsp)
.Ltmp977:
	leaq	80(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.70, %edi
	movl	$21, %esi
	movl	$.Lvtable.4, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp978:
# %bb.226:                              # %unreachable.i41.i
.LBB156_227:                            # %cleanup.i42.i
.Ltmp979:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp980:
	leaq	80(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Ltmp981:
# %bb.228:                              # %.noexc45.i
	cmpl	$0, 16(%rsp)
	jne	.LBB156_267
# %bb.229:                              # %bb7.i.i
	leaq	20(%rsp), %rdi
.Ltmp982:
	callq	_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE
.Ltmp983:
	jmp	.LBB156_267
.LBB156_230:                            # %cleanup25.i
.Ltmp984:
	jmp	.LBB156_256
.LBB156_231:                            # %cleanup.i74.i
.Ltmp950:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp951:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Ltmp952:
	jmp	.LBB156_266
.LBB156_232:                            # %cleanup27.i
.Ltmp953:
	jmp	.LBB156_248
.LBB156_233:                            # %cleanup29.i
.Ltmp900:
	jmp	.LBB156_256
.LBB156_234:                            # %cleanup30.i
.Ltmp947:
	jmp	.LBB156_256
.LBB156_235:                            # %cleanup.i108.i
.Ltmp1008:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp1009:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Ltmp1010:
	jmp	.LBB156_275
.LBB156_236:                            # %cleanup9.i
.Ltmp1011:
	jmp	.LBB156_258
.LBB156_237:                            # %cleanup.i.i
.Ltmp990:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp991:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Ltmp992:
	jmp	.LBB156_274
.LBB156_238:                            # %cleanup16.i
.Ltmp993:
	jmp	.LBB156_254
.LBB156_239:                            # %cleanup.i147.i
.Ltmp941:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp942:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Ltmp943:
	jmp	.LBB156_267
.LBB156_240:                            # %cleanup36.i
.Ltmp944:
	jmp	.LBB156_256
.LBB156_241:                            # %cleanup18.i
.Ltmp987:
	jmp	.LBB156_254
.LBB156_242:                            # %bb35.loopexit.split-lp.i.i.i.i.i.i
.Ltmp968:
	jmp	.LBB156_263
.LBB156_243:                            # %cleanup1
.Ltmp1017:
	movq	%rax, %rdi
	callq	_Unwind_Resume
.LBB156_244:                            # %cleanup2.i.i.i
.Ltmp929:
	jmp	.LBB156_250
.LBB156_245:                            # %bb17.i.i.i
.Ltmp956:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp957:
	leaq	80(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE
.Ltmp958:
	jmp	.LBB156_265
.LBB156_246:                            # %cleanup28.i
.Ltmp935:
	jmp	.LBB156_256
.LBB156_247:                            # %cleanup.i.i.i
.Ltmp932:
.LBB156_248:                            # %bb67.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB156_266
.LBB156_249:                            # %cleanup.i.i.i.i.i.i
.Ltmp922:
.LBB156_250:                            # %bb5.i.i59.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB156_265
.LBB156_251:                            # %bb20.i.i.i.i
.Ltmp886:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp887:
	leaq	80(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE
.Ltmp888:
	jmp	.LBB156_272
.LBB156_252:                            # %cleanup.loopexit.split-lp.i.i
.Ltmp1000:
	jmp	.LBB156_271
.LBB156_253:                            # %bb50.i
.Ltmp897:
.LBB156_254:                            # %bb27.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB156_274
.LBB156_255:                            # %bb79.i
.Ltmp938:
	jmp	.LBB156_256
.LBB156_257:                            # %bb11.i
.Ltmp870:
.LBB156_258:                            # %bb9.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB156_275
.LBB156_259:                            # %cleanup24.i
.Ltmp911:
.LBB156_256:                            # %bb57.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB156_267
.LBB156_260:                            # %bb35.thread82.i.i.i.i.i.i
.Ltmp961:
	movq	%rax, %r15
                                        # kill: killed $rdx
	movq	(%rbx), %rdi
	movq	8(%rbx), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	32(%rsp), %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB156_264
.LBB156_261:                            # %bb35.thread.i.i.i.i.i.i
.Ltmp917:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp918:
	leaq	16(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h02dd6b3a0a1c609bE
.Ltmp919:
	jmp	.LBB156_264
.LBB156_262:                            # %bb35.loopexit.i.i.i.i.i.i
.Ltmp914:
.LBB156_263:                            # %bb6.i.i.i.i.i48.i
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB156_264:                            # %bb6.i.i.i.i.i48.i
.Ltmp969:
	leaq	112(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E
.Ltmp970:
.LBB156_265:                            # %bb5.i.i59.i
.Ltmp972:
	leaq	128(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17ha3a3ed0fa0316897E
.Ltmp973:
.LBB156_266:                            # %bb67.i
.Ltmp975:
	leaq	104(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2bad6363e544193aE
.Ltmp976:
.LBB156_267:                            # %bb57.i
	leaq	136(%r14), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
	jmp	.LBB156_274
.LBB156_268:                            # %cleanup26.i
.Ltmp974:
	jmp	.LBB156_248
.LBB156_269:                            # %cleanup1.i.i.i
.Ltmp971:
	jmp	.LBB156_250
.LBB156_270:                            # %cleanup.loopexit.i.i
.Ltmp877:
.LBB156_271:                            # %cleanup.body.i.i
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB156_272:                            # %cleanup.body.i.i
.Ltmp1001:
	leaq	128(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
.Ltmp1002:
.LBB156_273:                            # %bb31.i
	movq	72(%rsp), %rdi          # 8-byte Reload
	callq	_ZN4core3ptr18real_drop_in_place17h42b179ded7dcfffcE
.LBB156_274:                            # %bb27.i
	leaq	104(%r14), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h314366b4417d5734E
.LBB156_275:                            # %bb9.i
	leaq	64(%r14), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hd1b3236be8bd03eaE
.LBB156_276:                            # %bb3.i
.Ltmp1012:
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h52b5450cfbc055ffE
.Ltmp1013:
# %bb.277:                              # %.noexc
	movl	$2, 128(%r14)
.LBB156_278:                            # %cleanup.body
	leaq	192(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h29f155998742d087E
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB156_279:                            # %cleanup
.Ltmp1014:
	movq	%rax, %r15
	jmp	.LBB156_278
.LBB156_280:                            # %cleanup13.i
.Ltmp1005:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB156_273
.Lfunc_end156:
	.size	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E, .Lfunc_end156-_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17he4a2e106d9378ec8E
	.cfi_endproc
	.section	.rodata,"a",@progbits
	.p2align	3
.LJTI156_0:
	.quad	.LBB156_1
	.quad	.LBB156_17
	.quad	.LBB156_19
	.quad	.LBB156_7
	.quad	.LBB156_6
	.quad	.LBB156_8
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table156:
.Lexception63:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end63-.Lcst_begin63
.Lcst_begin63:
	.uleb128 .Lfunc_begin63-.Lfunc_begin63 # >> Call Site 1 <<
	.uleb128 .Ltmp859-.Lfunc_begin63 #   Call between .Lfunc_begin63 and .Ltmp859
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp859-.Lfunc_begin63 # >> Call Site 2 <<
	.uleb128 .Ltmp860-.Ltmp859      #   Call between .Ltmp859 and .Ltmp860
	.uleb128 .Ltmp861-.Lfunc_begin63 #     jumps to .Ltmp861
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp862-.Lfunc_begin63 # >> Call Site 3 <<
	.uleb128 .Ltmp863-.Ltmp862      #   Call between .Ltmp862 and .Ltmp863
	.uleb128 .Ltmp864-.Lfunc_begin63 #     jumps to .Ltmp864
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp857-.Lfunc_begin63 # >> Call Site 4 <<
	.uleb128 .Ltmp856-.Ltmp857      #   Call between .Ltmp857 and .Ltmp856
	.uleb128 .Ltmp1014-.Lfunc_begin63 #     jumps to .Ltmp1014
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp865-.Lfunc_begin63 # >> Call Site 5 <<
	.uleb128 .Ltmp866-.Ltmp865      #   Call between .Ltmp865 and .Ltmp866
	.uleb128 .Ltmp867-.Lfunc_begin63 #     jumps to .Ltmp867
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp871-.Lfunc_begin63 # >> Call Site 6 <<
	.uleb128 .Ltmp872-.Ltmp871      #   Call between .Ltmp871 and .Ltmp872
	.uleb128 .Ltmp1005-.Lfunc_begin63 #     jumps to .Ltmp1005
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp873-.Lfunc_begin63 # >> Call Site 7 <<
	.uleb128 .Ltmp876-.Ltmp873      #   Call between .Ltmp873 and .Ltmp876
	.uleb128 .Ltmp877-.Lfunc_begin63 #     jumps to .Ltmp877
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp876-.Lfunc_begin63 # >> Call Site 8 <<
	.uleb128 .Ltmp884-.Ltmp876      #   Call between .Ltmp876 and .Ltmp884
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp884-.Lfunc_begin63 # >> Call Site 9 <<
	.uleb128 .Ltmp885-.Ltmp884      #   Call between .Ltmp884 and .Ltmp885
	.uleb128 .Ltmp886-.Lfunc_begin63 #     jumps to .Ltmp886
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp889-.Lfunc_begin63 # >> Call Site 10 <<
	.uleb128 .Ltmp892-.Ltmp889      #   Call between .Ltmp889 and .Ltmp892
	.uleb128 .Ltmp1000-.Lfunc_begin63 #     jumps to .Ltmp1000
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp893-.Lfunc_begin63 # >> Call Site 11 <<
	.uleb128 .Ltmp894-.Ltmp893      #   Call between .Ltmp893 and .Ltmp894
	.uleb128 .Ltmp1005-.Lfunc_begin63 #     jumps to .Ltmp1005
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp895-.Lfunc_begin63 # >> Call Site 12 <<
	.uleb128 .Ltmp896-.Ltmp895      #   Call between .Ltmp895 and .Ltmp896
	.uleb128 .Ltmp897-.Lfunc_begin63 #     jumps to .Ltmp897
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp901-.Lfunc_begin63 # >> Call Site 13 <<
	.uleb128 .Ltmp910-.Ltmp901      #   Call between .Ltmp901 and .Ltmp910
	.uleb128 .Ltmp911-.Lfunc_begin63 #     jumps to .Ltmp911
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp910-.Lfunc_begin63 # >> Call Site 14 <<
	.uleb128 .Ltmp912-.Ltmp910      #   Call between .Ltmp910 and .Ltmp912
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp912-.Lfunc_begin63 # >> Call Site 15 <<
	.uleb128 .Ltmp913-.Ltmp912      #   Call between .Ltmp912 and .Ltmp913
	.uleb128 .Ltmp914-.Lfunc_begin63 #     jumps to .Ltmp914
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp915-.Lfunc_begin63 # >> Call Site 16 <<
	.uleb128 .Ltmp916-.Ltmp915      #   Call between .Ltmp915 and .Ltmp916
	.uleb128 .Ltmp917-.Lfunc_begin63 #     jumps to .Ltmp917
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp959-.Lfunc_begin63 # >> Call Site 17 <<
	.uleb128 .Ltmp960-.Ltmp959      #   Call between .Ltmp959 and .Ltmp960
	.uleb128 .Ltmp961-.Lfunc_begin63 #     jumps to .Ltmp961
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp960-.Lfunc_begin63 # >> Call Site 18 <<
	.uleb128 .Ltmp920-.Ltmp960      #   Call between .Ltmp960 and .Ltmp920
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp920-.Lfunc_begin63 # >> Call Site 19 <<
	.uleb128 .Ltmp921-.Ltmp920      #   Call between .Ltmp920 and .Ltmp921
	.uleb128 .Ltmp922-.Lfunc_begin63 #     jumps to .Ltmp922
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp923-.Lfunc_begin63 # >> Call Site 20 <<
	.uleb128 .Ltmp924-.Ltmp923      #   Call between .Ltmp923 and .Ltmp924
	.uleb128 .Ltmp956-.Lfunc_begin63 #     jumps to .Ltmp956
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp925-.Lfunc_begin63 # >> Call Site 21 <<
	.uleb128 .Ltmp928-.Ltmp925      #   Call between .Ltmp925 and .Ltmp928
	.uleb128 .Ltmp929-.Lfunc_begin63 #     jumps to .Ltmp929
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp930-.Lfunc_begin63 # >> Call Site 22 <<
	.uleb128 .Ltmp931-.Ltmp930      #   Call between .Ltmp930 and .Ltmp931
	.uleb128 .Ltmp932-.Lfunc_begin63 #     jumps to .Ltmp932
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp933-.Lfunc_begin63 # >> Call Site 23 <<
	.uleb128 .Ltmp934-.Ltmp933      #   Call between .Ltmp933 and .Ltmp934
	.uleb128 .Ltmp935-.Lfunc_begin63 #     jumps to .Ltmp935
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp936-.Lfunc_begin63 # >> Call Site 24 <<
	.uleb128 .Ltmp937-.Ltmp936      #   Call between .Ltmp936 and .Ltmp937
	.uleb128 .Ltmp938-.Lfunc_begin63 #     jumps to .Ltmp938
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp868-.Lfunc_begin63 # >> Call Site 25 <<
	.uleb128 .Ltmp869-.Ltmp868      #   Call between .Ltmp868 and .Ltmp869
	.uleb128 .Ltmp870-.Lfunc_begin63 #     jumps to .Ltmp870
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1015-.Lfunc_begin63 # >> Call Site 26 <<
	.uleb128 .Ltmp1016-.Ltmp1015    #   Call between .Ltmp1015 and .Ltmp1016
	.uleb128 .Ltmp1017-.Lfunc_begin63 #     jumps to .Ltmp1017
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp996-.Lfunc_begin63 # >> Call Site 27 <<
	.uleb128 .Ltmp997-.Ltmp996      #   Call between .Ltmp996 and .Ltmp997
	.uleb128 .Ltmp1000-.Lfunc_begin63 #     jumps to .Ltmp1000
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp962-.Lfunc_begin63 # >> Call Site 28 <<
	.uleb128 .Ltmp963-.Ltmp962      #   Call between .Ltmp962 and .Ltmp963
	.uleb128 .Ltmp968-.Lfunc_begin63 #     jumps to .Ltmp968
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp994-.Lfunc_begin63 # >> Call Site 29 <<
	.uleb128 .Ltmp883-.Ltmp994      #   Call between .Ltmp994 and .Ltmp883
	.uleb128 .Ltmp1000-.Lfunc_begin63 #     jumps to .Ltmp1000
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp964-.Lfunc_begin63 # >> Call Site 30 <<
	.uleb128 .Ltmp967-.Ltmp964      #   Call between .Ltmp964 and .Ltmp967
	.uleb128 .Ltmp968-.Lfunc_begin63 #     jumps to .Ltmp968
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp880-.Lfunc_begin63 # >> Call Site 31 <<
	.uleb128 .Ltmp881-.Ltmp880      #   Call between .Ltmp880 and .Ltmp881
	.uleb128 .Ltmp1000-.Lfunc_begin63 #     jumps to .Ltmp1000
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp985-.Lfunc_begin63 # >> Call Site 32 <<
	.uleb128 .Ltmp986-.Ltmp985      #   Call between .Ltmp985 and .Ltmp986
	.uleb128 .Ltmp987-.Lfunc_begin63 #     jumps to .Ltmp987
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp939-.Lfunc_begin63 # >> Call Site 33 <<
	.uleb128 .Ltmp940-.Ltmp939      #   Call between .Ltmp939 and .Ltmp940
	.uleb128 .Ltmp941-.Lfunc_begin63 #     jumps to .Ltmp941
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp998-.Lfunc_begin63 # >> Call Site 34 <<
	.uleb128 .Ltmp999-.Ltmp998      #   Call between .Ltmp998 and .Ltmp999
	.uleb128 .Ltmp1000-.Lfunc_begin63 #     jumps to .Ltmp1000
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1003-.Lfunc_begin63 # >> Call Site 35 <<
	.uleb128 .Ltmp1004-.Ltmp1003    #   Call between .Ltmp1003 and .Ltmp1004
	.uleb128 .Ltmp1005-.Lfunc_begin63 #     jumps to .Ltmp1005
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp988-.Lfunc_begin63 # >> Call Site 36 <<
	.uleb128 .Ltmp989-.Ltmp988      #   Call between .Ltmp988 and .Ltmp989
	.uleb128 .Ltmp990-.Lfunc_begin63 #     jumps to .Ltmp990
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1006-.Lfunc_begin63 # >> Call Site 37 <<
	.uleb128 .Ltmp1007-.Ltmp1006    #   Call between .Ltmp1006 and .Ltmp1007
	.uleb128 .Ltmp1008-.Lfunc_begin63 #     jumps to .Ltmp1008
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp945-.Lfunc_begin63 # >> Call Site 38 <<
	.uleb128 .Ltmp946-.Ltmp945      #   Call between .Ltmp945 and .Ltmp946
	.uleb128 .Ltmp947-.Lfunc_begin63 #     jumps to .Ltmp947
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp898-.Lfunc_begin63 # >> Call Site 39 <<
	.uleb128 .Ltmp899-.Ltmp898      #   Call between .Ltmp898 and .Ltmp899
	.uleb128 .Ltmp900-.Lfunc_begin63 #     jumps to .Ltmp900
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp948-.Lfunc_begin63 # >> Call Site 40 <<
	.uleb128 .Ltmp949-.Ltmp948      #   Call between .Ltmp948 and .Ltmp949
	.uleb128 .Ltmp950-.Lfunc_begin63 #     jumps to .Ltmp950
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp954-.Lfunc_begin63 # >> Call Site 41 <<
	.uleb128 .Ltmp955-.Ltmp954      #   Call between .Ltmp954 and .Ltmp955
	.uleb128 .Ltmp956-.Lfunc_begin63 #     jumps to .Ltmp956
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp977-.Lfunc_begin63 # >> Call Site 42 <<
	.uleb128 .Ltmp978-.Ltmp977      #   Call between .Ltmp977 and .Ltmp978
	.uleb128 .Ltmp979-.Lfunc_begin63 #     jumps to .Ltmp979
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp980-.Lfunc_begin63 # >> Call Site 43 <<
	.uleb128 .Ltmp983-.Ltmp980      #   Call between .Ltmp980 and .Ltmp983
	.uleb128 .Ltmp984-.Lfunc_begin63 #     jumps to .Ltmp984
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp951-.Lfunc_begin63 # >> Call Site 44 <<
	.uleb128 .Ltmp952-.Ltmp951      #   Call between .Ltmp951 and .Ltmp952
	.uleb128 .Ltmp953-.Lfunc_begin63 #     jumps to .Ltmp953
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1009-.Lfunc_begin63 # >> Call Site 45 <<
	.uleb128 .Ltmp1010-.Ltmp1009    #   Call between .Ltmp1009 and .Ltmp1010
	.uleb128 .Ltmp1011-.Lfunc_begin63 #     jumps to .Ltmp1011
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp991-.Lfunc_begin63 # >> Call Site 46 <<
	.uleb128 .Ltmp992-.Ltmp991      #   Call between .Ltmp991 and .Ltmp992
	.uleb128 .Ltmp993-.Lfunc_begin63 #     jumps to .Ltmp993
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp942-.Lfunc_begin63 # >> Call Site 47 <<
	.uleb128 .Ltmp943-.Ltmp942      #   Call between .Ltmp942 and .Ltmp943
	.uleb128 .Ltmp944-.Lfunc_begin63 #     jumps to .Ltmp944
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp943-.Lfunc_begin63 # >> Call Site 48 <<
	.uleb128 .Ltmp957-.Ltmp943      #   Call between .Ltmp943 and .Ltmp957
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp957-.Lfunc_begin63 # >> Call Site 49 <<
	.uleb128 .Ltmp958-.Ltmp957      #   Call between .Ltmp957 and .Ltmp958
	.uleb128 .Ltmp974-.Lfunc_begin63 #     jumps to .Ltmp974
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp887-.Lfunc_begin63 # >> Call Site 50 <<
	.uleb128 .Ltmp888-.Ltmp887      #   Call between .Ltmp887 and .Ltmp888
	.uleb128 .Ltmp1000-.Lfunc_begin63 #     jumps to .Ltmp1000
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp918-.Lfunc_begin63 # >> Call Site 51 <<
	.uleb128 .Ltmp970-.Ltmp918      #   Call between .Ltmp918 and .Ltmp970
	.uleb128 .Ltmp971-.Lfunc_begin63 #     jumps to .Ltmp971
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp972-.Lfunc_begin63 # >> Call Site 52 <<
	.uleb128 .Ltmp973-.Ltmp972      #   Call between .Ltmp972 and .Ltmp973
	.uleb128 .Ltmp974-.Lfunc_begin63 #     jumps to .Ltmp974
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp975-.Lfunc_begin63 # >> Call Site 53 <<
	.uleb128 .Ltmp976-.Ltmp975      #   Call between .Ltmp975 and .Ltmp976
	.uleb128 .Ltmp1014-.Lfunc_begin63 #     jumps to .Ltmp1014
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1001-.Lfunc_begin63 # >> Call Site 54 <<
	.uleb128 .Ltmp1002-.Ltmp1001    #   Call between .Ltmp1001 and .Ltmp1002
	.uleb128 .Ltmp1005-.Lfunc_begin63 #     jumps to .Ltmp1005
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1012-.Lfunc_begin63 # >> Call Site 55 <<
	.uleb128 .Ltmp1013-.Ltmp1012    #   Call between .Ltmp1012 and .Ltmp1013
	.uleb128 .Ltmp1014-.Lfunc_begin63 #     jumps to .Ltmp1014
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1013-.Lfunc_begin63 # >> Call Site 56 <<
	.uleb128 .Lfunc_end156-.Ltmp1013 #   Call between .Ltmp1013 and .Lfunc_end156
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end63:
	.p2align	2
                                        # -- End function
	.text
	.p2align	4, 0x90         # -- Begin function _ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE
	.type	_ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE,@function
_ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE: # @"_ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE"
	.cfi_startproc
# %bb.0:                                # %start
	movq	%rsi, %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.56, %edi
	movl	$25, %esi
	jmpq	*_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h6dbcac32b99cea99E@GOTPCREL(%rip) # TAILCALL
.Lfunc_end157:
	.size	_ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE, .Lfunc_end157-_ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E
	.type	_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E,@function
_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E: # @"_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%rax
	.cfi_def_cfa_offset 16
	cmpq	$0, (%rdi)
	je	.LBB158_2
# %bb.1:                                # %bb3
	movq	%rdi, %rax
	movl	$.Lvtable.f, %edx
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.LBB158_2:                              # %bb1
	.cfi_def_cfa_offset 16
	callq	*_ZN3std7process5abort17hda23989dd14b7a85E@GOTPCREL(%rip)
.Lfunc_end158:
	.size	_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E, .Lfunc_end158-_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E
	.type	_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E,@function
_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E: # @"_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E"
	.cfi_startproc
# %bb.0:                                # %start
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	(%rdi), %rbx
	movq	8(%rdi), %r14
	movq	$0, (%rdi)
	testq	%rbx, %rbx
	je	.LBB159_3
# %bb.1:                                # %bb5
	movl	$16, %edi
	movl	$8, %esi
	callq	*__rust_alloc@GOTPCREL(%rip)
	testq	%rax, %rax
	je	.LBB159_4
# %bb.2:                                # %bb8
	movq	%rbx, (%rax)
	movq	%r14, 8(%rax)
	movl	$.Lvtable.f, %edx
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.LBB159_3:                              # %bb3
	.cfi_def_cfa_offset 32
	callq	*_ZN3std7process5abort17hda23989dd14b7a85E@GOTPCREL(%rip)
.LBB159_4:                              # %bb6.i.i
	movl	$16, %edi
	movl	$8, %esi
	callq	*_ZN5alloc5alloc18handle_alloc_error17h310b2b12e0c80cdaE@GOTPCREL(%rip)
.Lfunc_end159:
	.size	_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E, .Lfunc_end159-_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E
	.cfi_endproc
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function _ZN7just_bc4main17h75f1b496e4a6411bE
	.type	_ZN7just_bc4main17h75f1b496e4a6411bE,@function
_ZN7just_bc4main17h75f1b496e4a6411bE:   # @_ZN7just_bc4main17h75f1b496e4a6411bE
.Lfunc_begin64:
	.cfi_startproc
	.cfi_personality 3, rust_eh_personality
	.cfi_lsda 3, .Lexception64
# %bb.0:                                # %start
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$960, %rsp              # imm = 0x3C0
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	leaq	736(%rsp), %rbx
	movq	%rbx, %rdi
	callq	*_ZN5tokio7runtime7builder7Builder3new17h220c3a5aa3f6a834E@GOTPCREL(%rip)
.Ltmp1018:
	movq	%rbx, %rdi
	callq	*_ZN5tokio7runtime7builder7Builder15basic_scheduler17hf72f8ad1d4271961E@GOTPCREL(%rip)
.Ltmp1019:
# %bb.1:                                # %bb3
.Ltmp1020:
	movq	%rax, %rdi
	callq	*_ZN5tokio7runtime7builder7Builder18threaded_scheduler17hbf3494243855d0caE@GOTPCREL(%rip)
.Ltmp1021:
# %bb.2:                                # %bb5
.Ltmp1022:
	movq	%rax, %rdi
	callq	*_ZN5tokio7runtime7builder7Builder10enable_all17h54e883921efcd4b5E@GOTPCREL(%rip)
.Ltmp1023:
# %bb.3:                                # %bb6
.Ltmp1024:
	leaq	480(%rsp), %rdi
	movq	%rax, %rsi
	callq	*_ZN5tokio7runtime7builder7Builder5build17h0ef979bca679d777E@GOTPCREL(%rip)
.Ltmp1025:
# %bb.4:                                # %bb7
	cmpl	$1, 480(%rsp)
	je	.LBB160_5
# %bb.10:                               # %bb10
	movq	600(%rsp), %rax
	movq	%rax, 720(%rsp)
	movups	584(%rsp), %xmm0
	movaps	%xmm0, 704(%rsp)
	movups	568(%rsp), %xmm0
	movaps	%xmm0, 688(%rsp)
	movups	552(%rsp), %xmm0
	movaps	%xmm0, 672(%rsp)
	movups	488(%rsp), %xmm0
	movups	504(%rsp), %xmm1
	movups	520(%rsp), %xmm2
	movups	536(%rsp), %xmm3
	movaps	%xmm3, 656(%rsp)
	movaps	%xmm2, 640(%rsp)
	movaps	%xmm1, 624(%rsp)
	movaps	%xmm0, 608(%rsp)
	leaq	608(%rsp), %rax
	movq	%rax, 432(%rsp)
	movq	680(%rsp), %rcx
	testq	%rcx, %rcx
	je	.LBB160_11
# %bb.12:                               # %bb10
	cmpl	$1, %ecx
	je	.LBB160_13
# %bb.15:                               # %bb5.i.i.i.i
	movq	688(%rsp), %rax
	lock		addq	$1, (%rax)
	jle	.LBB160_238
# %bb.16:                               # %"_ZN84_$LT$tokio..runtime..thread_pool..spawner..Spawner$u20$as$u20$core..clone..Clone$GT$5clone17h84f6785b53b400fbE.exit.i.i.i.i"
	movl	$2, %ecx
	jmp	.LBB160_17
.LBB160_13:                             # %bb3.i.i.i.i
	movq	688(%rsp), %rax
	lock		addq	$1, (%rax)
	jle	.LBB160_238
# %bb.14:                               # %"_ZN79_$LT$tokio..runtime..basic_scheduler..Spawner$u20$as$u20$core..clone..Clone$GT$5clone17h456211e0e2aecec4E.exit.i.i.i.i"
	movl	$1, %ecx
	jmp	.LBB160_17
.LBB160_11:
                                        # implicit-def: $rax
.LBB160_17:                             # %"_ZN71_$LT$tokio..runtime..spawner..Spawner$u20$as$u20$core..clone..Clone$GT$5clone17h0bdb96de030b92dbE.exit.i.i.i"
	movq	696(%rsp), %rdx
	cmpq	$-1, %rdx
	je	.LBB160_21
# %bb.18:                               # %"_ZN71_$LT$tokio..runtime..spawner..Spawner$u20$as$u20$core..clone..Clone$GT$5clone17h0bdb96de030b92dbE.exit.i.i.i"
	testq	%rdx, %rdx
	jne	.LBB160_20
# %bb.19:
	xorl	%edx, %edx
	jmp	.LBB160_21
.LBB160_20:                             # %bb3.i.i.i.i.i.i
	lock		addq	$1, 8(%rdx)
	jle	.LBB160_238
.LBB160_21:                             # %bb7.i.i.i
	movq	704(%rsp), %rsi
	lock		addq	$1, (%rsi)
	jle	.LBB160_238
# %bb.22:                               # %bb2.i.i
	leaq	432(%rsp), %rdi
	movq	%rdi, 480(%rsp)
	movl	$0, 488(%rsp)
	movups	844(%rsp), %xmm0
	movups	860(%rsp), %xmm1
	movdqu	876(%rsp), %xmm2
	movups	892(%rsp), %xmm3
	movups	%xmm0, 492(%rsp)
	movups	%xmm1, 508(%rsp)
	movdqu	%xmm2, 524(%rsp)
	movups	%xmm3, 540(%rsp)
	movups	908(%rsp), %xmm0
	movups	%xmm0, 556(%rsp)
	movups	920(%rsp), %xmm0
	movups	%xmm0, 568(%rsp)
	movq	%rcx, 64(%rsp)
	movq	%rax, 72(%rsp)
	movq	%rdx, 80(%rsp)
	movq	%rsi, 88(%rsp)
.Ltmp1026:
	callq	*_ZN5tokio7runtime7context7CONTEXT7__getit17h1cb53017e0de9ae6E@GOTPCREL(%rip)
.Ltmp1027:
# %bb.23:                               # %bb4.i.i.i4.i.i
	testq	%rax, %rax
	je	.LBB160_24
# %bb.26:                               # %bb10.i.i.i.i.i
	movups	64(%rsp), %xmm0
	movups	80(%rsp), %xmm1
	movaps	%xmm1, 208(%rsp)
	movaps	%xmm0, 192(%rsp)
	cmpq	$0, (%rax)
	jne	.LBB160_27
# %bb.31:                               # %bb11.i.i.i.i.i
	movaps	192(%rsp), %xmm0
	movaps	208(%rsp), %xmm1
	movdqu	8(%rax), %xmm2
	movups	24(%rax), %xmm3
	movups	%xmm1, 24(%rax)
	movups	%xmm0, 8(%rax)
	movq	$0, (%rax)
	movdqa	%xmm2, 192(%rsp)
	movaps	%xmm3, 208(%rsp)
	movq	%xmm2, %rax
	cmpq	$4, %rax
	je	.LBB160_33
.LBB160_35:                             # %bb1.i.i.i
	leaq	488(%rsp), %rax
	movaps	192(%rsp), %xmm0
	movaps	208(%rsp), %xmm1
	movaps	%xmm1, 464(%rsp)
	movaps	%xmm0, 448(%rsp)
	movq	480(%rsp), %rcx
	movups	80(%rax), %xmm0
	movaps	%xmm0, 416(%rsp)
	movups	64(%rax), %xmm0
	movaps	%xmm0, 400(%rsp)
	movups	(%rax), %xmm0
	movups	16(%rax), %xmm1
	movups	32(%rax), %xmm2
	movups	48(%rax), %xmm3
	movaps	%xmm3, 384(%rsp)
	movaps	%xmm2, 368(%rsp)
	movaps	%xmm1, 352(%rsp)
	movaps	%xmm0, 336(%rsp)
	movq	(%rcx), %r13
	movq	(%r13), %rax
	testq	%rax, %rax
	je	.LBB160_42
# %bb.36:                               # %bb1.i.i.i
	cmpl	$1, %eax
	je	.LBB160_37
# %bb.169:                              # %bb6.i.i.i.i
	movaps	416(%rsp), %xmm0
	movaps	%xmm0, 144(%rsp)
	movaps	400(%rsp), %xmm0
	movaps	%xmm0, 128(%rsp)
	movaps	336(%rsp), %xmm0
	movaps	352(%rsp), %xmm1
	movdqa	368(%rsp), %xmm2
	movaps	384(%rsp), %xmm3
	movaps	%xmm3, 112(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movaps	%xmm1, 80(%rsp)
	movaps	%xmm0, 64(%rsp)
.Ltmp1038:
	callq	*_ZN5tokio7runtime5enter5enter17hb50d0ce37491acefE@GOTPCREL(%rip)
.Ltmp1039:
# %bb.170:                              # %bb2.i.i.i.i.i
	movaps	144(%rsp), %xmm0
	movaps	%xmm0, 272(%rsp)
	movaps	128(%rsp), %xmm0
	movaps	%xmm0, 256(%rsp)
	movaps	64(%rsp), %xmm0
	movaps	80(%rsp), %xmm1
	movdqa	96(%rsp), %xmm2
	movaps	112(%rsp), %xmm3
	movaps	%xmm3, 240(%rsp)
	movdqa	%xmm2, 224(%rsp)
	movaps	%xmm1, 208(%rsp)
	movaps	%xmm0, 192(%rsp)
.Ltmp1043:
	callq	*_ZN5tokio4park6thread16CachedParkThread3new17ha693081284c87577E@GOTPCREL(%rip)
.Ltmp1044:
# %bb.171:                              # %bb2.i.i.i.i.i.i
.Ltmp1045:
	leaq	24(%rsp), %rdi
	callq	*_ZN5tokio4park6thread16CachedParkThread10get_unpark17h7053f91707b4cff2E@GOTPCREL(%rip)
.Ltmp1046:
# %bb.172:                              # %bb5.i.i51.i.i.i.i
	testq	%rax, %rax
	je	.LBB160_173
# %bb.188:                              # %bb14.i.i.i.i.i.i
.Ltmp1047:
	movq	%rax, %rdi
	callq	*_ZN5tokio4park6thread12UnparkThread10into_waker17hca88cb214835e725E@GOTPCREL(%rip)
.Ltmp1048:
# %bb.189:                              # %bb15.i.i.i.i.i.i
	movq	%rax, 48(%rsp)
	movq	%rdx, 56(%rsp)
	leaq	48(%rsp), %rax
	movq	%rax, 320(%rsp)
	leaq	168(%rsp), %r14
	leaq	192(%rsp), %r15
	leaq	320(%rsp), %rbx
	leaq	24(%rsp), %r12
	movq	_ZN75_$LT$tokio..park..thread..CachedParkThread$u20$as$u20$tokio..park..Park$GT$4park17h7e2b34d4718641acE@GOTPCREL(%rip), %r13
	.p2align	4, 0x90
.LBB160_190:                            # %bb20.i.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp1050:
	movq	%r14, %rdi
	movq	%r15, %rsi
	movq	%rbx, %rdx
	callq	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E
.Ltmp1051:
# %bb.191:                              # %bb21.i.i55.i.i.i.i
                                        #   in Loop: Header=BB160_190 Depth=1
	cmpq	$0, 168(%rsp)
	je	.LBB160_195
# %bb.192:                              # %bb26.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_190 Depth=1
.Ltmp1052:
	movq	%r12, %rdi
	callq	*%r13
.Ltmp1053:
# %bb.193:                              # %bb28.i.i56.i.i.i.i
                                        #   in Loop: Header=BB160_190 Depth=1
	testb	%al, %al
	je	.LBB160_190
# %bb.194:
	movl	$1, %ebx
                                        # implicit-def: $r15
                                        # implicit-def: $r14
	jmp	.LBB160_196
.LBB160_24:                             # %bb9.i.i.i.i.i
	movq	$4, 192(%rsp)
.Ltmp1036:
	leaq	64(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
.Ltmp1037:
# %bb.25:                               # %.noexc.i.i.i
	movq	192(%rsp), %rax
	cmpq	$4, %rax
	jne	.LBB160_35
.LBB160_33:                             # %bb5.i.i.i.i.i
.Ltmp1210:
	leaq	24(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1211:
# %bb.34:                               # %unreachable.i.i.i.i.i
.LBB160_37:                             # %bb4.i.i.i.i
	movaps	416(%rsp), %xmm0
	movaps	%xmm0, 272(%rsp)
	movaps	400(%rsp), %xmm0
	movaps	%xmm0, 256(%rsp)
	movaps	336(%rsp), %xmm0
	movaps	352(%rsp), %xmm1
	movdqa	368(%rsp), %xmm2
	movaps	384(%rsp), %xmm3
	movaps	%xmm3, 240(%rsp)
	movdqa	%xmm2, 224(%rsp)
	movaps	%xmm1, 208(%rsp)
	movaps	%xmm0, 192(%rsp)
	movq	8(%r13), %r15
.Ltmp1080:
	callq	*_ZN5tokio7runtime15basic_scheduler6ACTIVE7__getit17hac08425e5fc636c5E@GOTPCREL(%rip)
.Ltmp1081:
# %bb.38:                               # %.noexc.i.i.i.i.i
	addq	$16, %r15
	testq	%rax, %rax
	je	.LBB160_39
# %bb.73:                               # %bb10.i.i.i.i.i.i.i
	movq	(%rax), %rcx
	movq	%r15, (%rax)
	xorl	%eax, %eax
	jmp	.LBB160_74
.LBB160_42:                             # %bb2.i.i.i.i
	movaps	416(%rsp), %xmm0
	movaps	%xmm0, 272(%rsp)
	movaps	400(%rsp), %xmm0
	movaps	%xmm0, 256(%rsp)
	movaps	336(%rsp), %xmm0
	movaps	352(%rsp), %xmm1
	movdqa	368(%rsp), %xmm2
	movaps	384(%rsp), %xmm3
	movaps	%xmm3, 240(%rsp)
	movdqa	%xmm2, 224(%rsp)
	movaps	%xmm1, 208(%rsp)
	movaps	%xmm0, 192(%rsp)
.Ltmp1162:
	callq	*_ZN5tokio7runtime5enter5enter17hb50d0ce37491acefE@GOTPCREL(%rip)
.Ltmp1163:
# %bb.43:                               # %bb6.i.i.i.i.i
	leaq	56(%r13), %rax
	movq	%rax, 48(%rsp)
	leaq	16(%r13), %rbx
	leaq	64(%rsp), %r14
	leaq	192(%rsp), %r15
	leaq	48(%rsp), %r12
	.p2align	4, 0x90
.LBB160_44:                             # %bb8.i.i.i.i.i
                                        # =>This Inner Loop Header: Depth=1
.Ltmp1164:
	movq	%r14, %rdi
	movq	%r15, %rsi
	movq	%r12, %rdx
	callq	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E
.Ltmp1165:
# %bb.45:                               # %bb9.i.i12.i.i.i
                                        #   in Loop: Header=BB160_44 Depth=1
	cmpq	$0, 64(%rsp)
	je	.LBB160_46
# %bb.59:                               # %bb14.i.i.i.i.i
                                        #   in Loop: Header=BB160_44 Depth=1
	cmpl	$1, 8(%r13)
	jne	.LBB160_60
# %bb.63:                               # %bb5.i15.i.i.i.i.i
                                        #   in Loop: Header=BB160_44 Depth=1
.Ltmp1168:
	movq	%rbx, %rdi
	callq	*_ZN69_$LT$tokio..park..thread..ParkThread$u20$as$u20$tokio..park..Park$GT$4park17he4f05110cc421267E@GOTPCREL(%rip)
.Ltmp1169:
# %bb.64:                               # %.noexc17.i.i.i.i.i
                                        #   in Loop: Header=BB160_44 Depth=1
	testb	%al, %al
	je	.LBB160_44
	jmp	.LBB160_65
	.p2align	4, 0x90
.LBB160_60:                             # %bb2.i13.i.i.i.i.i
                                        #   in Loop: Header=BB160_44 Depth=1
.Ltmp1166:
	movq	%r14, %rdi
	movq	%rbx, %rsi
	callq	*_ZN63_$LT$tokio..io..driver..Driver$u20$as$u20$tokio..park..Park$GT$4park17hdb7d962184c1111eE@GOTPCREL(%rip)
.Ltmp1167:
# %bb.61:                               # %.noexc16.i.i.i.i.i
                                        #   in Loop: Header=BB160_44 Depth=1
	movzbl	64(%rsp), %eax
	cmpb	$3, %al
	je	.LBB160_44
# %bb.62:                               # %bb15.i.i.i.i.i
	movq	65(%rsp), %rcx
	movq	72(%rsp), %rdx
	movq	%rdx, 175(%rsp)
	movq	%rcx, 168(%rsp)
	jmp	.LBB160_66
.LBB160_46:                             # %bb11.i.i13.i.i.i
	movq	72(%rsp), %r14
	movq	80(%rsp), %r15
.Ltmp1179:
	leaq	24(%rsp), %rdi
	callq	*_ZN70_$LT$tokio..runtime..enter..Enter$u20$as$u20$core..ops..drop..Drop$GT$4drop17h8c0022eb2aaec068E@GOTPCREL(%rip)
.Ltmp1180:
# %bb.47:                               # %bb12.i.i14.i.i.i
	movl	192(%rsp), %eax
	cmpl	$3, %eax
	je	.LBB160_50
# %bb.48:                               # %bb12.i.i14.i.i.i
	cmpl	$4, %eax
	jne	.LBB160_209
# %bb.49:                               # %bb11.i.i.i.i.i.i.i
	leaq	200(%rsp), %rdi
.Ltmp1192:
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp1193:
	jmp	.LBB160_209
.LBB160_39:
	movl	$1, %eax
                                        # implicit-def: $rcx
.LBB160_74:                             # %"_ZN3std6thread5local17LocalKey$LT$T$GT$8try_with17h229d7a8dda8165daE.exit.i.i.i.i.i.i"
	movq	%rax, 64(%rsp)
	movq	%rcx, 72(%rsp)
	testq	%rax, %rax
	jne	.LBB160_75
# %bb.79:                               # %bb4.i.i16.i.i.i
	movq	%rcx, 328(%rsp)
.Ltmp1087:
	callq	*_ZN5tokio7runtime5enter5enter17hb50d0ce37491acefE@GOTPCREL(%rip)
.Ltmp1088:
# %bb.80:                               # %bb5.i.i17.i.i.i
.Ltmp1089:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.52, %esi
	movq	%r15, %rdi
	callq	*_ZN4core4task4wake8RawWaker3new17h3348ef682dfa8f58E@GOTPCREL(%rip)
.Ltmp1090:
# %bb.81:                               # %bb13.i.i.i.i.i
	movq	%rax, 168(%rsp)
	movq	%rdx, 176(%rsp)
	leaq	168(%rsp), %rax
	movq	%rax, 440(%rsp)
	leaq	24(%r13), %rax
	movq	%rax, 32(%rsp)          # 8-byte Spill
	movq	%r15, 40(%rsp)          # 8-byte Spill
	jmp	.LBB160_82
	.p2align	4, 0x90
.LBB160_109:                            # %bb23.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
.Ltmp1129:
	movq	%r15, %rdi
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$18drain_pending_drop17hb750b93d9047f62aE
.Ltmp1130:
.LBB160_82:                             # %bb15.i17.i.i.i.i
                                        # =>This Loop Header: Depth=1
                                        #     Child Loop BB160_113 Depth 2
.Ltmp1091:
	leaq	64(%rsp), %rdi
	leaq	192(%rsp), %rsi
	leaq	440(%rsp), %rdx
	callq	_ZN80_$LT$std..future..GenFuture$LT$T$GT$$u20$as$u20$core..future..future..Future$GT$4poll17h9be6b0c02bf7bcb4E
.Ltmp1092:
# %bb.83:                               # %bb16.i18.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	cmpq	$0, 64(%rsp)
	je	.LBB160_84
# %bb.112:                              # %bb22.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	movq	%r15, 312(%rsp)
	movl	$60, %r14d
	.p2align	4, 0x90
.LBB160_113:                            # %bb7.i.i.i18.i.i.i
                                        #   Parent Loop BB160_82 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
	movl	64(%r13), %eax
	leal	1(%rax), %ecx
	movb	%cl, 64(%r13)
	imull	$-59, %eax, %eax
	cmpb	$20, %al
	jb	.LBB160_120
# %bb.114:                              # %bb1.i.i18.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	8(%r15), %rax
	cmpq	16(%r15), %rax
	jne	.LBB160_116
# %bb.115:                              # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$15next_local_task17h66b868d50e0e3c09E.exit.thread.i.i.i.i.i.i.i"
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	$0, 64(%rsp)
	jmp	.LBB160_117
	.p2align	4, 0x90
.LBB160_120:                            # %bb2.i30.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
.Ltmp1098:
	movq	%r15, %rdi
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE
.Ltmp1099:
# %bb.121:                              # %.noexc24.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	%rax, %r12
	testq	%rax, %rax
	je	.LBB160_130
# %bb.122:                              # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$9next_task17hccbc1ec89b7d12a9E.exit.thread108.i.i.i.i.i.i"
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	%r12, 24(%rsp)
	jmp	.LBB160_123
	.p2align	4, 0x90
.LBB160_116:                            # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$15next_local_task17h66b868d50e0e3c09E.exit.i.i.i.i.i.i.i"
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	24(%r15), %rcx
	movq	32(%r15), %rdx
	leaq	1(%rax), %rsi
	addq	$-1, %rdx
	andq	%rsi, %rdx
	movq	%rdx, 8(%r15)
	movq	(%rcx,%rax,8), %r12
	movq	%r12, 64(%rsp)
	testq	%r12, %r12
	jne	.LBB160_133
.LBB160_117:                            # %bb2.i4.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
.Ltmp1093:
	movq	%r15, %rdi
	callq	_ZN5tokio4task5queue19MpscQueues$LT$S$GT$16next_remote_task17hf72072eadbea6b1aE
.Ltmp1094:
# %bb.118:                              #   in Loop: Header=BB160_113 Depth=2
	movq	%rax, %r12
	jmp	.LBB160_133
.LBB160_130:                            # %bb2.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	8(%r15), %rax
	cmpq	16(%r15), %rax
	je	.LBB160_131
# %bb.132:                              # %bb2.i.i.i.i.i31.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	24(%r15), %rcx
	movq	32(%r15), %rdx
	leaq	1(%rax), %rsi
	addq	$-1, %rdx
	andq	%rsi, %rdx
	movq	%rdx, 8(%r15)
	movq	(%rcx,%rax,8), %r12
	.p2align	4, 0x90
.LBB160_133:                            # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$9next_task17hccbc1ec89b7d12a9E.exit.i.i.i.i.i.i"
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	%r12, 24(%rsp)
	testq	%r12, %r12
	je	.LBB160_134
.LBB160_123:                            # %bb12.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	leaq	312(%rsp), %rax
	movq	%rax, 320(%rsp)
	leaq	320(%rsp), %rax
	movq	%rax, 48(%rsp)
	leaq	48(%rsp), %rax
	movq	%rax, 64(%rsp)
.Ltmp1101:
	movl	$.Lvtable.e, %edx
	movq	%r12, %rdi
	leaq	64(%rsp), %rsi
	callq	*_ZN5tokio4task3raw7RawTask4poll17hb3991d7ce4a18df4E@GOTPCREL(%rip)
.Ltmp1102:
# %bb.124:                              # %bb18.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	testb	%al, %al
	je	.LBB160_151
# %bb.125:                              # %bb21.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	312(%rsp), %rbx
	movq	16(%rbx), %rdx
	movq	32(%rbx), %r15
	movq	%rdx, %rax
	subq	8(%rbx), %rax
	leaq	-1(%r15), %rcx
	andq	%rax, %rcx
	movq	%r15, %rax
	subq	%rcx, %rax
	cmpq	$1, %rax
	jne	.LBB160_150
# %bb.126:                              # %bb2.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	leaq	24(%rbx), %rdi
.Ltmp1106:
	callq	_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$6double17hb5a16733922d17ddE
.Ltmp1107:
# %bb.127:                              # %.noexc.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	8(%rbx), %rcx
	movq	16(%rbx), %rdx
	cmpq	%rdx, %rcx
	jbe	.LBB160_150
# %bb.128:                              # %bb2.i.i.i.i.i.i41.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	%r15, %rax
	subq	%rcx, %rax
	cmpq	%rax, %rdx
	jae	.LBB160_129
# %bb.149:                              # %bb4.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	24(%rbx), %rsi
	leaq	(%rsi,%r15,8), %rdi
	shlq	$3, %rdx
	callq	*memcpy@GOTPCREL(%rip)
	addq	16(%rbx), %r15
	movq	%r15, 16(%rbx)
	movq	%r15, %rdx
	jmp	.LBB160_150
.LBB160_129:                            # %bb3.i.i.i.i.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	32(%rbx), %r15
	subq	%rax, %r15
	movq	24(%rbx), %rdx
	leaq	(%rdx,%rcx,8), %rsi
	leaq	(%rdx,%r15,8), %rdi
	shlq	$3, %rax
	movq	%rax, %rdx
	callq	*memcpy@GOTPCREL(%rip)
	movq	%r15, 8(%rbx)
	movq	16(%rbx), %rdx
	.p2align	4, 0x90
.LBB160_150:                            # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$10push_local17h6296b0226803c8cfE.exit.i.i.i.i.i.i"
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	24(%rbx), %rax
	movq	32(%rbx), %rcx
	leaq	1(%rdx), %rsi
	addq	$-1, %rcx
	andq	%rsi, %rcx
	movq	%rcx, 16(%rbx)
	movq	%r12, (%rax,%rdx,8)
.LBB160_151:                            # %bb38.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	testq	%r14, %r14
	je	.LBB160_98
# %bb.152:                              # %bb38.bb7_crit_edge.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_113 Depth=2
	movq	312(%rsp), %r15
	addq	$-1, %r14
	jmp	.LBB160_113
	.p2align	4, 0x90
.LBB160_98:                             # %bb5.i.i38.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	cmpl	$1, 16(%r13)
	jne	.LBB160_99
# %bb.107:                              # %bb5.i.i17.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
.Ltmp1117:
	movq	32(%rsp), %rdi          # 8-byte Reload
	xorl	%esi, %esi
	xorl	%edx, %edx
	callq	*_ZN69_$LT$tokio..park..thread..ParkThread$u20$as$u20$tokio..park..Park$GT$12park_timeout17h087197e06b59a88fE@GOTPCREL(%rip)
.Ltmp1118:
	movq	40(%rsp), %r15          # 8-byte Reload
# %bb.108:                              # %.noexc21.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	testb	%al, %al
	je	.LBB160_109
	jmp	.LBB160_106
	.p2align	4, 0x90
.LBB160_99:                             # %bb2.i24.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
.Ltmp1112:
	leaq	64(%rsp), %rdi
	movq	32(%rsp), %rsi          # 8-byte Reload
	xorl	%edx, %edx
	xorl	%ecx, %ecx
	callq	*_ZN63_$LT$tokio..io..driver..Driver$u20$as$u20$tokio..park..Park$GT$12park_timeout17h940a1c25a9555decE@GOTPCREL(%rip)
.Ltmp1113:
	movq	40(%rsp), %r15          # 8-byte Reload
# %bb.100:                              # %.noexc20.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	movb	64(%rsp), %al
	cmpb	$3, %al
	je	.LBB160_109
	jmp	.LBB160_101
.LBB160_131:                            # %"_ZN5tokio4task5queue19MpscQueues$LT$S$GT$9next_task17hccbc1ec89b7d12a9E.exit.thread.i.i.i.i.i.i"
                                        #   in Loop: Header=BB160_82 Depth=1
	movq	$0, 24(%rsp)
	.p2align	4, 0x90
.LBB160_134:                            # %bb10.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	cmpl	$1, 16(%r13)
	jne	.LBB160_135
# %bb.143:                              # %bb5.i41.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
.Ltmp1126:
	movq	32(%rsp), %rdi          # 8-byte Reload
	callq	*_ZN69_$LT$tokio..park..thread..ParkThread$u20$as$u20$tokio..park..Park$GT$4park17he4f05110cc421267E@GOTPCREL(%rip)
.Ltmp1127:
	movq	40(%rsp), %r15          # 8-byte Reload
# %bb.144:                              # %.noexc43.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	testb	%al, %al
	je	.LBB160_109
	jmp	.LBB160_142
	.p2align	4, 0x90
.LBB160_135:                            # %bb2.i36.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
.Ltmp1121:
	leaq	64(%rsp), %rdi
	movq	32(%rsp), %rsi          # 8-byte Reload
	callq	*_ZN63_$LT$tokio..io..driver..Driver$u20$as$u20$tokio..park..Park$GT$4park17hdb7d962184c1111eE@GOTPCREL(%rip)
.Ltmp1122:
	movq	40(%rsp), %r15          # 8-byte Reload
# %bb.136:                              # %.noexc42.i.i.i.i.i.i
                                        #   in Loop: Header=BB160_82 Depth=1
	movb	64(%rsp), %al
	cmpb	$3, %al
	je	.LBB160_109
# %bb.137:                              # %bb7.i48.i.i.i.i.i.i
	cmpb	$2, %al
	jb	.LBB160_142
# %bb.138:                              # %bb2.i.i.i.i.i49.i.i.i.i.i.i
	movq	72(%rsp), %r14
	movq	(%r14), %rdi
	movq	8(%r14), %rax
.Ltmp1123:
	callq	*(%rax)
.Ltmp1124:
# %bb.139:                              # %bb3.i.i.i.i.i.i.i.i51.i.i.i.i.i.i
	movq	8(%r14), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB160_141
# %bb.140:                              # %bb4.i.i.i.i.i.i.i.i.i52.i.i.i.i.i.i
	movq	(%r14), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB160_141:                            # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i54.i.i.i.i.i.i
	movl	$24, %esi
	movl	$8, %edx
	movq	%r14, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB160_142:                            # %bb2.i59.i.i.i.i.i.i
	movb	$1, %bl
	xorl	%r12d, %r12d
.Ltmp1132:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.51, %edi
	movl	$14, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp1133:
# %bb.147:                              # %.noexc60.i.i.i.i.i.i
.LBB160_84:                             # %bb18.i.i.i.i.i
	movq	72(%rsp), %r14
	movq	80(%rsp), %r15
.Ltmp1142:
	leaq	24(%rsp), %rdi
	callq	*_ZN70_$LT$tokio..runtime..enter..Enter$u20$as$u20$core..ops..drop..Drop$GT$4drop17h8c0022eb2aaec068E@GOTPCREL(%rip)
.Ltmp1143:
# %bb.85:                               # %bb19.i.i.i.i.i
.Ltmp1147:
	leaq	328(%rsp), %rdi
	callq	*_ZN115_$LT$tokio..runtime..basic_scheduler..BasicScheduler$LT$P$GT$..block_on..Guard$u20$as$u20$core..ops..drop..Drop$GT$4drop17hbbd208e653d590c4E@GOTPCREL(%rip)
.Ltmp1148:
# %bb.86:                               # %bb20.i.i.i.i.i
	movl	192(%rsp), %eax
	cmpl	$3, %eax
	je	.LBB160_89
# %bb.87:                               # %bb20.i.i.i.i.i
	cmpl	$4, %eax
	jne	.LBB160_209
# %bb.88:                               # %bb11.i.i.i22.i.i.i.i
	leaq	200(%rsp), %rdi
.Ltmp1159:
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp1160:
	jmp	.LBB160_209
.LBB160_173:
	movl	$1, %ebx
                                        # implicit-def: $r15
                                        # implicit-def: $r14
	jmp	.LBB160_174
.LBB160_50:                             # %bb18.i.i.i.i.i.i.i
	cmpl	$3, 272(%rsp)
	jne	.LBB160_209
# %bb.51:                               # %bb12.i.i.i.i.i.i.i.i.i
	cmpl	$0, 232(%rsp)
	je	.LBB160_209
# %bb.52:                               # %bb2.i.i.i.i.i.i.i.i.i.i
	movq	240(%rsp), %rax
	movq	$0, 240(%rsp)
	testq	%rax, %rax
	je	.LBB160_209
# %bb.53:                               # %bb2.i.i.i.i.i.i.i.i.i.i.i.i
	movq	%rax, 64(%rsp)
.Ltmp1185:
	leaq	64(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
.Ltmp1186:
# %bb.54:                               # %.noexc.i.i.i.i.i.i.i
.Ltmp1187:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
.Ltmp1188:
# %bb.55:                               # %.noexc31.i.i.i.i.i.i.i
	testb	%al, %al
	jne	.LBB160_209
# %bb.56:                               # %bb5.i.i.i.i.i.i.i.i.i.i.i.i
	movq	64(%rsp), %rdi
.Ltmp1189:
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.Ltmp1190:
	jmp	.LBB160_209
.LBB160_89:                             # %bb18.i.i.i27.i.i.i.i
	cmpl	$3, 272(%rsp)
	jne	.LBB160_209
# %bb.90:                               # %bb12.i.i.i.i.i28.i.i.i.i
	cmpl	$0, 232(%rsp)
	je	.LBB160_209
# %bb.91:                               # %bb2.i.i.i.i.i37.i.i.i.i.i
	movq	240(%rsp), %rax
	movq	$0, 240(%rsp)
	testq	%rax, %rax
	je	.LBB160_209
# %bb.92:                               # %bb2.i.i.i.i.i.i.i.i29.i.i.i.i
	movq	%rax, 64(%rsp)
.Ltmp1152:
	leaq	64(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
.Ltmp1153:
# %bb.93:                               # %.noexc.i.i.i30.i.i.i.i
.Ltmp1154:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
.Ltmp1155:
# %bb.94:                               # %.noexc31.i.i.i31.i.i.i.i
	testb	%al, %al
	jne	.LBB160_209
# %bb.95:                               # %bb5.i.i.i.i.i.i.i.i33.i.i.i.i
	movq	64(%rsp), %rdi
.Ltmp1156:
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.Ltmp1157:
	jmp	.LBB160_209
.LBB160_195:                            # %bb39.i.i.i.i.i.i
	movq	176(%rsp), %r14
	movq	184(%rsp), %r15
	xorl	%ebx, %ebx
.LBB160_196:                            # %bb24.i.i.i.i.i.i
	movq	48(%rsp), %rdi
	movq	56(%rsp), %rax
.Ltmp1057:
	callq	*24(%rax)
.Ltmp1058:
.LBB160_174:                            # %bb12.i.i52.i.i.i.i
	movl	192(%rsp), %eax
	cmpl	$3, %eax
	je	.LBB160_179
# %bb.175:                              # %bb12.i.i52.i.i.i.i
	cmpl	$4, %eax
	jne	.LBB160_177
# %bb.176:                              # %bb11.i.i.i.i.i.i.i.i
	leaq	200(%rsp), %rdi
.Ltmp1069:
	callq	_ZN4core3ptr18real_drop_in_place17ha4eaf2372c827098E
.Ltmp1070:
	jmp	.LBB160_177
.LBB160_179:                            # %bb18.i.i.i.i.i.i.i.i
	cmpl	$3, 272(%rsp)
	jne	.LBB160_177
# %bb.180:                              # %bb12.i.i.i.i.i.i.i.i.i.i
	cmpl	$0, 232(%rsp)
	je	.LBB160_177
# %bb.181:                              # %bb2.i.i.i.i.i.i.i53.i.i.i.i
	movq	240(%rsp), %rax
	movq	$0, 240(%rsp)
	testq	%rax, %rax
	je	.LBB160_177
# %bb.182:                              # %bb2.i.i.i.i.i.i.i.i.i.i.i.i.i
	movq	%rax, 168(%rsp)
.Ltmp1062:
	leaq	168(%rsp), %rdi
	callq	*_ZN5tokio4task3raw7RawTask6header17h887b575297842f2aE@GOTPCREL(%rip)
.Ltmp1063:
# %bb.183:                              # %.noexc.i.i.i.i54.i.i.i.i
.Ltmp1064:
	movq	%rax, %rdi
	callq	*_ZN5tokio4task5state5State21drop_join_handle_fast17hda3cbd0e3b0dff84E@GOTPCREL(%rip)
.Ltmp1065:
# %bb.184:                              # %.noexc31.i.i.i.i.i.i.i.i
	testb	%al, %al
	jne	.LBB160_177
# %bb.185:                              # %bb5.i.i.i.i.i.i.i.i.i.i.i.i.i
	movq	168(%rsp), %rdi
.Ltmp1066:
	callq	*_ZN5tokio4task3raw7RawTask21drop_join_handle_slow17h0a08c8ada2900777E@GOTPCREL(%rip)
.Ltmp1067:
.LBB160_177:                            # %bb3.i60.i.i.i.i
	testq	%rbx, %rbx
	jne	.LBB160_178
# %bb.208:                              # %bb5.i61.i.i.i.i
.Ltmp1072:
	leaq	24(%rsp), %rdi
	callq	*_ZN70_$LT$tokio..runtime..enter..Enter$u20$as$u20$core..ops..drop..Drop$GT$4drop17h8c0022eb2aaec068E@GOTPCREL(%rip)
.Ltmp1073:
.LBB160_209:                            # %bb3.i.i.i
.Ltmp1197:
	leaq	448(%rsp), %rdi
	callq	*_ZN83_$LT$tokio..runtime..context..enter..DropGuard$u20$as$u20$core..ops..drop..Drop$GT$4drop17hfc81e99be70e3074E@GOTPCREL(%rip)
.Ltmp1198:
# %bb.210:                              # %bb4.i29.i.i.i
	cmpl	$3, 448(%rsp)
	je	.LBB160_212
# %bb.211:                              # %bb2.i.i30.i.i.i
.Ltmp1202:
	leaq	448(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
.Ltmp1203:
.LBB160_212:                            # %bb11
.Ltmp1205:
	leaq	608(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E
.Ltmp1206:
# %bb.213:                              # %bb12
	movq	768(%rsp), %rsi
	testq	%rsi, %rsi
	je	.LBB160_215
# %bb.214:                              # %bb4.i.i.i.i.i.i13
	movq	760(%rsp), %rdi
	movl	$1, %edx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB160_215:                            # %bb6.i
	movq	800(%rsp), %rax
	testq	%rax, %rax
	je	.LBB160_218
# %bb.216:                              # %bb2.i10.i
	lock		subq	$1, (%rax)
	jne	.LBB160_218
# %bb.217:                              # %bb3.i.i.i11.i
	leaq	800(%rsp), %rdi
	#MEMBARRIER
.Ltmp1207:
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
.Ltmp1208:
.LBB160_218:                            # %bb5.i14
	movq	816(%rsp), %rax
	testq	%rax, %rax
	je	.LBB160_221
# %bb.219:                              # %bb2.i.i16
	lock		subq	$1, (%rax)
	jne	.LBB160_221
# %bb.220:                              # %bb3.i.i.i.i17
	leaq	816(%rsp), %rdi
	#MEMBARRIER
	callq	_ZN5alloc4sync12Arc$LT$T$GT$9drop_slow17hce72188c7ef7cdffE
.LBB160_221:                            # %_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E.exit
	movq	%r14, %rax
	movq	%r15, %rdx
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.LBB160_65:
	.cfi_def_cfa %rbp, 16
	movb	$3, %al
.LBB160_66:                             # %bb5.i.i.i.i.i.i
	movb	%al, 64(%rsp)
	movq	168(%rsp), %rax
	movq	175(%rsp), %rcx
	movq	%rax, 65(%rsp)
	movq	%rcx, 72(%rsp)
.Ltmp1171:
	leaq	64(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.9, %edi
	movl	$43, %esi
	movl	$.Lvtable.8, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1172:
# %bb.67:                               # %unreachable.i.i.i.i.i.i
.LBB160_101:                            # %bb7.i26.i.i.i.i.i.i
	cmpb	$2, %al
	jb	.LBB160_106
# %bb.102:                              # %bb2.i.i.i.i.i.i.i.i.i.i.i
	movq	72(%rsp), %r14
	movq	(%r14), %rdi
	movq	8(%r14), %rax
.Ltmp1114:
	callq	*(%rax)
.Ltmp1115:
# %bb.103:                              # %bb3.i.i.i.i.i.i.i.i.i.i.i.i.i.i
	movq	8(%r14), %rax
	movq	8(%rax), %rsi
	testq	%rsi, %rsi
	je	.LBB160_105
# %bb.104:                              # %bb4.i.i.i.i.i.i.i.i.i.i.i.i.i.i.i
	movq	(%r14), %rdi
	movq	16(%rax), %rdx
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB160_105:                            # %_ZN4core3ptr18real_drop_in_place17h27b9bb4166fdb623E.exit.i.i.i.i.i.i.i.i.i.i.i
	movl	$24, %esi
	movl	$8, %edx
	movq	%r14, %rdi
	callq	*__rust_dealloc@GOTPCREL(%rip)
.LBB160_106:                            # %bb2.i27.i.i.i.i.i.i
.Ltmp1119:
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.51, %edi
	movl	$14, %esi
	callq	*_ZN4core6option13expect_failed17h7475be656707bdc0E@GOTPCREL(%rip)
.Ltmp1120:
# %bb.111:                              # %.noexc22.i.i.i.i.i
.LBB160_238:                            # %bb4.i.i.i.i.i.i
	ud2
.LBB160_5:                              # %bb5.i
	leaq	488(%rsp), %r14
	movups	488(%rsp), %xmm0
	movaps	%xmm0, 608(%rsp)
.Ltmp1219:
	leaq	608(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.9, %edi
	movl	$43, %esi
	movl	$.Lvtable.4, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1220:
# %bb.6:                                # %unreachable.i
.LBB160_27:                             # %bb5.i.i.i.i.i.i.i.i
.Ltmp1031:
	leaq	24(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.4, %edi
	movl	$16, %esi
	movl	$.Lvtable.5, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1032:
# %bb.28:                               # %.noexc.i.i.i.i.i.i
.LBB160_75:                             # %bb5.i.i.i.i.i.i.i
	leaq	72(%rsp), %r14
.Ltmp1082:
	leaq	24(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.2, %edi
	movl	$70, %esi
	movl	$.Lvtable.3, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1083:
# %bb.76:                               # %unreachable.i.i.i.i.i.i.i
.LBB160_178:                            # %bb5.i3.i.i.i.i.i
.Ltmp1075:
	leaq	24(%rsp), %rdx
	movl	$.Lanon.112aa5216417f3e30cbfa40815f3b444.48, %edi
	movl	$21, %esi
	movl	$.Lvtable.6, %ecx
	callq	*_ZN4core6result13unwrap_failed17hca6a012bfa3eb903E@GOTPCREL(%rip)
.Ltmp1076:
# %bb.202:                              # %.noexc4.i.i.i.i.i
.LBB160_77:                             # %cleanup.i.i.i.i.i.i.i
.Ltmp1084:
	movq	%rax, %r15
                                        # kill: killed $rdx
	cmpq	$0, 64(%rsp)
	jne	.LBB160_78
# %bb.239:                              # %bb7.i.i.i.i.i.i.i
.Ltmp1085:
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E
.Ltmp1086:
	jmp	.LBB160_78
.LBB160_29:                             # %bb7.i.i.i.i5.i.i
.Ltmp1033:
	movq	%rax, %r15
.Ltmp1034:
	leaq	192(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17he00dcfa818232a3eE
.Ltmp1035:
	jmp	.LBB160_225
.LBB160_7:                              # %cleanup.i
.Ltmp1221:
	movq	%rax, %r15
.Ltmp1222:
	leaq	608(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
.Ltmp1223:
# %bb.8:                                # %.noexc8
	cmpq	$0, 480(%rsp)
	jne	.LBB160_236
# %bb.9:                                # %bb7.i
.Ltmp1224:
	movq	%r14, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E
.Ltmp1225:
	jmp	.LBB160_236
.LBB160_223:                            # %cleanup.i.i.i.i.i
.Ltmp1212:
	movq	%rax, %r15
	cmpl	$4, 192(%rsp)
	je	.LBB160_225
# %bb.224:                              # %bb7.i.i.i.i.i
.Ltmp1213:
	leaq	192(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E
.Ltmp1214:
	jmp	.LBB160_225
.LBB160_110:                            # %cleanup.i.i.i.i.i.i.i.i.i.i.i.i.i.i
.Ltmp1116:
	movq	%rax, %r15
                                        # kill: killed $rdx
	movq	(%r14), %rdi
	movq	8(%r14), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB160_167
.LBB160_146:                            # %cleanup.i.i.i.i.i.i.i.i53.i.i.i.i.i.i
.Ltmp1125:
	movq	%rax, %r15
                                        # kill: killed $rdx
	movq	(%r14), %rdi
	movq	8(%r14), %rsi
	callq	_ZN5alloc5alloc8box_free17h39766183111e1fbdE
	movq	%r14, %rdi
	callq	_ZN5alloc5alloc8box_free17ha829dafaf86a282fE
	jmp	.LBB160_156
.LBB160_68:                             # %cleanup.i.i.i.i.i.i
.Ltmp1173:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp1174:
	leaq	64(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE
.Ltmp1175:
	jmp	.LBB160_72
.LBB160_70:                             # %cleanup2.body9.loopexit.split-lp.i.i.i.i.i
.Ltmp1176:
	jmp	.LBB160_71
.LBB160_97:                             # %cleanup5.i.i.i37.i.i.i.i
.Ltmp1158:
	jmp	.LBB160_229
.LBB160_58:                             # %cleanup5.i.i.i.i.i.i.i
.Ltmp1191:
	jmp	.LBB160_229
.LBB160_187:                            # %cleanup5.i.i.i.i.i.i.i.i
.Ltmp1068:
	jmp	.LBB160_206
.LBB160_96:                             # %cleanup4.i.i.i36.i.i.i.i
.Ltmp1161:
	jmp	.LBB160_229
.LBB160_57:                             # %cleanup4.i.i.i.i.i.i.i
.Ltmp1194:
.LBB160_229:                            # %bb7.thread.i.i.i
	movq	%rax, %r15
	jmp	.LBB160_230
.LBB160_186:                            # %cleanup4.i.i.i.i.i.i.i.i
.Ltmp1071:
.LBB160_206:                            # %bb8.thread.i.i.i.i.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_207
.LBB160_200:                            # %cleanup2.i.i58.i.i.i.i
.Ltmp1049:
	jmp	.LBB160_198
.LBB160_231:                            # %bb3.i
.Ltmp1209:
	movq	%rax, %r15
	leaq	816(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6bec50ca570047d9E
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB160_204:                            # %bb8.i63.i.i.i.i
.Ltmp1074:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_230
.LBB160_203:                            # %bb7.i.i20.i.i.i
.Ltmp1040:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp1041:
	leaq	64(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
.Ltmp1042:
	jmp	.LBB160_230
.LBB160_162:                            # %cleanup2.i.i.i.i.i
.Ltmp1144:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_168
.LBB160_161:                            # %cleanup.i43.i.i.i.i
.Ltmp1149:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_78
.LBB160_40:                             # %cleanup.i.i15.i.i.i
.Ltmp1181:
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_41
.LBB160_197:                            # %cleanup.i.i57.i.i.i.i
.Ltmp1059:
.LBB160_198:                            # %bb3.i.i.i.i7.i.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_199
.LBB160_222:                            # %cleanup.i.i.i.i
.Ltmp1199:
	movq	%rax, %r15
.Ltmp1200:
	leaq	448(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h6ad18ef181805c70E
.Ltmp1201:
	jmp	.LBB160_235
.LBB160_227:                            # %bb7.i10.i.i
.Ltmp1204:
.LBB160_234:                            # %cleanup1.body
	movq	%rax, %r15
	jmp	.LBB160_235
.LBB160_30:                             # %bb12.i.i.i.i.i
.Ltmp1028:
	movq	%rax, %r15
.Ltmp1029:
	leaq	64(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hc1784ee61e14ff36E
.Ltmp1030:
	jmp	.LBB160_225
.LBB160_226:                            # %bb7.thread63.i.i.i
.Ltmp1215:
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB160_225:                            # %bb6.i.i.i
.Ltmp1216:
	leaq	480(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hdd203de3b0125c5fE
.Ltmp1217:
	jmp	.LBB160_235
.LBB160_155:                            # %cleanup.i.loopexit.i.i.i.i.i
.Ltmp1128:
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB160_156:                            # %cleanup.body.i.i.i.i.i.i
	movb	$1, %bl
	xorl	%r12d, %r12d
	cmpq	$0, 24(%rsp)
	je	.LBB160_159
	jmp	.LBB160_153
.LBB160_232:                            # %cleanup
.Ltmp1226:
	movq	%rax, %r15
	jmp	.LBB160_236
.LBB160_201:                            # %cleanup3.body.i.i.i.i.i.i
.Ltmp1054:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp1055:
	leaq	48(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb226c2f8ad269285E
.Ltmp1056:
.LBB160_199:                            # %bb3.i.i.i.i7.i.i
.Ltmp1060:
	leaq	192(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
.Ltmp1061:
.LBB160_207:                            # %bb8.thread.i.i.i.i.i
.Ltmp1078:
	leaq	24(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE
.Ltmp1079:
	jmp	.LBB160_230
.LBB160_205:                            # %cleanup1.i.i.i.i.i
.Ltmp1077:
	jmp	.LBB160_206
.LBB160_69:                             # %cleanup2.body9.loopexit.i.i.i.i.i
.Ltmp1170:
.LBB160_71:                             # %cleanup2.body.i.i.i.i.i
	movq	%rax, %r15
                                        # kill: killed $rdx
.LBB160_72:                             # %cleanup2.body.i.i.i.i.i
.Ltmp1177:
	leaq	24(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE
.Ltmp1178:
.LBB160_41:                             # %bb3.i.i.i.i.i
.Ltmp1182:
	leaq	192(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
.Ltmp1183:
	jmp	.LBB160_230
.LBB160_164:                            # %cleanup3.body32.loopexit.split-lp.loopexit.i.i.i.i.i
.Ltmp1131:
	jmp	.LBB160_166
.LBB160_148:                            # %bb1.i.i.i.i.i.i.i.i
.Ltmp1108:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp1109:
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp1110:
	jmp	.LBB160_167
.LBB160_160:                            # %cleanup2.i.i.i.i.i.i
.Ltmp1111:
	jmp	.LBB160_166
.LBB160_163:                            # %cleanup3.body32.loopexit.i.i.i.i.i
.Ltmp1100:
.LBB160_166:                            # %cleanup3.body.i.i.i.i.i
	movq	%rax, %r15
                                        # kill: killed $rdx
	jmp	.LBB160_167
.LBB160_119:                            # %cleanup.i.i.i.i.i.i.i.i
.Ltmp1095:
	movq	%rax, %r15
                                        # kill: killed $rdx
.Ltmp1096:
	leaq	64(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
.Ltmp1097:
	jmp	.LBB160_167
.LBB160_145:                            # %bb1.i44.i.i.i.i.i.i
.Ltmp1103:
	movq	%rax, %r15
                                        # kill: killed $rdx
	xorl	%ebx, %ebx
.Ltmp1104:
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp1105:
# %bb.158:                              # %cleanup.body.i.i.i.i.i.i
	cmpq	$0, 24(%rsp)
	jne	.LBB160_153
.LBB160_159:                            # %bb30.i.i.i.i.i.i
.Ltmp1137:
	leaq	24(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h2de24b7a29ebf508E
.Ltmp1138:
	jmp	.LBB160_167
.LBB160_157:                            # %cleanup.i.loopexit.split-lp.i.i.i.i.i
.Ltmp1134:
	movq	%rax, %r15
                                        # kill: killed $rdx
	cmpq	$0, 24(%rsp)
	je	.LBB160_159
.LBB160_153:                            # %bb28.i.i.i.i.i.i
	testb	%bl, %bl
	je	.LBB160_167
# %bb.154:                              # %bb29.i.i.i.i.i.i
.Ltmp1135:
	movq	%r12, %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h032bb3b7232478c2E
.Ltmp1136:
.LBB160_167:                            # %cleanup3.body.i.i.i.i.i
.Ltmp1140:
	leaq	24(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb430a81eb84989bfE
.Ltmp1141:
.LBB160_168:                            # %bb6.i16.i.i.i.i
.Ltmp1145:
	leaq	328(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h4f79d343c5965205E
.Ltmp1146:
.LBB160_78:                             # %bb3.i15.i.i.i.i
.Ltmp1150:
	leaq	192(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hbd2dea592d9bfd01E
.Ltmp1151:
.LBB160_230:                            # %bb7.thread.i.i.i
.Ltmp1195:
	leaq	448(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17h1bb45bb9d03280c2E
.Ltmp1196:
.LBB160_235:                            # %cleanup1.body
	leaq	608(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hcef2c7d3daf67b63E
.LBB160_236:                            # %bb4
	leaq	736(%rsp), %rdi
	callq	_ZN4core3ptr18real_drop_in_place17hb03804ef44432157E
	movq	%r15, %rdi
	callq	_Unwind_Resume
.LBB160_233:                            # %cleanup1
.Ltmp1218:
	jmp	.LBB160_234
.LBB160_228:                            # %cleanup1.i.i.i
.Ltmp1184:
	jmp	.LBB160_229
.LBB160_165:                            # %cleanup3.body32.loopexit.split-lp.loopexit.split-lp.i.i.i.i.i
.Ltmp1139:
	jmp	.LBB160_166
.Lfunc_end160:
	.size	_ZN7just_bc4main17h75f1b496e4a6411bE, .Lfunc_end160-_ZN7just_bc4main17h75f1b496e4a6411bE
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table160:
.Lexception64:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end64-.Lcst_begin64
.Lcst_begin64:
	.uleb128 .Lfunc_begin64-.Lfunc_begin64 # >> Call Site 1 <<
	.uleb128 .Ltmp1018-.Lfunc_begin64 #   Call between .Lfunc_begin64 and .Ltmp1018
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1018-.Lfunc_begin64 # >> Call Site 2 <<
	.uleb128 .Ltmp1025-.Ltmp1018    #   Call between .Ltmp1018 and .Ltmp1025
	.uleb128 .Ltmp1226-.Lfunc_begin64 #     jumps to .Ltmp1226
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1026-.Lfunc_begin64 # >> Call Site 3 <<
	.uleb128 .Ltmp1027-.Ltmp1026    #   Call between .Ltmp1026 and .Ltmp1027
	.uleb128 .Ltmp1028-.Lfunc_begin64 #     jumps to .Ltmp1028
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1038-.Lfunc_begin64 # >> Call Site 4 <<
	.uleb128 .Ltmp1039-.Ltmp1038    #   Call between .Ltmp1038 and .Ltmp1039
	.uleb128 .Ltmp1040-.Lfunc_begin64 #     jumps to .Ltmp1040
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1043-.Lfunc_begin64 # >> Call Site 5 <<
	.uleb128 .Ltmp1046-.Ltmp1043    #   Call between .Ltmp1043 and .Ltmp1046
	.uleb128 .Ltmp1059-.Lfunc_begin64 #     jumps to .Ltmp1059
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1047-.Lfunc_begin64 # >> Call Site 6 <<
	.uleb128 .Ltmp1048-.Ltmp1047    #   Call between .Ltmp1047 and .Ltmp1048
	.uleb128 .Ltmp1049-.Lfunc_begin64 #     jumps to .Ltmp1049
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1050-.Lfunc_begin64 # >> Call Site 7 <<
	.uleb128 .Ltmp1053-.Ltmp1050    #   Call between .Ltmp1050 and .Ltmp1053
	.uleb128 .Ltmp1054-.Lfunc_begin64 #     jumps to .Ltmp1054
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1036-.Lfunc_begin64 # >> Call Site 8 <<
	.uleb128 .Ltmp1037-.Ltmp1036    #   Call between .Ltmp1036 and .Ltmp1037
	.uleb128 .Ltmp1215-.Lfunc_begin64 #     jumps to .Ltmp1215
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1210-.Lfunc_begin64 # >> Call Site 9 <<
	.uleb128 .Ltmp1211-.Ltmp1210    #   Call between .Ltmp1210 and .Ltmp1211
	.uleb128 .Ltmp1212-.Lfunc_begin64 #     jumps to .Ltmp1212
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1080-.Lfunc_begin64 # >> Call Site 10 <<
	.uleb128 .Ltmp1081-.Ltmp1080    #   Call between .Ltmp1080 and .Ltmp1081
	.uleb128 .Ltmp1149-.Lfunc_begin64 #     jumps to .Ltmp1149
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1162-.Lfunc_begin64 # >> Call Site 11 <<
	.uleb128 .Ltmp1163-.Ltmp1162    #   Call between .Ltmp1162 and .Ltmp1163
	.uleb128 .Ltmp1181-.Lfunc_begin64 #     jumps to .Ltmp1181
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1164-.Lfunc_begin64 # >> Call Site 12 <<
	.uleb128 .Ltmp1167-.Ltmp1164    #   Call between .Ltmp1164 and .Ltmp1167
	.uleb128 .Ltmp1170-.Lfunc_begin64 #     jumps to .Ltmp1170
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1179-.Lfunc_begin64 # >> Call Site 13 <<
	.uleb128 .Ltmp1180-.Ltmp1179    #   Call between .Ltmp1179 and .Ltmp1180
	.uleb128 .Ltmp1181-.Lfunc_begin64 #     jumps to .Ltmp1181
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1192-.Lfunc_begin64 # >> Call Site 14 <<
	.uleb128 .Ltmp1193-.Ltmp1192    #   Call between .Ltmp1192 and .Ltmp1193
	.uleb128 .Ltmp1194-.Lfunc_begin64 #     jumps to .Ltmp1194
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1087-.Lfunc_begin64 # >> Call Site 15 <<
	.uleb128 .Ltmp1088-.Ltmp1087    #   Call between .Ltmp1087 and .Ltmp1088
	.uleb128 .Ltmp1144-.Lfunc_begin64 #     jumps to .Ltmp1144
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1089-.Lfunc_begin64 # >> Call Site 16 <<
	.uleb128 .Ltmp1090-.Ltmp1089    #   Call between .Ltmp1089 and .Ltmp1090
	.uleb128 .Ltmp1139-.Lfunc_begin64 #     jumps to .Ltmp1139
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1129-.Lfunc_begin64 # >> Call Site 17 <<
	.uleb128 .Ltmp1092-.Ltmp1129    #   Call between .Ltmp1129 and .Ltmp1092
	.uleb128 .Ltmp1131-.Lfunc_begin64 #     jumps to .Ltmp1131
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1098-.Lfunc_begin64 # >> Call Site 18 <<
	.uleb128 .Ltmp1099-.Ltmp1098    #   Call between .Ltmp1098 and .Ltmp1099
	.uleb128 .Ltmp1100-.Lfunc_begin64 #     jumps to .Ltmp1100
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1093-.Lfunc_begin64 # >> Call Site 19 <<
	.uleb128 .Ltmp1094-.Ltmp1093    #   Call between .Ltmp1093 and .Ltmp1094
	.uleb128 .Ltmp1095-.Lfunc_begin64 #     jumps to .Ltmp1095
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1101-.Lfunc_begin64 # >> Call Site 20 <<
	.uleb128 .Ltmp1102-.Ltmp1101    #   Call between .Ltmp1101 and .Ltmp1102
	.uleb128 .Ltmp1103-.Lfunc_begin64 #     jumps to .Ltmp1103
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1106-.Lfunc_begin64 # >> Call Site 21 <<
	.uleb128 .Ltmp1107-.Ltmp1106    #   Call between .Ltmp1106 and .Ltmp1107
	.uleb128 .Ltmp1108-.Lfunc_begin64 #     jumps to .Ltmp1108
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1107-.Lfunc_begin64 # >> Call Site 22 <<
	.uleb128 .Ltmp1117-.Ltmp1107    #   Call between .Ltmp1107 and .Ltmp1117
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1117-.Lfunc_begin64 # >> Call Site 23 <<
	.uleb128 .Ltmp1113-.Ltmp1117    #   Call between .Ltmp1117 and .Ltmp1113
	.uleb128 .Ltmp1131-.Lfunc_begin64 #     jumps to .Ltmp1131
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1126-.Lfunc_begin64 # >> Call Site 24 <<
	.uleb128 .Ltmp1122-.Ltmp1126    #   Call between .Ltmp1126 and .Ltmp1122
	.uleb128 .Ltmp1128-.Lfunc_begin64 #     jumps to .Ltmp1128
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1123-.Lfunc_begin64 # >> Call Site 25 <<
	.uleb128 .Ltmp1124-.Ltmp1123    #   Call between .Ltmp1123 and .Ltmp1124
	.uleb128 .Ltmp1125-.Lfunc_begin64 #     jumps to .Ltmp1125
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1132-.Lfunc_begin64 # >> Call Site 26 <<
	.uleb128 .Ltmp1133-.Ltmp1132    #   Call between .Ltmp1132 and .Ltmp1133
	.uleb128 .Ltmp1134-.Lfunc_begin64 #     jumps to .Ltmp1134
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1142-.Lfunc_begin64 # >> Call Site 27 <<
	.uleb128 .Ltmp1143-.Ltmp1142    #   Call between .Ltmp1142 and .Ltmp1143
	.uleb128 .Ltmp1144-.Lfunc_begin64 #     jumps to .Ltmp1144
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1147-.Lfunc_begin64 # >> Call Site 28 <<
	.uleb128 .Ltmp1148-.Ltmp1147    #   Call between .Ltmp1147 and .Ltmp1148
	.uleb128 .Ltmp1149-.Lfunc_begin64 #     jumps to .Ltmp1149
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1159-.Lfunc_begin64 # >> Call Site 29 <<
	.uleb128 .Ltmp1160-.Ltmp1159    #   Call between .Ltmp1159 and .Ltmp1160
	.uleb128 .Ltmp1161-.Lfunc_begin64 #     jumps to .Ltmp1161
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1185-.Lfunc_begin64 # >> Call Site 30 <<
	.uleb128 .Ltmp1190-.Ltmp1185    #   Call between .Ltmp1185 and .Ltmp1190
	.uleb128 .Ltmp1191-.Lfunc_begin64 #     jumps to .Ltmp1191
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1152-.Lfunc_begin64 # >> Call Site 31 <<
	.uleb128 .Ltmp1157-.Ltmp1152    #   Call between .Ltmp1152 and .Ltmp1157
	.uleb128 .Ltmp1158-.Lfunc_begin64 #     jumps to .Ltmp1158
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1057-.Lfunc_begin64 # >> Call Site 32 <<
	.uleb128 .Ltmp1058-.Ltmp1057    #   Call between .Ltmp1057 and .Ltmp1058
	.uleb128 .Ltmp1059-.Lfunc_begin64 #     jumps to .Ltmp1059
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1069-.Lfunc_begin64 # >> Call Site 33 <<
	.uleb128 .Ltmp1070-.Ltmp1069    #   Call between .Ltmp1069 and .Ltmp1070
	.uleb128 .Ltmp1071-.Lfunc_begin64 #     jumps to .Ltmp1071
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1062-.Lfunc_begin64 # >> Call Site 34 <<
	.uleb128 .Ltmp1067-.Ltmp1062    #   Call between .Ltmp1062 and .Ltmp1067
	.uleb128 .Ltmp1068-.Lfunc_begin64 #     jumps to .Ltmp1068
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1072-.Lfunc_begin64 # >> Call Site 35 <<
	.uleb128 .Ltmp1073-.Ltmp1072    #   Call between .Ltmp1072 and .Ltmp1073
	.uleb128 .Ltmp1074-.Lfunc_begin64 #     jumps to .Ltmp1074
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1197-.Lfunc_begin64 # >> Call Site 36 <<
	.uleb128 .Ltmp1198-.Ltmp1197    #   Call between .Ltmp1197 and .Ltmp1198
	.uleb128 .Ltmp1199-.Lfunc_begin64 #     jumps to .Ltmp1199
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1202-.Lfunc_begin64 # >> Call Site 37 <<
	.uleb128 .Ltmp1203-.Ltmp1202    #   Call between .Ltmp1202 and .Ltmp1203
	.uleb128 .Ltmp1204-.Lfunc_begin64 #     jumps to .Ltmp1204
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1205-.Lfunc_begin64 # >> Call Site 38 <<
	.uleb128 .Ltmp1206-.Ltmp1205    #   Call between .Ltmp1205 and .Ltmp1206
	.uleb128 .Ltmp1226-.Lfunc_begin64 #     jumps to .Ltmp1226
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1207-.Lfunc_begin64 # >> Call Site 39 <<
	.uleb128 .Ltmp1208-.Ltmp1207    #   Call between .Ltmp1207 and .Ltmp1208
	.uleb128 .Ltmp1209-.Lfunc_begin64 #     jumps to .Ltmp1209
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1208-.Lfunc_begin64 # >> Call Site 40 <<
	.uleb128 .Ltmp1171-.Ltmp1208    #   Call between .Ltmp1208 and .Ltmp1171
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1171-.Lfunc_begin64 # >> Call Site 41 <<
	.uleb128 .Ltmp1172-.Ltmp1171    #   Call between .Ltmp1171 and .Ltmp1172
	.uleb128 .Ltmp1173-.Lfunc_begin64 #     jumps to .Ltmp1173
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1114-.Lfunc_begin64 # >> Call Site 42 <<
	.uleb128 .Ltmp1115-.Ltmp1114    #   Call between .Ltmp1114 and .Ltmp1115
	.uleb128 .Ltmp1116-.Lfunc_begin64 #     jumps to .Ltmp1116
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1119-.Lfunc_begin64 # >> Call Site 43 <<
	.uleb128 .Ltmp1120-.Ltmp1119    #   Call between .Ltmp1119 and .Ltmp1120
	.uleb128 .Ltmp1139-.Lfunc_begin64 #     jumps to .Ltmp1139
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1219-.Lfunc_begin64 # >> Call Site 44 <<
	.uleb128 .Ltmp1220-.Ltmp1219    #   Call between .Ltmp1219 and .Ltmp1220
	.uleb128 .Ltmp1221-.Lfunc_begin64 #     jumps to .Ltmp1221
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1031-.Lfunc_begin64 # >> Call Site 45 <<
	.uleb128 .Ltmp1032-.Ltmp1031    #   Call between .Ltmp1031 and .Ltmp1032
	.uleb128 .Ltmp1033-.Lfunc_begin64 #     jumps to .Ltmp1033
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1082-.Lfunc_begin64 # >> Call Site 46 <<
	.uleb128 .Ltmp1083-.Ltmp1082    #   Call between .Ltmp1082 and .Ltmp1083
	.uleb128 .Ltmp1084-.Lfunc_begin64 #     jumps to .Ltmp1084
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1075-.Lfunc_begin64 # >> Call Site 47 <<
	.uleb128 .Ltmp1076-.Ltmp1075    #   Call between .Ltmp1075 and .Ltmp1076
	.uleb128 .Ltmp1077-.Lfunc_begin64 #     jumps to .Ltmp1077
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1085-.Lfunc_begin64 # >> Call Site 48 <<
	.uleb128 .Ltmp1086-.Ltmp1085    #   Call between .Ltmp1085 and .Ltmp1086
	.uleb128 .Ltmp1149-.Lfunc_begin64 #     jumps to .Ltmp1149
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1034-.Lfunc_begin64 # >> Call Site 49 <<
	.uleb128 .Ltmp1035-.Ltmp1034    #   Call between .Ltmp1034 and .Ltmp1035
	.uleb128 .Ltmp1215-.Lfunc_begin64 #     jumps to .Ltmp1215
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1222-.Lfunc_begin64 # >> Call Site 50 <<
	.uleb128 .Ltmp1225-.Ltmp1222    #   Call between .Ltmp1222 and .Ltmp1225
	.uleb128 .Ltmp1226-.Lfunc_begin64 #     jumps to .Ltmp1226
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1213-.Lfunc_begin64 # >> Call Site 51 <<
	.uleb128 .Ltmp1214-.Ltmp1213    #   Call between .Ltmp1213 and .Ltmp1214
	.uleb128 .Ltmp1215-.Lfunc_begin64 #     jumps to .Ltmp1215
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1174-.Lfunc_begin64 # >> Call Site 52 <<
	.uleb128 .Ltmp1175-.Ltmp1174    #   Call between .Ltmp1174 and .Ltmp1175
	.uleb128 .Ltmp1176-.Lfunc_begin64 #     jumps to .Ltmp1176
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1175-.Lfunc_begin64 # >> Call Site 53 <<
	.uleb128 .Ltmp1041-.Ltmp1175    #   Call between .Ltmp1175 and .Ltmp1041
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1041-.Lfunc_begin64 # >> Call Site 54 <<
	.uleb128 .Ltmp1042-.Ltmp1041    #   Call between .Ltmp1041 and .Ltmp1042
	.uleb128 .Ltmp1184-.Lfunc_begin64 #     jumps to .Ltmp1184
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1200-.Lfunc_begin64 # >> Call Site 55 <<
	.uleb128 .Ltmp1201-.Ltmp1200    #   Call between .Ltmp1200 and .Ltmp1201
	.uleb128 .Ltmp1204-.Lfunc_begin64 #     jumps to .Ltmp1204
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1029-.Lfunc_begin64 # >> Call Site 56 <<
	.uleb128 .Ltmp1030-.Ltmp1029    #   Call between .Ltmp1029 and .Ltmp1030
	.uleb128 .Ltmp1215-.Lfunc_begin64 #     jumps to .Ltmp1215
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1216-.Lfunc_begin64 # >> Call Site 57 <<
	.uleb128 .Ltmp1217-.Ltmp1216    #   Call between .Ltmp1216 and .Ltmp1217
	.uleb128 .Ltmp1218-.Lfunc_begin64 #     jumps to .Ltmp1218
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1055-.Lfunc_begin64 # >> Call Site 58 <<
	.uleb128 .Ltmp1061-.Ltmp1055    #   Call between .Ltmp1055 and .Ltmp1061
	.uleb128 .Ltmp1077-.Lfunc_begin64 #     jumps to .Ltmp1077
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1078-.Lfunc_begin64 # >> Call Site 59 <<
	.uleb128 .Ltmp1183-.Ltmp1078    #   Call between .Ltmp1078 and .Ltmp1183
	.uleb128 .Ltmp1184-.Lfunc_begin64 #     jumps to .Ltmp1184
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1109-.Lfunc_begin64 # >> Call Site 60 <<
	.uleb128 .Ltmp1110-.Ltmp1109    #   Call between .Ltmp1109 and .Ltmp1110
	.uleb128 .Ltmp1111-.Lfunc_begin64 #     jumps to .Ltmp1111
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1096-.Lfunc_begin64 # >> Call Site 61 <<
	.uleb128 .Ltmp1097-.Ltmp1096    #   Call between .Ltmp1096 and .Ltmp1097
	.uleb128 .Ltmp1139-.Lfunc_begin64 #     jumps to .Ltmp1139
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1104-.Lfunc_begin64 # >> Call Site 62 <<
	.uleb128 .Ltmp1105-.Ltmp1104    #   Call between .Ltmp1104 and .Ltmp1105
	.uleb128 .Ltmp1134-.Lfunc_begin64 #     jumps to .Ltmp1134
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1137-.Lfunc_begin64 # >> Call Site 63 <<
	.uleb128 .Ltmp1136-.Ltmp1137    #   Call between .Ltmp1137 and .Ltmp1136
	.uleb128 .Ltmp1139-.Lfunc_begin64 #     jumps to .Ltmp1139
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1140-.Lfunc_begin64 # >> Call Site 64 <<
	.uleb128 .Ltmp1151-.Ltmp1140    #   Call between .Ltmp1140 and .Ltmp1151
	.uleb128 .Ltmp1184-.Lfunc_begin64 #     jumps to .Ltmp1184
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1195-.Lfunc_begin64 # >> Call Site 65 <<
	.uleb128 .Ltmp1196-.Ltmp1195    #   Call between .Ltmp1195 and .Ltmp1196
	.uleb128 .Ltmp1218-.Lfunc_begin64 #     jumps to .Ltmp1218
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1196-.Lfunc_begin64 # >> Call Site 66 <<
	.uleb128 .Lfunc_end160-.Ltmp1196 #   Call between .Ltmp1196 and .Lfunc_end160
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end64:
	.p2align	2
                                        # -- End function
	.text
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:                                # %top
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	%rsi, %rcx
	movslq	%edi, %rdx
	movq	$_ZN7just_bc4main17h75f1b496e4a6411bE, (%rsp)
	movq	%rsp, %rdi
	movl	$.Lvtable.0, %esi
	callq	*_ZN3std2rt19lang_start_internal17h14e7168ba039f170E@GOTPCREL(%rip)
                                        # kill: def $eax killed $eax killed $rax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end161:
	.size	main, .Lfunc_end161-main
	.cfi_endproc
                                        # -- End function
	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.0,@object # @anon.112aa5216417f3e30cbfa40815f3b444.0
	.section	.rodata,"a",@progbits
.Lanon.112aa5216417f3e30cbfa40815f3b444.0:
	.ascii	"stream did not contain valid UTF-8"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.0, 34

	.type	.Lvtable.0,@object      # @vtable.0
	.p2align	3
.Lvtable.0:
	.quad	_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE
	.quad	8                       # 0x8
	.quad	8                       # 0x8
	.quad	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE
	.quad	_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0ea676343dfb611dE
	.quad	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h3e432dc8d786e559E
	.size	.Lvtable.0, 48

	.type	.Lvtable.1,@object      # @vtable.1
	.p2align	3
.Lvtable.1:
	.quad	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN59_$LT$std..io..error..Error$u20$as$u20$std..error..Error$GT$11description17he40877cea95c4584E
	.quad	_ZN59_$LT$std..io..error..Error$u20$as$u20$std..error..Error$GT$5cause17hddd36968f8f5a547E
	.quad	_ZN59_$LT$std..io..error..Error$u20$as$u20$std..error..Error$GT$6source17he73be4a4d7732f87E
	.quad	_ZN3std5error5Error7type_id17h59d9d71ba629941fE
	.quad	_ZN3std5error5Error9backtrace17he692434e154190d0E
	.quad	_ZN60_$LT$std..io..error..Error$u20$as$u20$core..fmt..Display$GT$3fmt17ha002db5de735283eE
	.quad	_ZN58_$LT$std..io..error..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h80d51771597be04eE
	.size	.Lvtable.1, 80

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.1,@object # @anon.112aa5216417f3e30cbfa40815f3b444.1
.Lanon.112aa5216417f3e30cbfa40815f3b444.1:
	.ascii	"TLS Context not set. This is a rustc bug. Please file an issue on https://github.com/rust-lang/rust."
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.1, 100

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.2,@object # @anon.112aa5216417f3e30cbfa40815f3b444.2
.Lanon.112aa5216417f3e30cbfa40815f3b444.2:
	.ascii	"cannot access a Thread Local Storage value during or after destruction"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.2, 70

	.type	.Lvtable.2,@object      # @vtable.2
	.p2align	3
.Lvtable.2:
	.quad	_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$8take_box17hac6307d4e5f1ec34E
	.quad	_ZN91_$LT$std..panicking..begin_panic..PanicPayload$LT$A$GT$$u20$as$u20$core..panic..BoxMeUp$GT$3get17ha5c708c3e23a8ee2E
	.size	.Lvtable.2, 40

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.3,@object # @anon.112aa5216417f3e30cbfa40815f3b444.3
.Lanon.112aa5216417f3e30cbfa40815f3b444.3:
	.ascii	"()"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.3, 2

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.4,@object # @anon.112aa5216417f3e30cbfa40815f3b444.4
	.section	.rodata.cst16,"aM",@progbits,16
.Lanon.112aa5216417f3e30cbfa40815f3b444.4:
	.ascii	"already borrowed"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.4, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.5,@object # @anon.112aa5216417f3e30cbfa40815f3b444.5
	.section	.rodata,"a",@progbits
.Lanon.112aa5216417f3e30cbfa40815f3b444.5:
	.ascii	"/rustc/5e1a799842ba6ed4a57e91f7ab9435947482f7d8/src/libcore/macros/mod.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.5, 73

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.6,@object # @anon.112aa5216417f3e30cbfa40815f3b444.6
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.6:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.5
	.asciz	"I\000\000\000\000\000\000\000\017\000\000\000(\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.6, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.7,@object # @anon.112aa5216417f3e30cbfa40815f3b444.7
.Lanon.112aa5216417f3e30cbfa40815f3b444.7:
	.ascii	"assertion failed: mid <= len"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.7, 28

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.8,@object # @anon.112aa5216417f3e30cbfa40815f3b444.8
.Lanon.112aa5216417f3e30cbfa40815f3b444.8:
	.ascii	"called `Option::unwrap()` on a `None` value"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.8, 43

	.type	.Lvtable.3,@object      # @vtable.3
	.p2align	3
.Lvtable.3:
	.quad	_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.quad	0                       # 0x0
	.quad	1                       # 0x1
	.quad	_ZN68_$LT$std..thread..local..AccessError$u20$as$u20$core..fmt..Debug$GT$3fmt17he87ee9ea4512019bE
	.size	.Lvtable.3, 32

	.type	.Lvtable.4,@object      # @vtable.4
	.p2align	3
.Lvtable.4:
	.quad	_ZN4core3ptr18real_drop_in_place17h664ae0e66d8bb2d1E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN58_$LT$std..io..error..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h80d51771597be04eE
	.size	.Lvtable.4, 32

	.type	.Lvtable.5,@object      # @vtable.5
	.p2align	3
.Lvtable.5:
	.quad	_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.quad	0                       # 0x0
	.quad	1                       # 0x1
	.quad	_ZN63_$LT$core..cell..BorrowMutError$u20$as$u20$core..fmt..Debug$GT$3fmt17he84d908d86d62dc0E
	.size	.Lvtable.5, 32

	.type	.Lvtable.6,@object      # @vtable.6
	.p2align	3
.Lvtable.6:
	.quad	_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.quad	0                       # 0x0
	.quad	1                       # 0x1
	.quad	_ZN45_$LT$$LP$$RP$$u20$as$u20$core..fmt..Debug$GT$3fmt17he0b7e4faabc5658fE
	.size	.Lvtable.6, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.9,@object # @anon.112aa5216417f3e30cbfa40815f3b444.9
.Lanon.112aa5216417f3e30cbfa40815f3b444.9:
	.ascii	"called `Result::unwrap()` on an `Err` value"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.9, 43

	.type	.Lvtable.7,@object      # @vtable.7
	.p2align	3
.Lvtable.7:
	.quad	_ZN4core3ptr18real_drop_in_place17h66967e7ef667e5e9E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN82_$LT$std..sys_common..poison..PoisonError$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hf9cbaa475d0c625bE
	.size	.Lvtable.7, 32

	.type	.Lvtable.8,@object      # @vtable.8
	.p2align	3
.Lvtable.8:
	.quad	_ZN4core3ptr18real_drop_in_place17hb375d059e9ff58beE
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN77_$LT$tokio..park..either..Either$LT$A$C$B$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h512c0ff93e9d314dE
	.size	.Lvtable.8, 32

	.type	.Lvtable.9,@object      # @vtable.9
	.p2align	3
.Lvtable.9:
	.quad	_ZN4core3ptr18real_drop_in_place17h801f84abd31e57b7E
	.quad	0                       # 0x0
	.quad	1                       # 0x1
	.quad	_ZN59_$LT$core..alloc..LayoutErr$u20$as$u20$core..fmt..Debug$GT$3fmt17h851cba66435ade30E
	.size	.Lvtable.9, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.10,@object # @anon.112aa5216417f3e30cbfa40815f3b444.10
.Lanon.112aa5216417f3e30cbfa40815f3b444.10:
	.ascii	"Tried to shrink to a larger capacity"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.10, 36

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.11,@object # @anon.112aa5216417f3e30cbfa40815f3b444.11
.Lanon.112aa5216417f3e30cbfa40815f3b444.11:
	.ascii	"<::core::macros::panic macros>"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.11, 30

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.12,@object # @anon.112aa5216417f3e30cbfa40815f3b444.12
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.12:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.11
	.asciz	"\036\000\000\000\000\000\000\000\003\000\000\000\n\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.12, 24

	.type	.Lvtable.a,@object      # @vtable.a
	.p2align	3
.Lvtable.a:
	.quad	_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN70_$LT$mio..net..tcp..TcpListener$u20$as$u20$mio..event_imp..Evented$GT$8register17ha2cf03b5311a5922E
	.quad	_ZN70_$LT$mio..net..tcp..TcpListener$u20$as$u20$mio..event_imp..Evented$GT$10reregister17hd7ea0235cc2154fcE
	.quad	_ZN70_$LT$mio..net..tcp..TcpListener$u20$as$u20$mio..event_imp..Evented$GT$10deregister17h82b2ff00732d37f0E
	.size	.Lvtable.a, 48

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.13,@object # @anon.112aa5216417f3e30cbfa40815f3b444.13
.Lanon.112aa5216417f3e30cbfa40815f3b444.13:
	.ascii	"reactor gone"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.13, 12

	.type	.Lvtable.b,@object      # @vtable.b
	.p2align	3
.Lvtable.b:
	.quad	_ZN4core3ptr18real_drop_in_place17h1dfbf6d2047bdac8E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN68_$LT$mio..net..tcp..TcpStream$u20$as$u20$mio..event_imp..Evented$GT$8register17hc808485d1d0dc7dbE
	.quad	_ZN68_$LT$mio..net..tcp..TcpStream$u20$as$u20$mio..event_imp..Evented$GT$10reregister17h0f516ae1b10b3c84E
	.quad	_ZN68_$LT$mio..net..tcp..TcpStream$u20$as$u20$mio..event_imp..Evented$GT$10deregister17hbae7c9b5ade424e3E
	.size	.Lvtable.b, 48

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.14,@object # @anon.112aa5216417f3e30cbfa40815f3b444.14
.Lanon.112aa5216417f3e30cbfa40815f3b444.14:
	.ascii	"/home/addisoncrump/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-0.2.13/src/net/tcp/listener.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.14, 103

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.15,@object # @anon.112aa5216417f3e30cbfa40815f3b444.15
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.15:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.14
	.asciz	"g\000\000\000\000\000\000\000k\000\000\000M\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.15, 24

	.type	str.c,@object           # @str.c
	.p2align	4
str.c:
	.ascii	"`async fn` resumed after panicking"
	.size	str.c, 34

	.type	str.d,@object           # @str.d
	.p2align	4
str.d:
	.ascii	"`async fn` resumed after completion"
	.size	str.d, 35

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.16,@object # @anon.112aa5216417f3e30cbfa40815f3b444.16
	.section	.rodata.cst32,"aM",@progbits,32
.Lanon.112aa5216417f3e30cbfa40815f3b444.16:
	.ascii	"could not resolve to any address"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.16, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.17,@object # @anon.112aa5216417f3e30cbfa40815f3b444.17
	.section	.rodata,"a",@progbits
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.17:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.14
	.asciz	"g\000\000\000\000\000\000\000\237\000\000\000K\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.17, 24

	.type	.Lvtable.e,@object      # @vtable.e
	.p2align	3
.Lvtable.e:
	.quad	_ZN4core3ptr18real_drop_in_place17h17dac8a9e600688dE
	.quad	8                       # 0x8
	.quad	8                       # 0x8
	.quad	_ZN5tokio4task13Task$LT$S$GT$3run28_$u7b$$u7b$closure$u7d$$u7d$17h77a11ed1fa830a5cE
	.quad	_ZN4core3ops8function6FnOnce40call_once$u7b$$u7b$vtable.shim$u7d$$u7d$17h55201cde9aab2698E
	.size	.Lvtable.e, 40

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.18,@object # @anon.112aa5216417f3e30cbfa40815f3b444.18
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.18:
	.quad	_ZN5tokio4task3raw4poll17h8ae230134c718f4fE
	.quad	_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E
	.quad	_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E
	.quad	_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E
	.quad	_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E
	.quad	_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E
	.quad	_ZN5tokio4task3raw6cancel17h440673ff578b8afaE
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.18, 56

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.19,@object # @anon.112aa5216417f3e30cbfa40815f3b444.19
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.19:
	.quad	_ZN5tokio4task3raw4poll17h03fbca31b17747c9E
	.quad	_ZN5tokio4task3raw9drop_task17h422ee28bbd3f3a28E
	.quad	_ZN5tokio4task3raw11read_output17h71d9a739bc9e2fb8E
	.quad	_ZN5tokio4task3raw16store_join_waker17h1bbe26763ba3ece0E
	.quad	_ZN5tokio4task3raw15swap_join_waker17h7a617f21a6f3a220E
	.quad	_ZN5tokio4task3raw21drop_join_handle_slow17h9c3478b8a780d847E
	.quad	_ZN5tokio4task3raw6cancel17h1c94218425a95fb3E
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.19, 56

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.20,@object # @anon.112aa5216417f3e30cbfa40815f3b444.20
.Lanon.112aa5216417f3e30cbfa40815f3b444.20:
	.ascii	"internal error: entered unreachable code: "
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.20, 42

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.21,@object # @anon.112aa5216417f3e30cbfa40815f3b444.21
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.21:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.20
	.asciz	"*\000\000\000\000\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.21, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.22,@object # @anon.112aa5216417f3e30cbfa40815f3b444.22
	.section	.rodata.cst16,"aM",@progbits,16
.Lanon.112aa5216417f3e30cbfa40815f3b444.22:
	.ascii	"unexpected state"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.22, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.23,@object # @anon.112aa5216417f3e30cbfa40815f3b444.23
	.section	.rodata,"a",@progbits
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.23:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.22
	.asciz	"\020\000\000\000\000\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.23, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.24,@object # @anon.112aa5216417f3e30cbfa40815f3b444.24
.Lanon.112aa5216417f3e30cbfa40815f3b444.24:
	.ascii	"/home/addisoncrump/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-0.2.13/src/task/core.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.24, 96

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.25,@object # @anon.112aa5216417f3e30cbfa40815f3b444.25
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.25:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.24
	.asciz	"`\000\000\000\000\000\000\000\223\000\000\000\022\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.25, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.26,@object # @anon.112aa5216417f3e30cbfa40815f3b444.26
	.section	.rodata.cst16,"aM",@progbits,16
.Lanon.112aa5216417f3e30cbfa40815f3b444.26:
	.ascii	"unexpected stage"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.26, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.27,@object # @anon.112aa5216417f3e30cbfa40815f3b444.27
	.section	.rodata,"a",@progbits
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.27:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.26
	.asciz	"\020\000\000\000\000\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.27, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.28,@object # @anon.112aa5216417f3e30cbfa40815f3b444.28
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.28:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.24
	.asciz	"`\000\000\000\000\000\000\000t\000\000\000\026\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.28, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.29,@object # @anon.112aa5216417f3e30cbfa40815f3b444.29
.Lanon.112aa5216417f3e30cbfa40815f3b444.29:
	.ascii	"/home/addisoncrump/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-0.2.13/src/task/queue.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.29, 97

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.30,@object # @anon.112aa5216417f3e30cbfa40815f3b444.30
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.30:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.29
	.asciz	"a\000\000\000\000\000\000\000\017\001\000\000\033\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.30, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.31,@object # @anon.112aa5216417f3e30cbfa40815f3b444.31
.Lanon.112aa5216417f3e30cbfa40815f3b444.31:
	.ascii	"mutex poisoned"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.31, 14

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.32,@object # @anon.112aa5216417f3e30cbfa40815f3b444.32
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.32:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.29
	.asciz	"a\000\000\000\000\000\000\000\252\000\000\000\027\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.32, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.33,@object # @anon.112aa5216417f3e30cbfa40815f3b444.33
.Lanon.112aa5216417f3e30cbfa40815f3b444.33:
	.ascii	"must be called from the context of Tokio runtime configured with either `basic_scheduler` or `threaded_scheduler`"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.33, 113

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.34,@object # @anon.112aa5216417f3e30cbfa40815f3b444.34
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.34:
	.quad	_ZN5tokio4task5waker11clone_waker17haa21f8752533c19fE
	.quad	_ZN5tokio4task5waker11wake_by_val17h41615f92ed329f52E
	.quad	_ZN5tokio4task5waker11wake_by_ref17h978abe5b8a260ec3E
	.quad	_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.34, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.35,@object # @anon.112aa5216417f3e30cbfa40815f3b444.35
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.35:
	.quad	_ZN5tokio4task5waker11clone_waker17h801246328d671f18E
	.quad	_ZN5tokio4task5waker11wake_by_val17hec852c706a13295aE
	.quad	_ZN5tokio4task5waker11wake_by_ref17h66cc40f6f15cdd3cE
	.quad	_ZN5tokio4task5waker10drop_waker17h18c726c8746677b4E
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.35, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.36,@object # @anon.112aa5216417f3e30cbfa40815f3b444.36
.Lanon.112aa5216417f3e30cbfa40815f3b444.36:
	.ascii	"/home/addisoncrump/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-0.2.13/src/task/harness.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.36, 99

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.37,@object # @anon.112aa5216417f3e30cbfa40815f3b444.37
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.37:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.36
	.asciz	"c\000\000\000\000\000\000\0004\001\000\000\035\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.37, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.38,@object # @anon.112aa5216417f3e30cbfa40815f3b444.38
.Lanon.112aa5216417f3e30cbfa40815f3b444.38:
	.ascii	"executor should be set"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.38, 22

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.39,@object # @anon.112aa5216417f3e30cbfa40815f3b444.39
.Lanon.112aa5216417f3e30cbfa40815f3b444.39:
	.ascii	"first poll must happen from an executor"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.39, 39

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.40,@object # @anon.112aa5216417f3e30cbfa40815f3b444.40
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.40:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.36
	.asciz	"c\000\000\000\000\000\000\000\256\001\000\000\r\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.40, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.41,@object # @anon.112aa5216417f3e30cbfa40815f3b444.41
.Lanon.112aa5216417f3e30cbfa40815f3b444.41:
	.ascii	"assertion failed: !res.is_final_ref()"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.41, 37

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.42,@object # @anon.112aa5216417f3e30cbfa40815f3b444.42
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.42:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.36
	.asciz	"c\000\000\000\000\000\000\000\275\001\000\000\035\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.42, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.43,@object # @anon.112aa5216417f3e30cbfa40815f3b444.43
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.43:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.36
	.asciz	"c\000\000\000\000\000\000\000y\001\000\000\t\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.43, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.44,@object # @anon.112aa5216417f3e30cbfa40815f3b444.44
	.section	.rodata.cst8,"aM",@progbits,8
.Lanon.112aa5216417f3e30cbfa40815f3b444.44:
	.ascii	"state = "
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.44, 8

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.45,@object # @anon.112aa5216417f3e30cbfa40815f3b444.45
	.section	.rodata,"a",@progbits
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.45:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.44
	.asciz	"\b\000\000\000\000\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.45, 16

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.46,@object # @anon.112aa5216417f3e30cbfa40815f3b444.46
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.46:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.36
	.asciz	"c\000\000\000\000\000\000\000\243\000\000\000\t\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.46, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.47,@object # @anon.112aa5216417f3e30cbfa40815f3b444.47
.Lanon.112aa5216417f3e30cbfa40815f3b444.47:
	.ascii	"waker missing"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.47, 13

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.48,@object # @anon.112aa5216417f3e30cbfa40815f3b444.48
.Lanon.112aa5216417f3e30cbfa40815f3b444.48:
	.ascii	"failed to park thread"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.48, 21

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.49,@object # @anon.112aa5216417f3e30cbfa40815f3b444.49
.Lanon.112aa5216417f3e30cbfa40815f3b444.49:
	.ascii	"/home/addisoncrump/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-0.2.13/src/runtime/thread_pool/queue/local.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.49, 118

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.50,@object # @anon.112aa5216417f3e30cbfa40815f3b444.50
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.50:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.49
	.asciz	"v\000\000\000\000\000\000\000\251\000\000\000\030\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.50, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.51,@object # @anon.112aa5216417f3e30cbfa40815f3b444.51
.Lanon.112aa5216417f3e30cbfa40815f3b444.51:
	.ascii	"failed to park"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.51, 14

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.52,@object # @anon.112aa5216417f3e30cbfa40815f3b444.52
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.52:
	.quad	_ZN5tokio7runtime15basic_scheduler17sched_clone_waker17ha3df2b658df03654E
	.quad	_ZN5tokio7runtime15basic_scheduler10sched_noop17h3663dcd2af1f450dE
	.quad	_ZN5tokio7runtime15basic_scheduler17sched_wake_by_ref17h0f227d041b496857E
	.quad	_ZN5tokio7runtime15basic_scheduler10sched_noop17h3663dcd2af1f450dE
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.52, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.53,@object # @anon.112aa5216417f3e30cbfa40815f3b444.53
.Lanon.112aa5216417f3e30cbfa40815f3b444.53:
	.ascii	"/home/addisoncrump/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-0.2.13/src/runtime/spawner.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.53, 102

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.54,@object # @anon.112aa5216417f3e30cbfa40815f3b444.54
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.54:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.53
	.asciz	"f\000\000\000\000\000\000\000\035\000\000\000#\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.54, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.55,@object # @anon.112aa5216417f3e30cbfa40815f3b444.55
	.section	.rodata.cst32,"aM",@progbits,32
.Lanon.112aa5216417f3e30cbfa40815f3b444.55:
	.ascii	"spawning not enabled for runtime"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.55, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.56,@object # @anon.112aa5216417f3e30cbfa40815f3b444.56
	.section	.rodata,"a",@progbits
.Lanon.112aa5216417f3e30cbfa40815f3b444.56:
	.ascii	"PoisonError { inner: .. }"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.56, 25

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.57,@object # @anon.112aa5216417f3e30cbfa40815f3b444.57
.Lanon.112aa5216417f3e30cbfa40815f3b444.57:
	.ascii	"Error: "
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.57, 7

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.58,@object # @anon.112aa5216417f3e30cbfa40815f3b444.58
.Lanon.112aa5216417f3e30cbfa40815f3b444.58:
	.byte	10
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.58, 1

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.59,@object # @anon.112aa5216417f3e30cbfa40815f3b444.59
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.59:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.57
	.asciz	"\007\000\000\000\000\000\000"
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.58
	.asciz	"\001\000\000\000\000\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.59, 32

	.type	.Lvtable.f,@object      # @vtable.f
	.p2align	3
.Lvtable.f:
	.quad	_ZN4core3ptr18real_drop_in_place17h2c3b0f290c9aa1b2E
	.quad	16                      # 0x10
	.quad	8                       # 0x8
	.quad	_ZN36_$LT$T$u20$as$u20$core..any..Any$GT$7type_id17h3e94f3669ad6df0bE
	.size	.Lvtable.f, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.60,@object # @anon.112aa5216417f3e30cbfa40815f3b444.60
.Lanon.112aa5216417f3e30cbfa40815f3b444.60:
	.ascii	"park failed"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.60, 11

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.61,@object # @anon.112aa5216417f3e30cbfa40815f3b444.61
.Lanon.112aa5216417f3e30cbfa40815f3b444.61:
	.ascii	"lmaoniceonebuddypalfriendolino"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.61, 30

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.62,@object # @anon.112aa5216417f3e30cbfa40815f3b444.62
.Lanon.112aa5216417f3e30cbfa40815f3b444.62:
	.ascii	"src/main.rs"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.62, 11

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.63,@object # @anon.112aa5216417f3e30cbfa40815f3b444.63
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.63:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.62
	.asciz	"\013\000\000\000\000\000\000\000\030\000\000\000!\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.63, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.64,@object # @anon.112aa5216417f3e30cbfa40815f3b444.64
.Lanon.112aa5216417f3e30cbfa40815f3b444.64:
	.ascii	"Password: "
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.64, 10

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.65,@object # @anon.112aa5216417f3e30cbfa40815f3b444.65
.Lanon.112aa5216417f3e30cbfa40815f3b444.65:
	.ascii	"failed to write data to socket"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.65, 30

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.66,@object # @anon.112aa5216417f3e30cbfa40815f3b444.66
.Lanon.112aa5216417f3e30cbfa40815f3b444.66:
	.ascii	"couldn't read from input stream"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.66, 31

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.67,@object # @anon.112aa5216417f3e30cbfa40815f3b444.67
.Lanon.112aa5216417f3e30cbfa40815f3b444.67:
	.ascii	"Captured attempt: "
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.67, 18

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.68,@object # @anon.112aa5216417f3e30cbfa40815f3b444.68
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.68:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.67
	.asciz	"\022\000\000\000\000\000\000"
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.58
	.asciz	"\001\000\000\000\000\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.68, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.69,@object # @anon.112aa5216417f3e30cbfa40815f3b444.69
.Lanon.112aa5216417f3e30cbfa40815f3b444.69:
	.ascii	"/flag.txt"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.69, 9

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.70,@object # @anon.112aa5216417f3e30cbfa40815f3b444.70
.Lanon.112aa5216417f3e30cbfa40815f3b444.70:
	.ascii	"flag.txt wasn't found"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.70, 21

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.71,@object # @anon.112aa5216417f3e30cbfa40815f3b444.71
.Lanon.112aa5216417f3e30cbfa40815f3b444.71:
	.ascii	"flag.txt wasn't readable"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.71, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.72,@object # @anon.112aa5216417f3e30cbfa40815f3b444.72
	.section	.rodata.cst32,"aM",@progbits,32
.Lanon.112aa5216417f3e30cbfa40815f3b444.72:
	.ascii	"lmao nice try, but that's not it"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.72, 32

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.73,@object # @anon.112aa5216417f3e30cbfa40815f3b444.73
	.section	.rodata,"a",@progbits
	.p2align	3
.Lanon.112aa5216417f3e30cbfa40815f3b444.73:
	.quad	.Lanon.112aa5216417f3e30cbfa40815f3b444.62
	.asciz	"\013\000\000\000\000\000\000\000\020\000\000\000\001\000\000"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.73, 24

	.type	.Lanon.112aa5216417f3e30cbfa40815f3b444.74,@object # @anon.112aa5216417f3e30cbfa40815f3b444.74
.Lanon.112aa5216417f3e30cbfa40815f3b444.74:
	.ascii	"0.0.0.0:4932"
	.size	.Lanon.112aa5216417f3e30cbfa40815f3b444.74, 12

	.section	".note.GNU-stack","",@progbits
