
	.file	"__libc_start_main.S"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * .text
 ****************************************************************************/

	.text
    .code64

/****************************************************************************
 * Public Symbols
 ****************************************************************************/
    .global __libc_start_main


/****************************************************************************
 * Name: __libc_start_main
 *
 * Description:
 *   grab the main address and return using rsi as RIP
 *
 ****************************************************************************/

	.type	__libc_start_main, @function
__libc_start_main:

    // _start pushed rax and rsp, can calling __libc_start_main will push rip
    // reduce stack by 3 * 8 bytes to recover stack before calling _start
    leaq 24(%rsp), %rsp

    // _start pop return rip into rsi, push it back to stack fake a return from _start
    pushq %rsi
    
    // _start has passed embedded value of main address as first parameter, return it
    mov %rdi, %rax

    ret

	.size	__libc_start_main, . - __libc_start_main
