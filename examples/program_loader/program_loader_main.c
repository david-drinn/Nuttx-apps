/****************************************************************************
 * apps/examples/ostest/ostest_main.c
 *
 *   Copyright (C) 2007-2009, 2011-2012, 2014-2015 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/wait.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <syscall.h>

#include <nuttx/init.h>
#include <nuttx/sched.h>
#include <nuttx/mm/mm.h>

#include "program_loader.h"

/*extern struct tcb_s *this_task(void);*/

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define PRIORITY         100
#define NARGS              4
#define HALF_SECOND_USEC 500000L

#define MAX_PCB 4

#define ATTR_MORE 0x1

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct mallinfo g_mmbefore;
static struct mallinfo g_mmprevious;
static struct mallinfo g_mmafter;

enum{
    PING,
    PONG,
    RETURN,
    LOAD,
    START,
    TRASH,
    MAX_TYPE
};

struct packet_header{
    uint16_t type;
    uint32_t attribute;
    uint32_t fragement_number;
    uint32_t length;
} __attribute__((packed));

struct pcb{
    int pid;
    size_t size;
    void* base_address;
};

struct pcb program_list[MAX_PCB];

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: show_memory_usage
 ****************************************************************************/

static void show_memory_usage(struct mallinfo *mmbefore,
                              struct mallinfo *mmafter)
{
    printf("VARIABLE  BEFORE   AFTER\n");
    printf("======== ======== ========\n");
    printf("arena    %8x %8x\n", mmbefore->arena,    mmafter->arena);
    printf("ordblks  %8d %8d\n", mmbefore->ordblks,  mmafter->ordblks);
    printf("mxordblk %8x %8x\n", mmbefore->mxordblk, mmafter->mxordblk);
    printf("uordblks %8x %8x\n", mmbefore->uordblks, mmafter->uordblks);
    printf("fordblks %8x %8x\n", mmbefore->fordblks, mmafter->fordblks);
}

/****************************************************************************
 * Name: check_memory_usage
 ****************************************************************************/

static void check_memory_usage(void)
{
    /* Wait a little bit to let any threads terminate */

    usleep(HALF_SECOND_USEC);

    /* Get the current memory usage */

#ifdef CONFIG_CAN_PASS_STRUCTS
    g_mmafter = mallinfo();
#else
    (void)mallinfo(&g_mmafter);
#endif

    /* Show the change from the previous time */

    printf("\nMemory usage:\n");
    show_memory_usage(&g_mmprevious, &g_mmafter);

    /* Set up for the next test */

#ifdef CONFIG_CAN_PASS_STRUCTS
    g_mmprevious = g_mmafter;
#else
    memcpy(&g_mmprevious, &g_mmafter, sizeof(struct mallinfo));
#endif

    /* If so enabled, show the use of priority inheritance resources */

    dump_nfreeholders("user_main:");
}

int get_free_pcb(void){
    int i;
    for(i = 0; i < MAX_PCB; i++){
        if(program_list[i].size == 0){
            return i;
        }
    }

    return -1;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int program_loader_main(int argc, FAR char *argv[])
{
    struct packet_header hdr;
    struct pcb* pcb_ptr = 0;
    void* data_buffer;
    int ivshmem_fd;
    int run = 1;
    int tmp;
    int curr_size, offset;
    int i;
    char **cargv;
    char *argv_holder;
    int cargc;
    void* main_addr;

    /* Sample the memory usage now */

    usleep(HALF_SECOND_USEC);

#ifdef CONFIG_CAN_PASS_STRUCTS
    g_mmbefore = mallinfo();
    g_mmprevious = g_mmbefore;
#else
    (void)mallinfo(&g_mmbefore);
    memcpy(&g_mmprevious, &g_mmbefore, sizeof(struct mallinfo));
#endif


    memset(program_list, 0, sizeof(program_list));

    printf("\nLOADER: Starting...\n");

    ivshmem_fd = open("/dev/ivshmem", O_RDWR);
    if(ivshmem_fd == -1){
        printf("FATAL: Failed to open to /dev/ivshmem\n");
        PANIC();
    }

    while(run){
        printf("\nLOADER: waiting for command\n");
        ioctl(ivshmem_fd, IVSHMEM_WAIT, 0);

        lseek(ivshmem_fd, 0, SEEK_SET);
        read(ivshmem_fd, &hdr, sizeof(hdr));

        switch(hdr.type){
            case PING:
                printf("LOADER: got PING...\n");
                printf("LOADER: sent PONG...\n");

                memset(&hdr, 0, sizeof(hdr));
                hdr.type = PONG;
                lseek(ivshmem_fd, 0, SEEK_SET);
                write(ivshmem_fd, &hdr, sizeof(hdr));
                ioctl(ivshmem_fd, IVSHMEM_WAKE, 0);
                break;

            case PONG:
                break;

            case LOAD:
                printf("LOADER: allocating a new PCB..\n");
                tmp = get_free_pcb();
                pcb_ptr = program_list + tmp;

                if(tmp < 0){
                    printf("FATAL: Not enough PCB left\n");
                    PANIC();
                }

                printf("LOADER: new PCB size is %x..\n", hdr.length);
                pcb_ptr->size = hdr.length;
                pcb_ptr->base_address = malloc(pcb_ptr->size);
                if(pcb_ptr->base_address == NULL){
                    printf("Allocating pcb PROG_BITS failed\n");
                }
                memset(pcb_ptr->base_address, 0, pcb_ptr->size);

                check_memory_usage();

                while(1){
                    tmp = hdr.attribute & ATTR_MORE;

                    offset = (0x100000 - sizeof(hdr)) * hdr.fragement_number;
                    curr_size = tmp ? 0x100000 - sizeof(hdr) : hdr.length - offset;
                    printf("LOADER: loading binary base: %x from %x to %x..\n",
                            pcb_ptr->base_address,
                            pcb_ptr->base_address + offset,
                            pcb_ptr->base_address + offset + curr_size);
                    read(ivshmem_fd, pcb_ptr->base_address + offset, curr_size);

                    memset(&hdr, 0, sizeof(hdr));
                    hdr.type = PONG;
                    hdr.length = 0;
                    lseek(ivshmem_fd, 0, SEEK_SET);
                    write(ivshmem_fd, &hdr, sizeof(hdr));
                    ioctl(ivshmem_fd, IVSHMEM_WAKE, 0);

                    if(!(tmp)) break;

                    usleep(50000);

                    ioctl(ivshmem_fd, IVSHMEM_WAIT, 0);
                    lseek(ivshmem_fd, 0, SEEK_SET);
                    read(ivshmem_fd, &hdr, sizeof(hdr));
                }

                usleep(1000000);

                memset(&hdr, 0, sizeof(hdr));
                hdr.type = RETURN;
                hdr.length = sizeof(tmp);
                lseek(ivshmem_fd, 0, SEEK_SET);
                write(ivshmem_fd, &hdr, sizeof(hdr));
                write(ivshmem_fd, &tmp, sizeof(tmp));
                ioctl(ivshmem_fd, IVSHMEM_WAKE, 0);
                break;

            case START:
                // Read the argc and argv
                data_buffer = malloc(hdr.length);
                if(data_buffer == NULL){
                    printf("Allocating temporary data buffer failed\n");
                }
                read(ivshmem_fd, data_buffer, hdr.length);

                pcb_ptr = program_list + ((uint32_t*)data_buffer)[0];
                offset = ((uint32_t*)data_buffer)[1];

                cargc = ((uint32_t*)data_buffer)[2];
                printf("argc=%d\n", cargc);

                tmp = 0;
                for(i = 0; i < cargc; i++){
                    tmp += ((uint8_t*)data_buffer)[12 + tmp];
                }
                argv_holder = ((char*)data_buffer) + 12;

                cargv = (char**)malloc(cargc * sizeof(char*) + 1);
                if(cargv == NULL){
                    printf("Allocating argv failed\n");
                }

                tmp = 0;
                for(i = 0; i < cargc; i++){
                    cargv[i] = argv_holder + tmp + 1;
                    tmp += argv_holder[tmp];
                }
                cargv[i] = NULL; //mandantory to compliant POSIX interface

                tmp = ((uint32_t*)data_buffer)[0];
                free(data_buffer);

                main_addr = ((void* (*)(void))(pcb_ptr->base_address + offset - LINUX_ELF_OFFSET));
                // pre-execute _start and __libc_start_main to get the main address
                // _start will reset rbp, preserve it here, take caution on the ordering, because gcc use rbp to locate local variables
                asm volatile("push %%rbp":::"memory", "rsp");
                asm volatile("mov %0, %%rax; callq *%%rax"::"g"(main_addr):"rax");
                asm volatile("pop %%rbp":::"memory", "rsp");
                asm volatile("mov %%rax, %0":"=g"(main_addr)::"memory");

                printf("LOADER: starting program %d at %x, offset %x\n",
                        tmp,
                        pcb_ptr->base_address,
                        main_addr);

                pcb_ptr->pid = nxtask_create(cargv[0], SCHED_PRIORITY_DEFAULT + 10,
                                             0x400000,
                                             (main_t)(pcb_ptr->base_address + (uint64_t)main_addr - LINUX_ELF_OFFSET),
                                             cargv + 1);

                free(cargv); //argv had been copied to application's stack

                memset(&hdr, 0, sizeof(hdr));
                hdr.type = PONG;
                lseek(ivshmem_fd, 0, SEEK_SET);
                write(ivshmem_fd, &hdr, sizeof(hdr));
                ioctl(ivshmem_fd, IVSHMEM_WAKE, 0);
                break;

            default:
                printf("FATAL: Got trash from host %4x\n", hdr.type);
                memset(&hdr, 0, sizeof(hdr));
                hdr.type = TRASH;
                lseek(ivshmem_fd, 0, SEEK_SET);
                write(ivshmem_fd, &hdr, sizeof(hdr));
                ioctl(ivshmem_fd, IVSHMEM_WAKE, 0);
        }
    }

  return 0;
}

//Gonna fake some calls
long syscall(long nr){
    switch(nr){
        case __NR_gettid:
            return getpid();
    }

    return 0;
}
