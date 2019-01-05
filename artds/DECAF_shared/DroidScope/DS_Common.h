/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Lok Yan
 * @date 9/28/2011
 */

#ifndef DS_COMMON_H
#define DS_COMMON_H

//#include <inttypes.h>
//#include <stdio.h>
//#include "cpu.h"
#include "DECAF_shared/DECAF_types.h"

typedef enum {
  LOG_LEVEL_MINIMAL,
  LOG_LEVEL_SIMPLE,
  LOG_LEVEL_VERBOSE,
  LOG_LEVEL_EVERYTHING
} LogLevel;

/**
 * Strips the last bit of the link-register.
 * Remember that if bit 1 is 1 then the previous instruction was thumb, else it is not
 */
#define lp_strip(_lp) (_lp & ~0x1)

//There is some documentation that says that the PGDs for ARM must be 16k aligned - but we will just assume that they are 4k aligned and use that for stripping
//#define pgd_strip(_pgd) (_pgd & ~0xC0000000)
#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

/**
 * Linux uses 4K pages but QEMU for ARM is setup to use 1k pages.
 */
#define LINUX_PAGE_BITS 12
#define LINUX_PAGE_SIZE ( 1 << LINUX_PAGE_BITS )
#define LINUX_OFFSET_MASK ( LINUX_PAGE_SIZE - 1 )
#define LINUX_PAGE_MASK ( ~LINUX_OFFSET_MASK )

#define SET_TASK_COMM_ADDR 0xc00bad08 // set_task_comm -- modified -- zhouhao
#define DO_FORK_ADDR 0xc0018834 // do_fork -- modified -- zhouhao
#define DO_EXECVE_ADDR 0xc00baeac // do_execve -- modified -- zhouhao
#define DO_MMAP2_ADDR 0xc000e108 // sys_mmap2 -- modified -- zhouhao
#define DO_MMAP 0xc00a52f8 // do_mmap -- modified -- zhouhao
#define DO_PRCTL_ADDR 0xc002cf8c // sys_prctl -- modified -- zhouhao
#define DO_CLONE_ADDR 0xc0010808 // sys_clone -- modified -- zhouhao
#define SWITCH_TO 0xc000d8a4 // __switch_to -- modified -- zhouhao
#define DO_FORK_END_ADDR 0xc0018ba8 // modified -- zhouhao

#endif//DS_COMMON_H
