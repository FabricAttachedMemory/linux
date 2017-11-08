#ifdef CONFIG_ARM64
#include <linux/errno.h>
#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/cpufeature.h>

#include "alternative-asm.h"
#include "assembler.h"


/* begin arch/arm64/mm/proc-macros.S */

/*
 * Based on arch/arm/mm/proc-macros.S
 *
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * vma_vm_mm - get mm pointer from vma pointer (vma->vm_mm)
 */
        .macro  vma_vm_mm, rd, rn
        ldr     \rd, [\rn, #VMA_VM_MM]
        .endm

/*
 * mmid - get context id from mm pointer (mm->context.id)
 */
        .macro  mmid, rd, rn
        ldr     \rd, [\rn, #MM_CONTEXT_ID]
        .endm

/*
 * dcache_line_size - get the minimum D-cache line size from the CTR register.
 */
        .macro  dcache_line_size, reg, tmp
        mrs     \tmp, ctr_el0                   // read CTR
        ubfm    \tmp, \tmp, #16, #19            // cache line size encoding
        mov     \reg, #4                        // bytes per word
        lsl     \reg, \reg, \tmp                // actual cache line size
        .endm

/*
 * icache_line_size - get the minimum I-cache line size from the CTR register.
 */
        .macro  icache_line_size, reg, tmp
        mrs     \tmp, ctr_el0                   // read CTR
        and     \tmp, \tmp, #0xf                // cache line size encoding
        mov     \reg, #4                        // bytes per word
        lsl     \reg, \reg, \tmp                // actual cache line size
        .endm

/*
 * tcr_set_idmap_t0sz - update TCR.T0SZ so that we can load the ID map
 */
        .macro  tcr_set_idmap_t0sz, valreg, tmpreg
#ifndef CONFIG_ARM64_VA_BITS_48
        ldr_l   \tmpreg, idmap_t0sz
        bfi     \valreg, \tmpreg, #TCR_T0SZ_OFFSET, #TCR_TxSZ_WIDTH
#endif
        .endm

/* end  arch/arm64/mm/proc-macros.S */

/*
 *      __flush_dcache_all()
 *
 *      Flush the whole D-cache.
 *
 *      Corrupted registers: x0-x7, x9-x11
 */
.global __flush_dcache_all
__flush_dcache_all:
        dmb     sy                              // ensure ordering with previous memory accesses
        mrs     x0, clidr_el1                   // read clidr
        and     x3, x0, #0x7000000              // extract loc from clidr
        lsr     x3, x3, #23                     // left align loc bit field
        cbz     x3, finished                    // if loc is 0, then no need to clean
        mov     x10, #0                         // start clean at cache level 0
loop1:
        add     x2, x10, x10, lsr #1            // work out 3x current cache level
        lsr     x1, x0, x2                      // extract cache type bits from clidr
        and     x1, x1, #7                      // mask of the bits for current cache only
        cmp     x1, #2                          // see what cache we have at this level
        b.lt    skip                            // skip if no cache, or just i-cache
        save_and_disable_irqs x9                // make CSSELR and CCSIDR access atomic
        msr     csselr_el1, x10                 // select current cache level in csselr
        isb                                     // isb to sych the new cssr&csidr
        mrs     x1, ccsidr_el1                  // read the new ccsidr
        restore_irqs x9
        and     x2, x1, #7                      // extract the length of the cache lines
        add     x2, x2, #4                      // add 4 (line length offset)
        mov     x4, #0x3ff
        and     x4, x4, x1, lsr #3              // find maximum number on the way size
        clz     w5, w4                          // find bit position of way size increment
        mov     x7, #0x7fff
        and     x7, x7, x1, lsr #13             // extract max number of the index size
loop2:
        mov     x9, x4                          // create working copy of max way size
loop3:
        lsl     x6, x9, x5
        orr     x11, x10, x6                    // factor way and cache number into x11
        lsl     x6, x7, x2
        orr     x11, x11, x6                    // factor index number into x11
        dc      cisw, x11                       // clean & invalidate by set/way
        subs    x9, x9, #1                      // decrement the way
        b.ge    loop3
        subs    x7, x7, #1                      // decrement the index
        b.ge    loop2
skip:
        add     x10, x10, #2                    // increment cache number
        cmp     x3, x10
        b.gt    loop1
finished:
        mov     x10, #0                         // swith back to cache level 0
        msr     csselr_el1, x10                 // select current cache level in csselr
        dsb     sy
        isb
        ret
ENDPROC(__flush_dcache_all)
#endif
