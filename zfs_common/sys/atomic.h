/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ATOMIC_H
#define	_SYS_ATOMIC_H

#ifdef _KERNEL
#include <libkern/OSAtomic.h>


#ifndef __i386__

extern Boolean OSCompareAndSwap64(UInt64 oldValue, UInt64 newValue, volatile UInt64 *address);

extern SInt64 OSAddAtomic64(SInt64 theAmount, volatile SInt64 *address);

extern SInt64 OSIncrementAtomic64(volatile SInt64 *address);

extern SInt64 OSDecrementAtomic64(volatile SInt64 *address);

#endif  /* !__i386__ */

/*
 * Increment target.
 */
#define atomic_inc_8(addr)	(void)OSIncrementAtomic8((volatile SInt8 *)addr)
#define atomic_inc_16(addr)	(void)OSIncrementAtomic16((volatile SInt16 *)addr)
#define atomic_inc_32(addr)	(void)OSIncrementAtomic((volatile SInt32 *)addr)
#define atomic_inc_64(addr)	(void)OSIncrementAtomic64((volatile SInt64 *)addr)

/*
 * Decrement target
 */
#define atomic_dec_8(addr)	(void)OSDecrementAtomic8((volatile SInt8 *)addr)
#define atomic_dec_16(addr)	(void)OSDecrementAtomic16((volatile SInt16 *)addr)
#define atomic_dec_32(addr)	(void)OSDecrementAtomic((volatile SInt32 *)addr)
#define atomic_dec_64(addr)	(void)OSDecrementAtomic64((volatile SInt64 *)addr)

/*
 * Add delta to target
 */
#define atomic_add_8(addr, amt)		(void)OSAddAtomic8(amt, (volatile SInt8 *)addr)
#define atomic_add_16(addr, amt)	(void)OSAddAtomic16(amt, (volatile SInt16 *)addr)
#define atomic_add_32(addr, amt)	(void)OSAddAtomic(amt, (volatile SInt32 *)addr)
#define atomic_add_64(addr, amt)	(void)OSAddAtomic64(amt, (volatile SInt64 *)addr)

extern SInt64 OSAddAtomic64_NV(SInt64 theAmount, volatile SInt64 *address);
#define atomic_add_64_nv(addr, amt)	(uint64_t)OSAddAtomic64_NV(amt, (volatile SInt64 *)addr)

/*
 * logical OR bits with target
 */
#define atomic_or_8(addr, mask)		(void)OSBitOrAtomic8((UInt32)mask, (volatile UInt8 *)addr)
#define atomic_or_16(addr, mask)	(void)OSBitOrAtomic16((UInt32)mask, (volatile UInt16 *)addr)
#define atomic_or_32(addr, mask)	(void)OSBitOrAtomic((UInt32)mask, (volatile UInt32 *)addr)

/*
 * logical AND bits with target
 */
#define atomic_and_8(addr, mask)	(void)OSBitAndAtomic8((UInt32)mask, (volatile UInt8 *)addr)
#define atomic_and_16(addr, mask)	(void)OSBitAndAtomic16((UInt32)mask, (volatile UInt16 *)addr)
#define atomic_and_32(addr, mask)	(void)OSBitAndAtomic((UInt32)mask, (volatile UInt32 *)addr)

/*
 * If *arg1 == arg2, set *arg1 = arg3; return old value
 */
extern uint8_t atomic_cas_8(volatile uint8_t *, uint8_t, uint8_t);
extern uint16_t atomic_cas_16(volatile uint16_t *, uint16_t, uint16_t);
extern uint32_t atomic_cas_32(volatile uint32_t *, uint32_t, uint32_t);
extern uint64_t atomic_cas_64(volatile uint64_t *, uint64_t, uint64_t);
extern void *atomic_cas_ptr(volatile void *, void *, void *);

#endif

#endif	/* _SYS_ATOMIC_H */
