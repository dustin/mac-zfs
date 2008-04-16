/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1993-2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DEBUG_H
#define	_SYS_DEBUG_H

#define VERIFY(expr)                                           \
	do {                                                       \
		if (!(expr))                                           \
			panic("[ZFS]: assertion failed in %s line %d: %s", \
				__FILE__, __LINE__, # expr);                   \
	} while (0)

#define	VERIFY3_IMPL(LEFT, OP, RIGHT, TYPE)                                                       \
	do {                                                                                          \
	const TYPE __left = (TYPE)(LEFT);                                                             \
	const TYPE __right = (TYPE)(RIGHT);                                                           \
	if (!(__left OP __right))                                                                     \
		panic("%s failed, %d %s %d", #LEFT " " #OP " " #RIGHT, (int)__left, #OP, (int)__right);  \
	} while (0)

#if 1
#define	ASSERT3S(x, y, z)	VERIFY3_IMPL(x, y, z, int64_t)
#define	ASSERT3U(x, y, z)	VERIFY3_IMPL(x, y, z, uint64_t)
#define	ASSERT3P(x, y, z)	VERIFY3_IMPL(x, y, z, uintptr_t)
#else
#define	ASSERT3S(x, y, z)	((void)0)
#define	ASSERT3U(x, y, z)	((void)0)
#define	ASSERT3P(x, y, z)	((void)0)
#endif


#if 1
#define ASSERT(expr)	VERIFY(expr) 
#else
#define ASSERT(expr)	((void)0)
#endif

#define _NOTE(x)

#define	VERIFY3U(x, y, z)   VERIFY3_IMPL(x, y, z, uint64_t)


#endif	/* _SYS_DEBUG_H */
