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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_SYS_SOLARIS_TYPES_H
#define	_SYS_SOLARIS_TYPES_H

#include <stdint.h>
#include "/System/Library/Frameworks/Kernel.framework/Headers/sys/types.h"
#include <mach/boolean.h>

/*
 * POSIX Extensions
 */
typedef	unsigned char	uchar_t;
typedef	unsigned short	ushort_t;
typedef	unsigned int	uint_t;
typedef	unsigned long	ulong_t;

typedef unsigned long long  u_longlong_t;
typedef  long long  longlong_t;

typedef	short	cnt_t;
typedef short	pri_t;

/*
 * VM-related types
 */
typedef	ulong_t		pfn_t;		/* page frame number */
typedef	ulong_t		pgcnt_t;	/* number of pages */
typedef	long		spgcnt_t;	/* signed number of pages */

typedef	uchar_t		use_t;		/* use count for swap.  */
typedef	short		sysid_t;
typedef	short		index_t;


#define MAXNAMELEN 256


enum { B_FALSE, B_TRUE };

typedef void kthread_t;

/*
 *	Definitions for commonly used resolutions.
 */
#define	SEC		1
#define	MILLISEC	1000
#define	MICROSEC	1000000
#define	NANOSEC		1000000000

/*
 * Time expressed as a 64-bit nanosecond counter.
 */
typedef	long long	hrtime_t;

#ifndef __PTRDIFF_TYPE__
typedef	long	ptrdiff_t;		/* pointer difference */
#elseif _KERNEL
typedef	long	ptrdiff_t;		/* pointer difference */
#endif

typedef	longlong_t	offset_t;
typedef	u_longlong_t	u_offset_t;
typedef u_longlong_t	len_t;
typedef	u_longlong_t	diskaddr_t;

 
typedef	ushort_t o_mode_t;		/* old file attribute type */

#define	MAXOFFSET_T 	0x7fffffffffffffffLL

#endif /* _SYS_SOLARIS_TYPES_H */
