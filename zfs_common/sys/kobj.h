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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _SYS_KOBJ_H
#define	_SYS_KOBJ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/vnode.h>

#ifdef _KERNEL

/*
 * kobj file access
 */
struct _buf {
	struct vnode *	 _fd;
};

struct bootstat {
	uint32_t	st_mode;
	uint64_t	st_size;
};

extern struct _buf *  kobj_open_file(char *);
extern void  kobj_close_file(struct _buf *);
extern int  kobj_read_file(struct _buf *, char *, unsigned, unsigned);
extern int kobj_get_filesize(struct _buf *, uint64_t *size);
extern int  kobj_fstat(struct vnode *, struct bootstat *);

#endif

#endif /* !_SYS_KOBJ_H */
