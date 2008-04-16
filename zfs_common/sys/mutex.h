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

#ifndef _SYS_MUTEX_H
#define	_SYS_MUTEX_H

/* In Darwin, mutex locks are defined by "kern/locks.h" */
#ifdef _KERNEL
#include <kern/locks.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * MUTEX LOCKS
 */
typedef enum {
	MUTEX_ADAPTIVE = 0,	/* spin if owner is running, otherwise block */
	MUTEX_SPIN = 1,		/* block interrupts and spin */
	MUTEX_DRIVER = 4,	/* driver (DDI) mutex */
	MUTEX_DEFAULT = 6	/* kernel default mutex */
} kmutex_type_t;

#ifndef _KERNEL
	typedef int  lck_mtx_t;
#endif

struct kmutex {
	uint32_t	m_lock[4];	/* opaque lck_mtx_t data */
	void		*m_owner;
};

typedef struct kmutex  kmutex_t;

#ifdef _KERNEL

#define	MUTEX_HELD(x)		(mutex_owned(x))
#define	MUTEX_NOT_HELD(x)	(!mutex_owned(x))

extern  void  mutex_init(kmutex_t *, char *, kmutex_type_t, void *);
extern  void  mutex_destroy(kmutex_t *);
extern  void  mutex_enter(kmutex_t *);
extern  int   mutex_tryenter(kmutex_t *);
extern  void  mutex_exit(kmutex_t *);
extern  int   mutex_owned(kmutex_t *);
extern  kthread_t * mutex_owner(kmutex_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MUTEX_H */
