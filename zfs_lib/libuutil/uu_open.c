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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)uu_open.c	1.2	05/06/08 SMI"

#include "libuutil_common.h"

#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#ifdef _LP64
#define	TMPPATHFMT	"%s/uu%ld"
#else /* _LP64 */
#define	TMPPATHFMT	"%s/uu%lld"
#endif /* _LP64 */

static hrtime_t gethrtime(void);


/*ARGSUSED*/
int
uu_open_tmp(const char *dir, uint_t uflags)
{
	int f;
	char *fname = uu_zalloc(PATH_MAX);

	if (fname == NULL)
		return (-1);

	for (;;) {
		(void) snprintf(fname, PATH_MAX, "%s/uu%lld", dir, gethrtime());

		f = open(fname, O_CREAT | O_EXCL | O_RDWR, 0600);

		if (f >= 0 || errno != EEXIST)
			break;
	}

	if (f >= 0)
		(void) unlink(fname);

	uu_free(fname);

	return (f);
}

static hrtime_t
gethrtime(void)
{
	struct timeval tv;
	struct timezone tz;
	hrtime_t time;

	(void) gettimeofday(&tv, &tz);
	
	time = tv.tv_usec;
	time += (hrtime_t)tv.tv_sec * MICROSEC;

	return (time);
}

