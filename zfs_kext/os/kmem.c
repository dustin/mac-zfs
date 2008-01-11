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

/*
 * Portions Copyright 2007 Apple Inc.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel memory allocator, as described in the following two papers:
 *
 * Jeff Bonwick,
 * The Slab Allocator: An Object-Caching Kernel Memory Allocator.
 * Proceedings of the Summer 1994 Usenix Conference.
 * Available as /shared/sac/PSARC/1994/028/materials/kmem.pdf.
 *
 * Jeff Bonwick and Jonathan Adams,
 * Magazines and vmem: Extending the Slab Allocator to Many CPUs and
 * Arbitrary Resources.
 * Proceedings of the 2001 Usenix Conference.
 * Available as /shared/sac/PSARC/2000/550/materials/vmem.pdf.
 */

#include <sys/kmem_impl.h>
//#include <sys/vmem_impl.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/vm.h>
#include <sys/proc.h>
//#include <sys/tuneable.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/mutex.h>
#include <sys/bitmap.h>
#include <sys/atomic.h>
#include <sys/kobj.h>
//#include <sys/disp.h>
//#include <vm/seg_kmem.h>
//#include <sys/log.h>
#include <sys/callb.h>
#include <sys/taskq.h>
//#include <sys/modctl.h>
//#include <sys/reboot.h>
//#include <sys/id32.h>
// #include <sys/zone.h>


#define	VMEM_QCACHE_SLABSIZE(max) \
	MAX(1 << highbit(3 * (max)), 64)


static kmem_magtype_t kmem_magtype[] = {
	{ 1,	8,	3200,	65536	},
	{ 3,	16,	256,	32768	},
	{ 7,	32,	64,	16384	},
	{ 15,	64,	0,	8192	},
	{ 31,	64,	0,	4096	},
	{ 47,	64,	0,	2048	},
	{ 63,	64,	0,	1024	},
	{ 95,	64,	0,	512	},
	{ 143,	64,	0,	0	},
};

static uint32_t kmem_reaping;
static uint32_t kmem_reaping_idspace;

/*
 * kmem tunables
 */
#ifdef __APPLE__
struct timespec kmem_reap_interval;	/* cache reaping rate [15 * HZ ticks] */
#else
clock_t kmem_reap_interval;		/* cache reaping rate [15 * HZ ticks] */
#endif

int kmem_depot_contention = 3;	/* max failed tryenters per real interval */
int kmem_panic = 1;		/* whether to panic on error */
int kmem_logging = 1;		/* kmem_log_enter() override */

size_t kmem_content_maxsave = 256; /* KMF_CONTENTS max bytes to log */
size_t kmem_lite_minsize = 0;	/* minimum buffer size for KMF_LITE */
size_t kmem_lite_maxalign = 1024; /* maximum buffer alignment for KMF_LITE */
size_t kmem_maxverify;		/* maximum bytes to inspect in debug routines */
size_t kmem_minfirewall;	/* hardware-enforced redzone threshold */

#ifdef DEBUG
int kmem_flags = KMF_AUDIT | KMF_DEADBEEF | KMF_REDZONE | KMF_CONTENTS;
#else
int kmem_flags = 0;
#endif
int kmem_ready;

static kmem_cache_t	*kmem_slab_cache;
static kmem_cache_t	*kmem_bufctl_cache;

static kmutex_t		kmem_cache_lock;	/* inter-cache linkage only */
kmem_cache_t		kmem_null_cache;

static taskq_t		*kmem_taskq;
static kmutex_t		kmem_flags_lock;
static vmem_t		*kmem_msb_arena;	/* arena for metadata caches */
static vmem_t		*kmem_cache_arena;
static vmem_t		*kmem_hash_arena;
static vmem_t		*kmem_default_arena;
static vmem_t		*kmem_firewall_va_arena;
static vmem_t		*kmem_firewall_arena;

static vmem_t		 kmem_default_arena_instance;

#ifdef __APPLE__
vmem_t *zio_alloc_arena = NULL; /* arena for allocating zio memory */
#endif


#define	KMERR_MODIFIED	0	/* buffer modified while on freelist */
#define	KMERR_REDZONE	1	/* redzone violation (write past end of buf) */
#define	KMERR_DUPFREE	2	/* freed a buffer twice */
#define	KMERR_BADADDR	3	/* freed a bad (unallocated) address */
#define	KMERR_BADBUFTAG	4	/* buftag corrupted */
#define	KMERR_BADBUFCTL	5	/* bufctl corrupted */
#define	KMERR_BADCACHE	6	/* freed a buffer to the wrong cache */
#define	KMERR_BADSIZE	7	/* alloc size != free size */
#define	KMERR_BADBASE	8	/* buffer base address wrong */

struct {
	hrtime_t	kmp_timestamp;	/* timestamp of panic */
	int		kmp_error;	/* type of kmem error */
	void		*kmp_buffer;	/* buffer that induced panic */
	void		*kmp_realbuf;	/* real start address for buffer */
	kmem_cache_t	*kmp_cache;	/* buffer's cache according to client */
	kmem_cache_t	*kmp_realcache;	/* actual cache containing buffer */
	kmem_slab_t	*kmp_slab;	/* slab accoring to kmem_findslab() */
	kmem_bufctl_t	*kmp_bufctl;	/* bufctl */
} kmem_panic_info;


#ifdef __APPLE__
/*
 * Since we allow for slabs that are not slab size aligned we have
 * to find our slab header by looking at different page boundaries.
 */
kmem_slab_t * buftoslab(kmem_cache_t *, void *);

kmem_slab_t *
buftoslab(kmem_cache_t *cp, void *buf)
{
	size_t slabsize = cp->cache_slabsize;

	if (slabsize == PAGESIZE) {
		return KMEM_SLAB(cp, buf);	
	} else {
		kmem_slab_t *sp;
		size_t bufsize;
		char *ptr;

		/*
		 * Try all the possibilities (up to 8 for a 32K slab).
		 *
		 * Note that we must work backwards so we don't read
		 * outside of our buffer and cause a page fault.
		 */
		for (bufsize = PAGESIZE; bufsize <= slabsize; bufsize += PAGESIZE) {
			ptr = (char *)P2ALIGN((uintptr_t)buf, PAGESIZE) + bufsize;
			sp = (kmem_slab_t *)ptr - 1;
			if (sp->slab_cache == cp)
				return (sp);
		}
	}
	panic("KMEM_SLAB: can't find slab header for buf %p", buf);
	return (NULL);
}
#endif /* __APPLE__ */

static void
copy_pattern(uint64_t pattern, void *buf_arg, size_t size)
{
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf = buf_arg;

	while (buf < bufend)
		*buf++ = pattern;
}

static void *
verify_pattern(uint64_t pattern, void *buf_arg, size_t size)
{
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf;

	for (buf = buf_arg; buf < bufend; buf++)
		if (*buf != pattern)
			return (buf);
	return (NULL);
}

static void *
verify_and_copy_pattern(uint64_t old, uint64_t new, void *buf_arg, size_t size)
{
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf;

	for (buf = buf_arg; buf < bufend; buf++) {
		if (*buf != old) {
			copy_pattern(old, buf_arg,
				(char *)buf - (char *)buf_arg);
			return (buf);
		}
		*buf = new;
	}

	return (NULL);
}

static void
kmem_cache_applyall(void (*func)(kmem_cache_t *), taskq_t *tq, int tqflag)
{
	kmem_cache_t *cp;

	mutex_enter(&kmem_cache_lock);
	for (cp = kmem_null_cache.cache_next; cp != &kmem_null_cache;
	    cp = cp->cache_next)
		if (tq != NULL)
			(void) taskq_dispatch(tq, (task_func_t *)func, cp,
			    tqflag);
		else
			func(cp);
	mutex_exit(&kmem_cache_lock);
}

static void
kmem_cache_applyall_id(void (*func)(kmem_cache_t *), taskq_t *tq, int tqflag)
{
	kmem_cache_t *cp;

	mutex_enter(&kmem_cache_lock);
	for (cp = kmem_null_cache.cache_next; cp != &kmem_null_cache;
	    cp = cp->cache_next) {
		if (!(cp->cache_cflags & KMC_IDENTIFIER))
			continue;
		if (tq != NULL)
			(void) taskq_dispatch(tq, (task_func_t *)func, cp,
			    tqflag);
		else
			func(cp);
	}
	mutex_exit(&kmem_cache_lock);
}

/*
 * Debugging support.  Given a buffer address, find its slab.
 */
static kmem_slab_t *
kmem_findslab(kmem_cache_t *cp, void *buf)
{
	kmem_slab_t *sp;

	mutex_enter(&cp->cache_lock);
	for (sp = cp->cache_nullslab.slab_next;
	    sp != &cp->cache_nullslab; sp = sp->slab_next) {
		if (KMEM_SLAB_MEMBER(sp, buf)) {
			mutex_exit(&cp->cache_lock);
			return (sp);
		}
	}
	mutex_exit(&cp->cache_lock);

	return (NULL);
}

static void
kmem_error(int error, kmem_cache_t *cparg, void *bufarg)
{
	kmem_buftag_t *btp = NULL;
	kmem_bufctl_t *bcp = NULL;
	kmem_cache_t *cp = cparg;
	kmem_slab_t *sp;
	uint64_t *off;
	void *buf = bufarg;

	kmem_logging = 0;	/* stop logging when a bad thing happens */

	kmem_panic_info.kmp_timestamp = gethrtime();

	sp = kmem_findslab(cp, buf);
	if (sp == NULL) {
		for (cp = kmem_null_cache.cache_prev; cp != &kmem_null_cache;
		    cp = cp->cache_prev) {
			if ((sp = kmem_findslab(cp, buf)) != NULL)
				break;
		}
	}

	if (sp == NULL) {
		cp = NULL;
		error = KMERR_BADADDR;
	} else {
		if (cp != cparg)
			error = KMERR_BADCACHE;
		else
			buf = (char *)bufarg - ((uintptr_t)bufarg -
			    (uintptr_t)sp->slab_base) % cp->cache_chunksize;
		if (buf != bufarg)
			error = KMERR_BADBASE;
		if (cp->cache_flags & KMF_BUFTAG)
			btp = KMEM_BUFTAG(cp, buf);
		if (cp->cache_flags & KMF_HASH) {
			mutex_enter(&cp->cache_lock);
			for (bcp = *KMEM_HASH(cp, buf); bcp; bcp = bcp->bc_next)
				if (bcp->bc_addr == buf)
					break;
			mutex_exit(&cp->cache_lock);
			if (bcp == NULL && btp != NULL)
				bcp = btp->bt_bufctl;
			if (kmem_findslab(cp->cache_bufctl_cache, bcp) ==
			    NULL || P2PHASE((uintptr_t)bcp, KMEM_ALIGN) ||
			    bcp->bc_addr != buf) {
				error = KMERR_BADBUFCTL;
				bcp = NULL;
			}
		}
	}

	kmem_panic_info.kmp_error = error;
	kmem_panic_info.kmp_buffer = bufarg;
	kmem_panic_info.kmp_realbuf = buf;
	kmem_panic_info.kmp_cache = cparg;
	kmem_panic_info.kmp_realcache = cp;
	kmem_panic_info.kmp_slab = sp;
	kmem_panic_info.kmp_bufctl = bcp;

	printf("kernel memory allocator: ");

	switch (error) {

	case KMERR_MODIFIED:
		printf("buffer modified after being freed\n");
		off = verify_pattern(KMEM_FREE_PATTERN, buf, cp->cache_verify);
		if (off == NULL)	/* shouldn't happen */
			off = buf;
		printf("modification occurred at offset 0x%lx "
		    "(0x%llx replaced by 0x%llx)\n",
		    (uintptr_t)off - (uintptr_t)buf,
		    (longlong_t)KMEM_FREE_PATTERN, (longlong_t)*off);
		break;

	case KMERR_REDZONE:
		printf("redzone violation: write past end of buffer\n");
		break;

	case KMERR_BADADDR:
		printf("invalid free: buffer not in cache\n");
		break;

	case KMERR_DUPFREE:
		printf("duplicate free: buffer freed twice\n");
		break;

	case KMERR_BADBUFTAG:
		printf("boundary tag corrupted\n");
		printf("bcp ^ bxstat = %lx, should be %lx\n",
		    (intptr_t)btp->bt_bufctl ^ btp->bt_bxstat,
		    KMEM_BUFTAG_FREE);
		break;

	case KMERR_BADBUFCTL:
		printf("bufctl corrupted\n");
		break;

	case KMERR_BADCACHE:
		printf("buffer freed to wrong cache\n");
		printf("buffer was allocated from %s,\n", cp->cache_name);
		printf("caller attempting free to %s.\n", cparg->cache_name);
		break;

	case KMERR_BADSIZE:
		printf("bad free: free size (%u) != alloc size (%u)\n",
		    KMEM_SIZE_DECODE(((uint32_t *)btp)[0]),
		    KMEM_SIZE_DECODE(((uint32_t *)btp)[1]));
		break;

	case KMERR_BADBASE:
		printf("bad free: free address (%p) != alloc address (%p)\n",
		    bufarg, buf);
		break;
	}

	printf("buffer=%p  bufctl=%p  cache: %s\n",
	    bufarg, (void *)bcp, cparg->cache_name);

#ifndef __APPLE__
	if (bcp != NULL && (cp->cache_flags & KMF_AUDIT) &&
	    error != KMERR_BADBUFCTL) {
		int d;
		timestruc_t ts;
		kmem_bufctl_audit_t *bcap = (kmem_bufctl_audit_t *)bcp;

		hrt2ts(kmem_panic_info.kmp_timestamp - bcap->bc_timestamp, &ts);
		printf("previous transaction on buffer %p:\n", buf);
		printf("thread=%p  time=T-%ld.%09ld  slab=%p  cache: %s\n",
		    (void *)bcap->bc_thread, ts.tv_sec, ts.tv_nsec,
		    (void *)sp, cp->cache_name);
		for (d = 0; d < MIN(bcap->bc_depth, KMEM_STACK_DEPTH); d++) {
			ulong_t off;
			char *sym = kobj_getsymname(bcap->bc_stack[d], &off);
			printf("%s+%lx\n", sym ? sym : "?", off);
		}
	}
#endif /*!__APPLE__*/

	if (kmem_panic > 0)
		panic("kernel heap corruption detected");

#ifndef __APPLE__
	if (kmem_panic == 0)
		debug_enter(NULL);
#endif /*!__APPLE__*/

	kmem_logging = 1;	/* resume logging */
}


/*
 * Create a new slab for cache cp.
 */
static kmem_slab_t *
kmem_slab_create(kmem_cache_t *cp, int kmflag)
{
	size_t slabsize = cp->cache_slabsize;
	size_t chunksize = cp->cache_chunksize;
	int cache_flags = cp->cache_flags;
	size_t color, chunks;
	char *buf, *slab;
	kmem_slab_t *sp;
	kmem_bufctl_t *bcp;
	vmem_t *vmp = cp->cache_arena;

	color = cp->cache_color + cp->cache_align;
	if (color > cp->cache_maxcolor)
		color = cp->cache_mincolor;
	cp->cache_color = color;

	slab = vmem_alloc(vmp, slabsize, kmflag & KM_VMFLAGS);

	if (slab == NULL)
		goto vmem_alloc_failure;

	ASSERT(P2PHASE((uintptr_t)slab, vmp->vm_quantum) == 0);

	if (!(cp->cache_cflags & KMC_NOTOUCH))
		copy_pattern(KMEM_UNINITIALIZED_PATTERN, slab, slabsize);

	if (cache_flags & KMF_HASH) {
		if ((sp = kmem_cache_alloc(kmem_slab_cache, kmflag)) == NULL)
			goto slab_alloc_failure;
		chunks = (slabsize - color) / chunksize;
	} else {

#ifdef __APPLE__
		sp = ((kmem_slab_t *)((char *)slab + slabsize)) - 1;
#else
		sp = KMEM_SLAB(cp, slab);
#endif /* __APPLE__ */

		chunks = (slabsize - sizeof (kmem_slab_t) - color) / chunksize;
	}

	sp->slab_cache	= cp;
	sp->slab_head	= NULL;
	sp->slab_refcnt	= 0;
	sp->slab_base	= buf = slab + color;
	sp->slab_chunks	= chunks;

	ASSERT(chunks > 0);
	while (chunks-- != 0) {
		if (cache_flags & KMF_HASH) {
			bcp = kmem_cache_alloc(cp->cache_bufctl_cache, kmflag);
			if (bcp == NULL)
				goto bufctl_alloc_failure;

			bcp->bc_addr = buf;
			bcp->bc_slab = sp;
		} else {
			bcp = KMEM_BUFCTL(cp, buf);
		}

		bcp->bc_next = sp->slab_head;
		sp->slab_head = bcp;
		buf += chunksize;
	}

	return (sp);

bufctl_alloc_failure:

	while ((bcp = sp->slab_head) != NULL) {
		sp->slab_head = bcp->bc_next;
		kmem_cache_free(cp->cache_bufctl_cache, bcp);
	}
	kmem_cache_free(kmem_slab_cache, sp);

slab_alloc_failure:

	vmem_free(vmp, slab, slabsize);

vmem_alloc_failure:

	atomic_add_64(&cp->cache_alloc_fail, 1);

	return (NULL);
}

/*
 * Destroy a slab.
 */
static void
kmem_slab_destroy(kmem_cache_t *cp, kmem_slab_t *sp)
{
	vmem_t *vmp = cp->cache_arena;
	void *slab = (void *)P2ALIGN((uintptr_t)sp->slab_base, vmp->vm_quantum);

	ASSERT(sp->slab_cache == cp);

	if (cp->cache_flags & KMF_HASH) {
		kmem_bufctl_t *bcp;
		while ((bcp = sp->slab_head) != NULL) {
			sp->slab_head = bcp->bc_next;
			kmem_cache_free(cp->cache_bufctl_cache, bcp);
		}
		kmem_cache_free(kmem_slab_cache, sp);
	}
	vmem_free(vmp, slab, cp->cache_slabsize);
}

/*
 * Allocate a raw (unconstructed) buffer from cp's slab layer.
 */
static void *
kmem_slab_alloc(kmem_cache_t *cp, int kmflag)
{
	kmem_bufctl_t *bcp, **hash_bucket;
	kmem_slab_t *sp;
	void *buf;

	mutex_enter(&cp->cache_lock);
	cp->cache_slab_alloc++;
	sp = cp->cache_freelist;
	ASSERT(sp->slab_cache == cp);
	if (sp->slab_head == NULL) {
		/*
		 * The freelist is empty.  Create a new slab.
		 */
		mutex_exit(&cp->cache_lock);
		if ((sp = kmem_slab_create(cp, kmflag)) == NULL)
			return (NULL);
		mutex_enter(&cp->cache_lock);
		cp->cache_slab_create++;
		if ((cp->cache_buftotal += sp->slab_chunks) > cp->cache_bufmax)
			cp->cache_bufmax = cp->cache_buftotal;
		sp->slab_next = cp->cache_freelist;
		sp->slab_prev = cp->cache_freelist->slab_prev;
		sp->slab_next->slab_prev = sp;
		sp->slab_prev->slab_next = sp;
		cp->cache_freelist = sp;
	}

	sp->slab_refcnt++;
	ASSERT(sp->slab_refcnt <= sp->slab_chunks);

	/*
	 * If we're taking the last buffer in the slab,
	 * remove the slab from the cache's freelist.
	 */
	bcp = sp->slab_head;
	if ((sp->slab_head = bcp->bc_next) == NULL) {
		cp->cache_freelist = sp->slab_next;
		ASSERT(sp->slab_refcnt == sp->slab_chunks);
	}

	if (cp->cache_flags & KMF_HASH) {
		/*
		 * Add buffer to allocated-address hash table.
		 */
		buf = bcp->bc_addr;
		hash_bucket = KMEM_HASH(cp, buf);
		bcp->bc_next = *hash_bucket;
		*hash_bucket = bcp;
	} else {
		buf = KMEM_BUF(cp, bcp);
	}

	ASSERT(KMEM_SLAB_MEMBER(sp, buf));

	mutex_exit(&cp->cache_lock);

	return (buf);
}

/*
 * Free a raw (unconstructed) buffer to cp's slab layer.
 */
static void
kmem_slab_free(kmem_cache_t *cp, void *buf)
{
	kmem_slab_t *sp;
	kmem_bufctl_t *bcp, **prev_bcpp;

	ASSERT(buf != NULL);

	mutex_enter(&cp->cache_lock);
	cp->cache_slab_free++;

	if (cp->cache_flags & KMF_HASH) {
		/*
		 * Look up buffer in allocated-address hash table.
		 */
		prev_bcpp = KMEM_HASH(cp, buf);
		while ((bcp = *prev_bcpp) != NULL) {
			if (bcp->bc_addr == buf) {
				*prev_bcpp = bcp->bc_next;
				sp = bcp->bc_slab;
				break;
			}
			cp->cache_lookup_depth++;
			prev_bcpp = &bcp->bc_next;
		}
	} else {
		bcp = KMEM_BUFCTL(cp, buf);
#ifdef __APPLE__
		sp = buftoslab(cp, buf);
#else
		sp = KMEM_SLAB(cp, buf);
		ASSERT(sp->slab_cache == cp);
#endif /* __APPLE__ */

	}

	if (bcp == NULL || sp->slab_cache != cp || !KMEM_SLAB_MEMBER(sp, buf)) {
		mutex_exit(&cp->cache_lock);
		kmem_error(KMERR_BADADDR, cp, buf);
		return;
	}

	/*
	 * If this slab isn't currently on the freelist, put it there.
	 */
	if (sp->slab_head == NULL) {
		ASSERT(sp->slab_refcnt == sp->slab_chunks);
		ASSERT(cp->cache_freelist != sp);
		sp->slab_next->slab_prev = sp->slab_prev;
		sp->slab_prev->slab_next = sp->slab_next;
		sp->slab_next = cp->cache_freelist;
		sp->slab_prev = cp->cache_freelist->slab_prev;
		sp->slab_next->slab_prev = sp;
		sp->slab_prev->slab_next = sp;
		cp->cache_freelist = sp;
	}

	bcp->bc_next = sp->slab_head;
	sp->slab_head = bcp;

	ASSERT(sp->slab_refcnt >= 1);
	if (--sp->slab_refcnt == 0) {
		/*
		 * There are no outstanding allocations from this slab,
		 * so we can reclaim the memory.
		 */
		sp->slab_next->slab_prev = sp->slab_prev;
		sp->slab_prev->slab_next = sp->slab_next;
		if (sp == cp->cache_freelist)
			cp->cache_freelist = sp->slab_next;
		cp->cache_slab_destroy++;
		cp->cache_buftotal -= sp->slab_chunks;
		mutex_exit(&cp->cache_lock);
		kmem_slab_destroy(cp, sp);
		return;
	}
	mutex_exit(&cp->cache_lock);
}


/*
 * Free each object in magazine mp to cp's slab layer, and free mp itself.
 */
static void
kmem_magazine_destroy(kmem_cache_t *cp, kmem_magazine_t *mp, int nrounds)
{
	int round;

	ASSERT(cp->cache_next == NULL || taskq_member(kmem_taskq, curthread));

	for (round = 0; round < nrounds; round++) {
		void *buf = mp->mag_round[round];

		if (cp->cache_destructor != NULL) {
			cp->cache_destructor(buf, cp->cache_private);
		}
		kmem_slab_free(cp, buf);
	}
	ASSERT(KMEM_MAGAZINE_VALID(cp, mp));
	kmem_cache_free(cp->cache_magtype->mt_cache, mp);
}

/*
 * Allocate a magazine from the depot.
 */
static kmem_magazine_t *
kmem_depot_alloc(kmem_cache_t *cp, kmem_maglist_t *mlp)
{
	kmem_magazine_t *mp;

	/*
	 * If we can't get the depot lock without contention,
	 * update our contention count.  We use the depot
	 * contention rate to determine whether we need to
	 * increase the magazine size for better scalability.
	 */
	if (!mutex_tryenter(&cp->cache_depot_lock)) {
		mutex_enter(&cp->cache_depot_lock);
		cp->cache_depot_contention++;
	}

	if ((mp = mlp->ml_list) != NULL) {
		ASSERT(KMEM_MAGAZINE_VALID(cp, mp));
		mlp->ml_list = mp->mag_next;
		if (--mlp->ml_total < mlp->ml_min)
			mlp->ml_min = mlp->ml_total;
		mlp->ml_alloc++;
	}

	mutex_exit(&cp->cache_depot_lock);

	return (mp);
}

/*
 * Free a magazine to the depot.
 */
static void
kmem_depot_free(kmem_cache_t *cp, kmem_maglist_t *mlp, kmem_magazine_t *mp)
{
	mutex_enter(&cp->cache_depot_lock);
	ASSERT(KMEM_MAGAZINE_VALID(cp, mp));
	mp->mag_next = mlp->ml_list;
	mlp->ml_list = mp;
	mlp->ml_total++;
	mutex_exit(&cp->cache_depot_lock);
}

/*
 * Update the working set statistics for cp's depot.
 */
static void
kmem_depot_ws_update(kmem_cache_t *cp)
{
	mutex_enter(&cp->cache_depot_lock);
	cp->cache_full.ml_reaplimit = cp->cache_full.ml_min;
	cp->cache_full.ml_min = cp->cache_full.ml_total;
	cp->cache_empty.ml_reaplimit = cp->cache_empty.ml_min;
	cp->cache_empty.ml_min = cp->cache_empty.ml_total;
	mutex_exit(&cp->cache_depot_lock);
}

/*
 * Reap all magazines that have fallen out of the depot's working set.
 */
static void
kmem_depot_ws_reap(kmem_cache_t *cp)
{
	long reap;
	kmem_magazine_t *mp;

	ASSERT(cp->cache_next == NULL || taskq_member(kmem_taskq, curthread));

	reap = MIN(cp->cache_full.ml_reaplimit, cp->cache_full.ml_min);
	while (reap-- && (mp = kmem_depot_alloc(cp, &cp->cache_full)) != NULL)
		kmem_magazine_destroy(cp, mp, cp->cache_magtype->mt_magsize);

	reap = MIN(cp->cache_empty.ml_reaplimit, cp->cache_empty.ml_min);
	while (reap-- && (mp = kmem_depot_alloc(cp, &cp->cache_empty)) != NULL)
		kmem_magazine_destroy(cp, mp, 0);
}

static void
kmem_cpu_reload(kmem_cpu_cache_t *ccp, kmem_magazine_t *mp, int rounds)
{
	ASSERT((ccp->cc_loaded == NULL && ccp->cc_rounds == -1) ||
	    (ccp->cc_loaded && ccp->cc_rounds + rounds == ccp->cc_magsize));
	ASSERT(ccp->cc_magsize > 0);

	ccp->cc_ploaded = ccp->cc_loaded;
	ccp->cc_prounds = ccp->cc_rounds;
	ccp->cc_loaded = mp;
	ccp->cc_rounds = rounds;
}

/*
 * Allocate a constructed object from cache cp.
 */
void *
kmem_cache_alloc(kmem_cache_t *cp, int kmflag)
{
	kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);
	kmem_magazine_t *fmp;
	void *buf;

#ifdef __APPLE__
	atomic_inc_32(&cp->cache_buf_inuse);
	
	/*
	 * When allocating znodes, occasionally adjust our footprint target
	 */
	if ((cp == znode_cache_get()) && (cp->cache_buf_inuse & 0x3f) == 0) {

		recalc_target_footprint(cp->cache_buf_inuse);	
	}
#endif

	mutex_enter(&ccp->cc_lock);
	for (;;) {
		/*
		 * If there's an object available in the current CPU's
		 * loaded magazine, just take it and return.
		 */
		if (ccp->cc_rounds > 0) {
			buf = ccp->cc_loaded->mag_round[--ccp->cc_rounds];
			ccp->cc_alloc++;
			mutex_exit(&ccp->cc_lock);
			return (buf);
		}

		/*
		 * The loaded magazine is empty.  If the previously loaded
		 * magazine was full, exchange them and try again.
		 */
		if (ccp->cc_prounds > 0) {
			kmem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
			continue;
		}

		/*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

		/*
		 * Try to get a full magazine from the depot.
		 */
		fmp = kmem_depot_alloc(cp, &cp->cache_full);
		if (fmp != NULL) {
			if (ccp->cc_ploaded != NULL)
				kmem_depot_free(cp, &cp->cache_empty,
				    ccp->cc_ploaded);
			kmem_cpu_reload(ccp, fmp, ccp->cc_magsize);
			continue;
		}

		/*
		 * There are no full magazines in the depot,
		 * so fall through to the slab layer.
		 */
		break;
	}
	mutex_exit(&ccp->cc_lock);

	/*
	 * We couldn't allocate a constructed object from the magazine layer,
	 * so get a raw buffer from the slab layer and apply its constructor.
	 */
	buf = kmem_slab_alloc(cp, kmflag);

	if (buf == NULL)
		return (NULL);

	if (cp->cache_constructor != NULL &&
	    cp->cache_constructor(buf, cp->cache_private, kmflag) != 0) {
		atomic_add_64(&cp->cache_alloc_fail, 1);
		kmem_slab_free(cp, buf);
		return (NULL);
	}

	return (buf);
}

/*
 * Free a constructed object to cache cp.
 */
void
kmem_cache_free(kmem_cache_t *cp, void *buf)
{
	kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);
	kmem_magazine_t *emp;
	kmem_magtype_t *mtp;

#ifdef __APPLE__
	atomic_dec_32(&cp->cache_buf_inuse);

	/*
	 * When freeing znodes, occasionally adjust our footprint target
	 */
	if ((cp == znode_cache_get()) && (cp->cache_buf_inuse & 0x3f) == 0) {
		recalc_target_footprint(cp->cache_buf_inuse);
	}

	/*
	 * Stop caching dbufs/dnodes when we have too many dnodes.
	 */
	if (cp== dnode_cache_get() || cp == dbuf_cache_get()) {
		int dnode_cnt;
		int znode_cnt;

		dnode_cnt = dnode_cache_get()->cache_buftotal;
		znode_cnt = znode_cache_get()->cache_buftotal;
		if ((znode_cnt > 1000) && (dnode_cnt > (5 * znode_cnt))) {
			goto slabfree;
		}
	}
#endif */ __APPLE__ */

	mutex_enter(&ccp->cc_lock);
	for (;;) {
		/*
		 * If there's a slot available in the current CPU's
		 * loaded magazine, just put the object there and return.
		 */
		if ((uint_t)ccp->cc_rounds < ccp->cc_magsize) {
			ccp->cc_loaded->mag_round[ccp->cc_rounds++] = buf;
			ccp->cc_free++;
			mutex_exit(&ccp->cc_lock);
			return;
		}

		/*
		 * The loaded magazine is full.  If the previously loaded
		 * magazine was empty, exchange them and try again.
		 */
		if (ccp->cc_prounds == 0) {
			kmem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
			continue;
		}

		/*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

		/*
		 * Try to get an empty magazine from the depot.
		 */
		emp = kmem_depot_alloc(cp, &cp->cache_empty);
		if (emp != NULL) {
			if (ccp->cc_ploaded != NULL)
				kmem_depot_free(cp, &cp->cache_full,
				    ccp->cc_ploaded);
			kmem_cpu_reload(ccp, emp, 0);
			continue;
		}

		/*
		 * There are no empty magazines in the depot,
		 * so try to allocate a new one.  We must drop all locks
		 * across kmem_cache_alloc() because lower layers may
		 * attempt to allocate from this cache.
		 */
		mtp = cp->cache_magtype;
		mutex_exit(&ccp->cc_lock);
		emp = kmem_cache_alloc(mtp->mt_cache, KM_NOSLEEP);
		mutex_enter(&ccp->cc_lock);

		if (emp != NULL) {
			/*
			 * We successfully allocated an empty magazine.
			 * However, we had to drop ccp->cc_lock to do it,
			 * so the cache's magazine size may have changed.
			 * If so, free the magazine and try again.
			 */
			if (ccp->cc_magsize != mtp->mt_magsize) {
				mutex_exit(&ccp->cc_lock);
				kmem_cache_free(mtp->mt_cache, emp);
				mutex_enter(&ccp->cc_lock);
				continue;
			}

			/*
			 * We got a magazine of the right size.  Add it to
			 * the depot and try the whole dance again.
			 */
			kmem_depot_free(cp, &cp->cache_empty, emp);
			continue;
		}

		/*
		 * We couldn't allocate an empty magazine,
		 * so fall through to the slab layer.
		 */
		break;
	}
	mutex_exit(&ccp->cc_lock);

#ifdef __APPLE__
slabfree:
#endif
	/*
	 * We couldn't free our constructed object to the magazine layer,
	 * so apply its destructor and free it to the slab layer.
	 * Note that if KMF_DEADBEEF is in effect and KMF_LITE is not,
	 * kmem_cache_free_debug() will have already applied the destructor.
	 */
	if ((cp->cache_flags & (KMF_DEADBEEF | KMF_LITE)) != KMF_DEADBEEF &&
	    cp->cache_destructor != NULL) {
		if (cp->cache_flags & KMF_DEADBEEF) {	/* KMF_LITE implied */
			kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
			*(uint64_t *)buf = btp->bt_redzone;
			cp->cache_destructor(buf, cp->cache_private);
			*(uint64_t *)buf = KMEM_FREE_PATTERN;
		} else {
			cp->cache_destructor(buf, cp->cache_private);
		}
	}

	kmem_slab_free(cp, buf);
}

/*
 * Reclaim all unused memory from a cache.
 */
static void
kmem_cache_reap(kmem_cache_t *cp)
{
	/*
	 * Ask the cache's owner to free some memory if possible.
	 * The idea is to handle things like the inode cache, which
	 * typically sits on a bunch of memory that it doesn't truly
	 * *need*.  Reclaim policy is entirely up to the owner; this
	 * callback is just an advisory plea for help.
	 */
	if (cp->cache_reclaim != NULL)
		cp->cache_reclaim(cp->cache_private);

	kmem_depot_ws_reap(cp);
}

static void
kmem_reap_timeout(void *flag_arg)
{
	uint32_t *flag = (uint32_t *)flag_arg;

	ASSERT(flag == &kmem_reaping || flag == &kmem_reaping_idspace);
	*flag = 0;
}

static void
kmem_reap_done(void *flag)
{
#ifdef __APPLE__
	bsd_timeout(kmem_reap_timeout, flag, &kmem_reap_interval);
#else
	(void) timeout(kmem_reap_timeout, flag, kmem_reap_interval);
#endif
}

static void
kmem_reap_start(void *flag)
{
	ASSERT(flag == &kmem_reaping || flag == &kmem_reaping_idspace);

	if (flag == &kmem_reaping)
		kmem_cache_applyall(kmem_cache_reap, kmem_taskq, TQ_NOSLEEP);
	else
		kmem_cache_applyall_id(kmem_cache_reap, kmem_taskq, TQ_NOSLEEP);

	/*
	 * We use taskq_dispatch() to schedule a timeout to clear
	 * the flag so that kmem_reap() becomes self-throttling:
	 * we won't reap again until the current reap completes *and*
	 * at least kmem_reap_interval ticks have elapsed.
	 */
	if (!taskq_dispatch(kmem_taskq, kmem_reap_done, flag, TQ_NOSLEEP))
		kmem_reap_done(flag);
}

static void
kmem_reap_common(void *flag_arg)
{
	uint32_t *flag = (uint32_t *)flag_arg;

	if (MUTEX_HELD(&kmem_cache_lock) || kmem_taskq == NULL ||
	    atomic_cas_32(flag, 0, 1) != 0) {
		return;
	}
	/*
	 * It may not be kosher to do memory allocation when a reap is called
	 * (for example, if vmem_populate() is in the call chain).
	 * So we start the reap going with a TQ_NOALLOC dispatch.  If the
	 * dispatch fails, we reset the flag, and the next reap will try again.
	 */
	if (!taskq_dispatch(kmem_taskq, kmem_reap_start, flag, TQ_NOALLOC))
		*flag = 0;
}

/*
 * Reclaim all unused memory from all caches.  Called from the VM system
 * when memory gets tight.
 */
void
kmem_reap(void)
{
	kmem_reap_common(&kmem_reaping);
}

/*
 * Reclaim all unused memory from identifier arenas, called when a vmem
 * arena not back by memory is exhausted.  Since reaping memory-backed caches
 * cannot help with identifier exhaustion, we avoid both a large amount of
 * work and unwanted side-effects from reclaim callbacks.
 */
void
kmem_reap_idspace(void)
{
	kmem_reap_common(&kmem_reaping_idspace);
}

/*
 * Purge all magazines from a cache and set its magazine limit to zero.
 * All calls are serialized by the kmem_taskq lock, except for the final
 * call from kmem_cache_destroy().
 */
static void
kmem_cache_magazine_purge(kmem_cache_t *cp)
{
	kmem_cpu_cache_t *ccp;
	kmem_magazine_t *mp, *pmp;
	int rounds, prounds, cpu_seqid;

	ASSERT(cp->cache_next == NULL || taskq_member(kmem_taskq, curthread));
	ASSERT(MUTEX_NOT_HELD(&cp->cache_lock));

	for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
		ccp = &cp->cache_cpu[cpu_seqid];

		mutex_enter(&ccp->cc_lock);
		mp = ccp->cc_loaded;
		pmp = ccp->cc_ploaded;
		rounds = ccp->cc_rounds;
		prounds = ccp->cc_prounds;
		ccp->cc_loaded = NULL;
		ccp->cc_ploaded = NULL;
		ccp->cc_rounds = -1;
		ccp->cc_prounds = -1;
		ccp->cc_magsize = 0;
		mutex_exit(&ccp->cc_lock);

		if (mp)
			kmem_magazine_destroy(cp, mp, rounds);
		if (pmp)
			kmem_magazine_destroy(cp, pmp, prounds);
	}

	/*
	 * Updating the working set statistics twice in a row has the
	 * effect of setting the working set size to zero, so everything
	 * is eligible for reaping.
	 */
	kmem_depot_ws_update(cp);
	kmem_depot_ws_update(cp);

	kmem_depot_ws_reap(cp);
}

/*
 * Enable per-cpu magazines on a cache.
 */
static void
kmem_cache_magazine_enable(kmem_cache_t *cp)
{
	int cpu_seqid;

	if (cp->cache_flags & KMF_NOMAGAZINE)
		return;

	for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
		kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
		mutex_enter(&ccp->cc_lock);
		ccp->cc_magsize = cp->cache_magtype->mt_magsize;
		mutex_exit(&ccp->cc_lock);
	}

}

/*
 * Reap (almost) everything right now.  See kmem_cache_magazine_purge()
 * for explanation of the back-to-back kmem_depot_ws_update() calls.
 */
void
kmem_cache_reap_now(kmem_cache_t *cp)
{
	kmem_depot_ws_update(cp);
	kmem_depot_ws_update(cp);

	(void) taskq_dispatch(kmem_taskq,
	    (task_func_t *)kmem_depot_ws_reap, cp, TQ_SLEEP);
	taskq_wait(kmem_taskq);
}

/*
 * Recompute a cache's magazine size.  The trade-off is that larger magazines
 * provide a higher transfer rate with the depot, while smaller magazines
 * reduce memory consumption.  Magazine resizing is an expensive operation;
 * it should not be done frequently.
 *
 * Changes to the magazine size are serialized by the kmem_taskq lock.
 *
 * Note: at present this only grows the magazine size.  It might be useful
 * to allow shrinkage too.
 */
static void
kmem_cache_magazine_resize(kmem_cache_t *cp)
{
	kmem_magtype_t *mtp = cp->cache_magtype;

	ASSERT(taskq_member(kmem_taskq, curthread));

	if (cp->cache_chunksize < mtp->mt_maxbuf) {
		kmem_cache_magazine_purge(cp);
		mutex_enter(&cp->cache_depot_lock);
		cp->cache_magtype = ++mtp;
		cp->cache_depot_contention_prev =
		    cp->cache_depot_contention + INT_MAX;
		mutex_exit(&cp->cache_depot_lock);
		kmem_cache_magazine_enable(cp);
	}
}

/*
 * Rescale a cache's hash table, so that the table size is roughly the
 * cache size.  We want the average lookup time to be extremely small.
 */
static void
kmem_hash_rescale(kmem_cache_t *cp)
{
	kmem_bufctl_t **old_table, **new_table, *bcp;
	size_t old_size, new_size, h;

	ASSERT(taskq_member(kmem_taskq, curthread));

	new_size = MAX(KMEM_HASH_INITIAL,
	    1 << (highbit(3 * cp->cache_buftotal + 4) - 2));
	old_size = cp->cache_hash_mask + 1;

	if ((old_size >> 1) <= new_size && new_size <= (old_size << 1))
		return;

	new_table = vmem_alloc(kmem_hash_arena, new_size * sizeof (void *),
	    VM_NOSLEEP);
	if (new_table == NULL)
		return;
	bzero(new_table, new_size * sizeof (void *));

	mutex_enter(&cp->cache_lock);

	old_size = cp->cache_hash_mask + 1;
	old_table = cp->cache_hash_table;

	cp->cache_hash_mask = new_size - 1;
	cp->cache_hash_table = new_table;
	cp->cache_rescale++;

	for (h = 0; h < old_size; h++) {
		bcp = old_table[h];
		while (bcp != NULL) {
			void *addr = bcp->bc_addr;
			kmem_bufctl_t *next_bcp = bcp->bc_next;
			kmem_bufctl_t **hash_bucket = KMEM_HASH(cp, addr);
			bcp->bc_next = *hash_bucket;
			*hash_bucket = bcp;
			bcp = next_bcp;
		}
	}

	mutex_exit(&cp->cache_lock);

	vmem_free(kmem_hash_arena, old_table, old_size * sizeof (void *));
}

/*
 * Perform periodic maintenance on a cache: hash rescaling,
 * depot working-set update, and magazine resizing.
 */
static void
kmem_cache_update(kmem_cache_t *cp)
{
	int need_hash_rescale = 0;
	int need_magazine_resize = 0;

	ASSERT(MUTEX_HELD(&kmem_cache_lock));

	/*
	 * If the cache has become much larger or smaller than its hash table,
	 * fire off a request to rescale the hash table.
	 */
	mutex_enter(&cp->cache_lock);

	if ((cp->cache_flags & KMF_HASH) &&
	    (cp->cache_buftotal > (cp->cache_hash_mask << 1) ||
	    (cp->cache_buftotal < (cp->cache_hash_mask >> 1) &&
	    cp->cache_hash_mask > KMEM_HASH_INITIAL)))
		need_hash_rescale = 1;

	mutex_exit(&cp->cache_lock);

	/*
	 * Update the depot working set statistics.
	 */
	kmem_depot_ws_update(cp);

	/*
	 * If there's a lot of contention in the depot,
	 * increase the magazine size.
	 */
	mutex_enter(&cp->cache_depot_lock);

	if (cp->cache_chunksize < cp->cache_magtype->mt_maxbuf &&
	    (int)(cp->cache_depot_contention -
	    cp->cache_depot_contention_prev) > kmem_depot_contention)
		need_magazine_resize = 1;

	cp->cache_depot_contention_prev = cp->cache_depot_contention;

	mutex_exit(&cp->cache_depot_lock);

	if (need_hash_rescale)
		(void) taskq_dispatch(kmem_taskq,
		    (task_func_t *)kmem_hash_rescale, cp, TQ_NOSLEEP);

	if (need_magazine_resize)
		(void) taskq_dispatch(kmem_taskq,
		    (task_func_t *)kmem_cache_magazine_resize, cp, TQ_NOSLEEP);
}

#ifndef __APPLE__
static void
kmem_update_timeout(void *dummy)
{
	static void kmem_update(void *);

	(void) timeout(kmem_update, dummy, kmem_reap_interval);
}

static void
kmem_update(void *dummy)
{
	kmem_cache_applyall(kmem_cache_update, NULL, TQ_NOSLEEP);

	/*
	 * We use taskq_dispatch() to reschedule the timeout so that
	 * kmem_update() becomes self-throttling: it won't schedule
	 * new tasks until all previous tasks have completed.
	 */
	if (!taskq_dispatch(kmem_taskq, kmem_update_timeout, dummy, TQ_NOSLEEP))
		kmem_update_timeout(NULL);
}
#endif /*!__APPLE__*/

kmem_cache_t *
kmem_cache_create(
	char *name,		/* descriptive name for this cache */
	size_t bufsize,		/* size of the objects it manages */
	size_t align,		/* required object alignment */
	int (*constructor)(void *, void *, int), /* object constructor */
	void (*destructor)(void *, void *),	/* object destructor */
	void (*reclaim)(void *), /* memory reclaim callback */
	void *private,		/* pass-thru arg for constr/destr/reclaim */
	vmem_t *vmp,		/* vmem source for slab allocation */
	int cflags)		/* cache creation flags */
{
	int cpu_seqid;
	size_t chunksize;
	kmem_cache_t *cp, *cnext, *cprev;
	kmem_magtype_t *mtp;
	size_t csize = KMEM_CACHE_SIZE(max_ncpus);

#ifdef	DEBUG
	/*
	 * Cache names should conform to the rules for valid C identifiers
	 */
	if (!strident_valid(name)) {
		cmn_err(CE_CONT,
		    "kmem_cache_create: '%s' is an invalid cache name\n"
		    "cache names must conform to the rules for "
		    "C identifiers\n", name);
	}
#endif	/* DEBUG */

	if (vmp == NULL)
		vmp = kmem_default_arena;

	/*
	 * If this kmem cache has an identifier vmem arena as its source, mark
	 * it such to allow kmem_reap_idspace().
	 */
	ASSERT(!(cflags & KMC_IDENTIFIER));   /* consumer should not set this */
	if (vmp->vm_cflags & VMC_IDENTIFIER)
		cflags |= KMC_IDENTIFIER;

	/*
	 * Get a kmem_cache structure.  We arrange that cp->cache_cpu[]
	 * is aligned on a KMEM_CPU_CACHE_SIZE boundary to prevent
	 * false sharing of per-CPU data.
	 */
	cp = vmem_xalloc(kmem_cache_arena, csize, KMEM_CPU_CACHE_SIZE,
	    P2NPHASE(csize, KMEM_CPU_CACHE_SIZE), 0, NULL, NULL, VM_SLEEP);
	bzero(cp, csize);

	if (align == 0)
		align = KMEM_ALIGN;

	/*
	 * If we're not at least KMEM_ALIGN aligned, we can't use free
	 * memory to hold bufctl information (because we can't safely
	 * perform word loads and stores on it).
	 */
	if (align < KMEM_ALIGN)
		cflags |= KMC_NOTOUCH;

	if ((align & (align - 1)) != 0 || align > vmp->vm_quantum)
		panic("kmem_cache_create: bad alignment %lu", align);

	mutex_enter(&kmem_flags_lock);
	if (kmem_flags & KMF_RANDOMIZE)
		kmem_flags = (((kmem_flags | ~KMF_RANDOM) + 1) & KMF_RANDOM) |
		    KMF_RANDOMIZE;
	cp->cache_flags = (kmem_flags | cflags) & KMF_DEBUG;
	mutex_exit(&kmem_flags_lock);

	/*
	 * Make sure all the various flags are reasonable.
	 */
	ASSERT(!(cflags & KMC_NOHASH) || !(cflags & KMC_NOTOUCH));

	if (cp->cache_flags & KMF_LITE) {
		if (bufsize >= kmem_lite_minsize &&
		    align <= kmem_lite_maxalign &&
		    P2PHASE(bufsize, kmem_lite_maxalign) != 0) {
			cp->cache_flags |= KMF_BUFTAG;
			cp->cache_flags &= ~(KMF_AUDIT | KMF_FIREWALL);
		} else {
			cp->cache_flags &= ~KMF_DEBUG;
		}
	}

	if (cp->cache_flags & KMF_DEADBEEF)
		cp->cache_flags |= KMF_REDZONE;

	if ((cflags & KMC_QCACHE) && (cp->cache_flags & KMF_AUDIT))
		cp->cache_flags |= KMF_NOMAGAZINE;

	if (cflags & KMC_NODEBUG)
		cp->cache_flags &= ~KMF_DEBUG;

	if (cflags & KMC_NOTOUCH)
		cp->cache_flags &= ~KMF_TOUCH;

	if (cflags & KMC_NOHASH)
		cp->cache_flags &= ~(KMF_AUDIT | KMF_FIREWALL);

	if (cflags & KMC_NOMAGAZINE)
		cp->cache_flags |= KMF_NOMAGAZINE;

	if ((cp->cache_flags & KMF_AUDIT) && !(cflags & KMC_NOTOUCH))
		cp->cache_flags |= KMF_REDZONE;

	if (!(cp->cache_flags & KMF_AUDIT))
		cp->cache_flags &= ~KMF_CONTENTS;

	if ((cp->cache_flags & KMF_BUFTAG) && bufsize >= kmem_minfirewall &&
	    !(cp->cache_flags & KMF_LITE) && !(cflags & KMC_NOHASH))
		cp->cache_flags |= KMF_FIREWALL;

	if (vmp != kmem_default_arena || kmem_firewall_arena == NULL)
		cp->cache_flags &= ~KMF_FIREWALL;

	if (cp->cache_flags & KMF_FIREWALL) {
		cp->cache_flags &= ~KMF_BUFTAG;
		cp->cache_flags |= KMF_NOMAGAZINE;
		ASSERT(vmp == kmem_default_arena);
		vmp = kmem_firewall_arena;
	}

	/*
	 * Set cache properties.
	 */
	(void) strncpy(cp->cache_name, name, KMEM_CACHE_NAMELEN);
	strident_canon(cp->cache_name, KMEM_CACHE_NAMELEN);
	cp->cache_bufsize = bufsize;
	cp->cache_align = align;
	cp->cache_constructor = constructor;
	cp->cache_destructor = destructor;
	cp->cache_reclaim = reclaim;
	cp->cache_private = private;
	cp->cache_arena = vmp;
	cp->cache_cflags = cflags;

	/*
	 * Determine the chunk size.
	 */
	chunksize = bufsize;

	if (align >= KMEM_ALIGN) {
		chunksize = P2ROUNDUP(chunksize, KMEM_ALIGN);
		cp->cache_bufctl = chunksize - KMEM_ALIGN;
	}

	if (cp->cache_flags & KMF_DEADBEEF) {
		cp->cache_verify = MIN(cp->cache_buftag, kmem_maxverify);
		if (cp->cache_flags & KMF_LITE)
			cp->cache_verify = sizeof (uint64_t);
	}

	cp->cache_contents = MIN(cp->cache_bufctl, kmem_content_maxsave);

	cp->cache_chunksize = chunksize = P2ROUNDUP(chunksize, align);

	/*
	 * Now that we know the chunk size, determine the optimal slab size.
	 */
	if (vmp == kmem_firewall_arena) {
		cp->cache_slabsize = P2ROUNDUP(chunksize, vmp->vm_quantum);
		cp->cache_mincolor = cp->cache_slabsize - chunksize;
		cp->cache_maxcolor = cp->cache_mincolor;
		cp->cache_flags |= KMF_HASH;
		ASSERT(!(cp->cache_flags & KMF_BUFTAG));
	} else if ((cflags & KMC_NOHASH) || (!(cflags & KMC_NOTOUCH) &&
	    !(cp->cache_flags & KMF_AUDIT) &&
	    chunksize < vmp->vm_quantum / KMEM_VOID_FRACTION)) {
		cp->cache_slabsize = vmp->vm_quantum;

#ifdef __APPLE__
		/*
		 * Override some of the 4K slab sizes for popular
		 * object types so we don't blow out the kernel
		 * map entries.
		 */
		if ((cp->cache_slabsize == 4096) && (name != NULL)) {
			if ((strcmp(name, "zfs_znode_cache") == 0) ||
			    (strcmp(name, "dmu_buf_impl_t") == 0) ||
			    (strcmp(name, "dnode_t") == 0)) {
				cp->cache_slabsize = 32768;
			} else if (strcmp(name, "arc_buf_hdr_t") == 0) {
				cp->cache_slabsize = 8192;
			}
		}
#endif
		cp->cache_mincolor = 0;
		cp->cache_maxcolor =
		    (cp->cache_slabsize - sizeof (kmem_slab_t)) % chunksize;
		ASSERT(chunksize + sizeof (kmem_slab_t) <= cp->cache_slabsize);
		ASSERT(!(cp->cache_flags & KMF_AUDIT));
	} else {
		size_t chunks, bestfit, waste, slabsize;
		size_t minwaste = LONG_MAX;

		for (chunks = 1; chunks <= KMEM_VOID_FRACTION; chunks++) {
			slabsize = P2ROUNDUP(chunksize * chunks,
			    vmp->vm_quantum);
			chunks = slabsize / chunksize;
			waste = (slabsize % chunksize) / chunks;
			if (waste < minwaste) {
				minwaste = waste;
				bestfit = slabsize;
			}
		}
		if (cflags & KMC_QCACHE)
			bestfit = VMEM_QCACHE_SLABSIZE(vmp->vm_qcache_max);
		cp->cache_slabsize = bestfit;

#ifdef __APPLE__
		/*
		 * Override some of the slab sizes for popular
		 * object types so we don't blow out the kernel
		 * map entries.
		 */
		if (cp->cache_slabsize == 4096) {
			switch(cp->cache_bufsize) {
			case 512:
				cp->cache_slabsize = 32768;
				break;

			case 1024:
				cp->cache_slabsize = 16384;
				break;
			}
		} else if (cp->cache_slabsize == 16384 && cp->cache_bufsize == 16384) {
			cp->cache_slabsize = 16384;
		}
#endif
		cp->cache_mincolor = 0;
		cp->cache_maxcolor = bestfit % chunksize;
		cp->cache_flags |= KMF_HASH;
	}

	if (cp->cache_flags & KMF_HASH) {
		ASSERT(!(cflags & KMC_NOHASH));
		cp->cache_bufctl_cache = kmem_bufctl_cache;
	}

	if (cp->cache_maxcolor >= vmp->vm_quantum)
		cp->cache_maxcolor = vmp->vm_quantum - 1;

	cp->cache_color = cp->cache_mincolor;

	/*
	 * Initialize the rest of the slab layer.
	 */
	mutex_init(&cp->cache_lock, NULL, MUTEX_DEFAULT, NULL);

	cp->cache_freelist = &cp->cache_nullslab;
	cp->cache_nullslab.slab_cache = cp;
	cp->cache_nullslab.slab_refcnt = -1;
	cp->cache_nullslab.slab_next = &cp->cache_nullslab;
	cp->cache_nullslab.slab_prev = &cp->cache_nullslab;

	if (cp->cache_flags & KMF_HASH) {
		cp->cache_hash_table = vmem_alloc(kmem_hash_arena,
		    KMEM_HASH_INITIAL * sizeof (void *), VM_SLEEP);
		bzero(cp->cache_hash_table,
		    KMEM_HASH_INITIAL * sizeof (void *));
		cp->cache_hash_mask = KMEM_HASH_INITIAL - 1;
		cp->cache_hash_shift = highbit((ulong_t)chunksize) - 1;
	}

	/*
	 * Initialize the depot.
	 */
	mutex_init(&cp->cache_depot_lock, NULL, MUTEX_DEFAULT, NULL);

	for (mtp = kmem_magtype; chunksize <= mtp->mt_minbuf; mtp++)
		continue;

	cp->cache_magtype = mtp;

	/*
	 * Initialize the CPU layer.
	 */
	for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++) {
		kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
		mutex_init(&ccp->cc_lock, NULL, MUTEX_DEFAULT, NULL);
		ccp->cc_flags = cp->cache_flags;
		ccp->cc_rounds = -1;
		ccp->cc_prounds = -1;
	}

	/*
	 * Add the cache to the global list.  This makes it visible
	 * to kmem_update(), so the cache must be ready for business.
	 */
	mutex_enter(&kmem_cache_lock);
	cp->cache_next = cnext = &kmem_null_cache;
	cp->cache_prev = cprev = kmem_null_cache.cache_prev;
	cnext->cache_prev = cp;
	cprev->cache_next = cp;
	mutex_exit(&kmem_cache_lock);

	if (kmem_ready)
		kmem_cache_magazine_enable(cp);

	return (cp);
}

void
kmem_cache_destroy(kmem_cache_t *cp)
{
	int cpu_seqid;

	/*
	 * Remove the cache from the global cache list so that no one else
	 * can schedule tasks on its behalf, wait for any pending tasks to
	 * complete, purge the cache, and then destroy it.
	 */
	mutex_enter(&kmem_cache_lock);
	cp->cache_prev->cache_next = cp->cache_next;
	cp->cache_next->cache_prev = cp->cache_prev;
	cp->cache_prev = cp->cache_next = NULL;
	mutex_exit(&kmem_cache_lock);

	if (kmem_taskq != NULL)
		taskq_wait(kmem_taskq);

	kmem_cache_magazine_purge(cp);

	mutex_enter(&cp->cache_lock);
	if (cp->cache_buftotal != 0)
		cmn_err(CE_WARN, "kmem_cache_destroy: '%s' (%p) not empty",
		    cp->cache_name, (void *)cp);
	cp->cache_reclaim = NULL;
	/*
	 * The cache is now dead.  There should be no further activity.
	 * We enforce this by setting land mines in the constructor and
	 * destructor routines that induce a kernel text fault if invoked.
	 */
	cp->cache_constructor = (int (*)(void *, void *, int))1;
	cp->cache_destructor = (void (*)(void *, void *))2;
	mutex_exit(&cp->cache_lock);

	if (cp->cache_hash_table != NULL)
		vmem_free(kmem_hash_arena, cp->cache_hash_table,
		    (cp->cache_hash_mask + 1) * sizeof (void *));

	for (cpu_seqid = 0; cpu_seqid < max_ncpus; cpu_seqid++)
		mutex_destroy(&cp->cache_cpu[cpu_seqid].cc_lock);

	mutex_destroy(&cp->cache_depot_lock);
	mutex_destroy(&cp->cache_lock);

	vmem_free(kmem_cache_arena, cp, KMEM_CACHE_SIZE(max_ncpus));
}

#ifndef __APPLE__
static int
kmem_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	if (what == CPU_UNCONFIG) {
		kmem_cache_applyall(kmem_cache_magazine_purge,
		    kmem_taskq, TQ_SLEEP);
		kmem_cache_applyall(kmem_cache_magazine_enable,
		    kmem_taskq, TQ_SLEEP);
	}
	return (0);
}
#endif /* !__APPLE__ */

static void
kmem_cache_init(int pass, int use_large_pages)
{
	int i;
	size_t size;
	kmem_cache_t *cp;
	kmem_magtype_t *mtp;
	char name[KMEM_CACHE_NAMELEN + 1];

	for (i = 0; i < sizeof (kmem_magtype) / sizeof (*mtp); i++) {
		mtp = &kmem_magtype[i];
		(void) sprintf(name, "kmem_magazine_%d", mtp->mt_magsize);
		mtp->mt_cache = kmem_cache_create(name,
		    (mtp->mt_magsize + 1) * sizeof (void *),
		    mtp->mt_align, NULL, NULL, NULL, NULL,
		    kmem_msb_arena, KMC_NOHASH);
	}

	kmem_slab_cache = kmem_cache_create("kmem_slab_cache",
	    sizeof (kmem_slab_t), 0, NULL, NULL, NULL, NULL,
	    kmem_msb_arena, KMC_NOHASH);

	kmem_bufctl_cache = kmem_cache_create("kmem_bufctl_cache",
	    sizeof (kmem_bufctl_t), 0, NULL, NULL, NULL, NULL,
	    kmem_msb_arena, KMC_NOHASH);
}

void
kmem_init(void)
{
	mutex_init(&kmem_cache_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&kmem_flags_lock, NULL, MUTEX_DEFAULT, NULL);

	kmem_default_arena = &kmem_default_arena_instance;
	kmem_default_arena->vm_quantum = PAGESIZE;

	/* LINTED */
	ASSERT(sizeof (kmem_cpu_cache_t) == KMEM_CPU_CACHE_SIZE);

	kmem_null_cache.cache_next = &kmem_null_cache;
	kmem_null_cache.cache_prev = &kmem_null_cache;

	kmem_reap_interval.tv_sec = 15;
	kmem_reap_interval.tv_nsec = 0;

	kmem_cache_init(2, 0);

	/* Initialize the callb table locks for the taskq's*/
	callb_init();

	taskq_init();

	kmem_thread_init();

	kmem_cache_applyall(kmem_cache_magazine_enable, NULL, TQ_SLEEP);

	kmem_ready = 1;
}

void
kmem_thread_init(void)
{
	kmem_taskq = taskq_create("kmem_taskq", 1, minclsyspri,
	    300, INT_MAX, TASKQ_PREPOPULATE);
}

#ifdef __APPLE__
void
kmem_fini(void)
{
	int i;
	kmem_cache_t *cp;
	kmem_magtype_t *mtp;

	if (kmem_taskq) {
		taskq_destroy(kmem_taskq);
		kmem_taskq = NULL;
	}
	taskq_fini();

	for (i = 0; i < sizeof (kmem_magtype) / sizeof (*mtp); i++) {
		mtp = &kmem_magtype[i];
		if (mtp->mt_cache) {
			kmem_cache_destroy(mtp->mt_cache);
			mtp->mt_cache = NULL;
		}
	}
	if (kmem_slab_cache) {
		kmem_cache_destroy(kmem_slab_cache);
		kmem_slab_cache = NULL;
	}
	if (kmem_bufctl_cache) {
		kmem_cache_destroy(kmem_bufctl_cache);
		kmem_bufctl_cache = NULL;
	}
}

void
kmem_cache_stats(kmem_cache_stats_t *cache_stats, int max_stats, int *act_stats)
{
	kmem_cache_t *cp;
	int count = 0;

	if (!kmem_ready) {
		*act_stats = 0;
		return;
	}

	mutex_enter(&kmem_cache_lock);
	for (cp = kmem_null_cache.cache_next; cp != &kmem_null_cache; cp = cp->cache_next) {
		(void) strncpy(cache_stats->cache_name, cp->cache_name, KMEM_CACHE_NAMELEN);
		cache_stats->cache_obj_size = cp->cache_bufsize;
		cache_stats->cache_obj_count = cp->cache_buftotal;
		cache_stats->cache_obj_inuse = cp->cache_buf_inuse;
		cache_stats->cache_obj_peak = cp->cache_bufmax;
		cache_stats->cache_slab_size = cp->cache_slabsize;
		if (++count >= max_stats)
			break;
		++cache_stats;
	}
	mutex_exit(&kmem_cache_lock);
	*act_stats = count;
}
#endif /* __APPLE__ */

