/*
 * Copyright (c) 2007-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#define _ZFS_CONTEXT_IMP

#include <sys/zfs_context.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dmu.h>
#include <sys/malloc.h>
#include <sys/spa.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <sys/vdev_impl.h>
#include <sys/time.h>

#include <kern/locks.h>
#include <kern/thread_call.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>

#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>

#include <sys/dbuf.h>
#include <sys/kstat.h>

#include <sys/kauth.h>

#ifdef __APPLE__
#if defined(__arm___)
#include <arm/arch.h>
#endif
#endif

/*
 * Everywhere else in the ZFS code, kmem_alloc maps to zfs_kmem_alloc.
 * But here in zfs_context.c we need access to the Mac OS X kmem_alloc
 * implementation.
 */
#undef kmem_alloc
#undef kmem_free

extern kern_return_t	kmem_alloc(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size);

extern void		kmem_free(
				vm_map_t	map,
				vm_offset_t	addr,
				vm_size_t	size);
extern vm_map_t	kernel_map;

/*
 * CONTEXT GLOBALS
 */

lck_attr_t *  zfs_lock_attr = NULL;
lck_grp_attr_t *  zfs_group_attr = NULL;
lck_grp_t *  zfs_mutex_group = NULL;
lck_grp_t *  zfs_rwlock_group = NULL;
lck_grp_t *  zfs_spinlock_group = NULL;

OSMallocTag zfs_kmem_alloc_tag = NULL;


pgcnt_t	physmem;

extern uint64_t    max_mem;


unsigned int	max_ncpus;		/* max number of cpus */


#define KERN_MAP_MIN_SIZE	(8192+1)

size_t zfs_kernelmap_size;
size_t zfs_kallocmap_size;

#define ZFS_BASE_TARGET  (96 * 1024 * 1024)


zfs_memory_stats_t zfs_footprint;

int zfs_threads;


proc_t p0;		/* process 0 */


/*
 * CONTEXT INITIALIZATION
 */

void
zfs_context_init(void)
{
	uint64_t kern_mem_size;

	zfs_lock_attr = lck_attr_alloc_init();
	zfs_group_attr = lck_grp_attr_alloc_init();
#if 0
	lck_attr_setdebug(zfs_lock_attr);
#endif
	zfs_mutex_group  = lck_grp_alloc_init("zfs-mutex", zfs_group_attr);
	zfs_rwlock_group = lck_grp_alloc_init("zfs-rwlock", zfs_group_attr);
	zfs_spinlock_group = lck_grp_alloc_init("zfs-spinlock", zfs_group_attr);

	zfs_kmem_alloc_tag = OSMalloc_Tagalloc("ZFS general purpose", 
			OSMT_DEFAULT);

	max_ncpus = 1;

	/* kernel memory space is 4 GB max */
	kern_mem_size = MIN(max_mem, (uint64_t)0x0FFFFFFFFULL);

	/* Calculate number of pages of memory on the system */
	physmem = kern_mem_size / PAGE_SIZE;

	/* Constrain our memory use on smaller memory systems */
	if (kern_mem_size <= 0x20000000)
		zfs_footprint.maximum = kern_mem_size / 7;    /* 512MB: ~15 % */
	else if (kern_mem_size <= 0x30000000)
		zfs_footprint.maximum = kern_mem_size / 5;    /* 768MB: ~20 % */
	else if (kern_mem_size <= 0x40000000)
		zfs_footprint.maximum = kern_mem_size / 3;    /* 1GB: ~33 % */
	else	/* set to 1GB limit maximum*/ 
		zfs_footprint.maximum = MIN((kern_mem_size / 2), 0x40000000);

	recalc_target_footprint(100);

	printf("zfs_context_init: footprint.maximum=%lu, footprint.target=%lu\n",
		zfs_footprint.maximum, zfs_footprint.target);
}

void
zfs_context_fini(void)
{
	lck_attr_free(zfs_lock_attr);
	zfs_lock_attr = NULL;

	lck_grp_attr_free(zfs_group_attr);
	zfs_group_attr = NULL;

	lck_grp_free(zfs_mutex_group);
	zfs_mutex_group = NULL;

	lck_grp_free(zfs_rwlock_group);
	zfs_rwlock_group = NULL;

	lck_grp_free(zfs_spinlock_group);
	zfs_spinlock_group = NULL;

	OSMalloc_Tagfree(zfs_kmem_alloc_tag);
}


#define USEC_PER_SEC	1000000		/* microseconds per second */

/* Open Solaris lbolt is in hz */
uint64_t
zfs_lbolt()
{
	struct timeval tv;
	uint64_t lbolt_hz;

	microuptime(&tv);
	lbolt_hz = ((uint64_t)tv.tv_sec * USEC_PER_SEC + tv.tv_usec) / 10000;
	return (lbolt_hz);
}

/*
 * Returns true if the named dataset is visible in the current zone.
 * The 'write' parameter is set to 1 if the dataset is also writable.
 */
int
zone_dataset_visible(const char *dataset, int *write)
{
	if (write)
		*write = 0;
	return (0);
}


/*
 * Find highest one bit set.
 *	Returns bit number + 1 of highest bit that is set, otherwise returns 0.
 * High order bit is 31 (or 63 in _LP64 kernel).
 */
int
highbit(ulong_t i)
{
	register int h = 1;

	if (i == 0)
		return (0);
#if 0
	if (i & 0xffffffff00000000ul) {
		h += 32; i >>= 32;
	}
#endif
	if (i & 0xffff0000) {
		h += 16; i >>= 16;
	}
	if (i & 0xff00) {
		h += 8; i >>= 8;
	}
	if (i & 0xf0) {
		h += 4; i >>= 4;
	}
	if (i & 0xc) {
		h += 2; i >>= 2;
	}
	if (i & 0x2) {
		h += 1;
	}
	return (h);
}

/*
 * Return ptr to first occurrence of any character from `brkset'
 * in the character string `string'; NULL if none exists.
 */
char *
strpbrk(const char *string, const char *brkset)
{
	const char *p;

	do {
		for (p = brkset; *p != '\0' && *p != *string; ++p)
			;
		if (*p != '\0')
			return ((char *)string);
	} while (*string++);

	return (NULL);
}

/*
 * Return the ptr in sp at which the character c last
 * appears; NULL if not found
 */
char *
strrchr(const char *sp, int c)
{
	char *r = NULL;

	do {
		if (*sp == (char)c)
			r = (char *)sp;
	} while (*sp++);

	return (r);
}


/*
 * MISCELLANEOUS WRAPPERS
 */
int
uio_move(caddr_t cp, int n, int rw_flag, struct uio *uio)
{
	uio_setrw(uio, rw_flag);
	return uiomove(cp, n, uio);
}

void
dmu_buf_will_dirty(dmu_buf_t *db, dmu_tx_t *tx)
{
	dbuf_will_dirty((dmu_buf_impl_t *)db, tx);
}

void
dmu_buf_fill_done(dmu_buf_t *db, dmu_tx_t *tx)
{
	dbuf_fill_done((dmu_buf_impl_t *)db, tx);
}

void
dmu_buf_add_ref(dmu_buf_t *db, void* tag)
{
	dbuf_add_ref((dmu_buf_impl_t *)db, tag);
}

void
dmu_buf_rele(dmu_buf_t *db, void *tag)
{
	dbuf_rele((dmu_buf_impl_t *)db, tag);
}

uint64_t
dmu_buf_refcount(dmu_buf_t *db)
{
	return dbuf_refcount((dmu_buf_impl_t *)db);
}

/* NOTE: 
 * Mac OSX atomic operations return value is the number
 * BEFORE it is atomically incremented or decremented.
 * This is opposite that of Solaris.
 * We need a real KPI for this functionality!
 */
SInt64
OSAddAtomic64_NV(SInt64 theAmount, volatile SInt64 *address)
{
	SInt64 value = OSAddAtomic64(theAmount, address);
	/* the store to "*address" will be atomic, but we need to recalculate what it would be here */
	return value + theAmount;
}


#if !defined(__i386__) && !defined(__x86_64__)
/*
 * Emulated for architectures that don't have this primitive. Do an atomic
 * add for the low order bytes, try to detect overflow/underflow, and
 * update the high order bytes. The second update is definitely not
 * atomic, but it's better than nothing.
 */
SInt64
OSAddAtomic64(SInt64 theAmount, volatile SInt64 *address)
{
	volatile SInt32 *lowaddr;
	volatile SInt32 *highaddr;
	SInt32 highword;
	SInt32 lowword;
	
#ifdef __BIG_ENDIAN__
	highaddr = (volatile SInt32 *)address;
	lowaddr = highaddr + 1;
#else
	lowaddr = (volatile SInt32 *)address;
	highaddr = lowaddr + 1;
#endif
	
	highword = *highaddr;
	lowword = OSAddAtomic((SInt32)theAmount, lowaddr); // lowword is the old value
	if ((theAmount < 0) && (lowword < -theAmount)) {
		// underflow, decrement the high word
		(void)OSAddAtomic(-1, highaddr);
	} else if ((theAmount > 0) && ((UInt32)lowword > 0xFFFFFFFF-theAmount)) {
		// overflow, increment the high word
		(void)OSAddAtomic(1, highaddr);
	}
	return ((SInt64)highword << 32) | ((UInt32)lowword);
}

SInt64
OSIncrementAtomic64(volatile SInt64 *address)
{
	return OSAddAtomic64(1, address);
}
#endif  /* !__i386__ && !__x86_64__ */



uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t new)
{
	uint32_t old = *target;

	OSCompareAndSwap( cmp, new, (volatile UInt32 *)target );
	return old;
}

/*
 * This operation is not thread-safe and the user must
 * protect it my some other means.  The only known caller
 * is zfs_vnop_write() and the value is protected by the
 * znode's mutex.
 */
uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t cmp, uint64_t new)
{
	uint64_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

void *
atomic_cas_ptr(volatile void *target, void *cmp, void *new)
{
	void *old = *(void **)target;
	
#ifdef __LP64__
	OSCompareAndSwapPtr(cmp, new, target);
#else
	OSCompareAndSwap( (uint32_t)cmp, (uint32_t)new, (unsigned long *)target );
#endif
	return old;
}



/*
 * MUTEX LOCKS
 */
void
mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc)
{
	ASSERT(type != MUTEX_SPIN);
	ASSERT(ibc == NULL);

	lck_mtx_init((lck_mtx_t *)&mp->m_lock[0],
	             zfs_mutex_group, zfs_lock_attr);
	mp->m_owner = NULL;
}

void
mutex_destroy(kmutex_t *mp)
{
	lck_mtx_destroy((lck_mtx_t *)&mp->m_lock[0], zfs_mutex_group);
}

void
mutex_enter(kmutex_t *mp)
{
	if (mp->m_owner == current_thread())
		panic("mutex_enter: locking against myself!");
		
	lck_mtx_lock((lck_mtx_t *)&mp->m_lock[0]);
	mp->m_owner = current_thread();
}

void
mutex_exit(kmutex_t *mp)
{
	mp->m_owner = NULL;
	lck_mtx_unlock((lck_mtx_t *)&mp->m_lock[0]);
}

int
mutex_tryenter(kmutex_t *mp)
{
	int held;

	if (mp->m_owner == current_thread())
		panic("mutex_tryenter: locking against myself!");

	held = lck_mtx_try_lock((lck_mtx_t *)&mp->m_lock[0]);
	if (held)
		mp->m_owner = current_thread();
	 return (held);
}

int
mutex_owned(kmutex_t *mp)
{
	return (mp->m_owner == current_thread());
}

kthread_t *
mutex_owner(kmutex_t *mp)
{
	return (mp->m_owner);
}

/*
 * READER/WRITER LOCKS
 */

void
rw_init(krwlock_t *rwlp, char *name, krw_type_t type, __unused void *arg)
{
	ASSERT(type != RW_DRIVER);

	lck_rw_init((lck_rw_t *)&rwlp->rw_lock[0],
	            zfs_rwlock_group, zfs_lock_attr);
	rwlp->rw_owner = NULL;
	rwlp->rw_readers = 0;
}

void
rw_destroy(krwlock_t *rwlp)
{
	lck_rw_destroy((lck_rw_t *)&rwlp->rw_lock[0], zfs_rwlock_group);
}

void
rw_enter(krwlock_t *rwlp, krw_t rw)
{
	if (rw == RW_READER) {
		lck_rw_lock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
		OSIncrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
	} else {
		if (rwlp->rw_owner == current_thread())
			panic("rw_enter: locking against myself!");
		lck_rw_lock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
		rwlp->rw_owner = current_thread();
	}
}

/*
 * kernel private from osfmk/kern/locks.h
 */
extern boolean_t lck_rw_try_lock(lck_rw_t *lck, lck_rw_type_t lck_rw_type);


int
rw_tryenter(krwlock_t *rwlp, krw_t rw)
{
	int held = 0;

	if (rw == RW_READER) {
		held = lck_rw_try_lock((lck_rw_t *)&rwlp->rw_lock[0],
		                       LCK_RW_TYPE_SHARED);
		if (held)
			OSIncrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
	} else {
		if (rwlp->rw_owner == current_thread())
			panic("rw_tryenter: locking against myself!");
		held = lck_rw_try_lock((lck_rw_t *)&rwlp->rw_lock[0],
		                       LCK_RW_TYPE_EXCLUSIVE);
		if (held)
			rwlp->rw_owner = current_thread();
	}

	return (held);
}

/*
 * Not supported in Mac OS X kernel.
 */
int
rw_tryupgrade(krwlock_t *rwlp)
{
	return (0);
}

void
rw_exit(krwlock_t *rwlp)
{
	if (rwlp->rw_owner == current_thread()) {
		rwlp->rw_owner = NULL;
		lck_rw_unlock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
	} else {
		OSDecrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
		lck_rw_unlock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
	}
}

int
rw_lock_held(krwlock_t *rwlp)
{
	/*
	 * ### not sure about this one ###
	 */
	return (rwlp->rw_owner == current_thread() || rwlp->rw_readers > 0);
}

int
rw_write_held(krwlock_t *rwlp)
{
	return (rwlp->rw_owner == current_thread());
}

void
rw_downgrade(krwlock_t *rwlp)
{
	rwlp->rw_owner = NULL;
	lck_rw_lock_exclusive_to_shared((lck_rw_t *)&rwlp->rw_lock[0]);
	OSIncrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
}

size_t p2round(size_t);

size_t
p2round(size_t x)
{
	if (x < KERN_MAP_MIN_SIZE) {
		--x;
		x |= x >> 1;
		x |= x >> 2;
		x |= x >> 4;
		x |= x >> 8;
		x |= x >> 16;
		++x;
	}
	return (x);
}

int
is_ascii_str(const char * str)
{
	unsigned char ch;

	while ((ch = (unsigned char)*str++) != '\0') {
		if (ch >= 0x80)
			return (0);
	}
	return (1);
}


/*
 * General-Purpose Memory Allocation.
 */

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
	void *buf;

	if (kmflags & KM_NOSLEEP)
		buf = OSMalloc_noblock(size, zfs_kmem_alloc_tag);
	else
		buf = OSMalloc(size, zfs_kmem_alloc_tag);

	if (buf != NULL) {
		OSAddAtomic(p2round(size), (SInt32 *)&zfs_kallocmap_size);
		OSAddAtomic(p2round(size), (SInt32 *)&zfs_footprint.current);
		if (zfs_footprint.current > zfs_footprint.highest)
			zfs_footprint.highest = zfs_footprint.current;
	}
	return(buf);
}

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
	void *buf;

	buf = zfs_kmem_alloc(size, kmflags);
	if (buf != NULL)
		bzero(buf, size);
	return(buf);
}

void
zfs_kmem_free(void *buf, size_t size)
{
	OSFree(buf, size, zfs_kmem_alloc_tag);
	OSAddAtomic(-p2round(size), (SInt32 *)&zfs_kallocmap_size);
	OSAddAtomic(-p2round(size), (SInt32 *)&zfs_footprint.current);
}

int
kmem_debugging(void)
{
	return (0);
}


/*
 * Virtual Memory allocator.
 */
void *
vmem_alloc(__unused vmem_t *vmp, size_t size, int vmflag)
{
	void *buf;

	/*
	 * Only use kernel_map for sizes that are at least a page size
	 */
	if (size < KERN_MAP_MIN_SIZE) {
		buf = zfs_kmem_alloc(size, vmflag);
	} else if (kmem_alloc(kernel_map, (vm_offset_t *)&buf, size) != KERN_SUCCESS) {
		buf = NULL;
	} else {
		OSAddAtomic(size, (SInt32 *)&zfs_kernelmap_size);
		OSAddAtomic(size, (SInt32 *)&zfs_footprint.current);
		if (zfs_footprint.current > zfs_footprint.highest)
			zfs_footprint.highest = zfs_footprint.current;
	}
	
	if (buf == NULL) {
		if (vmflag & VM_NOSLEEP)
			return (NULL);
		else
			panic("zfs: vmem_alloc couldn't alloc %d bytes\n", size);
	}

	/*
	 * When were low on memory, call kmem_reap()
	 */

	return (buf);
}

void
vmem_free(__unused vmem_t *vmp, void *vaddr, size_t size)
{
	/*
	 * Only use kmem_alloc for sizes that are at least a page size
	 */
	if (size < KERN_MAP_MIN_SIZE) {
		zfs_kmem_free(vaddr, size);
	} else {
		kmem_free(kernel_map, (vm_offset_t)vaddr, size);
		OSAddAtomic(-size, (SInt32 *)&zfs_kernelmap_size);
		OSAddAtomic(-size, (SInt32 *)&zfs_footprint.current);
	}
}

void *
vmem_xalloc(vmem_t *vmp, size_t size, __unused size_t align_arg, __unused size_t phase,
	__unused size_t nocross, __unused void *minaddr, __unused void *maxaddr, int vmflag)
{
	return vmem_alloc(vmp, size, vmflag);
}

void
recalc_target_footprint(int znode_cnt)
{
	uint32_t target;

	/*
	 * Server Model Footprint Scaling
	 *
	 * for each znode assume:
	 *	1 znode
	 *	3 dnode_t
	 *	3 dbuf_t
	 *	3 arc_buf_hdr_t
	 *	2 arc_buf_t
	 *	16K of zio_bufs
	 *
	 * which is roughly 20K per znode.
	 */
	target = ZFS_BASE_TARGET + (znode_cnt * (20 * 1024));

	/*
	 * Bound it to fit in kernel memory size.
	 */
	zfs_footprint.target = MIN(target, zfs_footprint.maximum);
}


/*
 * Condition variables.
 */
void
cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg)
{
	cvp->cv_waiters = 0;
}

void
cv_destroy(kcondvar_t *cvp)
{
}

void
cv_signal(kcondvar_t *cvp)
{
	if (cvp->cv_waiters > 0) {
		wakeup_one((caddr_t)cvp);
		--cvp->cv_waiters;
	}
}

void
cv_broadcast(kcondvar_t *cvp)
{
	if (cvp->cv_waiters > 0) {
		wakeup((caddr_t)cvp);
		cvp->cv_waiters = 0;
	}
}

/*
 * Block on the indicated condition variable and
 * release the associated mutex while blocked.
 */
void
_cv_wait(kcondvar_t *cvp, kmutex_t *mp, const char *msg)
{
	if (msg != NULL && msg[0] == '&')
		++msg;  /* skip over '&' prefixes */

	++cvp->cv_waiters;

	mp->m_owner = NULL;
	(void) msleep(cvp, (lck_mtx_t *)&mp->m_lock[0], PRIBIO, msg, 0);
	mp->m_owner = current_thread();
}

/*
 * Same as cv_wait except the thread will unblock at 'tim'
 * (an absolute time) if it hasn't already unblocked.
 *
 * Returns the amount of time left from the original 'tim' value
 * when it was unblocked.
 */
int
_cv_timedwait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, const char *msg)
{
	struct timespec ts;
	int result;

	if (msg != NULL && msg[0] == '&')
		++msg;  /* skip over '&' prefixes */

	ts.tv_sec = MAX(1, (tim - zfs_lbolt()) / hz);
	ts.tv_nsec = 0;
#if 1
	if (ts.tv_sec < 1)
		ts.tv_sec = 1;
#endif
	++cvp->cv_waiters;

	mp->m_owner = NULL;
	result = msleep(cvp, (lck_mtx_t *)&mp->m_lock[0], PRIBIO, msg, &ts);
	mp->m_owner = current_thread();

	return (result == EWOULDBLOCK ? -1 : 0);
}


/*
 * kobj file access
 */

struct _buf *
kobj_open_file(char *name)
{
	struct vnode *vp;
	vfs_context_t vctx;
	struct _buf *file;
	int error;

	vctx = vfs_context_create((vfs_context_t)0);
	error = vnode_open(name, 0, 0, 0, &vp, vctx);
	(void) vfs_context_rele(vctx);

	printf("kobj_open_file: \"%s\", err %d from vnode_open\n", name ? name : "", error);

	if (error) {
		return ((struct _buf *)-1);
	}
	file = (struct _buf *)zfs_kmem_alloc(sizeof (struct _buf *), KM_SLEEP);
	file->_fd = vp;

	return (file);
}

void
kobj_close_file(struct _buf *file)
{
	vfs_context_t vctx;

	vctx = vfs_context_create((vfs_context_t)0);
	(void) vnode_close(file->_fd, 0, vctx);
	(void) vfs_context_rele(vctx);

	zfs_kmem_free(file, sizeof (struct _buf));
}

int
kobj_fstat(struct vnode *vp, struct bootstat *buf)
{
	struct vnode_attr vattr;
	vfs_context_t vctx;
	int error;

	if (buf == NULL)
		return (-1);

	VATTR_INIT(&vattr);
	VATTR_WANTED(&vattr, va_mode);
	VATTR_WANTED(&vattr, va_data_size);
	vattr.va_mode = 0;
	vattr.va_data_size = 0;

	vctx = vfs_context_create((vfs_context_t)0);
	error = vnode_getattr(vp, &vattr, vctx);
	(void) vfs_context_rele(vctx);

	if (error == 0) {
		buf->st_mode = (uint32_t)vattr.va_mode;
		buf->st_size = vattr.va_data_size;
	}
	return (error);
}

int
kobj_read_file(struct _buf *file, char *buf, unsigned size, unsigned off)
{
	struct vnode *vp = file->_fd;
	vfs_context_t vctx;
	uio_t auio;
	int count;
	int error;

	vctx = vfs_context_create((vfs_context_t)0);
	auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_READ);
	uio_reset(auio, off, UIO_SYSSPACE32, UIO_READ);
	uio_addiov(auio, (uintptr_t)buf, size);

	error = VNOP_READ(vp, auio, 0, vctx);

	if (error)
		count = -1;
	else
		count = size - uio_resid(auio);

	uio_free(auio);
	(void) vfs_context_rele(vctx);

	return (count);
}

/*
 * Get the file size.
 *
 * Before root is mounted, files are compressed in the boot_archive ramdisk
 * (in the memory). kobj_fstat would return the compressed file size.
 * In order to get the uncompressed file size, read the file to the end and
 * count its size.
 */
int
kobj_get_filesize(struct _buf *file, uint64_t *size)
{
	/*
	 * In OSX, the root will always be mounted, so we can
	 * just use kobj_fstat to stat the file
	 */
	struct bootstat bst;

	if (kobj_fstat(file->_fd, &bst) != 0)
		return (EIO);
	*size = bst.st_size;
	return (0);
}

/*
 * kernel threads
 */

kthread_t *
thread_create(
	caddr_t		stk,
	size_t		stksize,
	void		(*proc)(),
	void		*arg,
	size_t		len,
	proc_t 		*pp,
	int		state,
	pri_t		pri)
{
	kern_return_t	result;
	thread_t	thread;

	result = kernel_thread_start((thread_continue_t)proc, arg, &thread);
	if (result != KERN_SUCCESS)
		return (NULL);

	thread_deallocate(thread);

	OSIncrementAtomic((SInt32 *)&zfs_threads);

	return (thread);
}

void thread_exit(void)
{
	OSDecrementAtomic((SInt32 *)&zfs_threads);

	(void) thread_terminate(current_thread());
}


/*
 * kstat emulation
 */

/*
 * Extended kstat structure -- for internal use only.
 */
typedef struct ekstat {
	kstat_t		e_ks;		/* the kstat itself */
	size_t		e_size;		/* total allocation size */
	kthread_t	*e_owner;	/* thread holding this kstat */
	kcondvar_t	e_cv;		/* wait for owner == NULL */
} ekstat_t;

static void
kstat_set_string(char *dst, const char *src)
{
	bzero(dst, KSTAT_STRLEN);
	(void) strncpy(dst, src, KSTAT_STRLEN - 1);
}

kstat_t *
kstat_create(const char *ks_module, int ks_instance, const char *ks_name,
    const char *ks_class, uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags)
{
	kstat_t *ksp;
	ekstat_t *e;
	size_t size;

	/*
	 * Allocate memory for the new kstat header.
	 */
	size = sizeof (ekstat_t);
	e = (ekstat_t *)zfs_kmem_alloc(size, KM_SLEEP);
	if (e == NULL) {
		cmn_err(CE_NOTE, "kstat_create('%s', %d, '%s'): "
			"insufficient kernel memory",
			ks_module, ks_instance, ks_name);
		return (NULL);
	}
	bzero(e, size);
	e->e_size = size;
	cv_init(&e->e_cv, NULL, CV_DEFAULT, NULL);


	/*
	 * Initialize as many fields as we can.  The caller may reset
	 * ks_lock, ks_update, ks_private, and ks_snapshot as necessary.
	 * Creators of virtual kstats may also reset ks_data.  It is
	 * also up to the caller to initialize the kstat data section,
	 * if necessary.  All initialization must be complete before
	 * calling kstat_install().
	 */
	ksp = &e->e_ks;
	ksp->ks_crtime		= gethrtime();
	kstat_set_string(ksp->ks_module, ks_module);
	ksp->ks_instance	= ks_instance;
	kstat_set_string(ksp->ks_name, ks_name);
	ksp->ks_type		= ks_type;
	kstat_set_string(ksp->ks_class, ks_class);
	ksp->ks_flags		= ks_flags | KSTAT_FLAG_INVALID;
	ksp->ks_ndata		= ks_ndata;
	ksp->ks_snaptime	= ksp->ks_crtime;

	return (ksp);
}

void
kstat_delete(kstat_t *ksp)
{
	ekstat_t *e = (ekstat_t *)ksp;

	cv_destroy(&e->e_cv);
	zfs_kmem_free(e, e->e_size);
}

void
kstat_install(kstat_t *ksp)
{
	ksp->ks_flags &= ~KSTAT_FLAG_INVALID;
}


int
random_get_pseudo_bytes(uint8_t *ptr, size_t len)
{
	read_random(ptr, len);
	return (0);
}


/*
 * Return the total amount of memory whose type matches typemask.  Thus:
 *
 *	typemask VMEM_ALLOC yields total memory allocated (in use).
 *	typemask VMEM_FREE yields total memory free (available).
 *	typemask (VMEM_ALLOC | VMEM_FREE) yields total arena size.
 */
size_t
vmem_size(vmem_t *vmp, int typemask)
{
	uint64_t size = 0;

	if (typemask ==  (VMEM_ALLOC | VMEM_FREE))
		size = physmem * PAGE_SIZE;
	
	/* 
	 * XXXNoel- change this to be able to report actual memory used and 
	 * memory free instead of guessing. Otherwise the arc_reclaim thread 
	 * will run constantly and can hurt our performance
	 */
	else
		size = (physmem * PAGE_SIZE) >> 2;

	return ((size_t)size);
}

/*
 * Returns true if the current process has a signal to process, and
 * the signal is not held.  The signal to process is put in p_cursig.
 * This is asked at least once each time a process enters the system
 * (though this can usually be done without actually calling issig by
 * checking the pending signal masks).  A signal does not do anything
 * directly to a process; it sets a flag that asks the process to do
 * something to itself.
 *
 * The "why" argument indicates the allowable side-effects of the call:
 *
 * FORREAL:  Extract the next pending signal from p_sig into p_cursig;
 * stop the process if a stop has been requested or if a traced signal
 * is pending.
 *
 * JUSTLOOKING:  Don't stop the process, just indicate whether or not
 * a signal might be pending (FORREAL is needed to tell for sure).
 */

#define threadmask (sigmask(SIGILL)|sigmask(SIGTRAP)|\
		    sigmask(SIGIOT)|sigmask(SIGEMT)|\
		    sigmask(SIGFPE)|sigmask(SIGBUS)|\
		    sigmask(SIGSEGV)|sigmask(SIGSYS)|\
		    sigmask(SIGPIPE)|sigmask(SIGKILL)|\
		    sigmask(SIGTERM)|sigmask(SIGINT))


int
issig(int why)
{
	if (why == JUSTLOOKING)
		return (1);
	else 
		return (thread_issignal(current_proc(), current_thread(), 
				threadmask));
}

/*
 * Arrange that all stores issued before this point in the code reach
 * global visibility before any stores that follow; useful in producer
 * modules that update a data item, then set a flag that it is available.
 * The memory barrier guarantees that the available flag is not visible
 * earlier than the updated data, i.e. it imposes store ordering.
 */
void
membar_producer(void)
{
#if defined (__ppc__) || defined (__ppc64__)
	__asm__ volatile("sync");
#elif defined (__i386__) || defined(__x86_64__)
	__asm__ volatile("sfence");
#elif defined (__arm__)
#if defined(_ARM_ARCH_6)
//	__asm__ volatile("dmb");
#endif
#else
#error architecture not supported
#endif
}

/*
 * gethrtime() provides high-resolution timestamps with machine-dependent origin.
 * Hence its primary use is to specify intervals.
 */

static hrtime_t
zfs_abs_to_nano(uint64_t elapsed)
{
	static mach_timebase_info_data_t    sTimebaseInfo = { 0, 0 };

	/*
	 * If this is the first time we've run, get the timebase.
	 * We can use denom == 0 to indicate that sTimebaseInfo is
	 * uninitialised because it makes no sense to have a zero
	 * denominator in a fraction.
	 */

	if ( sTimebaseInfo.denom == 0 ) {
		(void) clock_timebase_info(&sTimebaseInfo);
	}

	/*
	 * Convert to nanoseconds.
	 * return (elapsed * (uint64_t)sTimebaseInfo.numer)/(uint64_t)sTimebaseInfo.denom;
	 *
	 * Provided the final result is representable in 64 bits the following maneuver will
	 * deliver that result without intermediate overflow.
	 */
	if (sTimebaseInfo.denom == sTimebaseInfo.numer)
		return elapsed;
	else if (sTimebaseInfo.denom == 1)
		return elapsed * (uint64_t)sTimebaseInfo.numer;
	else {
		/* Decompose elapsed = eta32 * 2^32 + eps32: */
		uint64_t eta32 = elapsed >> 32;
		uint64_t eps32 = elapsed & 0x00000000ffffffffLL;

		uint32_t numer = sTimebaseInfo.numer, denom = sTimebaseInfo.denom;

		/* Form product of elapsed64 (decomposed) and numer: */
		uint64_t mu64 = numer * eta32;
		uint64_t lambda64 = numer * eps32;

		/* Divide the constituents by denom: */
		uint64_t q32 = mu64/denom;
		uint64_t r32 = mu64 - (q32 * denom); /* mu64 % denom */

		return (q32 << 32) + ((r32 << 32) + lambda64)/denom;
	}
}

hrtime_t
gethrtime(void)
{
	static uint64_t start = 0;

	if (start == 0)
		start = mach_absolute_time();
		
	return zfs_abs_to_nano(mach_absolute_time() - start);
}

void
gethrestime(struct timespec *ts)
{
	nanotime(ts);
}

time_t
gethrestime_sec(void)
{
	struct timeval tv;

	microtime(&tv);
	return (tv.tv_sec);
}


int
vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode,
                    struct vnode **vpp, enum create crwhy, mode_t umask)
{
	vfs_context_t vctx;
	int fmode;
	int error;

	fmode = filemode;
	if (crwhy)
		fmode |= O_CREAT;
	// TODO I think this should be 'fmode' instead of 'filemode'
	vctx = vfs_context_create((vfs_context_t)0);
	error = vnode_open(pnamep, filemode, createmode, 0, vpp, vctx);
	(void) vfs_context_rele(vctx);
	return (error);
}


int
vn_openat(char *pnamep, enum uio_seg seg, int filemode, int createmode,
		struct vnode **vpp, enum create crwhy,
		mode_t umask, struct vnode *startvp)
{
	char *path;
	int pathlen = MAXPATHLEN;
	int error;

	path = (char *)zfs_kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	error = vn_getpath(startvp, path, &pathlen);
	if (error == 0) {
		strlcat(path, pnamep, MAXPATHLEN);
		error = vn_open(path, seg, filemode, createmode, vpp, crwhy,
				umask);
	}

	zfs_kmem_free(path, MAXPATHLEN);
	return (error);
}

extern errno_t vnode_rename(const char *, const char *, int, vfs_context_t);

errno_t
vnode_rename(const char *from, const char *to, int flags, vfs_context_t vctx)
{
	/*
	 * We need proper KPI changes to be able to safely update
	 * the zpool.cache file. For now, we return EPERM.
	 */
	return (EPERM);
}

int
vn_rename(char *from, char *to, enum uio_seg seg)
{
	vfs_context_t vctx;
	int error;

	vctx = vfs_context_create((vfs_context_t)0);

	error = vnode_rename(from, to, 0, vctx);

	(void) vfs_context_rele(vctx);

	return (error);
}

extern errno_t vnode_remove(const char *, int, enum vtype, vfs_context_t);

errno_t
vnode_remove(const char *name, int flag, enum vtype type, vfs_context_t vctx)
{
	printf("vnode_remove: \"%s\"\n", name);
	printf("zfs: vnode_remove not yet supported\n");
	return (EPERM);
}

int
vn_remove(char *fnamep, enum uio_seg seg, enum rm dirflag)
{
	vfs_context_t vctx;
	enum vtype type;
	int error;

	type = dirflag == RMDIRECTORY ? VDIR : VREG;

	vctx = vfs_context_create((vfs_context_t)0);

	error = vnode_remove(fnamep, 0, type, vctx);

	(void) vfs_context_rele(vctx);

	return (error);
}

int
zfs_vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, ssize_t len,
		offset_t offset, enum uio_seg seg, int ioflag, rlim64_t ulimit,
		cred_t *cr, ssize_t *residp)
{
	uio_t auio;
	int spacetype;
	int error=0;
	vfs_context_t vctx;

	spacetype = UIO_SEG_IS_USER_SPACE(seg) ? UIO_USERSPACE32 : UIO_SYSSPACE;

	vctx = vfs_context_create((vfs_context_t)0);
	auio = uio_create(1, 0, spacetype, rw);
	uio_reset(auio, offset, spacetype, rw);
	uio_addiov(auio, (uint64_t)(uintptr_t)base, len);

	if (rw == UIO_READ) {
		error = VNOP_READ(vp, auio, ioflag, vctx);
	} else {
		error = VNOP_WRITE(vp, auio, ioflag, vctx);
	}

	if (residp) {
		*residp = uio_resid(auio);
	} else {
		if (uio_resid(auio) && error == 0)
			error = EIO;
	}

	uio_free(auio);
	vfs_context_rele(vctx);

	return (error);
}

/*
 * VOP Glue (needed for zfs replay)
 */
#if 1
int VOP_CREATE(void);
int VOP_LINK(void);
int VOP_MKDIR(void);
int VOP_REMOVE(void);
int VOP_RENAME(void);
int VOP_RMDIR(void);
int VOP_SETATTR(void);
int VOP_SETSECATTR(void);
int VOP_SYMLINK(void);

int VOP_CREATE(void)
{
	printf("zfs: VOP_CREATE not yet supported\n");
	return(ENOTSUP);
}
int VOP_LINK(void)
{
	printf("zfs: VOP_LINK not yet supported\n");
	return(ENOTSUP);
}
int VOP_MKDIR(void)
{
	printf("zfs: VOP_MKDIR not yet supported\n");
	return(ENOTSUP);
}
int VOP_REMOVE(void)
{
	printf("zfs: VOP_REMOVE not yet supported\n");
	return(ENOTSUP);
}
int VOP_RENAME(void)
{
	printf("zfs: VOP_RENAME not yet supported\n");
	return(ENOTSUP);
}
int VOP_RMDIR(void)
{
	printf("zfs: VOP_RMDIR not yet supported\n");
	return(ENOTSUP);
}
int VOP_SETATTR(void)
{
	printf("zfs: VOP_SETATTR not yet supported\n");
	return(ENOTSUP);
}
int VOP_SETSECATTR(void)
{
	printf("zfs: VOP_SETSECATTR not yet supported\n");
	return(ENOTSUP);
}
int VOP_SYMLINK(void)
{
	printf("zfs: VOP_SYMLINK not yet supported\n");
	return(ENOTSUP);
}
#endif

int
VOP_SPACE(struct vnode *vp, int cmd, void *fl, int flags, offset_t off, cred_t *cr, void *ctx);

int
VOP_SPACE(struct vnode *vp, int cmd, void *fl, int flags, offset_t off, cred_t *cr, void *ctx)
{
	return (0);
}

int
VOP_CLOSE(struct vnode *vp, int flag, int count, offset_t off, void *cr)
{
	vfs_context_t vctx;
	int error;

	vctx = vfs_context_create((vfs_context_t)0);
	error = vnode_close(vp, flag & FWRITE, vctx);
	(void) vfs_context_rele(vctx);
	return (error);
}

int
VOP_FSYNC(struct vnode *vp, int flags, void* unused)
{
	vfs_context_t vctx;
	int error;

	vctx = vfs_context_create((vfs_context_t)0);
	error = VNOP_FSYNC(vp, (flags == FSYNC), vctx);
	(void) vfs_context_rele(vctx);
	return (error);
}

/*
 * ACLs
 */

/*
 * ace_trivial:
 * determine whether an ace_t acl is trivial
 *
 * Trivialness implys that the acl is composed of only
 * owner, group, everyone entries.  ACL can't
 * have read_acl denied, and write_owner/write_acl/write_attributes
 * can only be owner@ entry.
 */
int
ace_trivial(ace_t *acep, int aclcnt)
{
	int i;
	int owner_seen = 0;
	int group_seen = 0;
	int everyone_seen = 0;

	for (i = 0; i != aclcnt; i++) {
		switch (acep[i].a_flags & 0xf040) {
		case ACE_OWNER:
			if (group_seen || everyone_seen)
				return (1);
			owner_seen++;
			break;
		case ACE_GROUP|ACE_IDENTIFIER_GROUP:
			if (everyone_seen || owner_seen == 0)
				return (1);
			group_seen++;
			break;

		case ACE_EVERYONE:
			if (owner_seen == 0 || group_seen == 0)
				return (1);
			everyone_seen++;
			break;
		default:
			return (1);

		}

		if (acep[i].a_flags & (ACE_FILE_INHERIT_ACE|
		    ACE_DIRECTORY_INHERIT_ACE|ACE_NO_PROPAGATE_INHERIT_ACE|
		    ACE_INHERIT_ONLY_ACE))
			return (1);

		/*
		 * Special check for some special bits
		 *
		 * Don't allow anybody to deny reading basic
		 * attributes or a files ACL.
		 */
		if ((acep[i].a_access_mask &
		    (ACE_READ_ACL|ACE_READ_ATTRIBUTES)) &&
		    (acep[i].a_type == ACE_ACCESS_DENIED_ACE_TYPE))
			return (1);

		/*
		 * Allow on owner@ to allow
		 * write_acl/write_owner/write_attributes
		 */
		if (acep[i].a_type == ACE_ACCESS_ALLOWED_ACE_TYPE &&
		    (!(acep[i].a_flags & ACE_OWNER) && (acep[i].a_access_mask &
		    (ACE_WRITE_OWNER|ACE_WRITE_ACL|ACE_WRITE_ATTRIBUTES))))
			return (1);
	}

	if ((owner_seen == 0) || (group_seen == 0) || (everyone_seen == 0))
	    return (1);

	return (0);
}

void
adjust_ace_pair(ace_t *pair, mode_t mode)
{
	if (mode & S_IROTH)
		pair[1].a_access_mask |= ACE_READ_DATA;
	else
		pair[0].a_access_mask |= ACE_READ_DATA;
	if (mode & S_IWOTH)
		pair[1].a_access_mask |=
		    ACE_WRITE_DATA|ACE_APPEND_DATA;
	else
		pair[0].a_access_mask |=
		    ACE_WRITE_DATA|ACE_APPEND_DATA;
	if (mode & S_IXOTH)
		pair[1].a_access_mask |= ACE_EXECUTE;
	else
		pair[0].a_access_mask |= ACE_EXECUTE;
}

gid_t
crgetgid(const cred_t *cr)
{
	return kauth_cred_getgid((kauth_cred_t)cr);
}

/*
 * Returns true if any vdevs in the hierarchy is a disk
 */
int
vdev_contains_disks(vdev_t *vd)
{
	int c;

	if (vd == NULL)
		return (0);

	for (c = 0; c < vd->vdev_children; c++)
		if (vdev_contains_disks(vd->vdev_child[c]))
			return (1);

	if (vd->vdev_ops && vd->vdev_ops->vdev_op_leaf &&
	    strcmp(vd->vdev_ops->vdev_op_type, VDEV_TYPE_DISK) == 0) {
		return (1);
	}
	return (0);
}


int
chklock(struct vnode *vp, int iomode, u_offset_t offset, ssize_t len, int fmode, void *ct)
{
	return (0);
}


/*
 * Security Policy Stubs
 */

int
secpolicy_zinject(const cred_t *cr)
{
	/* Superuser privledges required */
	if (kauth_cred_issuser((kauth_cred_t)cr))
		return (0);
	else 
		return (1);
}

int
secpolicy_zfs(const cred_t *cr)
{
	return (0);
}

int
secpolicy_sys_config(const cred_t *cr, boolean_t checkonly)
{
	return (0);
}

void
secpolicy_setid_clear(vattr_t *vap, cred_t *cr)
{
}


int
secpolicy_vnode_remove(const cred_t *cr)
{
	return (0);
}

int
secpolicy_vnode_setid_retain(const cred_t *cred, boolean_t issuidroot)
{
	return (0);
}

int
secpolicy_vnode_setids_setgids(const cred_t *cred, gid_t gid)
{
	return (0);
}

int
secpolicy_vnode_create_gid(const cred_t *cred)
{
	return (0);
}

int
secpolicy_vnode_setdac(const cred_t *cred, uid_t owner)
{
	return (0);
}

int
secpolicy_vnode_access(const cred_t *cr, struct vnode *vp, uid_t owner, mode_t mode)
{
	return (0);
}


int zfsctl_root_lookup(struct vnode *, char *, struct vnode **, void *, int , struct vnode *, cred_t *);

int
zfsctl_root_lookup(struct vnode *dvp, char *nm, struct vnode **vpp, void *pnp,
    int flags, struct vnode *rdir, cred_t *cr)
{
	return (ENOENT);
}

ino64_t zfsctl_root_inode_cb(struct vnode *, int);

ino64_t
zfsctl_root_inode_cb(struct vnode *vp, int index)
{
	ASSERT(index == 0);
	return (0);
}

struct vnode * zfsctl_root(void *);

struct vnode *
zfsctl_root(void *zp)
{
	return (NULLVP);
}


int zvol_busy(void);

int
zvol_busy(void)
{
	return 0;
};

void zvol_check_volblocksize(void);
void zvol_check_volsize(void);
int zvol_close(void);
void zvol_create_cb(void);
void zvol_create_minor(void);
void zvol_fini(void);
void zvol_get_stats(void);
void zvol_init(void);
int zvol_open(void);
void zvol_read(void);
void zvol_remove_minor(void);
void zvol_set_volblocksize(void);
void zvol_set_volsize(void);
void zvol_write(void);

void zvol_check_volblocksize(void) {};
void zvol_check_volsize(void) {};
int zvol_close(void) {return (0);};
void zvol_create_cb(void) {};
void zvol_create_minor(void) {};
void zvol_fini(void) {};
void zvol_get_stats(void) {};
void zvol_init(void) {};
int zvol_open(void) {return (0);};
void zvol_read(void) {};
void zvol_remove_minor(void) {};
void zvol_set_volblocksize(void) {};
void zvol_set_volsize(void) {};
void zvol_write(void) {};

#ifdef __APPLE__
// log message to an internal buffer for debugging

// these values may need to be changed according to the available memory and message length
#define ZFS_MAX_MSG_NUM 100000
#define ZFS_MAX_MSG_LEN 128

// 
// because most debug messages have the same length, allocate one chunk of memory to avoid heap fragmentation
// 
typedef char ( *zfs_msg_buf_t )[ZFS_MAX_MSG_NUM][ZFS_MAX_MSG_LEN];

int zfs_msg_buf_enabled = 1;
int zfs_dprintf_enabled = 0;
UInt32 zfs_msg_buf_initialized = 0;
volatile int zfs_msg_buf_init_not_done = 1;
size_t zfs_msg_total = 0;
size_t zfs_msg_next = 0;
zfs_msg_buf_t zfs_msg_buf = NULL;
kmutex_t zfs_msg_lock;

static errno_t
init_debug_msg()
{
	size_t i;
	mutex_init(&zfs_msg_lock, NULL, MUTEX_DEFAULT, NULL);
	zfs_msg_next = zfs_msg_total = 0;
	MALLOC(zfs_msg_buf, zfs_msg_buf_t, ZFS_MAX_MSG_NUM * ZFS_MAX_MSG_LEN,
			M_TEMP, M_WAITOK);
	if (zfs_msg_buf == NULL) {
		panic("init_debug_msg out of memory");
	}
	for (i = 0; i<ZFS_MAX_MSG_NUM; i++)
		(*zfs_msg_buf)[i][0] = 0;	   /* make every string empty*/

	/* so other threads can continue*/
	zfs_msg_buf_init_not_done = 0;
	return 0;
}

void
debug_msg_internal(const char *fmt, ...)
{
	va_list args;

	if (!zfs_msg_buf_enabled)
		return;

	/* 
	 * Change zfs_msg_buf_initialized to 1 only when it was 0.  
	 * This avoids duplicated initialization 
	 */
	if (OSCompareAndSwap(0, 1, &zfs_msg_buf_initialized))
		if (init_debug_msg() != 0)
			return;

	while (zfs_msg_buf_init_not_done) {
		/* wait until init is done */
	}

	mutex_enter(&zfs_msg_lock);

	va_start(args, fmt);
	char *ptr = (*zfs_msg_buf)[zfs_msg_next];
	int len = snprintf(ptr, ZFS_MAX_MSG_LEN, "thr %p ", current_thread());
	vsnprintf(ptr + len, ZFS_MAX_MSG_LEN - len, fmt, args);
	va_end(args);

	/* Remove trailing newlines since gdb will print a newline*/
	char *ptr_end = ptr + strlen(ptr);
	ASSERT(ptr_end - ptr < ZFS_MAX_MSG_LEN);
	ptr_end--;
	while (*ptr_end == '\n') {
		*ptr_end = 0;
		ptr_end--;
	}

	zfs_msg_total++;
	zfs_msg_next = zfs_msg_total % ZFS_MAX_MSG_NUM;
	
	mutex_exit(&zfs_msg_lock);
}

void
dprint_stack_internal(char func_name[], char file_name[], int line)
{
	const char *newfile;
	/*
	 * Get rid of annoying "../common/" prefix to filename.
	 */
	newfile = strrchr(file_name, '/');
	if (newfile != NULL) {
		newfile = newfile + 1; /* Get rid of leading / */
	} else {
		newfile = file_name;
	}
	debug_msg("%s:%d %s() %p %p %p %p %p", newfile, line, func_name,
			 __builtin_return_address(1), __builtin_return_address(2),
			 __builtin_return_address(3));
}
#endif

