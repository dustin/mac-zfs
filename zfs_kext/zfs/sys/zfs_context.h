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
 *
 * Portions Copyright 2007-2008 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ZFS_CONTEXT_H
#define	_SYS_ZFS_CONTEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#if 0
#include <sys/note.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/buf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/kobj.h>
#include <sys/conf.h>
#include <sys/disp.h>
#include <sys/debug.h>
#include <sys/random.h>
#include <sys/byteorder.h>
#include <sys/systm.h>
#include <sys/list.h>
#include <sys/uio.h>
#include <sys/dirent.h>
#include <sys/time.h>
#include <vm/seg_kmem.h>
#include <sys/zone.h>
#include <sys/uio.h>
#include <sys/zfs_debug.h>
#endif

#define _SYS_KERNEL_H_

#include <sys/types.h>
#include <sys/param.h>

#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/cmn_err.h>
#endif

#include <sys/atomic.h>
#include <sys/mutex.h>
#include <sys/time.h>
#include <sys/list.h>
#include <sys/kmem.h>
#include <sys/bitmap.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/zfs_debug.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/kobj.h>
#include <sys/cred.h>

#include <stdarg.h>
#include <string.h>

#include <sys/fs/zfs_sysctl.h>

#include <sys/disk.h>
#define DKIOCFLUSHWRITECACHE DKIOCSYNCHRONIZECACHE

#define ZFS_SNAPDIR_VISIBLE 0

#ifndef MAX_UPL_TRANSFER
#define MAX_UPL_TRANSFER 256
#endif

/* Constants for sysevents framework*/
#define ESC_ZFS_VDEV_CLEAR      "ESC_ZFS_vdev_clear"
#define ESC_ZFS_VDEV_REMOVE     "ESC_ZFS_vdev_remove"
#define ESC_ZFS_POOL_DESTROY    "ESC_ZFS_pool_destroy"
#define ESC_ZFS_RESILVER_FINISH "ESC_ZFS_resilver_finish"
#define ESC_ZFS_RESILVER_START "ESC_ZFS_resilver_start"
#define ESC_ZFS_VDEV_CHECK      "ESC_ZFS_vdev_check"

/*
 * On Mac OS X we don't yet have access to cpu_number on all platforms.
 *
 * So we currently don't support per processor transaction state.
 */
#define	CPU_SEQID	(0)

#ifdef _KERNEL
extern kthread_t *thread_create(
	caddr_t		stk,
	size_t		stksize,
	void		(*proc)(),
	void		*arg,
	size_t		len,
	proc_t 		*pp,
	int		state,
	pri_t		pri);
#endif
	
extern void thread_exit(void);

#define	DEV_BSIZE	512
#define	DEV_BSHIFT	9		/* log2(DEV_BSIZE) */

#define	lbtodb(bytes)			/* calculates (bytes / DEV_BSIZE) */ \
	((u_offset_t)(bytes) >> DEV_BSHIFT)
#define	ldbtob(db)			/* calculates (db * DEV_BSIZE) */ \
	((u_offset_t)(db) << DEV_BSHIFT)

#include <sys/taskq.h>

/*
 * Definitions for commonly used resolutions.
 */
#define	SEC		1
#define	MILLISEC	1000
#define	MICROSEC	1000000
#define	NANOSEC		1000000000


void  zfs_context_init(void);
void  zfs_context_fini(void);

/*
 * READER/WRITER LOCKS
 */
typedef enum {
	RW_DRIVER = 2,		/* driver (DDI) rwlock */
	RW_DEFAULT = 4		/* kernel default rwlock */
} krw_type_t;

typedef enum {
	RW_WRITER,
	RW_READER
} krw_t;

#ifndef _KERNEL
typedef int lck_rw_t;
#endif

struct krwlock {
	uint32_t   rw_lock[4];   /* opaque lck_rw_t data */
	void       *rw_owner;    /* writer (exclusive) lock only */
	int        rw_readers;   /* reader lock only */
};
typedef struct krwlock  krwlock_t;

#define	RW_WRITE_HELD(x)	(rw_write_held((x)))
#define	RW_LOCK_HELD(x)		(rw_lock_held((x)))

extern  void  rw_init(krwlock_t *, char *, krw_type_t, void *);
extern  void  rw_destroy(krwlock_t *);
extern  void  rw_enter(krwlock_t *, krw_t);
extern  int   rw_tryenter(krwlock_t *, krw_t);
extern  void  rw_exit(krwlock_t *);
extern  void  rw_downgrade(krwlock_t *);
extern  int   rw_tryupgrade(krwlock_t *);
extern  int   rw_write_held(krwlock_t *);
extern  int   rw_lock_held(krwlock_t *);



/*
 * CONDITION VARIABLES
 */

typedef	enum {
	CV_DEFAULT,
	CV_DRIVER
} kcv_type_t;

struct cv {
	uint32_t   cv_waiters;
};
typedef struct cv  kcondvar_t;

extern void  cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg);
extern void  cv_destroy(kcondvar_t *cvp);
extern void  _cv_wait(kcondvar_t *cvp, kmutex_t *mp, const char *msg);
extern int   _cv_timedwait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, const char *msg);
extern void  cv_signal(kcondvar_t *cvp);
extern void  cv_broadcast(kcondvar_t *cvp);

/*
 * Use these wrapper macros to obtain the CV variable
 * name to make ZFS more gdb debugging friendly!
 * This name shows up as a thread's wait_event string.
 */
#define	cv_wait(cvp, mp)	\
	_cv_wait((cvp), (mp), #cvp)
#define	cv_timedwait(cvp, mp, tim)	\
	_cv_timedwait((cvp), (mp), (tim), #cvp)

#define UIO_USERISPACE  UIO_USERSPACE

/* Note: All FAPPEND flags have been changed to IO_APPEND
 * so any further FAPPEND flags ported must also be changed
 */

#define EBADE EBADMACHO

extern uint64_t  zfs_lbolt(void);
#define lbolt zfs_lbolt()
#define lbolt64 zfs_lbolt()

extern int hz;			/* system clock's frequency */

/* file flags */

#define	FSYNC		0x10	/* file (data+inode) integrity while writing */
#define	FDSYNC		0x40	/* file data only integrity while writing */
#define	FRSYNC		0x8000	/* sync read operations at same level of */
				/* integrity as specified for writes by */
				/* FSYNC and FDSYNC flags */
#define	FOFFMAX		0x2000	/* large file */
//#define	FNONBLOCK	0x80

//#define	FMASK		0xa0ff	/* all flags that can be changed by F_SETFL */

/* Note that OpenSolaris PAGEMASK is the inverse of Mac OS X PAGE_MASK! */
#define PAGESIZE     PAGE_SIZE
#define PAGEMASK     (~PAGEOFFSET)
#define	PAGEOFFSET   (PAGE_SIZE - 1)
#define PAGESHIFT    PAGE_SHIFT


typedef struct upl  page_t;


#define	btop(x)		(((x) >> PAGESHIFT))

#define DTRACE_PROBE1(a,b,c)
#define DTRACE_PROBE2(a,b,c,d,e)
#define DTRACE_PROBE3(a,b,c,d,e,f,g) 
#define DTRACE_PROBE4(a,b,c,d,e,f,g,h,i)


#define minclsyspri  0
#define maxclsyspri  0


#define heap_arena (vmem_t *)0


#ifdef _KERNEL
extern proc_t p0;		/* process 0 */

extern pgcnt_t	physmem;

extern size_t zfs_kernelmap_size;
extern size_t zfs_kallocmap_size;

extern zfs_memory_stats_t zfs_footprint;

extern int zfs_threads;

extern void recalc_target_footprint(int);


extern void kmem_cache_stats(kmem_cache_stats_t *cache_stats, int max_stats, int *act_stats);
extern void arc_get_stats(zfs_memory_stats_t *stats);


#endif

#define curproc  current_proc()

#define	INGLOBALZONE(p)   (1)

#define dnlc_reduce_cache(per)

/* Mac OS X Proc Status values. */
#define	SIDL	1		/* Process being created by fork. */
#define	SRUN	2		/* Currently runnable. */
#define	SSLEEP	3		/* Sleeping on an address. */
#define	SSTOP	4		/* Process debugging or suspension. */
#define	SZOMB	5		/* Awaiting collection by parent. */
#define SREAP	6		/* getting reaped in kernel */

#define	TS_SLEEP	SSLEEP
#define	TS_RUN		SRUN
#define	TS_ZOMB		SZOMB
#define	TS_STOPPED	SSTOP



/* open-only modes */
#include  <sys/fcntl.h>
#define	FCREAT		O_CREAT
#define	FTRUNC		O_TRUNC
#define	FEXCL		O_EXCL
#define	FNOCTTY		O_NOCTTY
//#define	FASYNC		O_SYNC
#define	FNOFOLLOW	O_NOFOLLOW

#define kcred	(cred_t *)NOCRED

#ifndef _KERNEL
typedef int  cred_t;
#endif


/* Buffer flags not used in Mac OS X */
#define B_FAILFAST  0

typedef struct flock flock64_t;

#define F_FREESP 0

#define	MODEMASK	07777		/* mode bits plus permission bits */

/*
 * Flags for vnode operations.
 */
enum rm         { RMFILE, RMDIRECTORY };        /* rm or rmdir (remove) */
//enum symfollow  { NO_FOLLOW, FOLLOW };          /* follow symlinks (or not) */
//enum vcexcl     { NONEXCL, EXCL };              /* (non)excl create */
enum create     { CRCREAT, CRMKNOD, CRMKDIR };  /* reason for create */

typedef struct vnode_attr  vattr_t;

#define va_mask		va_active
#define va_nodeid   va_fileid
#define va_nblocks  va_filerev

/*
 * vnode attr translations
 */
#define	AT_TYPE		VNODE_ATTR_va_type
#define	AT_MODE		VNODE_ATTR_va_mode
#define	AT_UID		VNODE_ATTR_va_uid
#define	AT_GID		VNODE_ATTR_va_gid
#define	AT_ATIME	VNODE_ATTR_va_access_time
#define	AT_MTIME	VNODE_ATTR_va_modify_time
#define AT_CTIME	VNODE_ATTR_va_change_time
#define AT_SIZE		VNODE_ATTR_va_data_size


#define va_size		va_data_size
#define va_atime	va_access_time
#define va_mtime	va_modify_time
#define va_ctime	va_change_time

typedef u_longlong_t	rlim64_t;


/*
 * Structure used on Open Solaris VOP_GETSECATTR and VOP_SETSECATTR operations
 */

typedef struct vsecattr {
	uint_t		vsa_mask;	/* See below */
	int		vsa_aclcnt;	/* ACL entry count */
	void		*vsa_aclentp;	/* pointer to ACL entries */
	int		vsa_dfaclcnt;	/* default ACL entry count */
	void		*vsa_dfaclentp;	/* pointer to default ACL entries */
} vsecattr_t;

/* vsa_mask values */
#define	VSA_ACL		0x0001
#define	VSA_ACLCNT	0x0002
#define	VSA_DFACL	0x0004
#define	VSA_DFACLCNT	0x0008
#define	VSA_ACE		0x0010
#define	VSA_ACECNT	0x0020

#define	RLIM64_INFINITY		((rlim64_t)-3)
#define	RLIM64_SAVED_MAX	((rlim64_t)-2)
#define	RLIM64_SAVED_CUR	((rlim64_t)-1)


/*
 * Package up an I/O request on a vnode into a uio and do it.
 */
extern int	zfs_vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, ssize_t len,
		offset_t offset, enum uio_seg seg, int ioflag, rlim64_t ulimit,
		cred_t *cr, ssize_t *residp);

#define vn_rdwr(rw, vp, base, len, off, seg, flg, limit, cr, resid)  \
		zfs_vn_rdwr((rw), (vp), (base), (len), (off), (seg), (flg), (limit), (cr), (resid))
		

extern void delay();

extern char *strrchr(const char *, int);

#define IS_DEVVP(vp)	(0)

#define	CRED()		(cred_t *)kauth_cred_get()

/*
 * The general purpose memory allocator in open solaris
 * is much different from the mach kmem_alloc functions.
 * So we remap kmem_alloc callouts to our zfs_kmem_alloc
 * implementation.
 */
extern void * zfs_kmem_alloc(size_t, int);
extern void * zfs_kmem_zalloc(size_t, int);
extern void   zfs_kmem_free(void *, size_t);

#define kmem_alloc(s, f)    zfs_kmem_alloc((s), (f))
#define kmem_zalloc(s, f)   zfs_kmem_zalloc((s), (f))
#define kmem_free(b, s)     zfs_kmem_free((b), (s))


struct vmem {
	int vm_quantum;
	int vm_qcache_max;
	int vm_cflags;
};

#define segkmem_alloc_lp	NULL
#define segkmem_free_lp		NULL
#define segkmem_alloc		NULL
#define segkmem_free		NULL


#define strident_canon(s, l)	

extern void *vmem_alloc(vmem_t *, size_t, int);
extern void *vmem_xalloc(vmem_t *, size_t, size_t, size_t, size_t, void *, void *, int);
extern void vmem_free(vmem_t *, void *, size_t);


//extern	unsigned int	real_ncpus;		/* real number of cpus */
extern	unsigned int	max_ncpus;		/* max number of cpus */

#define ncpus max_ncpus

typedef struct _dev_info {
	void	*_opaque[1];
} dev_info_t;


struct dk_callback {
	void (*dkc_callback)(void *dkc_cookie, int error);
	void *dkc_cookie;
};

extern	void 		gethrestime(struct timespec *);
extern	time_t 		gethrestime_sec(void);
extern	hrtime_t 	gethrtime(void);

extern int random_add_entropy(uint8_t *, size_t, uint_t);
extern int random_get_bytes(uint8_t *, size_t);
extern int random_get_pseudo_bytes(uint8_t *, size_t);

#define	_ST_FSTYPSZ 16		/* array size for file system type name */

typedef struct timespec timestruc_t;	/* definition per SVr4 */


#define  xcopyin(src, dst, size)   copyin(src, dst, size)
#define  xcopyout(src, dst, size)  copyout(src, dst, size)


extern int uio_move(caddr_t cp, int n, int rw_flag, struct uio *uio);

/* Reasons for calling issig() */

#define	FORREAL		0	/* Usual side-effects */
#define	JUSTLOOKING	1	/* Don't stop the process */


//extern volatile int64_t lbolt64;	/* lbolt computed as 64-bit value */

#define vn_is_readonly(vp)  vnode_vfsisrdonly(vp)

#define	VNFS_ADDFSREF	0x04	/* take fs (named) reference */

#define VT_ZFS 17


typedef __int32_t	major_t;	/* major part of device number */
typedef __int32_t	minor_t;	/* minor part of device number */


#define	ptob(x)		((x) << PAGESHIFT)

/*
 * 32-bit Solaris device major/minor sizes.
 */
#define	NBITSMAJOR32	14
#define	NBITSMINOR32	18
#define	MAXMAJ32	0x3ffful	/* SVR4 max major value */
#define	MAXMIN32	0x3fffful	/* SVR4 max minor value */

#define	NODEV32	(dev32_t)(-1)

typedef	uint32_t	dev32_t;

/*
 * Arrange that all stores issued before this point in the code reach
 * global visibility before any stores that follow; useful in producer
 * modules that update a data item, then set a flag that it is available.
 * The memory barrier guarantees that the available flag is not visible
 * earlier than the updated data, i.e. it imposes store ordering.
 */
extern void membar_producer(void);


/* Root directory vnode for the system a.k.a. '/' */
#ifdef __APPLE__
/* Must use vfs_rootvnode() to acquire a reference, and
 * vnode_put() to release it
 */
#if ZFS_LEOPARD_ONLY
extern struct vnode *rootvnode;
#define getrootdir()  rootvnode
#else
static inline struct vnode *getrootdir() { 
	struct vnode *rvnode = vfs_rootvnode(); 
	if (rvnode)
		vnode_put(rvnode);
	return rvnode; 
}
#endif
#endif /*__APPLE__*/

extern int issig(int);



/*
 * VNODE SUPPORT
 */

extern int	vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode,
                    struct vnode **vpp, enum create crwhy, mode_t umask);

extern int	vn_openat(char *pnamep, enum uio_seg seg, int filemode, int createmode,
		struct vnode **vpp, enum create crwhy,
		mode_t umask, struct vnode *startvp);

extern int	vn_rename(char *from, char *to, enum uio_seg seg);

extern int	vn_remove(char *fnamep, enum uio_seg seg, enum rm dirflag);

/* vn_has_cached_data() determines if a file is mapped */
#ifdef ZFS_LEOPARD_ONLY
#define vn_has_cached_data(VP)	(VTOZ(VP)->z_mmapped)
#else
#define vn_has_cached_data(VP)	(VTOZ(VP)->z_mmapped || vnode_isswap(VP))
#endif

extern int VOP_CLOSE(struct vnode *, int, int, offset_t, void *);

extern int VOP_FSYNC(struct vnode*, int, void *);


typedef struct dirent dirent_t;
typedef struct direntry dirent64_t;

#if defined(_KERNEL)
#define	DIRENT_RECLEN(namelen, ext)  \
	((ext) ?  \
	((sizeof(dirent64_t) + (namelen) - (MAXPATHLEN-1) + 7) & ~7)  \
	:  \
	((sizeof(dirent_t) - (NAME_MAX+1)) + (((namelen)+1 + 7) &~ 7)))
#endif

#define crgetuid(cr)  kauth_cred_getuid((kauth_cred_t)cr)

#define	DNLC_NO_VNODE (struct vnode *)(-1)

#define vn_ismntpt(vp)   (vnode_mountedhere(vp) != NULL)


/*
 * Check whether mandatory file locking is enabled.
 */

#define	MANDMODE(mode)		(((mode) & (VSGID|(VEXEC>>3))) == VSGID)
#define	MANDLOCK(vp, mode)	(vnode_isreg(vp) && MANDMODE(mode))


#define VN_HOLD(vp)	vnode_getwithref(vp)

#define VN_RELE(vp)					\
	do {						\
		if ((vp) && (vp) != DNLC_NO_VNODE)	\
			vnode_put(vp);			\
	} while (0)


#define vn_exists(vp)	

#define        CREATE_XATTR_DIR        0x04    /* Create extended attr dir */

extern int  chklock(struct vnode *, int, u_offset_t, ssize_t, int, void *);

#ifndef _KERNEL
extern int mkdirp(const char *, mode_t);
#endif

/* Pre-faulting pages not yet supported for Mac OS X */
#define	zfs_prefault_write(n, uio)  


/*
 * Returns true if the named pool/dataset is visible in the current zone.
 */
extern int zone_dataset_visible(const char *, int *);


/*
 * Returns true if any vdevs in the hierarchy is a disk
 */
typedef struct vdev vdev_t;
extern int vdev_contains_disks(vdev_t *);

/*
 * Security Policy
 */

extern int secpolicy_zinject(const cred_t *);

extern int secpolicy_zfs(const cred_t *);

extern int secpolicy_sys_config(const cred_t *, boolean_t);

extern int secpolicy_vnode_setid_retain(const cred_t *, boolean_t );

extern void secpolicy_setid_clear(vattr_t *, cred_t *);

extern int secpolicy_vnode_setid_retain(const cred_t *, boolean_t);

extern int secpolicy_vnode_remove(const cred_t *);

extern int secpolicy_vnode_setid_retain(const cred_t *, boolean_t );

extern int secpolicy_vnode_setids_setgids(const cred_t *, gid_t);

extern int secpolicy_vnode_create_gid(const cred_t *);

extern int secpolicy_vnode_setdac(const cred_t *, uid_t);

extern int secpolicy_vnode_access(const cred_t *, struct vnode *, uid_t, mode_t);


#define __KPRINTFLIKE(a)  

#define NO_FOLLOW 0

#define DDI_SUCCESS 0

#define OTYP_LYR 0

#define OTYPCNT 1


extern char * strpbrk(const char *, const char *);

/* ACLs */
#include <sys/acl.h>

extern void adjust_ace_pair(ace_t *pair, mode_t mode);
extern int ace_trivial(ace_t *acep, int aclcnt);

extern gid_t crgetgid(const cred_t *);


extern struct kmem_cache * znode_cache_get(void);
extern struct kmem_cache * dnode_cache_get(void);
extern struct kmem_cache * dbuf_cache_get(void);

extern void zfs_ioctl_init(void);
extern void zfs_ioctl_fini(void);

extern int is_ascii_str(const char * str);

#ifdef __APPLE__

#define debug_msg(a...) debug_msg_internal(a)
void debug_msg_internal(const char *fmt, ...) __printflike(1, 2);

extern int zfs_msg_buf_enabled;
extern int zfs_dprintf_enabled;

#else

#define debug_msg(...)

#endif

extern void dprint_stack_internal(char func_name[], char file_name[], int line);
#define dprint_stack dprint_stack_internal(__func__, __FILE__, __LINE__)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_CONTEXT_H */
