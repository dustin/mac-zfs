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

/* Portions Copyright 2007 Jeremy Teo */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/unistd.h>
#include <sys/xattr.h>

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/dirent.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_rlock.h>
#include <sys/unistd.h>
#include <sys/utfconv.h>
#include <sys/ubc.h>


/*
 * Programming rules.
 *
 * Each vnode op performs some logical unit of work.  To do this, the ZPL must
 * properly lock its in-core state, create a DMU transaction, do the work,
 * record this work in the intent log (ZIL), commit the DMU transaction,
 * and wait the the intent log to commit if it's is a synchronous operation.
 * Morover, the vnode ops must work in both normal and log replay context.
 * The ordering of events is important to avoid deadlocks and references
 * to freed memory.  The example below illustrates the following Big Rules:
 *
 *  (1) A check must be made in each zfs thread for a mounted file system.
 *	This is done avoiding races using ZFS_ENTER(zfsvfs).
 *	A ZFS_EXIT(zfsvfs) is needed before all returns.
 *
 *  (2)	VN_RELE() should always be the last thing except for zil_commit()
 *	(if necessary) and ZFS_EXIT(). This is for 3 reasons:
 *	First, if it's the last reference, the vnode/znode
 *	can be freed, so the zp may point to freed memory.  Second, the last
 *	reference will call zfs_zinactive(), which may induce a lot of work --
 *	pushing cached pages (which acquires range locks) and syncing out
 *	cached atime changes.  Third, zfs_zinactive() may require a new tx,
 *	which could deadlock the system if you were already holding one.
 *
 *  (3)	All range locks must be grabbed before calling dmu_tx_assign(),
 *	as they can span dmu_tx_assign() calls.
 *
 *  (4)	Always pass zfsvfs->z_assign as the second argument to dmu_tx_assign().
 *	In normal operation, this will be TXG_NOWAIT.  During ZIL replay,
 *	it will be a specific txg.  Either way, dmu_tx_assign() never blocks.
 *	This is critical because we don't want to block while holding locks.
 *	Note, in particular, that if a lock is sometimes acquired before
 *	the tx assigns, and sometimes after (e.g. z_lock), then failing to
 *	use a non-blocking assign can deadlock the system.  The scenario:
 *
 *	Thread A has grabbed a lock before calling dmu_tx_assign().
 *	Thread B is in an already-assigned tx, and blocks for this lock.
 *	Thread A calls dmu_tx_assign(TXG_WAIT) and blocks in txg_wait_open()
 *	forever, because the previous txg can't quiesce until B's tx commits.
 *
 *	If dmu_tx_assign() returns ERESTART and zfsvfs->z_assign is TXG_NOWAIT,
 *	then drop all locks, call dmu_tx_wait(), and try again.
 *
 *  (5)	If the operation succeeded, generate the intent log entry for it
 *	before dropping locks.  This ensures that the ordering of events
 *	in the intent log matches the order in which they actually occurred.
 *
 *  (6)	At the end of each vnode op, the DMU tx must always commit,
 *	regardless of whether there were any errors.
 *
 *  (7)	After dropping all locks, invoke zil_commit(zilog, seq, foid)
 *	to ensure that synchronous semantics are provided when necessary.
 *
 * In general, this is how things should be ordered in each vnode op:
 *
 *	ZFS_ENTER(zfsvfs);		// exit if unmounted
 * top:
 *	zfs_dirent_lock(&dl, ...)	// lock directory entry (may VN_HOLD())
 *	rw_enter(...);			// grab any other locks you need
 *	tx = dmu_tx_create(...);	// get DMU tx
 *	dmu_tx_hold_*();		// hold each object you might modify
 *	error = dmu_tx_assign(tx, zfsvfs->z_assign);	// try to assign
 *	if (error) {
 *		rw_exit(...);		// drop locks
 *		zfs_dirent_unlock(dl);	// unlock directory entry
 *		VN_RELE(...);		// release held vnodes
 *		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
 *			dmu_tx_wait(tx);
 *			dmu_tx_abort(tx);
 *			goto top;
 *		}
 *		dmu_tx_abort(tx);	// abort DMU tx
 *		ZFS_EXIT(zfsvfs);	// finished in zfs
 *		return (error);		// really out of space
 *	}
 *	error = do_real_work();		// do whatever this VOP does
 *	if (error == 0)
 *		zfs_log_*(...);		// on success, make ZIL entry
 *	dmu_tx_commit(tx);		// commit DMU tx -- error or not
 *	rw_exit(...);			// drop locks
 *	zfs_dirent_unlock(dl);		// unlock directory entry
 *	VN_RELE(...);			// release held vnodes
 *	zil_commit(zilog, seq, foid);	// synchronous when necessary
 *	ZFS_EXIT(zfsvfs);		// finished in zfs
 *	return (error);			// done, report error
 */


typedef int vcexcl_t;

enum vcexcl	{ NONEXCL, EXCL };


static int zfs_getsecattr(znode_t *, kauth_acl_t *, cred_t *);

static int zfs_setsecattr(znode_t *, kauth_acl_t, cred_t *);

int zfs_obtain_xattr(znode_t *, const char *, mode_t, cred_t *,
                     struct vnode **, int);



static int
zfs_vnop_open(struct vnop_open_args *ap)
{
	return (0);
}

static int
zfs_vnop_close(struct vnop_close_args *ap)
{
	return (0);
}

/*
 * Spotlight specific fcntl()'s
 */
#define SPOTLIGHT_GET_MOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00002)
#define SPOTLIGHT_GET_UNMOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00003)

static int
zfs_vnop_ioctl(struct vnop_ioctl_args *ap)
{
	znode_t	*zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	user_addr_t useraddr = CAST_USER_ADDR_T(ap->a_data);
	int error;

	ZFS_ENTER(zfsvfs);

	switch (ap->a_command) {
	case SPOTLIGHT_GET_MOUNT_TIME:
		error = copyout(&zfsvfs->z_mount_time, useraddr,
		                sizeof (zfsvfs->z_mount_time));
		break;

	case SPOTLIGHT_GET_UNMOUNT_TIME:
		error = copyout(&zfsvfs->z_last_unmount_time, useraddr,
		                sizeof (zfsvfs->z_last_unmount_time));
		break;

	default:
		error = ENOTTY;
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Write:	If we find a memory mapped page, we write to *both*
 *		the page and the dmu buffer.
 *
 * NOTE: We will always "break up" the IO into PAGESIZE uiomoves when
 *	the file is memory mapped.
 */
static int
mappedwrite(struct vnode *vp, int nbytes, struct uio *uio, dmu_tx_t *tx)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	vm_offset_t vaddr;
	upl_t upl;
	upl_page_info_t *pl = NULL;
	off_t upl_start;
	int upl_size;
	int upl_page;
	off_t off;
	int len = nbytes;
	int error = 0;

	upl_start = uio_offset(uio);
	off = upl_start & (PAGE_SIZE - 1);
	upl_start &= ~PAGE_MASK;
	upl_size = (off + nbytes + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	/*
	 * Create a UPL for the current range and map its
	 * page list into the kernel virtual address space.
	 */
	if ( ubc_create_upl(vp, upl_start, upl_size, &upl, NULL,
	                    UPL_FILE_IO | UPL_SET_LITE) == KERN_SUCCESS ) {
		pl = ubc_upl_pageinfo(upl);
		ubc_upl_map(upl, &vaddr);
	}

	for (upl_page = 0; len > 0; ++upl_page) {
		uint64_t bytes = MIN(PAGESIZE - off, len);
		uint64_t woff = uio_offset(uio);

		/*
		 * We don't want a new page to "appear" in the middle of
		 * the file update (because it may not get the write
		 * update data), so we grab a lock to block
		 * zfs_getpage().
		 */
		rw_enter(&zp->z_map_lock, RW_WRITER);
		if (pl && upl_valid_page(pl, upl_page)) {
			rw_exit(&zp->z_map_lock);
			uio_setrw(uio, UIO_WRITE);
			error = uiomove((caddr_t)vaddr + off, bytes, uio);
			if (error == 0) {
				dmu_write(zfsvfs->z_os, zp->z_id,
				    woff, bytes, (caddr_t)vaddr + off, tx);
				/*
				 * We don't need a ubc_upl_commit_range()
				 * here since the dmu_write() effectively
				 * pushed this page to disk.
				 */
			} else {
				/*
				 * page is now in an unknown state so dump it.
				 */
				ubc_upl_abort_range(upl, upl_start, PAGESIZE,
				                    UPL_ABORT_DUMP_PAGES);
			}
		} else {
			error = dmu_write_uio(zfsvfs->z_os, zp->z_id,
			    uio, bytes, tx);
			rw_exit(&zp->z_map_lock);
		}
		vaddr += PAGE_SIZE;
		upl_start += PAGE_SIZE;
		len -= bytes;
		off = 0;
		if (error)
			break;
	}

	/*
	 * Unmap the page list and free the UPL.
	 */
	if (pl) {
		(void) ubc_upl_unmap(upl);
		/*
		 * We want to abort here since due to dmu_write()
		 * we effectively didn't dirty any pages.
		 */
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
	}

	return (error);
}

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Read:	We "read" preferentially from memory mapped pages,
 *		else we default from the dmu buffer.
 *
 * NOTE: We will always "break up" the IO into PAGESIZE uiomoves when
 *	the file is memory mapped.
 */
static int
mappedread(struct vnode *vp, int nbytes, struct uio *uio)
{
	znode_t *zp = VTOZ(vp);
	objset_t *os = zp->z_zfsvfs->z_os;
	vm_offset_t vaddr;
	upl_t upl;
	upl_page_info_t *pl = NULL;
	off_t upl_start;
	int upl_size;
	int upl_page;
	off_t off;
	int len = nbytes;
	int error = 0;

	upl_start = uio_offset(uio);
	off = upl_start & PAGE_MASK;
	upl_start &= ~PAGE_MASK;
	upl_size = (off + nbytes + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	/*
	 * Create a UPL for the current range and map its
	 * page list into the kernel virtual address space.
	 */
	if ( ubc_create_upl(vp, upl_start, upl_size, &upl, NULL,
	                    UPL_FILE_IO | UPL_SET_LITE) == KERN_SUCCESS ) {
		pl = ubc_upl_pageinfo(upl);
		ubc_upl_map(upl, &vaddr);
	}

	for (upl_page = 0; len > 0; ++upl_page) {
		uint64_t bytes = MIN(PAGE_SIZE - off, len);

		if (pl && upl_valid_page(pl, upl_page)) {
			uio_setrw(uio, UIO_READ);
			error = uiomove((caddr_t)vaddr + off, bytes, uio);
		} else {
			error = dmu_read_uio(os, zp->z_id, uio, bytes);
		}
		vaddr += PAGE_SIZE;
		len -= bytes;
		off = 0;
		if (error)
			break;
	}

	/*
	 * Unmap the page list and free the UPL.
	 */
	if (pl) {
		(void) ubc_upl_unmap(upl);
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
	}

	return (error);
}

uint_t zfs_read_chunk_size = MAX_UPL_TRANSFER * PAGE_SIZE; /* Tunable */

static int
zfs_vnop_read(struct vnop_read_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	struct uio	*uio = ap->a_uio;
	int			ioflag = ap->a_ioflag;
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os = zfsvfs->z_os;
	ssize_t		n, nbytes;
	int		error;
	rl_t		*rl;

	ZFS_ENTER(zfsvfs);

	/*
	 * Validate file offset
	 */
	if (uio_offset(uio) < (offset_t)0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Fasttrack empty reads
	 */
	if (uio_resid(uio) == 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 */

	/*
	 * If we're in FRSYNC mode, sync out this znode before reading it.
	 */
	if (ioflag & FRSYNC)
		zil_commit(zfsvfs->z_log, zp->z_last_itx, zp->z_id);

	/*
	 * Lock the range against changes.
	 */
	rl = zfs_range_lock(zp, uio_offset(uio), uio_resid(uio), RL_READER);

	/*
	 * If we are reading past end-of-file we can skip
	 * to the end; but we might still need to set atime.
	 */
	if (uio_offset(uio) >= zp->z_phys->zp_size) {
		error = 0;
		goto out;
	}

		ASSERT(uio_offset(uio) < zp->z_phys->zp_size);
	n = MIN(uio_resid(uio), zp->z_phys->zp_size - uio_offset(uio));

	while (n > 0) {
		nbytes = MIN(n, zfs_read_chunk_size -
		    P2PHASE(uio_offset(uio), zfs_read_chunk_size));

		if (vn_has_cached_data(vp))
			error = mappedread(vp, nbytes, uio);
		else
			error = dmu_read_uio(os, zp->z_id, uio, nbytes);
		if (error)
			break;

		n -= nbytes;
	}

out:
	zfs_range_unlock(rl);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifndef ZFS_READONLY

static int
zfs_vnop_write(struct vnop_write_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	struct uio	*uio = ap->a_uio;
	int			ioflag = ap->a_ioflag;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	znode_t		*zp = VTOZ(vp);
	rlim64_t	limit = MAXOFFSET_T;
	ssize_t		start_resid = uio_resid(uio);
	ssize_t		tx_bytes;
	uint64_t	end_size;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	offset_t	woff;
	ssize_t		n, nbytes;
	rl_t		*rl;
	int		max_blksz = zfsvfs->z_max_blksz;
	int		error;

	/*
	 * Fasttrack empty write
	 */
	n = start_resid;
	if (n == 0)
		return (0);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	ZFS_ENTER(zfsvfs);

	/*
	 * Pre-fault the pages to ensure slow (eg NFS) pages
	 * don't hold up txg.
	 */
	zfs_prefault_write(n, uio);

	/*
	 * If in append mode, set the io offset pointer to eof.
	 *
	 * Note: OSX uses IO_APPEND flag in order to indicate to 
	 * append to a file as opposed to Solaris which uses the
	 * FAPPEND ioflag
	 */
	if (ioflag & IO_APPEND) {
		/*
		 * Range lock for a file append:
		 * The value for the start of range will be determined by
		 * zfs_range_lock() (to guarantee append semantics).
		 * If this write will cause the block size to increase,
		 * zfs_range_lock() will lock the entire file, so we must
		 * later reduce the range after we grow the block size.
		 */
		rl = zfs_range_lock(zp, 0, n, RL_APPEND);
		if (rl->r_len == UINT64_MAX) {
			/* overlocked, zp_size can't change */
			woff = zp->z_phys->zp_size;
		} else {
			woff = rl->r_off;
		}
		uio_setoffset(uio, woff);
	} else {
		woff = uio_offset(uio);
		/*
		 * Validate file offset
		 */
		if (woff < 0) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		/*
		 * If we need to grow the block size then zfs_range_lock()
		 * will lock a wider range than we request here.
		 * Later after growing the block size we reduce the range.
		 */
		rl = zfs_range_lock(zp, woff, n, RL_WRITER);
	}

	if (woff >= limit) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (EFBIG);
	}

	if ((woff + n) > limit || woff > (limit - n))
		n = limit - woff;

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 */

	end_size = MAX(zp->z_phys->zp_size, woff + n);

	/*
	 * Write the file in reasonable size chunks.  Each chunk is written
	 * in a separate transaction; this keeps the intent log records small
	 * and allows us to do more fine-grained space accounting.
	 */
	while (n > 0) {
		/*
		 * Start a transaction.
		 */
		woff = uio_offset(uio);
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);
		dmu_tx_hold_write(tx, zp->z_id, woff, MIN(n, max_blksz));
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				continue;
			}
			dmu_tx_abort(tx);
			break;
		}

		/*
		 * If zfs_range_lock() over-locked we grow the blocksize
		 * and then reduce the lock range.  This will only happen
		 * on the first iteration since zfs_range_reduce() will
		 * shrink down r_len to the appropriate size.
		 */
		if (rl->r_len == UINT64_MAX) {
			uint64_t new_blksz;

			if (zp->z_blksz > max_blksz) {
				ASSERT(!ISP2(zp->z_blksz));
				new_blksz = MIN(end_size, SPA_MAXBLOCKSIZE);
			} else {
				new_blksz = MIN(end_size, max_blksz);
			}
			zfs_grow_blocksize(zp, new_blksz, tx);
			zfs_range_reduce(rl, woff, n);
		}

		/*
		 * XXX - should we really limit each write to z_max_blksz?
		 * Perhaps we should use SPA_MAXBLOCKSIZE chunks?
		 */
		nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
		rw_enter(&zp->z_map_lock, RW_READER);

		tx_bytes = uio_resid(uio);
		if (vn_has_cached_data(vp)) {
			rw_exit(&zp->z_map_lock);
			error = mappedwrite(vp, nbytes, uio, tx);
		} else {
			error = dmu_write_uio(zfsvfs->z_os, zp->z_id,
			    uio, nbytes, tx);
			rw_exit(&zp->z_map_lock);
		}
		tx_bytes -= uio_resid(uio);

		/*
		 * If we made no progress, we're done.  If we made even
		 * partial progress, update the znode and ZIL accordingly.
		 */
		if (tx_bytes == 0) {
			dmu_tx_commit(tx);
			ASSERT(error != 0);
			break;
		}

		/*
		 * Clear Set-UID/Set-GID bits on successful write if not
		 * privileged and at least one of the excute bits is set.
		 *
		 * It would be nice to to this after all writes have
		 * been done, but that would still expose the ISUID/ISGID
		 * to another app after the partial write is committed.
		 */
		mutex_enter(&zp->z_acl_lock);
		if ((zp->z_phys->zp_mode & (S_IXUSR | (S_IXUSR >> 3) |
		    (S_IXUSR >> 6))) != 0 &&
		    (zp->z_phys->zp_mode & (S_ISUID | S_ISGID)) != 0 &&
		    secpolicy_vnode_setid_retain(cr,
		    (zp->z_phys->zp_mode & S_ISUID) != 0 &&
		    zp->z_phys->zp_uid == 0) != 0) {
			zp->z_phys->zp_mode &= ~(S_ISUID | S_ISGID);
		}
		mutex_exit(&zp->z_acl_lock);

		/*
		 * Update time stamp.  NOTE: This marks the bonus buffer as
		 * dirty, so we don't have to do it again for zp_size.
		 */
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);

		/*
		 * Update the file size (zp_size) if it has changed;
		 * account for possible concurrent updates.
		 */
		while ((end_size = zp->z_phys->zp_size) < uio_offset(uio))
			(void) atomic_cas_64(&zp->z_phys->zp_size, end_size,
			    uio_offset(uio));
		zfs_log_write(zilog, tx, TX_WRITE, zp, woff, tx_bytes, ioflag);
		dmu_tx_commit(tx);

		if (error != 0)
			break;
		ASSERT(tx_bytes == nbytes);
		n -= nbytes;
	}

	zfs_range_unlock(rl);

	/*
	 * If we're in replay mode, or we made no progress, return error.
	 * Otherwise, it's at least a partial write, so it's successful.
	 */
	if (zfsvfs->z_assign >= TXG_INITIAL || uio_resid(uio) == start_resid) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (ioflag & (FSYNC | FDSYNC))
		zil_commit(zilog, zp->z_last_itx, zp->z_id);

	/* Mac OS X: pageout requires that the UBC file size be current. */
	if (tx_bytes != 0) {
		ubc_setsize(vp, zp->z_phys->zp_size);
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif /* !ZFS_READONLY */

static void
zfs_get_done(dmu_buf_t *db, void *vzgd)
{
	zgd_t *zgd = (zgd_t *)vzgd;
	rl_t *rl = zgd->zgd_rl;
	struct vnode *vp = ZTOV(rl->r_zp);

	dmu_buf_rele(db, vzgd);
	zfs_range_unlock(rl);
	VN_RELE(vp);
	zil_add_vdev(zgd->zgd_zilog, DVA_GET_VDEV(BP_IDENTITY(zgd->zgd_bp)));
	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
int
zfs_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio)
{
	zfsvfs_t *zfsvfs = arg;
	objset_t *os = zfsvfs->z_os;
	znode_t *zp;
	uint64_t off = lr->lr_offset;
	dmu_buf_t *db;
	rl_t *rl;
	zgd_t *zgd;
	int dlen = lr->lr_length;		/* length of user data */
	int error = 0;

	ASSERT(zio);
	ASSERT(dlen != 0);

	/*
	 * Nothing to do if the file has been removed
	 */
	if (zfs_zget(zfsvfs, lr->lr_foid, &zp) != 0)
		return (ENOENT);
	if (zp->z_unlinked) {
		VN_RELE(ZTOV(zp));
		return (ENOENT);
	}

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) { /* immediate write */
		rl = zfs_range_lock(zp, off, dlen, RL_READER);
		/* test for truncation needs to be done while range locked */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		VERIFY(0 == dmu_read(os, lr->lr_foid, off, dlen, buf));
	} else { /* indirect write */
		uint64_t boff; /* block starting offset */

		/*
		 * Have to lock the whole block to ensure when it's
		 * written out and it's checksum is being calculated
		 * that no one can change the data. We need to re-check
		 * blocksize after we get the lock in case it's changed!
		 */
		for (;;) {
			if (ISP2(zp->z_blksz)) {
				boff = P2ALIGN_TYPED(off, zp->z_blksz,
				    uint64_t);
			} else {
				boff = 0;
			}
			dlen = zp->z_blksz;
			rl = zfs_range_lock(zp, boff, dlen, RL_READER);
			if (zp->z_blksz == dlen)
				break;
			zfs_range_unlock(rl);
		}
		/* test for truncation needs to be done while range locked */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		zgd = (zgd_t *)kmem_alloc(sizeof (zgd_t), KM_SLEEP);
		zgd->zgd_rl = rl;
		zgd->zgd_zilog = zfsvfs->z_log;
		zgd->zgd_bp = &lr->lr_blkptr;
		VERIFY(0 == dmu_buf_hold(os, lr->lr_foid, boff, zgd, &db));
		ASSERT(boff == db->db_offset);
		lr->lr_blkoff = off - boff;
		error = dmu_sync(zio, db, &lr->lr_blkptr,
		    lr->lr_common.lrc_txg, zfs_get_done, zgd);
		ASSERT((error && error != EINPROGRESS) ||
		    lr->lr_length <= zp->z_blksz);
		if (error == 0) {
			zil_add_vdev(zfsvfs->z_log,
			    DVA_GET_VDEV(BP_IDENTITY(&lr->lr_blkptr)));
		}
		/*
		 * If we get EINPROGRESS, then we need to wait for a
		 * write IO initiated by dmu_sync() to complete before
		 * we can release this dbuf.  We will finish everything
		 * up in the zfs_get_done() callback.
		 */
		if (error == EINPROGRESS)
			return (0);
		dmu_buf_rele(db, zgd);
		kmem_free(zgd, sizeof (zgd_t));
	}
out:
	zfs_range_unlock(rl);
	VN_RELE(ZTOV(zp));
	return (error);
}

static int
zfs_vnop_access(struct vnop_access_args *ap)
{
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	cred_t *cr;
	int mode = 0;
	int action = ap->a_action;
	int error;

	cr = (cred_t *)vfs_context_ucred(ap->a_context);
	/* owner permissions */
	if (action & VREAD)
		mode |= S_IRUSR;
	if (action & VWRITE)
		mode |= S_IWUSR;
	if (action & VEXEC)
		mode |= S_IXUSR;

	/* group permissions */
	if (action & VREAD)
		mode |= S_IRGRP;
	if (action & VWRITE)
		mode |= S_IWGRP;
	if (action & VEXEC)
		mode |= S_IXGRP;

	/* world permissions */
	if (action & VREAD)
		mode |= S_IROTH;
	if (action & VWRITE)
		mode |= S_IWOTH;
	if (action & VEXEC)
		mode |= S_IXOTH;

	ZFS_ENTER(zfsvfs);
	error = zfs_zaccess_rwx(zp, mode, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_lookup(struct vnop_lookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	znode_t *zdp = VTOZ(dvp);
	zfsvfs_t *zfsvfs = zdp->z_zfsvfs;
	struct componentname *cnp = ap->a_cnp;
	char smallname[64];
	char *filename = NULL;
	char * nm;
	cred_t *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	u_long namehash;
	int error;

	ZFS_ENTER(zfsvfs);

	*vpp = NULL;

	if (!vnode_isdir(dvp)) {
		ZFS_EXIT(zfsvfs);
		return (ENOTDIR);
	}

	/*
	 * Check accessibility of directory.
	 */
#ifndef __APPLE__
	if (error = zfs_zaccess(zdp, ACE_EXECUTE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif

	/* Copy the component name so we can null terminate it. */
	if (cnp->cn_namelen < sizeof(smallname)) {
		filename = &smallname[0];
	} else {
		MALLOC(filename, char *, cnp->cn_namelen+1, M_TEMP, M_WAITOK);
	}	
	bcopy(cnp->cn_nameptr, filename, cnp->cn_namelen);
	filename[cnp->cn_namelen] = '\0';
	namehash = cnp->cn_flags & MAKEENTRY ? cnp->cn_hash : 0;

	error = zfs_dirlook(zdp, filename, namehash, vpp);

	if (filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}

	switch (cnp->cn_nameiop) {
	case CREATE:
	case RENAME:
		if ((cnp->cn_flags & ISLASTCN) && (error == ENOENT)) {
			error = EJUSTRETURN;
		}
		break;
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifndef ZFS_READONLY
/*
 * Create a new file.
 */
static int
zfs_vnop_create(struct vnop_create_args *ap)
{
	struct vnode  *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	znode_t  *dzp = VTOZ(dvp);
	znode_t  *zp;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	objset_t  *os = zfsvfs->z_os;
	cred_t *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct vnode_attr  *vap = ap->a_vap;
	struct componentname  *cnp = ap->a_cnp;
	uint64_t  zoid;
	vcexcl_t excl;
	int  mode;
	int  error;

	ZFS_ENTER(zfsvfs);

top:
	*vpp = NULL;

	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;
	mode = MAKEIMODE(vap->va_type, vap->va_mode);

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, 0)) {
		if (strcmp(cnp->cn_nameptr, "..") == 0)
			error = EISDIR;
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	zoid = zp ? zp->z_id : -1ULL;

	if (zp == NULL) {
		/*
		 * Create a new file object and update the directory
		 * to reference it.
		 */
#ifndef __APPLE__
		/* On Mac OS X, VFS performs the necessary access checks. */
		if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
			goto out;
		}
#endif /*!__APPLE__*/
		/*
		 * We only support the creation of regular files in
		 * extended attribute directories.
		 */
		if ((dzp->z_phys->zp_flags & ZFS_XATTR) &&
		    (vap->va_type != VREG)) {
			error = EINVAL;
			goto out;
		}

		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
		dmu_tx_hold_bonus(tx, dzp->z_id);
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, cnp->cn_nameptr);
		if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, SPA_MAXBLOCKSIZE);
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			zfs_dirent_unlock(dl);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);
		ASSERT(zp->z_id == zoid);
		(void) zfs_link_create(dl, zp, tx, ZNEW);
		zfs_log_create(zilog, tx, TX_CREATE, dzp, zp, cnp->cn_nameptr);
		dmu_tx_commit(tx);
	} else {
		/*
		 * A directory entry already exists for this name.
		 */
		/*
		 * Can't truncate an existing file if in exclusive mode.
		 */
		if (excl == EXCL) {
			error = EEXIST;
			goto out;
		}
		/*
		 * Can't open a directory for writing.
		 */
		if (vnode_isdir(ZTOV(zp)) && (mode & S_IWRITE)) {
			error = EISDIR;
			goto out;
		}
		/*
		 * Verify requested access to file.
		 */
#ifndef __APPLE__
		/* On Mac OS X, VFS performs the necessary access checks. */
		if (mode && (error = zfs_zaccess_rwx(zp, mode, cr))) {
			goto out;
		}
#endif /*!__APPLE__*/

		mutex_enter(&dzp->z_lock);
		dzp->z_seq++;
		mutex_exit(&dzp->z_lock);

		/*
		 * Truncate regular files if requested.
		 */
		if (vnode_isreg(ZTOV(zp)) &&
		    (zp->z_phys->zp_size != 0) &&
		    (vap->va_mask & AT_SIZE) && (vap->va_size == 0)) {
			error = zfs_freesp(zp, 0, 0, mode, TRUE);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				/* NB: we already did dmu_tx_wait() */
				zfs_dirent_unlock(dl);
				VN_RELE(ZTOV(zp));
				goto top;
			}
		}
	}

out:

	if (dl)
		zfs_dirent_unlock(dl);

	if (error) {
		if (zp)
			vnode_put(ZTOV(zp));
	} else {
		*vpp = ZTOV(zp);
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove a file entry from a directory.
 */
static int
zfs_vnop_remove(struct vnop_remove_args *ap)
{
	struct vnode  *dvp = ap->a_dvp;
	struct vnode  *vp;
	znode_t  *dzp = VTOZ(dvp);
	znode_t  *zp;
	znode_t  *xzp = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	struct componentname  *cnp = ap->a_cnp;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	uint64_t  acl_obj, xattr_obj;
	boolean_t may_delete_now = FALSE, delete_now = FALSE;
	boolean_t  unlinked;
	int  error;

	ZFS_ENTER(zfsvfs);

top:
	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZEXISTS)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess_delete(dzp, zp, cr)) {
		goto out;
	}
#endif /*!__APPLE__*/

	/*
	 * Need to use rmdir for removing directories.
	 */
	if (vnode_isdir(vp)) {
		error = EPERM;
		goto out;
	}
	/* Remove our entry from the namei cache. */
	cache_purge(vp);
	
	/*
	 * On Mac OSX, we lose the option of having this optimization because 
	 * the VFS layer holds the last reference on the vnode whereas in 
	 * Solaris this code holds the last ref.  Hence, it's sketchy 
	 * business(not to mention hackish) to start deleting the znode 
	 * and clearing out the vnode when the VFS still has a reference 
	 * open on it, even though it's dropping it shortly.
	 */	
#ifndef __APPLE__
        mutex_enter(&vp->v_lock);
        may_delete_now = vp->v_count == 1 && !vn_has_cached_data(vp);
        mutex_exit(&vp->v_lock);
#endif
	/*
	 * We may delete the znode now, or we may put it in the unlinked set;
	 * it depends on whether we're the last link, and on whether there are
	 * other holds on the vnode.  So we dmu_tx_hold() the right things to
	 * allow for either case.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, cnp->cn_nameptr);
	dmu_tx_hold_bonus(tx, zp->z_id);
	if (may_delete_now)
		dmu_tx_hold_free(tx, zp->z_id, 0, DMU_OBJECT_END);

	/* are there any extended attributes? */
	if ((xattr_obj = zp->z_phys->zp_xattr) != 0) {
		/* XXX - do we need this if we are deleting? */
		dmu_tx_hold_bonus(tx, xattr_obj);
	}

	/* are there any additional acls */
	if ((acl_obj = zp->z_phys->zp_acl.z_acl_extern_obj) != 0 &&
	    may_delete_now)
		dmu_tx_hold_free(tx, acl_obj, 0, DMU_OBJECT_END);

	/* charge as an update -- would be nice not to charge at all */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Remove the directory entry.
	 */
	error = zfs_link_destroy(dl, zp, tx, 0, &unlinked);

	if (error) {
		dmu_tx_commit(tx);
		goto out;
	}

	if (unlinked) {
		delete_now = may_delete_now &&
			!vnode_isinuse(vp, 0) &&
			zp->z_phys->zp_xattr == xattr_obj &&
			zp->z_phys->zp_acl.z_acl_extern_obj == acl_obj;
	}

	if (delete_now) {
		if (zp->z_phys->zp_xattr) {
			error = zfs_zget(zfsvfs, zp->z_phys->zp_xattr, &xzp);
			ASSERT3U(error, ==, 0);
			ASSERT3U(xzp->z_phys->zp_links, ==, 2);
			dmu_buf_will_dirty(xzp->z_dbuf, tx);
			mutex_enter(&xzp->z_lock);
			xzp->z_unlinked = 1;
			xzp->z_phys->zp_links = 0;
			mutex_exit(&xzp->z_lock);
			zfs_unlinked_add(xzp, tx);
			zp->z_phys->zp_xattr = 0; /* probably unnecessary */
		}
		
		/* Release the hold zfs_zget put on the vnode */ 
		vnode_put(vp);
		
		/* zfs_znode_delete clears out the dbufs AND 
		 * frees the entire znode as part of the dmu's 
		 * evict func during the sync thread 
		 */
		zfs_znode_delete(zp, tx);
	        vnode_removefsref(vp);
	        vnode_clearfsnode(vp);
		vnode_recycle(vp);
		VFS_RELE(zfsvfs->z_vfs);
	} else if (unlinked) {
		zfs_unlinked_add(zp, tx);
	}

	zfs_log_remove(zilog, tx, TX_REMOVE, dzp, cnp->cn_nameptr);

	dmu_tx_commit(tx);

out:
	zfs_dirent_unlock(dl);

	if (!delete_now) {
		VN_RELE(vp);
	} else if (xzp) {
		/* this rele delayed to prevent nesting transactions */
		VN_RELE(ZTOV(xzp));
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Create a new directory.
 */
static int
zfs_vnop_mkdir(struct vnop_mkdir_args *ap)
{
	struct vnode  *dvp = ap->a_dvp;
	struct vnode  **vpp = ap->a_vpp;
	znode_t  *dzp = VTOZ(dvp);
	znode_t  *zp;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	struct vnode_attr  *vap = ap->a_vap;
	struct componentname  *cnp = ap->a_cnp;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	zfs_dirlock_t  *dl = NULL;
	uint64_t  zoid = 0;
	dmu_tx_t  *tx;
	int  error;

	ASSERT(vap->va_type == VDIR);

	ZFS_ENTER(zfsvfs);

	if (dzp->z_phys->zp_flags & ZFS_XATTR) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
top:
	*vpp = NULL;

	/*
	 * First make sure the new directory doesn't exist.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZNEW)) {
		goto exit;
	}

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess(dzp, ACE_ADD_SUBDIRECTORY, cr)) {
		goto exit;
	}
#endif /*!__APPLE__*/

	/*
	 * Add a new entry to the directory.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, cnp->cn_nameptr);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
		    0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		dl = NULL;
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto exit;
	}

	/*
	 * Create new node.
	 */
	zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);

	/*
	 * Now put new name in parent dir.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	*vpp = ZTOV(zp);

	zfs_log_create(zilog, tx, TX_MKDIR, dzp, zp, cnp->cn_nameptr);
	dmu_tx_commit(tx);

exit:
	if (dl) {
		zfs_dirent_unlock(dl);
	}
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove a directory entry from a directory.
 */
static int
zfs_vnop_rmdir(struct vnop_rmdir_args *ap)
{
	struct vnode  *dvp = ap->a_dvp;
	struct vnode  *vp;
	znode_t  *dzp = VTOZ(dvp);
	znode_t  *zp;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	zfs_dirlock_t  *dl = NULL;
	dmu_tx_t  *tx;
	struct componentname  *cnp = ap->a_cnp;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  error;

	ZFS_ENTER(zfsvfs);

top:
	zp = NULL;

	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZEXISTS)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess_delete(dzp, zp, cr)) {
		goto out;
	}
#endif /*!__APPLE__*/

	if (!vnode_isdir(vp)) {
		error = ENOTDIR;
		goto out;
	}

	/* Remove our entry from the namei cache. */
	cache_purge(vp);

	/*
	 * Grab a lock on the directory to make sure that no one is
	 * trying to add (or lookup) entries while we are removing it.
	 */
	rw_enter(&zp->z_name_lock, RW_WRITER);

	/*
	 * Grab a lock on the parent pointer to make sure we play well
	 * with the treewalk and directory rename code.
	 */
	rw_enter(&zp->z_parent_lock, RW_WRITER);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, cnp->cn_nameptr);
	dmu_tx_hold_bonus(tx, zp->z_id);
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		rw_exit(&zp->z_parent_lock);
		rw_exit(&zp->z_name_lock);
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_destroy(dl, zp, tx, 0, NULL);

	if (error == 0)
		zfs_log_remove(zilog, tx, TX_RMDIR, dzp, cnp->cn_nameptr);

	dmu_tx_commit(tx);

	rw_exit(&zp->z_parent_lock);
	rw_exit(&zp->z_name_lock);

out:
	if (dl) {
		zfs_dirent_unlock(dl);
	}
	vnode_put(vp);

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !ZFS_READONLY */

/*
 * Read as many directory entries as will fit into the provided
 * buffer from the given directory cursor position (specified in
 * the uio structure.
 *
 *	IN:
 *		a_vp		- vnode of directory to read.
 *		a_uio		- structure supplying read location,
 *			  		and return buffer.
 *		a_context	- credentials of caller.
 *
 *	OUT:	uio		- updated offset, buffer filled.
 *		a_numdirent	- updated number of directory entries.
 *		a_eofflag	- set to true if end-of-file detected.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	zp - atime updated
 *
 */

static int
zfs_vnop_readdir(struct vnop_readdir_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	uio_t		uio = ap->a_uio;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int		*eofp =  ap->a_eofflag;
	znode_t		*zp = VTOZ(vp);
	char		*bufptr;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	caddr_t		outbuf = NULL;
	size_t		bufsize;
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	uint_t		bytes_wanted;
	uint64_t	offset; /* must be unsigned; checks for < 1 */
	int		local_eof;
	int		outcount;
	int		error;
	uint8_t		prefetch;
	int		extended;
	int		numdirent;
	boolean_t	isdotdir = B_TRUE;

	ZFS_ENTER(zfsvfs);

	/*
	 * If we are not given an eof variable,
	 * use a local one.
	 */
	if (eofp == NULL)
		eofp = &local_eof;

	/*
	 * Check for valid iov_len.
	 */

	/*
	 * Quit if directory has been removed (posix)
	 */
	if ((*eofp = zp->z_unlinked) != 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	error = 0;
	os = zfsvfs->z_os;
	offset = uio_offset(uio);
	prefetch = zp->z_zn_prefetch;
	extended = (ap->a_flags & VNODE_READDIR_EXTENDED);
	numdirent = 0;

	/*
	 * Initialize the iterator cursor.
	 */
	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, os, zp->z_id, offset);
	}

	/*
	 * Get space to change directory entries into fs independent format.
	 */
	bytes_wanted = uio_curriovlen(uio);
	bufsize = (size_t)bytes_wanted;
	outbuf = kmem_alloc(bufsize, KM_SLEEP);
	bufptr = (char *)outbuf;


	/*
	 * Transform to file-system independent format
	 */
	outcount = 0;
	while (outcount < bytes_wanted) {
		ino64_t objnum;
		ushort_t reclen;
		uint64_t *next;
		uint8_t dtype;
		size_t namelen;
		int ascii;

		/*
		 * Special case `.', `..', and `.zfs'.
		 *
		 * Note that the low 4 bits of the cookie returned by zap is 
		 * alsways zero. This allows us to use the low nibble for 
		 * "special" entries:
		 * We use 0 for '.', and 1 for '..'.
		 * If this is the root of the filesystem, we use the offset 2 
		 * for the *'.zfs' directory.
		 */
		if (offset == 0) {
			(void) strcpy(zap.za_name, ".");
			objnum = zp->z_id;
		} else if (offset == 1) {
			(void) strcpy(zap.za_name, "..");
			objnum = zp->z_phys->zp_parent;
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strcpy(zap.za_name, ZFS_CTLDIR_NAME);
			objnum = ZFSCTL_INO_ROOT;
		} else {
			/* This is not a special case directory */
			isdotdir = B_FALSE;

			/*
			 * Grab next entry.
			 */
			if (error = zap_cursor_retrieve(&zc, &zap)) {
				if ((*eofp = (error == ENOENT)) != 0)
					break;
				else
					goto update;
			}

			if (zap.za_integer_length != 8 ||
			    zap.za_num_integers != 1) {
				cmn_err(CE_WARN, "zap_readdir: bad directory "
				    "entry, obj = %lld, offset = %lld\n",
				    (u_longlong_t)zp->z_id,
			        (u_longlong_t)offset);
				error = ENXIO;
				goto update;
			}
			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
		}
		
		/* Extract the object type for OSX to use */
		if (isdotdir)
			dtype = DT_DIR;
		else
			dtype = ZFS_DIRENT_TYPE(zap.za_first_integer);

		/*
		 * Check if name will fit.
		 *
		 * Note: non-ascii names may expand (up to 3x) when converted to NFD
		 */
		namelen = strlen(zap.za_name);
		ascii = is_ascii_str(zap.za_name);
		if (!ascii)
			namelen = MIN(extended ? MAXPATHLEN-1 : MAXNAMLEN, namelen * 3);
		reclen = DIRENT_RECLEN(namelen, extended);

		/*
		 * Will this entry fit in the buffer?
		 */
		if (outcount + reclen > bufsize) {
			/*
			 * Did we manage to fit anything in the buffer?
			 */
			if (!outcount) {
				error = EINVAL;
				goto update;
			}
			break;
		}
		/*
		 * Add this entry:
		 */
		if (extended) {
			dirent64_t  *odp;
			size_t  nfdlen;

			odp = (dirent64_t  *)bufptr;
			/* NOTE: d_seekoff is the offset for the *next* entry */
			next = &(odp->d_seekoff);
			odp->d_ino = objnum;
			odp->d_type = dtype;
	
			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (ascii ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXPATHLEN-1, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
				(void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		} else {
			dirent_t  *odp;
			size_t  nfdlen;

			odp = (dirent_t  *)bufptr;
			odp->d_ino = objnum;
			odp->d_type = dtype;

			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (ascii ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXNAMLEN, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
				(void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		}
		outcount += reclen;
		bufptr += reclen;
		numdirent++;
		ASSERT(outcount <= bufsize);

		/* Prefetch znode */
		if (prefetch)
			dmu_prefetch(os, objnum, 0, 0);

		/*
		 * Move to the next entry, fill in the previous offset.
		 */
		if (offset > 2 || (offset == 2 && !zfs_show_ctldir(zp))) {
			zap_cursor_advance(&zc);
			offset = zap_cursor_serialize(&zc);
		} else {
			offset += 1;
		}
		if (extended) {
			*next = offset;
		}
	}
	zp->z_zn_prefetch = B_FALSE; /* a lookup will re-enable pre-fetching */

	if (error = uio_move(outbuf, (long)outcount, UIO_READ, uio)) {
		/*
		 * Reset the pointer.
		 */
		offset = uio_offset(uio);
	}

update:
	zap_cursor_fini(&zc);
	if (outbuf) {
		kmem_free(outbuf, bufsize);
	}
	if (error == ENOENT) {
		error = 0;
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	uio_setoffset(uio, offset);
	if (ap->a_numdirent) {
		*ap->a_numdirent = numdirent;
	}
	ZFS_EXIT(zfsvfs);
	return (error);
}

ulong_t zfs_fsync_sync_cnt = 4;

static int
zfs_vnop_fsync(struct vnop_fsync_args *ap)
{
#ifndef ZFS_READONLY
	struct vnode  *vp = ap->a_vp;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs;

#ifndef __APPLE__
	/*
	 * Regardless of whether this is required for standards conformance,
	 * this is the logical behavior when fsync() is called on a file with
	 * dirty pages.  We use B_ASYNC since the ZIL transactions are already
	 * going to be pushed out as part of the zil_commit().
	 */
	if (vn_has_cached_data(vp) && !(syncflag & FNODSYNC) &&
	    vnode_isreg(vp) && !(vnode_isswap(vp)))
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0, B_ASYNC, cr);

		(void) tsd_set(zfs_fsyncer_key, (void *)zfs_fsync_sync_cnt);
#endif /*!__APPLE__*/

	/* Check if this znode has already been synced, freed,
	 * and recycled by znode_pageout_func
	 */
	if (zp == NULL)
		return(0);
	zfsvfs = zp->z_zfsvfs;
	ZFS_ENTER(zfsvfs);
#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_fsync_zil);
#endif
	zil_commit(zfsvfs->z_log, zp->z_last_itx, zp->z_id);
	ZFS_EXIT(zfsvfs);

#endif /* !ZFS_READONLY */

	return (0);
}

/*
 * Get file attributes.
 */
static int
zfs_vnop_getattr(struct vnop_getattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode_attr  *vap = ap->a_vap;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	znode_phys_t  *pzp = zp->z_phys;
	uint64_t links;

	ZFS_ENTER(zfsvfs);

	/*
	 * Return all attributes.  It's cheaper to provide the answer
	 * than to determine whether we were asked the question.
	 */
	mutex_enter(&zp->z_lock);

	vap->va_mode = pzp->zp_mode & MODEMASK;
#ifdef ZFS_READONLY
	vap->va_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
#endif
	vap->va_uid = pzp->zp_uid;
	vap->va_gid = pzp->zp_gid;
//	vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;
	/*
	 * On Mac OS X we always export the root directory id as 2
	 */
	vap->va_fileid = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;
#ifndef __APPLE__
	if ((vp->v_flag & VROOT) && zfs_show_ctldir(zp))
		links = pzp->zp_links + 1;
	else
		links = pzp->zp_links;
	vap->va_nlink = MIN(links, UINT32_MAX);	/* nlink_t limit! */
#else
	vap->va_nlink = pzp->zp_links;
#endif
	vap->va_data_size = pzp->zp_size;
	vap->va_total_size = pzp->zp_size;
	vap->va_rdev = pzp->zp_rdev;
	vap->va_gen = pzp->zp_gen;

	ZFS_TIME_DECODE(&vap->va_create_time, pzp->zp_crtime);
	ZFS_TIME_DECODE(&vap->va_access_time, pzp->zp_atime);
	ZFS_TIME_DECODE(&vap->va_modify_time, pzp->zp_mtime);
	ZFS_TIME_DECODE(&vap->va_change_time, pzp->zp_ctime);
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		vap->va_backup_time.tv_sec = 0;
		vap->va_backup_time.tv_nsec = 0;	
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}
	vap->va_flags = 0;
	/*
	 * On Mac OS X we always export the root directory id as 2 and its parent as 1
	 */
	if (zp->z_id == zfsvfs->z_root)
		vap->va_parentid = 1;
	else if (pzp->zp_parent == zfsvfs->z_root)
		vap->va_parentid = 2;
	else
		vap->va_parentid = pzp->zp_parent;

	vap->va_iosize = zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;

	vap->va_supported |=
		VNODE_ATTR_va_mode |
		VNODE_ATTR_va_uid |
		VNODE_ATTR_va_gid |
//		VNODE_ATTR_va_fsid |
		VNODE_ATTR_va_fileid |
		VNODE_ATTR_va_nlink |
		VNODE_ATTR_va_data_size |
		VNODE_ATTR_va_total_size |
		VNODE_ATTR_va_rdev |
		VNODE_ATTR_va_gen |
		VNODE_ATTR_va_create_time |
		VNODE_ATTR_va_access_time |
		VNODE_ATTR_va_modify_time |
		VNODE_ATTR_va_change_time |
		VNODE_ATTR_va_flags |
		VNODE_ATTR_va_parentid |
		VNODE_ATTR_va_iosize;

#ifndef __APPLE__
	/*
	 * If ACL is trivial don't bother looking for ACE_READ_ATTRIBUTES.
	 * Also, if we are the owner don't bother, since owner should
	 * always be allowed to read basic attributes of file.
	 */
	if (!(zp->z_phys->zp_flags & ZFS_ACL_TRIVIAL) &&
	    (zp->z_phys->zp_uid != crgetuid(cr))) {
		if (error = zfs_zaccess(zp, ACE_READ_ATTRIBUTES, cr)) {
			mutex_exit(&zp->z_lock);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}
#endif /*!__APPLE__*/

	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(vp))
		VATTR_RETURN(vap, va_nchildren, pzp->zp_size);

	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		if (zp->z_phys->zp_acl.z_acl_count == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
		} else {
			int error;

			if ((error = zfs_getacl(zp, &vap->va_acl, cr))) {
				ZFS_EXIT(zfsvfs);
				return (error);
			}
		}
		VATTR_SET_SUPPORTED(vap, va_acl);
		/* va_acl implies that va_uuuid and va_guuid are also supported. */
		VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
		VATTR_RETURN(vap, va_guuid, kauth_null_guid);
	}
	mutex_exit(&zp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_data_alloc) || VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		uint32_t  blksize;
		u_longlong_t  nblks;

		dmu_object_size_from_db(zp->z_dbuf, &blksize, &nblks);

		vap->va_data_alloc = (uint64_t)512LL * (uint64_t)nblks;
		vap->va_total_alloc = vap->va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_data_alloc | 
					VNODE_ATTR_va_total_alloc;
	}

	if (VATTR_IS_ACTIVE(vap, va_name) && !vnode_isvroot(vp)) {
		if (zap_value_search(zfsvfs->z_os, pzp->zp_parent, zp->z_id, 
			 	    ZFS_DIRENT_OBJ(-1ULL), vap->va_name) == 0)
			VATTR_SET_SUPPORTED(vap, va_name);
	}
	ZFS_EXIT(zfsvfs);
	return (0);
}

#ifndef ZFS_READONLY
/*
 * Set file attributes.
 */
static int
zfs_vnop_setattr(struct vnop_setattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct znode  *zp = VTOZ(vp);
	znode_phys_t  *pzp = zp->z_phys;
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	struct vnode_attr  *vap = ap->a_vap;
	dmu_tx_t  *tx;
//	vattr_t  oldva;
	uint64_t  mask = vap->va_active;
	uint64_t  saved_mask;
	int  trim_mask = FALSE;
	uint64_t  new_mode;
	znode_t  *attrzp;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  need_policy = FALSE;
	int  error;
	ZFS_ENTER(zfsvfs);

top:
	attrzp = NULL;

	if (vfs_isrdonly(zfsvfs->z_vfs)) {
		ZFS_EXIT(zfsvfs);
		return (EROFS);
	}

	/*
	 * First validate permissions
	 */

	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		/*
		 * XXX - Note, we are not providing any open
		 * mode flags here (like FNDELAY), so we may
		 * block if there are locks present... this
		 * should be addressed in openat().
		 */
		do {
			error = zfs_freesp(zp, vap->va_data_size, 0, 0, FALSE);
			/* NB: we already did dmu_tx_wait() if necessary */
		} while (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		/* Mac OS X: pageout requires that the UBC file size to be current. */
		ubc_setsize(vp, vap->va_data_size);

		VATTR_SET_SUPPORTED(vap, va_data_size);
	}

#ifndef __APPLE__
	if (mask & (VNODE_ATTR_va_uid | VNODE_ATTR_va_gid)) {
		int	idmask = (mask & (VNODE_ATTR_va_uid | VNODE_ATTR_va_gid));
		int	take_owner;
		int	take_group;

		/*
		 * NOTE: even if a new mode is being set,
		 * we may clear S_ISUID/S_ISGID bits.
		 */

		if (!VATTR_IS_ACTIVE(vap, va_mode))
			vap->va_mode = pzp->zp_mode;

		/*
		 * Take ownership or chgrp to group we are a member of
		 */

		take_owner = (mask & VNODE_ATTR_va_uid) && (vap->va_uid == crgetuid(cr));
		take_group = (mask & VNODE_ATTR_va_gid) && groupmember(vap->va_gid, cr);

		/*
		 * If both AT_UID and AT_GID are set then take_owner and
		 * take_group must both be set in order to allow taking
		 * ownership.
		 *
		 * Otherwise, send the check through secpolicy_vnode_setattr()
		 *
		 */

		if (((idmask == (AT_UID|AT_GID)) && take_owner && take_group) ||
		    ((idmask == AT_UID) && take_owner) ||
		    ((idmask == AT_GID) && take_group)) {
			if (zfs_zaccess_v4_perm(zp, ACE_WRITE_OWNER, cr) == 0) {
				/*
				 * Remove setuid/setgid for non-privileged users
				 */
				secpolicy_setid_clear(vap, cr);
				trim_mask = TRUE;
				saved_mask = vap->va_mask;
			} else {
				need_policy =  TRUE;
			}
		} else {
			need_policy =  TRUE;
		}
	}

	if (VATTR_IS_ACTIVE(vap, va_mode))
		need_policy = TRUE;

	if (need_policy) {
		mutex_enter(&zp->z_lock);
		oldva.va_mode = pzp->zp_mode;
		oldva.va_uid = zp->z_phys->zp_uid;
		oldva.va_gid = zp->z_phys->zp_gid;
		mutex_exit(&zp->z_lock);

		/*
		 * If trim_mask is set then take ownership
		 * has been granted.  In that case remove
		 * UID|GID from mask so that
		 * secpolicy_vnode_setattr() doesn't revoke it.
		 */
		if (trim_mask)
			vap->va_mask &= ~(AT_UID|AT_GID);

		error = secpolicy_vnode_setattr(cr, vp, vap, &oldva, flags,
		    (int (*)(void *, int, cred_t *))zfs_zaccess_rwx, zp);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}

		if (trim_mask)
			vap->va_mask |= (saved_mask & (AT_UID|AT_GID));
	}
#endif /*!__APPLE__*/

	/*
	 * secpolicy_vnode_setattr, or take ownership may have changed va_mask
	 */
	mask = vap->va_active;

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, zp->z_id);

	if (VATTR_IS_ACTIVE(vap, va_mode) || VATTR_IS_ACTIVE(vap, va_acl)) {
		uint64_t pmode = pzp->zp_mode;

		new_mode = (pmode & S_IFMT) | (vap->va_mode & ~S_IFMT);

		if (zp->z_phys->zp_acl.z_acl_extern_obj)
			dmu_tx_hold_write(tx,
			    pzp->zp_acl.z_acl_extern_obj, 0, SPA_MAXBLOCKSIZE);
		else
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, ZFS_ACL_SIZE(MAX_ACL_SIZE));
	}

	if ((mask & (VNODE_ATTR_va_uid | VNODE_ATTR_va_gid)) &&
	    zp->z_phys->zp_xattr != 0) {
		error = zfs_zget(zp->z_zfsvfs, zp->z_phys->zp_xattr, &attrzp);
		if (error) {
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		dmu_tx_hold_bonus(tx, attrzp->z_id);
	}

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (attrzp)
			vnode_put(ZTOV(attrzp));
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	dmu_buf_will_dirty(zp->z_dbuf, tx);

	/*
	 * Set each attribute requested.
	 * We group settings according to the locks they need to acquire.
	 *
	 * Note: you cannot set ctime directly, although it will be
	 * updated as a side-effect of calling this function.
	 */

	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		if ((vap->va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE) &&
		    (vap->va_acl->acl_entrycount != KAUTH_FILESEC_NOACL)) {
			if ((error = zfs_setacl(zp, vap->va_acl, cr, tx)))
				goto out;
		} else {
			struct kauth_acl blank_acl;
	
			bzero(&blank_acl, sizeof blank_acl);
			if ((error = zfs_setacl(zp, &blank_acl, cr, tx)))
				goto out;
		}
		VATTR_SET_SUPPORTED(vap, va_acl);
	}

	mutex_enter(&zp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_mode)) {
#ifdef __APPLE__
		zp->z_phys->zp_mode = new_mode;
#else
		error = zfs_acl_chmod_setattr(zp, new_mode, tx);
#endif
		ASSERT3U(error, ==, 0);
		VATTR_SET_SUPPORTED(vap, va_mode);
	}

	if (attrzp)
		mutex_enter(&attrzp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		zp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		if (attrzp) {
			attrzp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		}
		VATTR_SET_SUPPORTED(vap, va_uid);
	}

	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		zp->z_phys->zp_gid = (uint64_t)vap->va_gid;
		if (attrzp)
			attrzp->z_phys->zp_gid = (uint64_t)vap->va_gid;
		VATTR_SET_SUPPORTED(vap, va_gid);
	}

	if (attrzp)
		mutex_exit(&attrzp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		ZFS_TIME_ENCODE(&vap->va_access_time, pzp->zp_atime);
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
		ZFS_TIME_ENCODE(&vap->va_modify_time, pzp->zp_mtime);
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_create_time)) {
		ZFS_TIME_ENCODE(&vap->va_create_time, pzp->zp_crtime);
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}

	if (VATTR_IS_ACTIVE(vap, va_data_size))
		zfs_time_stamper_locked(zp, CONTENT_MODIFIED, tx);
	else if (mask != 0)
		zfs_time_stamper_locked(zp, STATE_CHANGED, tx);

	if (mask != 0)
		zfs_log_setattr(zilog, tx, TX_SETATTR, zp, vap, mask);

	mutex_exit(&zp->z_lock);
out:
	if (attrzp) {
		vnode_put(ZTOV(attrzp));
	}
	dmu_tx_commit(tx);

	ZFS_EXIT(zfsvfs);
	return (error);
}

typedef struct zfs_zlock {
	krwlock_t	*zl_rwlock;	/* lock we acquired */
	znode_t		*zl_znode;	/* znode we held */
	struct zfs_zlock *zl_next;	/* next in list */
} zfs_zlock_t;

/*
 * Drop locks and release vnodes that were held by zfs_rename_lock().
 */
static void
zfs_rename_unlock(zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;

	while ((zl = *zlpp) != NULL) {
		if (zl->zl_znode != NULL)
			VN_RELE(ZTOV(zl->zl_znode));
		rw_exit(zl->zl_rwlock);
		*zlpp = zl->zl_next;
		kmem_free(zl, sizeof (*zl));
	}
}

/*
 * Search back through the directory tree, using the ".." entries.
 * Lock each directory in the chain to prevent concurrent renames.
 * Fail any attempt to move a directory into one of its own descendants.
 * XXX - z_parent_lock can overlap with map or grow locks
 */
static int
zfs_rename_lock(znode_t *szp, znode_t *tdzp, znode_t *sdzp, zfs_zlock_t **zlpp)
{
	zfs_zlock_t	*zl;
	znode_t 	*zp = tdzp;
	uint64_t	rootid = zp->z_zfsvfs->z_root;
	uint64_t	*oidp = &zp->z_id;
	krwlock_t	*rwlp = &szp->z_parent_lock;
	krw_t		rw = RW_WRITER;

	/*
	 * First pass write-locks szp and compares to zp->z_id.
	 * Later passes read-lock zp and compare to zp->z_parent.
	 */
	do {
		if (!rw_tryenter(rwlp, rw)) {
			/*
			 * Another thread is renaming in this path.
			 * Note that if we are a WRITER, we don't have any
			 * parent_locks held yet.
			 */
			if (rw == RW_READER && zp->z_id > szp->z_id) {
				/*
				 * Drop our locks and restart
				 */
				zfs_rename_unlock(&zl);
				*zlpp = NULL;
				zp = tdzp;
				oidp = &zp->z_id;
				rwlp = &szp->z_parent_lock;
				rw = RW_WRITER;
				continue;
			} else {
				/*
				 * Wait for other thread to drop its locks
				 */
				rw_enter(rwlp, rw);
			}
		}

		zl = kmem_alloc(sizeof (*zl), KM_SLEEP);
		zl->zl_rwlock = rwlp;
		zl->zl_znode = NULL;
		zl->zl_next = *zlpp;
		*zlpp = zl;

		if (*oidp == szp->z_id)		/* We're a descendant of szp */
			return (EINVAL);

		if (*oidp == rootid)		/* We've hit the top */
			return (0);

		if (rw == RW_READER) {		/* i.e. not the first pass */
			int error = zfs_zget(zp->z_zfsvfs, *oidp, &zp);
			if (error)
				return (error);
			zl->zl_znode = zp;
		}
		oidp = &zp->z_phys->zp_parent;
		rwlp = &zp->z_parent_lock;
		rw = RW_READER;

	} while (zp->z_id != sdzp->z_id);

	return (0);
}

static int
zfs_vnop_rename(struct vnop_rename_args *ap)
{
	struct vnode  *sdvp = ap->a_fdvp;
	struct vnode  *tdvp = ap->a_tdvp;
	znode_t		*tdzp, *szp, *tzp;
	znode_t		*sdzp = VTOZ(sdvp);
	zfsvfs_t	*zfsvfs = sdzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	zfs_dirlock_t	*sdl, *tdl;
	dmu_tx_t	*tx;
	zfs_zlock_t	*zl;
	int		cmp, serr, terr, error;
	struct componentname *scnp = ap->a_fcnp;
	struct componentname *tcnp = ap->a_tcnp;

	ZFS_ENTER(zfsvfs);

#ifndef __APPLE__
	/*
	 * Make sure we have the real vp for the target directory.
	 */
	if (VOP_REALVP(tdvp, &realvp) == 0)
		tdvp = realvp;

	if (tdvp->v_vfsp != sdvp->v_vfsp) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}

	if (ap->a_tcnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
#endif /*!__APPLE__*/

	tdzp = VTOZ(tdvp);
top:
	szp = NULL;
	tzp = NULL;
	zl = NULL;

	/*
	 * This is to prevent the creation of links into attribute space
	 * by renaming a linked file into/outof an attribute directory.
	 * See the comment in zfs_link() for why this is considered bad.
	 */
	if ((tdzp->z_phys->zp_flags & ZFS_XATTR) !=
	    (sdzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Lock source and target directory entries.  To prevent deadlock,
	 * a lock ordering must be defined.  We lock the directory with
	 * the smallest object id first, or if it's a tie, the one with
	 * the lexically first name.
	 */
	if (sdzp->z_id < tdzp->z_id) {
		cmp = -1;
	} else if (sdzp->z_id > tdzp->z_id) {
		cmp = 1;
	} else {
		cmp = strcmp(scnp->cn_nameptr, tcnp->cn_nameptr);
		if (cmp == 0) {
			/*
			 * POSIX: "If the old argument and the new argument
			 * both refer to links to the same existing file,
			 * the rename() function shall return successfully
			 * and perform no other action."
			 */
			ZFS_EXIT(zfsvfs);
			return (0);
		}
	}
	if (cmp < 0) {
		serr = zfs_dirent_lock(&sdl, sdzp, scnp, &szp, ZEXISTS);
		terr = zfs_dirent_lock(&tdl, tdzp, tcnp, &tzp, 0);
	} else {
		terr = zfs_dirent_lock(&tdl, tdzp, tcnp, &tzp, 0);
		serr = zfs_dirent_lock(&sdl, sdzp, scnp, &szp, ZEXISTS);
	}

	if (serr) {
		/*
		 * Source entry invalid or not there.
		 */
		if (!terr) {
			zfs_dirent_unlock(tdl);
			if (tzp)
				VN_RELE(ZTOV(tzp));
		}
		if (strcmp(scnp->cn_nameptr, "..") == 0)
			serr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (serr);
	}
	if (terr) {
		zfs_dirent_unlock(sdl);
		VN_RELE(ZTOV(szp));
		if (strcmp(tcnp->cn_nameptr, "..") == 0)
			terr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (terr);
	}

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	/*
	 * Must have write access at the source to remove the old entry
	 * and write access at the target to create the new entry.
	 * Note that if target and source are the same, this can be
	 * done in a single check.
	 */
	if (error = zfs_zaccess_rename(sdzp, szp, tdzp, tzp, cr))
		goto out;
#endif /*!__APPLE__*/

	if (vnode_isdir(ZTOV(szp))) {
		/*
		 * Check to make sure rename is valid.
		 * Can't do a move like this: /usr/a/b to /usr/a/b/c/d
		 */
		if (error = zfs_rename_lock(szp, tdzp, sdzp, &zl))
			goto out;
	}

	/*
	 * Does target exist?
	 */
	if (tzp) {
#ifndef __APPLE__
		/*
		 * Source and target must be the same type.
		 */
		if (ZTOV(szp)->v_type == VDIR) {
			if (ZTOV(tzp)->v_type != VDIR) {
				error = ENOTDIR;
				goto out;
			}
		} else {
			if (ZTOV(tzp)->v_type == VDIR) {
				error = EISDIR;
				goto out;
			}
		}
#endif /*!__APPLE__*/
		/*
		 * POSIX dictates that when the source and target
		 * entries refer to the same file object, rename
		 * must do nothing and exit without error.
		 */
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);	/* nlink changes */
	dmu_tx_hold_bonus(tx, sdzp->z_id);	/* nlink changes */
	dmu_tx_hold_zap(tx, sdzp->z_id, FALSE, scnp->cn_nameptr);
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, tcnp->cn_nameptr);
	if (sdzp != tdzp)
		dmu_tx_hold_bonus(tx, tdzp->z_id);	/* nlink changes */
	if (tzp)
		dmu_tx_hold_bonus(tx, tzp->z_id);	/* parent changes */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (zl != NULL)
			zfs_rename_unlock(&zl);
		zfs_dirent_unlock(sdl);
		zfs_dirent_unlock(tdl);
		VN_RELE(ZTOV(szp));
		if (tzp)
			VN_RELE(ZTOV(tzp));
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (tzp)	/* Attempt to remove the existing target */
		error = zfs_link_destroy(tdl, tzp, tx, 0, NULL);

	if (error == 0) {
		error = zfs_link_create(tdl, szp, tx, ZRENAMING);
		if (error == 0) {
			error = zfs_link_destroy(sdl, szp, tx, ZRENAMING, NULL);
			ASSERT(error == 0);
			zfs_log_rename(zilog, tx, TX_RENAME, sdzp,
			    sdl->dl_name, tdzp, tdl->dl_name, szp);
		}
	}

	/* Remove entries from the namei cache. */
	cache_purge(ZTOV(szp));
	if (tzp)
		cache_purge(ZTOV(tzp));

	dmu_tx_commit(tx);

out:
	if (zl != NULL)
		zfs_rename_unlock(&zl);

	zfs_dirent_unlock(sdl);
	zfs_dirent_unlock(tdl);

	VN_RELE(ZTOV(szp));
	if (tzp)
		vnode_put(ZTOV(tzp));

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_symlink(struct vnop_symlink_args *ap)
{
	struct vnode  *dvp = ap->a_dvp;
	znode_t  *zp = NULL, *dzp = VTOZ(dvp);
	zfs_dirlock_t  *dl = NULL;
	dmu_tx_t  *tx = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	struct componentname  *cnp = ap->a_cnp;
	struct vnode_attr  *vap = ap->a_vap;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	char  *link = ap->a_target;
	uint64_t  zoid;
	int  len = strlen(link);
	int  error;

	ASSERT(vap->va_type == VLNK);

	ZFS_ENTER(zfsvfs);
top:

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /*!__APPLE__*/

	if ((len > MAXPATHLEN) || (cnp->cn_namelen >= ZAP_MAXNAMELEN)) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, MAX(1, len));
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, cnp->cn_nameptr);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		dl = NULL;
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	dmu_buf_will_dirty(dzp->z_dbuf, tx);

	/*
	 * Create a new object for the symlink.
	 * Put the link content into bonus buffer if it will fit;
	 * otherwise, store it just like any other file data.
	 */
	zoid = 0;
	if (sizeof (znode_phys_t) + len <= dmu_bonus_max()) {
		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, len);
		if (len != 0)
			bcopy(link, zp->z_phys + 1, len);
	} else {
		dmu_buf_t *dbp;

		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);

		/*
		 * Nothing can access the znode yet so no locking needed
		 * for growing the znode's blocksize.
		 */
		zfs_grow_blocksize(zp, len, tx);

		VERIFY(0 == dmu_buf_hold(zfsvfs->z_os, zoid, 0, FTAG, &dbp));
		dmu_buf_will_dirty(dbp, tx);

		ASSERT3U(len, <=, dbp->db_size);
		bcopy(link, dbp->db_data, len);
		dmu_buf_rele(dbp, FTAG);
	}
	zp->z_phys->zp_size = len;

	/*
	 * Insert the new object into the directory.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	if (error == 0)
		zfs_log_symlink(zilog, tx, TX_SYMLINK, dzp, zp,
		                cnp->cn_nameptr, link);

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	vnode_put(ZTOV(zp));

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !ZFS_READONLY */

static int
zfs_vnop_readlink(struct vnop_readlink_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio  *uio = ap->a_uio;
	size_t  bufsz;
	int  error;

	ZFS_ENTER(zfsvfs);

	bufsz = (size_t)zp->z_phys->zp_size;
	if (bufsz + sizeof (znode_phys_t) <= zp->z_dbuf->db_size) {
		error = uio_move((caddr_t)(zp->z_phys + 1),
		    MIN((size_t)bufsz, uio_resid(uio)), UIO_READ, uio);
	} else {
		dmu_buf_t *dbp;
		error = dmu_buf_hold(zfsvfs->z_os, zp->z_id, 0, FTAG, &dbp);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		error = uio_move(dbp->db_data,
		    MIN((size_t)bufsz, uio_resid(uio)), UIO_READ, uio);
		dmu_buf_rele(dbp, FTAG);
	}

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifndef ZFS_READONLY

static int
zfs_vnop_link(struct vnop_link_args *ap)
{
	struct vnode  *tdvp = ap->a_tdvp;
	struct vnode  *svp = ap->a_vp;
	znode_t  *dzp = VTOZ(tdvp);
	znode_t  *tzp, *szp;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	zfs_dirlock_t  *dl = NULL;
	dmu_tx_t  *tx = NULL;
	struct componentname  *cnp = ap->a_cnp;
	int  error;

	ASSERT(vnode_isdir(tdvp));

	ZFS_ENTER(zfsvfs);

#ifndef __APPLE__
	if (VOP_REALVP(svp, &realvp) == 0)
		svp = realvp;
#endif /*!__APPLE__*/

	if (vnode_mount(svp) != vnode_mount(tdvp)) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	szp = VTOZ(svp);
top:
	/*
	 * We do not support links between attributes and non-attributes
	 * because of the potential security risk of creating links
	 * into "normal" file space in order to circumvent restrictions
	 * imposed in attribute space.
	 */
	if ((szp->z_phys->zp_flags & ZFS_XATTR) !=
	    (dzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * POSIX dictates that we return EPERM here.
	 * Better choices include ENOTSUP or EISDIR.
	 */
	if (vnode_isdir(svp)) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if ((uid_t)szp->z_phys->zp_uid != crgetuid(cr) &&
	    secpolicy_basic_link(cr) != 0) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

	if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /*!__APPLE__*/

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &tzp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, cnp->cn_nameptr);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_create(dl, szp, tx, 0);

	if (error == 0)
		zfs_log_link(zilog, tx, TX_LINK, dzp, szp, cnp->cn_nameptr);

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !ZFS_READONLY */

static int
zfs_vnop_pagein(struct vnop_pagein_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	offset_t	off = ap->a_f_offset;
	size_t		len = ap->a_size;
	upl_t		upl = ap->a_pl;
	vm_offset_t	upl_offset = ap->a_pl_offset;
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	vm_offset_t	vaddr;
	int		flags = ap->a_flags;
	int		need_unlock = 0;
	int		error = 0;

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pagein: no upl!");

	if (len <= 0) {
		printf("zfs_vnop_pagein: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		return (EINVAL);
	}

	ZFS_ENTER(zfsvfs);

	ASSERT(vn_has_cached_data(vp));
	ASSERT(zp->z_dbuf_held && zp->z_phys);

	/* can't fault past EOF */
	if ((off < 0) || (off >= zp->z_phys->zp_size) ||
	    (len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
		ZFS_EXIT(zfsvfs);
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (EFAULT);
	}

	/*
	 * If we already own the lock, then we must be page faulting
	 * in the middle of a write to this file (i.e., we are writing
	 * to this file using data from a mapped region of the file).
	 */
	if (!rw_write_held(&zp->z_map_lock)) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}

	ubc_upl_map(upl, &vaddr);
	vaddr += upl_offset;
	/*
	 * Fill pages with data from the file.
	 */
	while (len > 0) {
		if (len < PAGESIZE)
			break;

		error = dmu_read(zp->z_zfsvfs->z_os, zp->z_id, off, PAGESIZE, (void *)vaddr);
		if (error) {
			printf("zfs_vnop_pagein: dmu_read err %d\n", error);
			break;
		}
		off += PAGESIZE;
		vaddr += PAGESIZE;
		if (len > PAGESIZE)
			len -= PAGESIZE;
		else
			len = 0;
	}
	ubc_upl_unmap(upl);

	if (!(flags & UPL_NOCOMMIT)) {
		if (error) {
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
					    UPL_ABORT_ERROR |
					    UPL_ABORT_FREE_ON_EMPTY);
		} else {
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
		}
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/*
	 * We can't grab the range lock for the page as reader which would
	 * stop truncation as this leads to deadlock. So we need to recheck
	 * the file size.
	 */
	if (ap->a_f_offset >= zp->z_phys->zp_size) {
		error = EFAULT;
	}
	if (need_unlock) {
		rw_exit(&zp->z_map_lock);
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifndef ZFS_READONLY

static int
zfs_vnop_pageout(struct vnop_pageout_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	offset_t	off = ap->a_f_offset;
	size_t		len = ap->a_size;
	int		flags = ap->a_flags;
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	dmu_tx_t	*tx;
	upl_t		upl = ap->a_pl;
	vm_offset_t	upl_offset = ap->a_pl_offset;
	rl_t		*rl;
	uint64_t	filesz;
	int		error = 0;

	if (zfsvfs == NULL) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES |
			              UPL_ABORT_FREE_ON_EMPTY);
		return (ENXIO);
	}

	ZFS_ENTER(zfsvfs);

	ASSERT(vn_has_cached_data(vp));
	ASSERT(zp->z_dbuf_held && zp->z_phys);

	if (upl == (upl_t)NULL) {
		panic("zfs_vnop_pageout: no upl!");
	}
	if (len <= 0) {
		printf("zfs_vnop_pageout: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		error = EINVAL;
		goto exit;
	}
        if (vnode_vfsisrdonly(vp)) {
		if (!(flags & UPL_NOCOMMIT))
		        ubc_upl_abort_range(upl, upl_offset, len,
		                            UPL_ABORT_FREE_ON_EMPTY);
		error = EROFS;
		goto exit;
	}
	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if ((off < 0) || (off >= filesz) ||
	    (off & PAGE_MASK_64) || (len & PAGE_MASK)) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			                    UPL_ABORT_FREE_ON_EMPTY);
		error = EINVAL;
		goto exit;
	}
	len = MIN(len, filesz - off);

top:
	zilog = zfsvfs->z_log;
	rl = zfs_range_lock(zp, off, len, RL_WRITER);
	/*
	 * Can't push pages past end-of-file.
	 */
	if (off + len > zp->z_phys->zp_size) {
#if 0
		int npages = btopr(zp->z_phys->zp_size - off);
		page_t *trunc;

		page_list_break(&pp, &trunc, npages);
		/* ignore pages past end of file */
		if (trunc)
			pvn_write_done(trunc, B_INVAL | flags);
#endif
		len = zp->z_phys->zp_size - off;
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, zp->z_id, off, len);
	dmu_tx_hold_bonus(tx, zp->z_id);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error != 0) {
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			zfs_range_unlock(rl);
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			error = 0;
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	if (/*zp->z_blksz*/ len <= PAGESIZE) {
		caddr_t  va;

		ASSERT3U(len, <=, PAGESIZE);

		ubc_upl_map(upl, (vm_offset_t *)&va);
		va += upl_offset;
		dmu_write(zfsvfs->z_os, zp->z_id, off, len, va, tx);
		ubc_upl_unmap(upl);
	} else {
		error = dmu_write_pages(zfsvfs->z_os, zp->z_id,
		                        off, len, upl, tx);
	}

	if (error == 0) {
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);
		(void) zfs_log_write(zilog, tx, TX_WRITE, zp, off, len, 0);
		dmu_tx_commit(tx);
	} else {
		/* XXX TBD, but at least clean up the tx */
		dmu_tx_abort(tx);
	}
out:
	zfs_range_unlock(rl);

	if (flags & UPL_IOSYNC)
		zil_commit(zfsvfs->z_log, UINT64_MAX, zp->z_id);

	if (!(flags & UPL_NOCOMMIT)) {
		if (error)
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
					    UPL_ABORT_ERROR |
					    UPL_ABORT_FREE_ON_EMPTY);
		else
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
	}
exit:
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !ZFS_READONLY */

static int
zfs_vnop_mmap(struct vnop_mmap_args *ap)
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	if ( !vnode_isreg(vp) ) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	rw_enter(&zp->z_map_lock, RW_WRITER);
	zp->z_mmapped = 1;
	rw_exit(&zp->z_map_lock);

	ZFS_EXIT(zfsvfs);
	return (0);
}

static int
zfs_vnop_inactive(struct vnop_inactive_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	znode_phys_t  *pzp = zp->z_phys;

	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_READER);	

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_inactive);
#endif
	/* If we're force unmounting, go to reclaim */
	if (zfsvfs->z_unmounted) {
		rw_exit(&zfsvfs->z_unmount_inactive_lock);
		return(0);
	}

	/*
	 * Destroy the on-disk znode and flag the vnode to be recycled. 
	 * If this was a directory then zfs_link_destroy will have set 
	 * zp_links = 0
	 */
	if (pzp->zp_links == 0) {
		vnode_recycle(vp);
	}

	rw_exit(&zfsvfs->z_unmount_inactive_lock);
	return (0);
}

static int
zfs_vnop_reclaim(struct vnop_reclaim_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_READER);

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_reclaim);
#endif

	/*
	 * It's possible to get here without going through zfs_zinactive 
	 * so check to see if the znode has been tagged to be deleted yet. 
	 */
      	mutex_enter(&zp->z_lock);
	if (zp->z_dbuf == NULL) {
		/* vnop_inactive called zfs_zinactive already */
                mutex_exit(&zp->z_lock);
                zfs_znode_free(zp);

	} else if (zp->z_dbuf_held && vfs_isforce(zfsvfs->z_vfs)) {
		/*
		 * A forced unmount relclaim prior to zfs_unmount.
		 * Relinquish the vnode back to VFS and let
		 * zfs_objset_close() deal with the znode.
		 */
		zp->z_vnode = NULL;
		mutex_exit(&zp->z_lock);
	} else {
		mutex_exit(&zp->z_lock);
		zfs_zreclaim(zp, TRUE/*get_zhold_lock*/);
	}

	/* Mark the vnode as not used and NULL out the vp's data*/
	vnode_removefsref(vp);
	vnode_clearfsnode(vp);
	rw_exit(&zfsvfs->z_unmount_inactive_lock);
	return (0);
}

#ifndef ZFS_READONLY
static int
zfs_vnop_mknod(struct vnop_mknod_args *ap)
{
	return zfs_vnop_create((struct vnop_create_args *)ap);
}
#endif /* !ZFS_READONLY */

static int 
zfs_vnop_whiteout(struct vnop_whiteout_args *ap)
{
	struct vnode *vp = NULLVP;
	int error = 0;

	switch (ap->a_flags) {
		case LOOKUP: {
			error = 0;
			break;
		}
		case CREATE: {
#ifdef ZFS_READONLY	
			return (EROFS);
#else
			struct vnop_mknod_args mknod_args;
			struct vnode_attr va;

			VATTR_INIT(&va);
			VATTR_SET(&va, va_type, VREG);
			VATTR_SET(&va, va_mode, S_IFWHT);
			VATTR_SET(&va, va_uid, 0);
			VATTR_SET(&va, va_gid, 0);

			mknod_args.a_desc = &vnop_mknod_desc;
			mknod_args.a_dvp = ap->a_dvp;
			mknod_args.a_vpp = &vp;
			mknod_args.a_cnp = ap->a_cnp;
			mknod_args.a_vap = &va;
			mknod_args.a_context = ap->a_context;
			
			error = zfs_vnop_mknod(&mknod_args);
			/*
			 * No need to release the vnode since
			 * a vnode isn't created for whiteouts.
			 */
			break;
#endif /* ZFS_READONLY */
		}
		case DELETE: {
#ifdef ZFS_READONLY	
			return (EROFS);
#else
			struct vnop_remove_args remove_args;
			struct vnop_lookup_args lookup_args;

			lookup_args.a_dvp = ap->a_dvp;
			lookup_args.a_vpp = &vp;
			lookup_args.a_cnp = ap->a_cnp;
			lookup_args.a_context = ap->a_context;

			error = zfs_vnop_lookup(&lookup_args);
			if (error) {
				break;
			}
			
			remove_args.a_dvp = ap->a_dvp;
			remove_args.a_vp = vp;
			remove_args.a_cnp = ap->a_cnp;
			remove_args.a_flags = 0;
			remove_args.a_context = ap->a_context;

			error = zfs_vnop_remove(&remove_args);
			vnode_put(vp);
			break;
#endif /* ZFS_READONLY */
		}

		default:
			error = EINVAL;
	};

	return (error);
}

static int
zfs_vnop_pathconf(struct vnop_pathconf_args *ap)
{
	register_t  *valp = ap->a_retval;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*valp = LONG_MAX;  /* Can't use -1 since that signals error */
		break;

	case _PC_PIPE_BUF:
		*valp = PIPE_BUF;
		break;

	case _PC_CHOWN_RESTRICTED:
		*valp = 200112;  /* POSIX */
		break;

	case _PC_NO_TRUNC:
		*valp = 200112;  /* POSIX */
		break;

	case _PC_NAME_MAX:
	case _PC_NAME_CHARS_MAX:
		*valp = ZAP_MAXNAMELEN - 1;  /* 255 */
		break;

	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		*valp = PATH_MAX;  /* 1024 */
		break;

	case _PC_CASE_SENSITIVE:
		*valp = 1;
		break;

	case _PC_CASE_PRESERVING:
		*valp = 1;
		break;

	case _PC_FILESIZEBITS:
		*valp = 64;
		break;

	default:
		return (EINVAL);
	}
	return (0);
}

/*
 * Retrieve the data of an extended attribute.
 */
static int
zfs_vnop_getxattr(struct vnop_getxattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	struct vnode  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (zp->z_phys->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, 0, &xvp)) ) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	/* Read the attribute data. */
	if (uio == NULL) {
		znode_t  *xzp = VTOZ(xvp);
	
		mutex_enter(&xzp->z_lock);
		*ap->a_size = (size_t)xzp->z_phys->zp_size;
		mutex_exit(&xzp->z_lock);
	} else {
		error = VNOP_READ(xvp, uio, 0, ap->a_context);
	}
out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

#ifndef ZFS_READONLY
/*
 * Lookup/Create an extended attribute entry.
 *
 * Input arguments:
 *	dzp	- znode for hidden attribute directory
 *	name	- name of attribute
 *	flag	- ZNEW: if the entry already exists, fail with EEXIST.
 *		  ZEXISTS: if the entry does not exist, fail with ENOENT.
 *
 * Output arguments:
 *	vpp	- pointer to the vnode for the entry (NULL if there isn't one)
 *
 * Return value: 0 on success or errno value on failure.
 */
int
zfs_obtain_xattr(znode_t *dzp, const char *name, mode_t mode, cred_t *cr,
                 struct vnode **vpp, int flag)
{
	znode_t  *xzp = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	struct vnode_attr  vattr;
	uint64_t  zoid;
	int error;
	struct componentname cn;

	/* zfs_dirent_lock() expects a component name */
	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)name;
	cn.cn_namelen = strlen(name);
top:
	/* Lock the attribute entry name. */
	if ( (error = zfs_dirent_lock(&dl, dzp, &cn, &xzp, flag)) ) {
		goto out;
	}
	/* If the name already exists, we're done. */
	if (xzp != NULL) {
		zfs_dirent_unlock(dl);
		goto out;
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, (char *)name);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	}
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if ((error == ERESTART) && (zfsvfs->z_assign == TXG_NOWAIT)) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, mode & ~S_IFMT);
	zfs_mknode(dzp, &vattr, &zoid, tx, cr, 0, &xzp, 0);

	ASSERT(xzp->z_id == zoid);
	(void) zfs_link_create(dl, xzp, tx, ZNEW);
	zfs_log_create(zilog, tx, TX_CREATE, dzp, xzp, (char *)name);
	dmu_tx_commit(tx);
	zfs_dirent_unlock(dl);
out:
	if (error == EEXIST)
		error = ENOATTR;
	if (xzp)
		*vpp = ZTOV(xzp);
	return (error);
}

/*
 * Set the data of an extended attribute.
 */
static int
zfs_vnop_setxattr(struct vnop_setxattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	struct vnode  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  flag;
	int  error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ap->a_name) >= ZAP_MAXNAMELEN) {
		error = ENAMETOOLONG;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;     /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name,
	                         VTOZ(vp)->z_phys->zp_mode, cr, &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = VNOP_WRITE(xvp, uio, 0, ap->a_context);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	if (xvp) {
		vnode_put(xvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Remove an extended attribute.
 */
static int
zfs_vnop_removexattr(struct vnop_removexattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	struct vnode  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct vnop_remove_args  args;
	struct componentname  cn;
	int  error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (zp->z_phys->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, 0, &xvp)) ) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = DELETE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	args.a_desc = &vnop_remove_desc;
	args.a_dvp = xdvp;
	args.a_vp = xvp;
	args.a_cnp = &cn;
	args.a_flags = 0;
	args.a_context = ap->a_context;

	error = zfs_vnop_remove(&args);

out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}
#endif /* !ZFS_READONLY */

/*
 * Generate a list of extended attribute names.
 */
static int
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	zap_cursor_t  zc;
	zap_attribute_t  za;
	objset_t  *os;
	size_t size = 0;
	char  *nameptr;
	char  nfd_name[ZAP_MAXNAMELEN];
	size_t  namelen;
	int  error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	/* Do we even have any attributes? */
	if (zp->z_phys->zp_xattr == 0) {
		goto out;  /* all done */
	}
	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	     zap_cursor_retrieve(&zc, &za) == 0;
	     zap_cursor_advance(&zc)) {

		if (xattr_protected(za.za_name))
			continue;     /* skip */

		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);
		if (!is_ascii_str(za.za_name) &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
				      (u_int8_t *)nfd_name, &namelen,
				      sizeof (nfd_name), UTF_DECOMPOSED) == 0) {
			nameptr = nfd_name;
		} else {
			nameptr = &za.za_name[0];
		}

		++namelen;  /* account for NULL termination byte */
		if (uio == NULL) {
			size += namelen;
		} else {
			if (namelen > uio_resid(uio)) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t)nameptr, namelen, uio);
			if (error) {
				break;
			}
		}
	}
	zap_cursor_fini(&zc);
out:
	if (uio == NULL) {
		*ap->a_size = size;
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Obtain the vnode for a stream.
 */
static int
zfs_vnop_getnamedstream(struct vnop_getnamedstream_args* ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  **svpp = ap->a_svpp;
	struct vnode  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  error = ENOATTR;

	*svpp = NULLVP;
	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0 ||
	    zp->z_phys->zp_xattr == 0) {
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, 0, svpp)) ) {
		if (error == ENOENT)
			error = ENOATTR;
	}
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

#ifndef ZFS_READONLY
/*
 * Create a stream.
 */
static int
zfs_vnop_makenamedstream(struct vnop_makenamedstream_args* ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct componentname  cn;
	struct vnode_attr  vattr;
	struct vnop_create_args  args;
	int  error = 0;

	*ap->a_svpp = NULLVP;
	ZFS_ENTER(zfsvfs);

	/* Only regular files can have a resource fork stream. */
	if ( !vnode_isreg(vp) ) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_phys->zp_mode & ~S_IFMT);

	args.a_desc = &vnop_create_desc;
	args.a_dvp = xdvp;
	args.a_vpp = ap->a_svpp;
	args.a_cnp = &cn;
	args.a_vap = &vattr;
	args.a_context = ap->a_context;

	error = zfs_vnop_create(&args);
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Remove a stream.
 */
static int
zfs_vnop_removenamedstream(struct vnop_removenamedstream_args* ap)
{
	vnode_t svp = ap->a_svp;
	znode_t  *zp = VTOZ(svp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* ### MISING CODE ### */
	printf("zfs_vnop_removenamedstream\n");
	error = EPERM;
out:
	ZFS_EXIT(zfsvfs);

	return (error);
}

static int
zfs_vnop_exchange(__unused struct vnop_exchange_args *ap)
{
	struct vnode  *fvp = ap->a_fvp;
	struct vnode  *tvp = ap->a_tvp;
	znode_t  *fzp;
	znode_t  *tzp;
	zfsvfs_t  *zfsvfs;

	/* The files must be on the same volume. */
	if (vnode_mount(fvp) != vnode_mount(tvp))
		return (EXDEV);

	if (fvp == tvp)
		return (EINVAL);

	/* Only normal files can be exchanged. */
	if (!vnode_isreg(fvp) || !vnode_isreg(tvp))
		return (EINVAL);

	fzp = VTOZ(fvp);
	tzp = VTOZ(tvp);
	zfsvfs = fzp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	/* ADD MISSING CODE HERE */

	ZFS_EXIT(zfsvfs);

	return (EPERM);
}

#endif /* !ZFS_READONLY */

static int
zfs_vnop_revoke(__unused struct vnop_revoke_args *ap)
{
	return vn_revoke(ap->a_vp, ap->a_flags, ap->a_context);
}

static int
zfs_vnop_blktooff(__unused struct vnop_blktooff_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_offtoblk(__unused struct vnop_offtoblk_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_blockmap(__unused struct vnop_blockmap_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_strategy(__unused struct vnop_strategy_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_select(__unused struct vnop_select_args *ap)
{
	return (1);
}

static int
zfs_inval(__unused void *ap)
{
	return (EINVAL);
}

static int
zfs_isdir(__unused void *ap)
{
	return (EISDIR);
}


#ifdef ZFS_READONLY
static int zfs_vnop_create(void *ap) { return (EROFS); }
static int zfs_vnop_mknod(void *ap) { return (EROFS); }
static int zfs_vnop_setattr(void *ap) { return (EROFS); }
static int zfs_vnop_write(void *ap) { return (EROFS); }
static int zfs_vnop_remove(void *ap) { return (EROFS); }
static int zfs_vnop_link(void *ap) { return (EROFS); }
static int zfs_vnop_rename(void *ap) { return (EROFS); }
static int zfs_vnop_mkdir(void *ap) { return (EROFS); }
static int zfs_vnop_rmdir(void *ap) { return (EROFS); }
static int zfs_vnop_symlink(void *ap) { return (EROFS); }
static int zfs_vnop_pageout(void *ap) { return (EROFS); }
static int zfs_vnop_setxattr(void *ap) { return (EROFS); }
static int zfs_vnop_removexattr(void *ap) { return (EROFS); }
static int zfs_vnop_makenamedstream(void *ap) { return (EROFS); }
static int zfs_vnop_removenamedstream(void *ap) { return (EROFS); }
static int zfs_vnop_exchange(void *ap) { return (EROFS); }
#endif

#define VOPFUNC int (*)(void *)

/*
 * Directory vnode operations template
 */
int (**zfs_dvnodeops) (void *);
struct vnodeopv_entry_desc zfs_dvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_mknod},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_write_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_mkdir},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_symlink},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_dvnodeop_opv_desc =
{ &zfs_dvnodeops, zfs_dvnodeops_template };


/*
 * Regular file vnode operations template
 */
int (**zfs_fvnodeops) (void *);
struct vnodeopv_entry_desc zfs_fvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
	{&vnop_mmap_desc,	(VOPFUNC)zfs_vnop_mmap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fvnodeop_opv_desc =
{ &zfs_fvnodeops, zfs_fvnodeops_template };


/*
 * Symbolic link vnode operations template
 */
int (**zfs_symvnodeops) (void *);
struct vnodeopv_entry_desc zfs_symvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_readlink_desc,	(VOPFUNC)zfs_vnop_readlink},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_symvnodeop_opv_desc =
{ &zfs_symvnodeops, zfs_symvnodeops_template };


/*
 * Extended attribute directory vnode operations template
 *	This template is similar to the directory vnodes
 *	operation template except for restricted operations:
 *		VNOP_MKDIR()
 *		VNOP_SYMLINK()
 *		VNOP_MKNOD()
 * Note that there are other restrictions embedded in:
 *	zfs_vnop_create() - restrict type to VREG
 *	zfs_vnop_link()   - no links into/out of attribute space
 *	zfs_vnop_rename() - no moves into/out of attribute space
 */
int (**zfs_xdvnodeops) (void *);
struct vnodeopv_entry_desc zfs_xdvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_inval},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_inval},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_inval},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_xdvnodeop_opv_desc =
{ &zfs_xdvnodeops, zfs_xdvnodeops_template };

/*
 * Error vnode operations template
 */
int (**zfs_evnodeops) (void *);
struct vnodeopv_entry_desc zfs_evnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_evnodeop_opv_desc =
{ &zfs_evnodeops, zfs_evnodeops_template };

