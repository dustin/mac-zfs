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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/zfs_context.h>

#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_ctldir.h>
#include <sys/refcount.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_deleg.h>
#include <sys/spa.h>
#include <sys/zap.h>


static int  zfs_vfs_init (struct vfsconf *vfsp);
static int  zfs_vfs_start (struct mount *mp, int flags, vfs_context_t context);
static int  zfs_vfs_mount (struct mount *mp, vnode_t devvp, user_addr_t data, vfs_context_t context);
static int  zfs_vfs_unmount (struct mount *mp, int mntflags, vfs_context_t context);
static int  zfs_vfs_root (struct mount *mp, struct vnode **vpp, vfs_context_t context);
static int  zfs_vfs_vget (struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);
static int  zfs_vfs_getattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
static int  zfs_vfs_setattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
static int  zfs_vfs_sync (struct mount *mp, int waitfor, vfs_context_t context);
static int  zfs_vfs_fhtovp (struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp, vfs_context_t context);
static int  zfs_vfs_vptofh (struct vnode *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);
static int  zfs_vfs_sysctl (int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp,  user_addr_t newp, size_t newlen, vfs_context_t context);
static int  zfs_vfs_quotactl ( struct mount *mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t context);
static void zfs_objset_close(zfsvfs_t *zfsvfs);

int  zfs_module_start(kmod_info_t *ki, void *data);
int  zfs_module_stop(kmod_info_t *ki, void *data);


/*
 * Mac OS X needs a file system modify time
 *
 * We use the mtime of the "com.apple.system.mtime" 
 * extended attribute, which is associated with the
 * file system root directory.  This attribute has
 * no associated data.
 */
#define ZFS_MTIME_XATTR		"com.apple.system.mtime"

extern int zfs_obtain_xattr(znode_t *, const char *, mode_t, cred_t *,
                            struct vnode **, int);

/*
 * zfs vfs operations.
 */
static struct vfsops zfs_vfsops_template = {
	zfs_vfs_mount,
	zfs_vfs_start,
	zfs_vfs_unmount,
	zfs_vfs_root,
	zfs_vfs_quotactl,
	zfs_vfs_getattr,
	zfs_vfs_sync,
	zfs_vfs_vget,
	zfs_vfs_fhtovp,
	zfs_vfs_vptofh,
	zfs_vfs_init,
	zfs_vfs_sysctl,
	zfs_vfs_setattr,
	{NULL}
};


extern struct vnodeopv_desc zfs_dvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_symvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_xdvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_evnodeop_opv_desc;

#define ZFS_VNOP_TBL_CNT	5

static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	&zfs_evnodeop_opv_desc,
};

static vfstable_t zfs_vfsconf;

/*
 * We need to keep a count of active fs's.
 * This is necessary to prevent our kext
 * from being unloaded after a umount -f
 */
static SInt32	zfs_active_fs_count = 0;

extern void zfs_ioctl_init(void);
extern void zfs_ioctl_fini(void);


static int
zfs_vfs_sync(struct mount *mp, __unused int waitfor, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X needs a file system modify time
	 *
	 * We use the mtime of the "com.apple.system.mtime" 
	 * extended attribute, which is associated with the
	 * file system root directory.
	 *
	 * Here we sync any mtime changes to this attribute.
	 */
	if (zfsvfs->z_mtime_vp != NULL) {
		timestruc_t  mtime;
		znode_t  *zp;
top:
		zp = VTOZ(zfsvfs->z_mtime_vp);
		ZFS_TIME_DECODE(&mtime, zp->z_phys->zp_mtime);
		if (zfsvfs->z_last_mtime_synced < mtime.tv_sec) {
			dmu_tx_t  *tx;
			int  error;

			tx = dmu_tx_create(zfsvfs->z_os);
			dmu_tx_hold_bonus(tx, zp->z_id);
			error = dmu_tx_assign(tx, zfsvfs->z_assign);
			if (error) {
				if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top;
				}
				dmu_tx_abort(tx);
			} else {
				dmu_buf_will_dirty(zp->z_dbuf, tx);
				dmu_tx_commit(tx);
				zfsvfs->z_last_mtime_synced = mtime.tv_sec;
			}
		}
	}

	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, UINT64_MAX, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
	ZFS_EXIT(zfsvfs);

	return (0);
}

static int
zfs_domount(struct mount *mp, dev_t mount_dev, char *osname, vfs_context_t ctx)
{
	uint64_t readonly;
	int error = 0;
	int mode;
	zfsvfs_t *zfsvfs;
	znode_t *zp = NULL;
	struct timeval tv;

	ASSERT(mp);
	ASSERT(osname);

	/*
	 * Initialize the zfs-specific filesystem structure.
	 * Should probably make this a kmem cache, shuffle fields,
	 * and just bzero up to z_hold_mtx[].
	 */
	zfsvfs = kmem_zalloc(sizeof (zfsvfs_t), KM_SLEEP);
	zfsvfs->z_vfs = mp;
	zfsvfs->z_parent = zfsvfs;
	zfsvfs->z_assign = TXG_NOWAIT;
	zfsvfs->z_max_blksz = SPA_MAXBLOCKSIZE;
	zfsvfs->z_show_ctldir = ZFS_SNAPDIR_VISIBLE;

	mutex_init(&zfsvfs->z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs->z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));
	rw_init(&zfsvfs->z_unmount_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zfsvfs->z_unmount_inactive_lock, NULL, RW_DEFAULT, NULL);
#ifndef __APPLE__
	/* Initialize the generic filesystem structure. */
	vfsp->vfs_bcount = 0;
	vfsp->vfs_data = NULL;

	if (zfs_create_unique_device(&mount_dev) == -1) {
		error = ENODEV;
		goto out;
	}
	ASSERT(vfs_devismounted(mount_dev) == 0);
#endif

	vfs_setfsprivate(mp, zfsvfs);

	if (error = dsl_prop_get_integer(osname, "readonly", &readonly, NULL))
		goto out;

	if (readonly) {
		mode = DS_MODE_PRIMARY | DS_MODE_READONLY;
		vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_RDONLY));
	} else {
		mode = DS_MODE_PRIMARY;
	}
	error = dmu_objset_open(osname, DMU_OST_ZFS, mode, &zfsvfs->z_os);
	if (error == EROFS) {
		mode = DS_MODE_PRIMARY | DS_MODE_READONLY;
		error = dmu_objset_open(osname, DMU_OST_ZFS, mode,
		    &zfsvfs->z_os);
	}

	if (error)
		goto out;

	if (error = zfs_init_fs(zfsvfs, &zp, vfs_context_ucred(ctx)))
		goto out;

	/* The call to zfs_init_fs leaves the vnode held, release it here. */
	vnode_put(ZTOV(zp));

	if (dmu_objset_is_snapshot(zfsvfs->z_os)) {
		uint64_t xattr;

		ASSERT(mode & DS_MODE_READONLY);
#if 0
		atime_changed_cb(zfsvfs, B_FALSE);
		readonly_changed_cb(zfsvfs, B_TRUE);
		if (error = dsl_prop_get_integer(osname, "xattr", &xattr, NULL))
			goto out;
		xattr_changed_cb(zfsvfs, xattr);
#endif
		zfsvfs->z_issnap = B_TRUE;
	} else {
		
		if (!vfs_isrdonly(mp))
			zfs_unlinked_drain(zfsvfs);

#ifndef __APPLE__
		/*
		 * Parse and replay the intent log.
		 *
		 * Because of ziltest, this must be done after
		 * zfs_unlinked_drain().  (Further note: ziltest doesn't
		 * use readonly mounts, where zfs_unlinked_drain() isn't
		 * called.)  This is because ziltest causes spa_sync()
		 * to think it's committed, but actually it is not, so
		 * the intent log contains many txg's worth of changes.
		 *
		 * In particular, if object N is in the unlinked set in
		 * the last txg to actually sync, then it could be
		 * actually freed in a later txg and then reallocated in
		 * a yet later txg.  This would write a "create object
		 * N" record to the intent log.  Normally, this would be
		 * fine because the spa_sync() would have written out
		 * the fact that object N is free, before we could write
		 * the "create object N" intent log record.
		 *
		 * But when we are in ziltest mode, we advance the "open
		 * txg" without actually spa_sync()-ing the changes to
		 * disk.  So we would see that object N is still
		 * allocated and in the unlinked set, and there is an
		 * intent log record saying to allocate it.
		 */
		zil_replay(zfsvfs->z_os, zfsvfs, &zfsvfs->z_assign,
		    zfs_replay_vector);

		if (!zil_disable)
			zfsvfs->z_log = zil_open(zfsvfs->z_os, zfs_get_data);
#endif
	}

#if 0
	if (!zfsvfs->z_issnap)
		zfsctl_create(zfsvfs);
#endif

	/*
	 * Record the mount time (for Spotlight)
	 */
	microtime(&tv);
	zfsvfs->z_mount_time = tv.tv_sec;
	
out:
	if (error) {
		if (zfsvfs->z_os)
			dmu_objset_close(zfsvfs->z_os);
		mutex_destroy(&zfsvfs->z_znodes_lock);
		list_destroy(&zfsvfs->z_all_znodes);
		rw_destroy(&zfsvfs->z_unmount_lock);
		rw_destroy(&zfsvfs->z_unmount_inactive_lock);
		kmem_free(zfsvfs, sizeof (zfsvfs_t));
	} else {
		OSIncrementAtomic(&zfs_active_fs_count);
		(void) copystr(osname, vfs_statfs(mp)->f_mntfromname, MNAMELEN - 1, 0);
		vfs_getnewfsid(mp);
	}

	return (error);

}

static int
zfs_vfs_mount(struct mount *mp, vnode_t devvp, user_addr_t data, vfs_context_t context)
{
	char	*osname = NULL;
	size_t  osnamelen = 0;
	int		error = 0;
	int		canwrite;

	/*
	 * Get the objset name (the "special" mount argument).
	 * The filesystem that we mount as root is defined in the
	 * "zfs-bootfs" property. 
	 */
	if (data) {
		char *tmp;
#ifndef __APPLE__
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_DONTPASS, "zfs-bootfs", &zfs_bootpath) !=
		    DDI_SUCCESS)
			return (EIO);

		error = parse_bootpath(zfs_bootpath, rootfs.bo_name);
		ddi_prop_free(zfs_bootpath);
#endif
		osname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if ( (error = copyin(data, (caddr_t)&tmp, sizeof(tmp))) )
			goto out;	

		if ( (error = copyinstr(CAST_USER_ADDR_T(tmp), osname, MAXPATHLEN, &osnamelen)) )
			goto out;
	}

#if 0
	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 &&
	    (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * ZFS does not support passing unparsed data in via MS_DATA.
	 * Users should use the MS_OPTIONSTR interface; this means
	 * that all option parsing is already done and the options struct
	 * can be interrogated.
	 */
	if ((uap->flags & MS_DATA) && uap->datalen > 0)
		return (EINVAL);

	/*
	 * Get the objset name (the "special" mount argument).
	 */
	if (error = pn_get(uap->spec, fromspace, &spn))
		return (error);

	osname = spn.pn_path;
#endif
	/*
	 * Check for mount privilege?
	 *
	 * If we don't have privilege then see if
	 * we have local permission to allow it
	 */
#ifndef __APPLE__
	error = secpolicy_fs_mount(cr, mvp, vfsp);
	if (error) {
		error = dsl_deleg_access(osname, ZFS_DELEG_PERM_MOUNT, cr);
		if (error == 0) {
			vattr_t		vattr;

			/*
			 * Make sure user is the owner of the mount point
			 * or has sufficient privileges.
			 */

			vattr.va_mask = AT_UID;

			if (error = VOP_GETATTR(mvp, &vattr, 0, cr)) {
				goto out;
			}

			if (error = secpolicy_vnode_owner(cr, vattr.va_uid)) {
				goto out;
			}

			if (error = VOP_ACCESS(mvp, VWRITE, 0, cr)) {
				goto out;
			}

			secpolicy_fs_mount_clearopts(cr, vfsp);
		} else {
			goto out;
		}
	}
#endif

	error = zfs_domount(mp, 0, osname, context);
	if (error)
		printf("zfs_vfs_mount: error %d\n", error);
	if (error == 0) {
		zfsvfs_t *zfsvfs = NULL;

		/* Make the Finder treat sub file systems just like a folder */
		if (strpbrk(osname, "/"))
			vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_DONTBROWSE));

		/* Indicate to VFS that we support ACLs. */
		vfs_setextendedsecurity(mp);

		/* Advisory locking should be handled at the VFS layer */
		vfs_setlocklocal(mp);

#ifdef ZFS_READONLY
		vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_RDONLY));
#endif
		/*
		 * Mac OS X needs a file system modify time
		 *
		 * We use the mtime of the "com.apple.system.mtime" 
		 * extended attribute, which is associated with the
		 * file system root directory.
		 *
		 * Here we need to take a ref on z_mtime_vp to keep it around.
		 * If the attribute isn't there, attempt to create it.
		 */
		zfsvfs = vfs_fsprivate(mp);
		if (zfsvfs->z_mtime_vp == NULL) {
			struct vnode * rvp;
			struct vnode *xdvp = NULLVP;
			struct vnode *xvp = NULLVP;
			znode_t *rootzp;
			timestruc_t modify_time;
			cred_t  *cr;
			timestruc_t  now;
			int flag;
			int result;

			if (zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp) != 0) {
				goto out;
			}
			rvp = ZTOV(rootzp);
			cr = (cred_t *)vfs_context_ucred(context);

			/* Grab the hidden attribute directory vnode. */
			result = zfs_get_xattrdir(rootzp, &xdvp, cr, CREATE_XATTR_DIR);
			vnode_put(rvp);	/* all done with root vnode */
			rvp = NULL;
			if (result) {
				goto out;
			}

			/*
			 * HACK - workaround missing vnode_setnoflush() KPI...
			 *
			 * We tag zfsvfs so that zfs_attach_vnode() can then set
			 * vnfs_marksystem when the vnode gets created.
			 */
			zfsvfs->z_last_unmount_time = 0xBADC0DE;
			zfsvfs->z_last_mtime_synced = VTOZ(xdvp)->z_id;
#ifdef ZFS_READONLY
			/* Lookup the attribute name. */
			if (zfs_dirlook(VTOZ(xdvp), ZFS_MTIME_XATTR, 0, &xvp)) {
					zfsvfs->z_last_unmount_time = 0;
					zfsvfs->z_last_mtime_synced = 0;
					vnode_put(xdvp);
					goto out;
			}
#else
			flag = vfs_isrdonly(mp) ? 0 : ZEXISTS;
			/* Lookup or create the named attribute. */
			if ( zfs_obtain_xattr(VTOZ(xdvp), ZFS_MTIME_XATTR,
			                          S_IRUSR | S_IWUSR, cr, &xvp,
			                          flag) ) {
					zfsvfs->z_last_unmount_time = 0;
					zfsvfs->z_last_mtime_synced = 0;
					vnode_put(xdvp);
					goto out;
				}
				gethrestime(&now);
			ZFS_TIME_ENCODE(&now, VTOZ(xvp)->z_phys->zp_mtime);
#endif
			vnode_put(xdvp);
			vnode_ref(xvp);

			zfsvfs->z_mtime_vp = xvp;
			ZFS_TIME_DECODE(&modify_time, VTOZ(xvp)->z_phys->zp_mtime);
			zfsvfs->z_last_unmount_time = modify_time.tv_sec;
			zfsvfs->z_last_mtime_synced = modify_time.tv_sec;

			/*
			 * Keep this referenced vnode from impeding an unmount.
			 *
			 * XXX vnode_setnoflush() is MIA from KPI (see workaround above).
			 */
#if 0
			vnode_setnoflush(xvp);
#endif
			vnode_put(xvp);
		}
	}
out:
	if (osname) {
		kmem_free(osname, MAXPATHLEN);
	}
	return (error);
}

/*
 * ZFS file system features.
 */
const vol_capabilities_attr_t zfs_capabilities = {
	{
		/* Format capabilities we support: */
		VOL_CAP_FMT_PERSISTENTOBJECTIDS |
		VOL_CAP_FMT_SYMBOLICLINKS |
		VOL_CAP_FMT_HARDLINKS |
		VOL_CAP_FMT_SPARSE_FILES |
		VOL_CAP_FMT_CASE_SENSITIVE |
		VOL_CAP_FMT_CASE_PRESERVING |
		VOL_CAP_FMT_FAST_STATFS | 
		VOL_CAP_FMT_2TB_FILESIZE |
		VOL_CAP_FMT_HIDDEN_FILES |
		VOL_CAP_FMT_PATH_FROM_ID,

		/* Interface capabilities we support: */
		VOL_CAP_INT_ATTRLIST |
		VOL_CAP_INT_NFSEXPORT |
		VOL_CAP_INT_EXCHANGEDATA |
		VOL_CAP_INT_VOL_RENAME |
		VOL_CAP_INT_ADVLOCK |
		VOL_CAP_INT_FLOCK |
		VOL_CAP_INT_EXTENDED_SECURITY |
		VOL_CAP_INT_NAMEDSTREAMS |
		VOL_CAP_INT_EXTENDED_ATTR ,

		0 , 0
	},
	{
		/* Format capabilities we know about: */
		VOL_CAP_FMT_PERSISTENTOBJECTIDS |
		VOL_CAP_FMT_SYMBOLICLINKS |
		VOL_CAP_FMT_HARDLINKS |
		VOL_CAP_FMT_JOURNAL |
		VOL_CAP_FMT_JOURNAL_ACTIVE |
		VOL_CAP_FMT_NO_ROOT_TIMES |
		VOL_CAP_FMT_SPARSE_FILES |
		VOL_CAP_FMT_ZERO_RUNS |
		VOL_CAP_FMT_CASE_SENSITIVE |
		VOL_CAP_FMT_CASE_PRESERVING |
		VOL_CAP_FMT_FAST_STATFS | 
		VOL_CAP_FMT_2TB_FILESIZE |
		VOL_CAP_FMT_OPENDENYMODES |
		VOL_CAP_FMT_HIDDEN_FILES |
		VOL_CAP_FMT_PATH_FROM_ID ,

		/* Interface capabilities we know about: */
		VOL_CAP_INT_SEARCHFS |
		VOL_CAP_INT_ATTRLIST |
		VOL_CAP_INT_NFSEXPORT |
		VOL_CAP_INT_READDIRATTR |
		VOL_CAP_INT_EXCHANGEDATA |
		VOL_CAP_INT_COPYFILE |
		VOL_CAP_INT_ALLOCATE |
		VOL_CAP_INT_VOL_RENAME |
		VOL_CAP_INT_ADVLOCK |
		VOL_CAP_INT_FLOCK |
		VOL_CAP_INT_EXTENDED_SECURITY |
		VOL_CAP_INT_USERACCESS |
		VOL_CAP_INT_MANLOCK |
		VOL_CAP_INT_NAMEDSTREAMS |
		VOL_CAP_INT_EXTENDED_ATTR ,

		0, 0
	}
};

/*
 * ZFS file system attributes (for getattrlist).
 */
const attribute_set_t zfs_attributes = {
		ATTR_CMN_NAME	|
		ATTR_CMN_DEVID	|
		ATTR_CMN_FSID	|
		ATTR_CMN_OBJTYPE |
		ATTR_CMN_OBJTAG	|
		ATTR_CMN_OBJID	|
		ATTR_CMN_OBJPERMANENTID |
		ATTR_CMN_PAROBJID |
		ATTR_CMN_CRTIME |
		ATTR_CMN_MODTIME |
		ATTR_CMN_CHGTIME |
		ATTR_CMN_ACCTIME |
		ATTR_CMN_BKUPTIME |
		ATTR_CMN_FNDRINFO |
		ATTR_CMN_OWNERID |
		ATTR_CMN_GRPID	|
		ATTR_CMN_ACCESSMASK |
		ATTR_CMN_FLAGS	|
		ATTR_CMN_USERACCESS |
		ATTR_CMN_EXTENDED_SECURITY |
		ATTR_CMN_UUID |
		ATTR_CMN_GRPUUID ,

		ATTR_VOL_FSTYPE	|
		ATTR_VOL_SIGNATURE |
		ATTR_VOL_SIZE	|
		ATTR_VOL_SPACEFREE |
		ATTR_VOL_SPACEAVAIL |
		ATTR_VOL_MINALLOCATION |
		ATTR_VOL_ALLOCATIONCLUMP |
		ATTR_VOL_IOBLOCKSIZE |
		ATTR_VOL_OBJCOUNT |
		ATTR_VOL_FILECOUNT |
		ATTR_VOL_DIRCOUNT |
		ATTR_VOL_MAXOBJCOUNT |
		ATTR_VOL_MOUNTPOINT |
		ATTR_VOL_NAME	|
		ATTR_VOL_MOUNTFLAGS |
		ATTR_VOL_MOUNTEDDEVICE |
		ATTR_VOL_CAPABILITIES |
		ATTR_VOL_ATTRIBUTES ,

		ATTR_DIR_LINKCOUNT |
		ATTR_DIR_ENTRYCOUNT |
		ATTR_DIR_MOUNTSTATUS ,

		ATTR_FILE_LINKCOUNT |
		ATTR_FILE_TOTALSIZE |
		ATTR_FILE_ALLOCSIZE |
		/* ATTR_FILE_IOBLOCKSIZE */
		ATTR_FILE_DEVTYPE |
		ATTR_FILE_DATALENGTH |
		ATTR_FILE_DATAALLOCSIZE |
		ATTR_FILE_RSRCLENGTH |
		ATTR_FILE_RSRCALLOCSIZE ,

		0
};

static int
zfs_vfs_getattr(struct mount *mp, struct vfs_attr *fsap, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	uint64_t refdbytes, availbytes, usedobjs, availobjs;

	ZFS_ENTER(zfsvfs);

	dmu_objset_space(zfsvfs->z_os,
	    &refdbytes, &availbytes, &usedobjs, &availobjs);

	VFSATTR_RETURN(fsap, f_objcount, usedobjs);
	VFSATTR_RETURN(fsap, f_maxobjcount, 0x7fffffffffffffff);
	/*
	 * Carbon depends on f_filecount and f_dircount so
	 * make up some values based on total objects.
	 */
	VFSATTR_RETURN(fsap, f_filecount, usedobjs - (usedobjs / 4));
	VFSATTR_RETURN(fsap, f_dircount, usedobjs / 4);

	/*
	 * The underlying storage pool actually uses multiple block sizes.
	 * We report the fragsize as the smallest block size we support,
	 * and we report our blocksize as the filesystem's maximum blocksize.
	 */
	VFSATTR_RETURN(fsap, f_bsize, 1UL << SPA_MINBLOCKSHIFT);
	VFSATTR_RETURN(fsap, f_iosize, zfsvfs->z_max_blksz);

	/*
	 * The following report "total" blocks of various kinds in the
	 * file system, but reported in terms of f_frsize - the
	 * "fragment" size.
	 */
	VFSATTR_RETURN(fsap, f_blocks,
	               (u_int64_t)((refdbytes + availbytes) >> SPA_MINBLOCKSHIFT));
	VFSATTR_RETURN(fsap, f_bfree, (u_int64_t)(availbytes >> SPA_MINBLOCKSHIFT));
	VFSATTR_RETURN(fsap, f_bavail, fsap->f_bfree);  /* no root reservation */
	VFSATTR_RETURN(fsap, f_bused, fsap->f_blocks - fsap->f_bfree);

	/*
	 * statvfs() should really be called statufs(), because it assumes
	 * static metadata.  ZFS doesn't preallocate files, so the best
	 * we can do is report the max that could possibly fit in f_files,
	 * and that minus the number actually used in f_ffree.
	 * For f_ffree, report the smaller of the number of object available
	 * and the number of blocks (each object will take at least a block).
	 */
	VFSATTR_RETURN(fsap, f_ffree, (u_int64_t)MIN(availobjs, fsap->f_bfree));
	VFSATTR_RETURN(fsap, f_files,  fsap->f_ffree + usedobjs);

#if 0
	statp->f_flag = vf_to_stf(vfsp->vfs_flag);
#endif

	if (VFSATTR_IS_ACTIVE(fsap, f_fsid)) {
		VFSATTR_RETURN(fsap, f_fsid, vfs_statfs(mp)->f_fsid);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		bcopy(&zfs_capabilities, &fsap->f_capabilities, sizeof (zfs_capabilities));
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		bcopy(&zfs_attributes, &fsap->f_attributes.validattr, sizeof (zfs_attributes));
		bcopy(&zfs_attributes, &fsap->f_attributes.nativeattr, sizeof (zfs_attributes));
		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_create_time)) {
		dmu_objset_stats_t dmu_stat;

		dmu_objset_fast_stat(zfsvfs->z_os, &dmu_stat);
		fsap->f_create_time.tv_sec = dmu_stat.dds_creation_time;
		fsap->f_create_time.tv_nsec = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_create_time);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_modify_time)) {
		if (zfsvfs->z_mtime_vp != NULL) {
			znode_t *mzp;

			mzp = VTOZ(zfsvfs->z_mtime_vp);
			ZFS_TIME_DECODE(&fsap->f_modify_time, mzp->z_phys->zp_mtime);
		} else {
			fsap->f_modify_time.tv_sec = 0;
			fsap->f_modify_time.tv_nsec = 0;
		}
		VFSATTR_SET_SUPPORTED(fsap, f_modify_time);
	}
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused 
	 * attribute
	 */
	if (VFSATTR_IS_ACTIVE(fsap, f_backup_time)) {
		fsap->f_backup_time.tv_sec = 0;
		fsap->f_backup_time.tv_nsec = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_backup_time);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		spa_t *spa = dmu_objset_spa(zfsvfs->z_os);
		spa_config_enter(spa, RW_READER, FTAG);
		strlcpy(fsap->f_vol_name, spa_name(spa), MAXPATHLEN);
		spa_config_exit(spa, FTAG);
		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}
	VFSATTR_RETURN(fsap, f_fssubtype, 0);
	VFSATTR_RETURN(fsap, f_signature, 0x5a21);  /* 'Z!' */
	VFSATTR_RETURN(fsap, f_carbon_fsid, 0);

	ZFS_EXIT(zfsvfs);

	return (0);
}

static int
zfs_vfs_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	znode_t *rootzp;
	int error;

	ZFS_ENTER(zfsvfs);

	error = zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp);
	if (error == 0)
		*vpp = ZTOV(rootzp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*ARGSUSED*/
static int
zfs_vfs_unmount(struct mount *mp, int mntflags, vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);	
	objset_t *os = zfsvfs->z_os;
	znode_t	*zp, *nextzp;
	int ret, i;
	int flags;
	
	/*XXX NOEL: delegation admin stuffs, add back if we use delg. admin */
#if 0
	ret = secpolicy_fs_unmount(cr, vfsp);
	if (ret) {
		ret = dsl_deleg_access((char *)refstr_value(vfsp->vfs_resource),
		    ZFS_DELEG_PERM_MOUNT, cr);
		if (ret)
			return (ret);
	}

	/*
	 * We purge the parent filesystem's vfsp as the parent filesystem
	 * and all of its snapshots have their vnode's v_vfsp set to the
	 * parent's filesystem's vfsp.  Note, 'z_parent' is self
	 * referential for non-snapshots.
	 */
	(void) dnlc_purge_vfsp(zfsvfs->z_parent->z_vfs, 0);
#endif

	/*
	 * Unmount any snapshots mounted under .zfs before unmounting the
	 * dataset itself.
	 */
#if 0
	if (zfsvfs->z_ctldir != NULL &&
	    (ret = zfsctl_umount_snapshots(vfsp, fflag, cr)) != 0) {
		return (ret);
#endif
	flags = SKIPSYSTEM;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	ret = vflush(mp, NULLVP, flags);

	/*
	 * Mac OS X needs a file system modify time
	 *
	 * We use the mtime of the "com.apple.system.mtime" 
	 * extended attribute, which is associated with the
	 * file system root directory.
	 *
	 * Here we need to release the ref we took on z_mtime_vp during mount.
	 */
	if ((ret == 0) || (mntflags & MNT_FORCE)) {
		if (zfsvfs->z_mtime_vp != NULL) {
			struct vnode *mvp;

			mvp = zfsvfs->z_mtime_vp;
			zfsvfs->z_mtime_vp = NULL;

			if (vnode_get(mvp) == 0) {
				vnode_rele(mvp);
				vnode_recycle(mvp);
				vnode_put(mvp);
			}
		}
	}

	if (!(mntflags & MNT_FORCE)) {
		/*
		 * Check the number of active vnodes in the file system.
		 * Our count is maintained in the vfs structure, but the
		 * number is off by 1 to indicate a hold on the vfs
		 * structure itself.
		 *
		 * The '.zfs' directory maintains a reference of its
		 * own, and any active references underneath are
		 * reflected in the vnode count.
		 */
		
		if (ret)
			return (EBUSY);
#if 0
		if (zfsvfs->z_ctldir == NULL) {
			if (vfsp->vfs_count > 1)
				return (EBUSY);
		} else {
			if (vfsp->vfs_count > 2 ||
			    zfsvfs->z_ctldir->v_count > 1) {
				return (EBUSY);
			}
		}
#endif
	}

	rw_enter(&zfsvfs->z_unmount_lock, RW_WRITER);
	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_WRITER);

	/*
	 * At this point there are no vops active, and any new vops will
	 * fail with EIO since we have z_unmount_lock for writer (only
	 * relavent for forced unmount).
	 *
	 * Release all holds on dbufs.
	 * Note, the dmu can still callback via znode_pageout_func()
	 * which can zfs_znode_free() the znode.  So we lock
	 * z_all_znodes; search the list for a held dbuf; drop the lock
	 * (we know zp can't disappear if we hold a dbuf lock) then
	 * regrab the lock and restart.
	 */
	mutex_enter(&zfsvfs->z_znodes_lock);
	for (zp = list_head(&zfsvfs->z_all_znodes); zp; zp = nextzp) {
		nextzp = list_next(&zfsvfs->z_all_znodes, zp);
		if (zp->z_dbuf_held) {
			/* dbufs should only be held when force unmounting */
			zp->z_dbuf_held = 0;
			mutex_exit(&zfsvfs->z_znodes_lock);
			dmu_buf_rele(zp->z_dbuf, NULL);
			/* Start again */
			mutex_enter(&zfsvfs->z_znodes_lock);
			nextzp = list_head(&zfsvfs->z_all_znodes);
		}
	}
	mutex_exit(&zfsvfs->z_znodes_lock);

	/*
	 * Set the unmounted flag and let new vops unblock.
	 * zfs_inactive will have the unmounted behavior, and all other
	 * vops will fail with EIO.
	 */
	zfsvfs->z_unmounted = B_TRUE;
	rw_exit(&zfsvfs->z_unmount_lock);
	rw_exit(&zfsvfs->z_unmount_inactive_lock);

	/*
	 * Unregister properties.
	 */
#ifndef __APPLE__
	if (!dmu_objset_is_snapshot(os))
		zfs_unregister_callbacks(zfsvfs);
#endif
	/*
	 * Close the zil. NB: Can't close the zil while zfs_inactive
	 * threads are blocked as zil_close can call zfs_inactive.
	 */
	if (zfsvfs->z_log) {
		zil_close(zfsvfs->z_log);
		zfsvfs->z_log = NULL;
	}

	/*
	 * Evict all dbufs so that cached znodes will be freed
	 */
	if (dmu_objset_evict_dbufs(os, B_TRUE)) {
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
		(void) dmu_objset_evict_dbufs(os, B_FALSE);
	}

	/*
	 * Finally close the objset
	 */
	dmu_objset_close(os);

	/*
	 * We can now safely destroy the '.zfs' directory node.
	 */
#if 0
	if (zfsvfs->z_ctldir != NULL)
		zfsctl_destroy(zfsvfs);
#endif

	/*
	 * Note that this work is normally done in zfs_freevfs, but since
	 * there is no VOP_FREEVFS in OSX, we free VFS items here
	 */
	OSDecrementAtomic((SInt32 *)&zfs_active_fs_count);
 	for (i = 0; i != ZFS_OBJ_MTX_SZ; i++)
 		mutex_destroy(&zfsvfs->z_hold_mtx[i]);
 
 	mutex_destroy(&zfsvfs->z_znodes_lock);
 	list_destroy(&zfsvfs->z_all_znodes);
 	rw_destroy(&zfsvfs->z_unmount_lock);
 	rw_destroy(&zfsvfs->z_unmount_inactive_lock);

	return (0);
}


 
struct vnode* vnode_getparent(struct vnode *vp);  /* sys/vnode_internal.h */

static int
zfs_vget_internal(zfsvfs_t *zfsvfs, ino64_t ino, struct vnode **vpp)
{
	struct vnode	*vp;
	struct vnode	*dvp = NULL;
	znode_t		*zp;
	int		error;

	*vpp = NULL;
	
	/*
	 * On Mac OS X we always export the root directory id as 2
	 * and its parent as 1
	 */
	if (ino == 2 || ino == 1)
		ino = zfsvfs->z_root;
	
	if ((error = zfs_zget(zfsvfs, ino, &zp)))
		goto out;

	/* Don't expose EA objects! */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		vnode_put(ZTOV(zp));
		error = ENOENT;
		goto out;
	}

	*vpp = vp = ZTOV(zp);

	if (vnode_isvroot(vp))
		goto out;

	/*
	 * If this znode didn't just come from the cache then
	 * it won't have a valid identity (parent and name).
	 *
	 * Manually fix its identity here (normally done by namei lookup).
	 */
	if ((dvp = vnode_getparent(vp)) == NULL) {
		if (zp->z_phys->zp_parent != 0 &&
		    zfs_vget_internal(zfsvfs, zp->z_phys->zp_parent, &dvp)) {
			goto out;
		}
		if ( vnode_isdir(dvp) ) {
			char objname[ZAP_MAXNAMELEN];  /* 256 bytes */
			int flags = VNODE_UPDATE_PARENT;

			/* Look for znode's name in its parent's zap */
			if ( zap_value_search(zfsvfs->z_os,
			                      zp->z_phys->zp_parent, 
			                      zp->z_id,
			                      ZFS_DIRENT_OBJ(-1ULL),
			                      objname) == 0 ) {
				flags |= VNODE_UPDATE_NAME;
			}

			/* Update the znode's parent and name */
			vnode_update_identity(vp, dvp, objname, 0, 0, flags);
		}
	}
	/* All done with znode's parent */
	vnode_put(dvp);
out:
	return (error);
}

/*
 * Get a vnode from a file id (ignoring the generation)
 *
 * Use by NFS Server (readdirplus) and VFS (build_path)
 */
static int
zfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	int error;

	ZFS_ENTER(zfsvfs);

	/*
	 * On Mac OS X we always export the root directory id as 2.
	 * So we don't expect to see the real root directory id
	 * from zfs_vfs_vget KPI (unless of course the real id was
	 * already 2).
	 */
	if ((ino == zfsvfs->z_root) && (zfsvfs->z_root != 2)) {
		ZFS_EXIT(zfsvfs);
		return (ENOENT);
	}
	error = zfs_vget_internal(zfsvfs, ino, vpp);

	ZFS_EXIT(zfsvfs);
	return (error);
}


static int
zfs_vfs_init(__unused struct vfsconf *vfsp)
{
	return (0);
}

static void
zfs_init(void)
{
	/*
	 * Initialize our context globals
	 */
	zfs_context_init();

	/*
	 * Initialize slab allocator and taskq layers
	 */
	kmem_init();

	/*
	 * Initialize .zfs directory structures
	 */
#if 0
	zfsctl_init();
#endif
	/*
	 * Initialize znode cache, vnode ops, etc...
	 */
	zfs_znode_init();

	/*
	 * Initialize /dev/zfs
	 */
	zfs_ioctl_init();
}

static void
zfs_fini(void)
{
	zfs_ioctl_fini();
#if 0
	zfsctl_fini();
#endif
	zfs_znode_fini();

	kmem_fini();

	zfs_context_fini();
}



static int
zfs_vfs_setattr(__unused struct mount *mp, __unused struct vfs_attr *fsap, __unused vfs_context_t context)
{
#ifdef ZFS_READONLY
	return (EROFS);
#else
	return (ENOTSUP);
#endif
}


/*
 * NFS Server File Handle File ID
 */
typedef struct zfs_zfid {
	uint8_t   zf_object[8];		/* obj[i] = obj >> (8 * i) */
	uint8_t   zf_gen[8];		/* gen[i] = gen >> (8 * i) */
} zfs_zfid_t;

/*
 * File handle to vnode pointer
 */
static int
zfs_vfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp,
               struct vnode **vpp, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	zfs_zfid_t	*zfid = (zfs_zfid_t *)fhp;
	znode_t		*zp;
	uint64_t	obj_num = 0;
	uint64_t	fid_gen = 0;
	uint64_t	zp_gen;
	int 		i;
	int		error;

	*vpp = NULL;

	ZFS_ENTER(zfsvfs);

	if (fhlen < sizeof (zfs_zfid_t)) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Grab the object and gen numbers in an endian neutral manner
	 */
	for (i = 0; i < sizeof (zfid->zf_object); i++)
		obj_num |= ((uint64_t)zfid->zf_object[i]) << (8 * i);
	
	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		fid_gen |= ((uint64_t)zfid->zf_gen[i]) << (8 * i);

	if ((error = zfs_zget(zfsvfs, obj_num, &zp))) {
		goto out;
	}

	zp_gen = zp->z_phys->zp_gen;
	if (zp_gen == 0)
		zp_gen = 1;

	if (zp->z_unlinked || zp_gen != fid_gen) {
		vnode_put(ZTOV(zp));
		error = EINVAL;
		goto out;
	}
	*vpp = ZTOV(zp);
out:
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Vnode pointer to File handle
 *
 * XXX Do we want to check the DSL sharenfs property?
 */
static int
zfs_vfs_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, __unused vfs_context_t context)
{
	zfsvfs_t	*zfsvfs = vfs_fsprivate(vnode_mount(vp));
	zfs_zfid_t	*zfid = (zfs_zfid_t *)fhp;
	znode_t		*zp = VTOZ(vp);
	uint64_t	obj_num;
	uint64_t	zp_gen;
	int		i;
	int		error;

	if (*fhlenp < sizeof (zfs_zfid_t)) {
		return (EOVERFLOW);
	}

	ZFS_ENTER(zfsvfs);

	obj_num = zp->z_id;
	zp_gen = zp->z_phys->zp_gen;
	if (zp_gen == 0)
		zp_gen = 1;

	/*
	 * Store the object and gen numbers in an endian neutral manner
	 */
	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(obj_num >> (8 * i));

	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = (uint8_t)(zp_gen >> (8 * i));

	*fhlenp = sizeof (zfs_zfid_t);

	ZFS_EXIT(zfsvfs);
	return (0);
}


static int
zfs_vfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp, 
               user_addr_t newp, size_t newlen, __unused vfs_context_t context)
{
	int error;

	switch(name[0]) {
	case ZFS_SYSCTL_FOOTPRINT: {
		zfs_footprint_stats_t *footprint;
		size_t copyinsize;
		size_t copyoutsize;
		int max_caches;
		int act_caches;

		if (newp) {
			return (EINVAL);
		}
		if (!oldp) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (0);
		}
		copyinsize = *oldlenp;
		if (copyinsize < sizeof (zfs_footprint_stats_t)) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (ENOMEM);
		}
		footprint = kmem_alloc(copyinsize, KM_SLEEP);

		max_caches = copyinsize - sizeof (zfs_footprint_stats_t);
		max_caches += sizeof (kmem_cache_stats_t);
		max_caches /= sizeof (kmem_cache_stats_t);

		footprint->version = ZFS_FOOTPRINT_VERSION;

		footprint->memory_stats.current = zfs_footprint.current;
		footprint->memory_stats.target = zfs_footprint.target;
		footprint->memory_stats.highest = zfs_footprint.highest;
		footprint->memory_stats.maximum = zfs_footprint.maximum;

		arc_get_stats(&footprint->arc_stats);

		kmem_cache_stats(&footprint->cache_stats[0], max_caches, &act_caches);
		footprint->caches_count = act_caches;
		footprint->thread_count = zfs_threads;

		copyoutsize = sizeof (zfs_footprint_stats_t) +
		              ((act_caches - 1) * sizeof (kmem_cache_stats_t));

		error = copyout(footprint, oldp, copyoutsize);

		kmem_free(footprint, copyinsize);

		return (error);
	    }

#ifdef ZFS_READONLY
	case ZFS_SYSCTL_READONLY: {
		int rdonly = 1;
		/*
		 * Inform user commands that zfs file systems are read-only
		 */
		error = copyout(&rdonly, oldp, sizeof (rdonly));
		return (error);
	    }
#endif /* ZFS_READONLY */

	case ZFS_SYSCTL_CONFIG_DEBUGMSG:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_msg_buf_enabled);
		return error;

	case ZFS_SYSCTL_CONFIG_DPRINTF:
#ifdef ZFS_DEBUG
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_dprintf_enabled);
#else
		error = ENOTSUP;
#endif
		return error;
	}

	return (ENOTSUP);
}

static int
zfs_vfs_quotactl(__unused struct mount *mp, __unused int cmds, __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
	return (ENOTSUP);
}

static int
zfs_vfs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{
	return (0);
}

int
zfs_module_start(__unused kmod_info_t *ki, __unused void *data)
{
	struct vfs_fsentry vfe;

#ifdef ZFS_READONLY
	printf("zfs: read-only implementation loaded\n");
#endif

	zfs_init();

	printf("zfs_module_start: memory footprint %d (kalloc %d, kernel %d)\n",
		zfs_footprint.current, zfs_kallocmap_size, zfs_kernelmap_size);
	
	vfe.vfe_vfsops = &zfs_vfsops_template;
	vfe.vfe_vopcnt = ZFS_VNOP_TBL_CNT;
	vfe.vfe_opvdescs = zfs_vnodeop_opv_desc_list;
#if 1
	strcpy(vfe.vfe_fsname, "zfs");
#else
	strlcpy(vfe.vfe_fsname, "zfs", sizeof(vfe.vfe_fsname));
#endif
	/*
	 * Note: must set VFS_TBLGENERICMNTARGS with VFS_TBLLOCALVOL
	 * to suppress local mount argument handling.
	 */
	vfe.vfe_flags = VFS_TBLTHREADSAFE |
	                VFS_TBLNOTYPENUM |
	                VFS_TBLLOCALVOL |
	                VFS_TBL64BITREADY |
	                VFS_TBLNATIVEXATTR |
	                VFS_TBLGENERICMNTARGS|
			VFS_TBLREADDIR_EXTENDED;
	vfe.vfe_reserv[0] = 0;
	vfe.vfe_reserv[1] = 0;
	
	if (vfs_fsadd(&vfe, &zfs_vfsconf) != 0)
		return KERN_FAILURE;
	else
		return KERN_SUCCESS;
}

int  
zfs_module_stop(__unused kmod_info_t *ki, __unused void *data)
{
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    zvol_busy() ||
	    vfs_fsremove(zfs_vfsconf) != 0) {
		return KERN_FAILURE;   /* ZFS Still busy! */
	}
	zfs_fini();

	printf("zfs_module_stop: memory footprint %d (kalloc %d, kernel %d)\n",
		zfs_footprint.current, zfs_kallocmap_size, zfs_kernelmap_size);
	
	return KERN_SUCCESS;
}

int
zfs_busy(void)
{
	return (zfs_active_fs_count != 0);
}

int
zfs_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	uint64_t val;

	error = zap_lookup(os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1, &val);
	if (error == 0)
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VERSION, val);

	return (error);
}

int
zfs_set_version(const char *name, uint64_t newvers)
{
	int error;
	objset_t *os;
	dmu_tx_t *tx;
	uint64_t curvers;

	/*
	 * XXX for now, require that the filesystem be unmounted.  Would
	 * be nice to find the zfsvfs_t and just update that if
	 * possible.
	 */

	if (newvers < ZPL_VERSION_INITIAL || newvers > ZPL_VERSION)
		return (EINVAL);

	error = dmu_objset_open(name, DMU_OST_ZFS, DS_MODE_PRIMARY, &os);
	if (error)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZPL_VERSION_STR,
	    8, 1, &curvers);
	if (error)
		goto out;
	if (newvers < curvers) {
		error = EINVAL;
		goto out;
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, 0, ZPL_VERSION_STR);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		goto out;
	}
	error = zap_update(os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
	    &newvers, tx);

	spa_history_internal_log(LOG_DS_UPGRADE,
	    dmu_objset_spa(os), tx, CRED(),
	    "oldver=%llu newver=%llu dataset = %llu", curvers, newvers,
	    dmu_objset_id(os));
	dmu_tx_commit(tx);

out:
	dmu_objset_close(os);
	return (error);
}
