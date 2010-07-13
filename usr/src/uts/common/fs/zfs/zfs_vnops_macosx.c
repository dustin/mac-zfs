/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/attr.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/utfconv.h>
#include <sys/xattr.h>

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_dir.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/dirent.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_rlock.h>

#include <libkern/OSByteOrder.h>


/*
 * Mac OS X / Darwin specific vnode operations.
 * Provides support for HFS Plus file system APIs:
 *	searchfs(2)
 *	getdirentriesattr(2)
 */


/*
 * Account for user timespec structure differences
 */
#ifdef ZFS_LEOPARD_ONLY
typedef struct timespec		timespec_user32_t;
typedef struct user_timespec	timespec_user64_t;
#else
typedef struct user32_timespec	timespec_user32_t;
typedef struct user64_timespec	timespec_user64_t;
#endif

#define UNKNOWNUID ((uid_t)99)

#define DTTOVT(dtype)	(iftovt_tab[(dtype)])

#define kTextEncodingMacUnicode	0x7e

#define ZAP_AVENAMELEN	(ZAP_MAXNAMELEN / 4)


/* Finder information */
struct finderinfo {
	u_int32_t  fi_type;        /* files only */
	u_int32_t  fi_creator;     /* files only */
	u_int16_t  fi_flags;
	struct {
		int16_t  v;
		int16_t  h;
	} fi_location;
	int8_t  fi_opaque[18];
} __attribute__((aligned(2), packed));
typedef struct finderinfo finderinfo_t;

enum {
	/* Finder Flags */
	kHasBeenInited		= 0x0100,
	kHasCustomIcon		= 0x0400,
	kIsStationery		= 0x0800,
	kNameLocked		= 0x1000,
	kHasBundle		= 0x2000,
	kIsInvisible		= 0x4000,
	kIsAlias		= 0x8000
};

/* Attribute packing information */
typedef struct attrinfo {
	struct attrlist * ai_attrlist;
	void **		  ai_attrbufpp;
	void **		  ai_varbufpp;
	void *		  ai_varbufend;
	vfs_context_t	  ai_context;
} attrinfo_t;

/*
 * Attributes that we can get for free from the zap (ie without a znode)
 */
#define ZFS_DIR_ENT_ATTRS (					\
	ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID |	\
	ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |	\
	ATTR_CMN_OBJPERMANENTID | ATTR_CMN_SCRIPT |		\
	ATTR_CMN_FILEID )

/*
 * Attributes that we support
 */
#define ZFS_ATTR_BIT_MAP_COUNT	5

#define ZFS_ATTR_CMN_VALID (					\
	ATTR_CMN_NAME | ATTR_CMN_DEVID	| ATTR_CMN_FSID |	\
	ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |	\
	ATTR_CMN_OBJPERMANENTID | ATTR_CMN_PAROBJID |		\
	ATTR_CMN_SCRIPT | ATTR_CMN_CRTIME | ATTR_CMN_MODTIME |	\
	ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME |			\
	ATTR_CMN_BKUPTIME | ATTR_CMN_FNDRINFO |			\
	ATTR_CMN_OWNERID | ATTR_CMN_GRPID |			\
	ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS |			\
	ATTR_CMN_USERACCESS | ATTR_CMN_FILEID |			\
	ATTR_CMN_PARENTID )

#define ZFS_ATTR_DIR_VALID (				\
	ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT |	\
	ATTR_DIR_MOUNTSTATUS)

#define ZFS_ATTR_FILE_VALID (				 \
	ATTR_FILE_LINKCOUNT |ATTR_FILE_TOTALSIZE |	 \
	ATTR_FILE_ALLOCSIZE | ATTR_FILE_IOBLOCKSIZE |	 \
	ATTR_FILE_DEVTYPE | ATTR_FILE_DATALENGTH |	 \
	ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_RSRCLENGTH | \
	ATTR_FILE_RSRCALLOCSIZE)

int zfs_vnop_readdirattr(struct vnop_readdirattr_args *ap);


static void  commonattrpack(attrinfo_t *aip, zfsvfs_t *zfsvfs, znode_t *zp,
                            const char *name, ino64_t objnum, enum vtype vtype,
                            boolean_t user64);
static void  dirattrpack(attrinfo_t *aip, znode_t *zp);
static void  fileattrpack(attrinfo_t *aip, zfsvfs_t *zfsvfs, znode_t *zp);
static void  nameattrpack(attrinfo_t *aip, const char *name, int namelen);
static int   getpackedsize(struct attrlist *alp, boolean_t user64);
static void  getfinderinfo(znode_t *zp, znode_phys_t *pzp, cred_t *cr,
                           finderinfo_t *fip);
static u_int32_t  getuseraccess(znode_t *zp, vfs_context_t ctx);


/*
 * ZFS support for Mac OS X getdirentriesattr(2) API
 */
int
zfs_vnop_readdirattr(struct vnop_readdirattr_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	struct attrlist	*alp = ap->a_alist;
	struct uio	*uio = ap->a_uio;
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	attrinfo_t	attrinfo;
	int		maxcount = ap->a_maxcount;
	uint64_t	offset = (uint64_t)uio_offset(uio);
	u_int32_t	fixedsize;
	u_int32_t	defaultvariablesize;
	u_int32_t	maxsize;
	u_int32_t	attrbufsize;
	void		*attrbufptr = NULL;
	void		*attrptr;
	void		*varptr;  /* variable-length storage area */
	boolean_t	user64 = vfs_context_is64bit(ap->a_context);
	int		prefetch = 0;
	int		error = 0;

	*(ap->a_actualcount) = 0;
	*(ap->a_eofflag) = 0;

	/*
	 * Check for invalid options or invalid uio.
	 */
	if (((ap->a_options & ~(FSOPT_NOINMEMUPDATE | FSOPT_NOFOLLOW)) != 0) ||
	    (uio_resid(uio) <= 0) || (maxcount <= 0)) {
		return (EINVAL);
	}
	/*
	 * Reject requests for unsupported attributes.
	 */
	if ( (alp->bitmapcount != ZFS_ATTR_BIT_MAP_COUNT) ||
	     (alp->commonattr & ~ZFS_ATTR_CMN_VALID) ||
	     (alp->dirattr & ~ZFS_ATTR_DIR_VALID) ||
	     (alp->fileattr & ~ZFS_ATTR_FILE_VALID) ||
	     (alp->volattr != 0 || alp->forkattr != 0) ) {
		return (EINVAL);
	}
	/*
	 * Check if we should prefetch znodes
	 */
	if ((alp->commonattr & ~ZFS_DIR_ENT_ATTRS) ||
	     (alp->dirattr != 0) || (alp->fileattr != 0)) {
		prefetch = TRUE;
	}
	/*
	 * Setup a buffer to hold the packed attributes.
	 */
	fixedsize = sizeof(u_int32_t) + getpackedsize(alp, user64);
	maxsize = fixedsize;
	if (alp->commonattr & ATTR_CMN_NAME) 
		maxsize += ZAP_MAXNAMELEN + 1;
	MALLOC(attrbufptr, void *, maxsize, M_TEMP, M_WAITOK);
	if (attrbufptr == NULL) {
		return (ENOMEM);
	}
	attrptr = attrbufptr;
	varptr = (char *)attrbufptr + fixedsize;

	attrinfo.ai_attrlist = alp;
	attrinfo.ai_varbufend = (char *)attrbufptr + maxsize;
	attrinfo.ai_context = ap->a_context;

	ZFS_ENTER(zfsvfs);

	/*
	 * Initialize the zap iterator cursor.
	 */
	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, zfsvfs->z_os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, zfsvfs->z_os, zp->z_id, offset);
	}

	while (1) {
		ino64_t objnum;
		enum vtype vtype = VNON;
		znode_t *tmp_zp = NULL;

		/*
		 * Note that the low 4 bits of the cookie returned by zap is 
		 * always zero. This allows us to use the low nibble for 
		 * "special" entries:
		 * We use 0 for '.', and 1 for '..' (ignored here).
		 * If this is the root of the filesystem, we use the offset 2 
		 * for the *'.zfs' directory.
		 */
		if (offset <= 1) {
			offset = 2;
			continue;
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strcpy(zap.za_name, ZFS_CTLDIR_NAME);
			objnum = ZFSCTL_INO_ROOT;
			vtype = VDIR;
		} else {
			/*
			 * Grab next entry.
			 */
			if (error = zap_cursor_retrieve(&zc, &zap)) {
				*(ap->a_eofflag) = (error == ENOENT);
					goto update;
			}

			if (zap.za_integer_length != 8 ||
			    zap.za_num_integers != 1) {
				error = ENXIO;
				goto update;
			}

			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
			vtype = DTTOVT(ZFS_DIRENT_TYPE(zap.za_first_integer));
			/* Check if vtype is MIA */
			if ((vtype == 0) && !prefetch &&
			    (alp->dirattr || alp->fileattr ||
			     (alp->commonattr & ATTR_CMN_OBJTYPE))) {
				prefetch = 1;
			}
		}

		/*
		 * Setup for the next item's attribute list
		 */
		*((u_int32_t *)attrptr) = 0;           /* byte count slot */
		attrptr = ((u_int32_t *)attrptr) + 1;  /* fixed attr start */
		attrinfo.ai_attrbufpp = &attrptr;
		attrinfo.ai_varbufpp = &varptr;

		/* Grab znode if required */
		if (prefetch) {
			dmu_prefetch(zfsvfs->z_os, objnum, 0, 0);
			if (zfs_zget(zfsvfs, objnum, &tmp_zp) == 0) {
				if (vtype == VNON)
					vtype = IFTOVT(tmp_zp->z_phys->zp_mode);
			} else {
				tmp_zp = NULL;
				error = ENXIO;
				goto update;
			}
		}
		/*
		 * Pack entries into attribute buffer.
		 */
		if (alp->commonattr) {
			commonattrpack(&attrinfo, zfsvfs, tmp_zp, zap.za_name,
			               objnum, vtype, user64);
		}
		if (alp->dirattr && vtype == VDIR) {
			dirattrpack(&attrinfo, tmp_zp);
		}
		if (alp->fileattr && vtype != VDIR) {
			fileattrpack(&attrinfo, zfsvfs, tmp_zp);
		}
		/* All done with tmp znode. */
		if (prefetch && tmp_zp) {
			vnode_put(ZTOV(tmp_zp));
			tmp_zp = NULL;
		}
		attrbufsize = ((char *)varptr - (char *)attrbufptr);

		/*
		 * Make sure there's enough buffer space remaining.
		 */
		if (uio_resid(uio) < 0 ||
		    attrbufsize > (u_int32_t)uio_resid(uio)) {
			break;
		} else {
			*((u_int32_t *)attrbufptr) = attrbufsize;
			error = uiomove((caddr_t)attrbufptr, attrbufsize, uio);
			if (error != 0) {
				break;
			}
			attrptr = attrbufptr;
			/* Point to variable-length storage */
			varptr = (char *)attrbufptr + fixedsize; 
			*(ap->a_actualcount) += 1;
	
			/*
			 * Move to the next entry, fill in the previous offset.
			 */
			if ((offset > 2) ||
			    (offset == 2 && !zfs_show_ctldir(zp))) {
				zap_cursor_advance(&zc);
				offset = zap_cursor_serialize(&zc);
			} else {
				offset += 1;
			}

			/* Termination checks */
			if ((--maxcount <= 0) ||
			    uio_resid(uio) < 0 ||
			    ((u_int32_t)uio_resid(uio) <
			     (fixedsize + ZAP_AVENAMELEN))) {
				break;
			}
		}
	}
update:
	zap_cursor_fini(&zc);

	if (attrbufptr) {
		FREE(attrbufptr, M_TEMP);
	}
	if (error == ENOENT) {
		error = 0;
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/* XXX newstate TBD */
	*ap->a_newstate = zp->z_phys->zp_mtime[0] + zp->z_phys->zp_mtime[1];
	uio_setoffset(uio, offset);

	ZFS_EXIT(zfsvfs);

	return (error);
}


static void
commonattrpack(attrinfo_t *aip, zfsvfs_t *zfsvfs, znode_t *zp, const char *name,
               ino64_t objnum, enum vtype vtype, boolean_t user64)
{
	attrgroup_t commonattr = aip->ai_attrlist->commonattr;
	void *attrbufptr = *aip->ai_attrbufpp;
	void *varbufptr = *aip->ai_varbufpp;
	znode_phys_t *pzp = zp ? zp->z_phys : NULL;
	struct mount *mp = zfsvfs->z_vfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(aip->ai_context);
	finderinfo_t finderinfo;

	finderinfo.fi_flags = 0;
	
	if (ATTR_CMN_NAME & commonattr) {
		nameattrpack(aip, name, strlen(name));
		attrbufptr = *aip->ai_attrbufpp;
		varbufptr = *aip->ai_varbufpp;
	}
	if (ATTR_CMN_DEVID & commonattr) {
		*((dev_t *)attrbufptr) = vfs_statfs(mp)->f_fsid.val[0];
		attrbufptr = ((dev_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_FSID & commonattr) {
		*((fsid_t *)attrbufptr) = vfs_statfs(mp)->f_fsid;
		attrbufptr = ((fsid_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_OBJTYPE & commonattr) {
		*((fsobj_type_t *)attrbufptr) = vtype;
		attrbufptr = ((fsobj_type_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_OBJTAG & commonattr) {
		*((fsobj_tag_t *)attrbufptr) = VT_ZFS;
		attrbufptr = ((fsobj_tag_t *)attrbufptr) + 1;
	}
	/*
	 * Note: ATTR_CMN_OBJID is lossy (only 32 bits).
	 */
	if ((ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID) & commonattr) {
		u_int32_t fileid;
		/*
		 * On Mac OS X we always export the root directory id as 2
		 */
		fileid = (objnum == zfsvfs->z_root) ? 2 : objnum;

		if (ATTR_CMN_OBJID & commonattr) {
			((fsobj_id_t *)attrbufptr)->fid_objno = fileid;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			attrbufptr = ((fsobj_id_t *)attrbufptr) + 1;
		}
		if (ATTR_CMN_OBJPERMANENTID & commonattr) {
			((fsobj_id_t *)attrbufptr)->fid_objno = fileid;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			attrbufptr = ((fsobj_id_t *)attrbufptr) + 1;
		}
	}
	/*
	 * Note: ATTR_CMN_PAROBJID is lossy (only 32 bits).
	 */
	if (ATTR_CMN_PAROBJID & commonattr) {
		u_int32_t parentid;

		/*
		 * On Mac OS X we always export the root
		 * directory id as 2 and its parent as 1
		 */
		if (zp && zp->z_id == zfsvfs->z_root)
			parentid = 1;
		else if (pzp && pzp->zp_parent == zfsvfs->z_root)
			parentid = 2;
		else
			parentid = pzp ? pzp->zp_parent : 0;
		ASSERT(parentid != 0);
		
		((fsobj_id_t *)attrbufptr)->fid_objno = parentid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		attrbufptr = ((fsobj_id_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_SCRIPT & commonattr) {
		*((text_encoding_t *)attrbufptr) = kTextEncodingMacUnicode; 
		attrbufptr = ((text_encoding_t *)attrbufptr) + 1;
	}
	if (pzp && ATTR_CMN_CRTIME & commonattr) {
		if (user64) {
			ZFS_TIME_DECODE((timespec_user64_t *)attrbufptr,
			                pzp->zp_crtime);
			attrbufptr = ((timespec_user64_t *)attrbufptr) + 1;
		} else {
			ZFS_TIME_DECODE((timespec_user32_t *)attrbufptr,
			                pzp->zp_crtime);
			attrbufptr = ((timespec_user32_t *)attrbufptr) + 1;
		}
	}
	if (pzp && ATTR_CMN_MODTIME & commonattr) {
		if (user64) {
			ZFS_TIME_DECODE((timespec_user64_t *)attrbufptr,
			                pzp->zp_mtime);
			attrbufptr = ((timespec_user64_t *)attrbufptr) + 1;
		} else {
			ZFS_TIME_DECODE((timespec_user32_t *)attrbufptr,
			                pzp->zp_mtime);
			attrbufptr = ((timespec_user32_t *)attrbufptr) + 1;
		}
	}
	if (pzp && ATTR_CMN_CHGTIME & commonattr) {
		if (user64) {
			ZFS_TIME_DECODE((timespec_user64_t *)attrbufptr,
			                pzp->zp_ctime);
			attrbufptr = ((timespec_user64_t *)attrbufptr) + 1;
		} else {
			ZFS_TIME_DECODE((timespec_user32_t *)attrbufptr,
			                pzp->zp_ctime);
			attrbufptr = ((timespec_user32_t *)attrbufptr) + 1;
		}
	}
	if (pzp && ATTR_CMN_ACCTIME & commonattr) {
		if (user64) {
			ZFS_TIME_DECODE((timespec_user64_t *)attrbufptr,
			                pzp->zp_atime);
			attrbufptr = ((timespec_user64_t *)attrbufptr) + 1;
		} else {
			ZFS_TIME_DECODE((timespec_user32_t *)attrbufptr,
			                pzp->zp_atime);
			attrbufptr = ((timespec_user32_t *)attrbufptr) + 1;
		}
	}
	if (pzp && ATTR_CMN_BKUPTIME & commonattr) {
		/* legacy attribute -- just pass zero */
		if (user64) {
			((timespec_user64_t *)attrbufptr)->tv_sec = 0;
			((timespec_user64_t *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((timespec_user64_t *)attrbufptr) + 1;
		}  else {
			((timespec_user32_t *)attrbufptr)->tv_sec = 0;
			((timespec_user32_t *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((timespec_user32_t *)attrbufptr) + 1;
		}
	}
	if (pzp && ATTR_CMN_FNDRINFO & commonattr) {
		getfinderinfo(zp, pzp, cr, &finderinfo);
		/* Shadow ZFS_HIDDEN to Finder Info's invisible bit */
		if (pzp && pzp->zp_flags & ZFS_HIDDEN) {
			finderinfo.fi_flags |=
				OSSwapHostToBigConstInt16(kIsInvisible);
		}
		bcopy(&finderinfo, attrbufptr, sizeof (finderinfo));
		attrbufptr = (char *)attrbufptr + 32;
	}
	if (pzp && ATTR_CMN_OWNERID & commonattr) {
		*((uid_t *)attrbufptr) = pzp->zp_uid;
		attrbufptr = ((uid_t *)attrbufptr) + 1;
	}
	if (pzp && ATTR_CMN_GRPID & commonattr) {
		*((gid_t *)attrbufptr) = pzp->zp_gid;
		attrbufptr = ((gid_t *)attrbufptr) + 1;
	}
	if (pzp && ATTR_CMN_ACCESSMASK & commonattr) {
		*((u_int32_t *)attrbufptr) = pzp->zp_mode;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_FLAGS & commonattr) {
		u_int32_t flags = zfs_getbsdflags(zp);

		/* Shadow Finder Info's invisible bit to UF_HIDDEN */
		if ((ATTR_CMN_FNDRINFO & commonattr) &&
		    (OSSwapBigToHostInt16(finderinfo.fi_flags) & kIsInvisible))
			flags |= UF_HIDDEN;

		*((u_int32_t *)attrbufptr) = flags;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_USERACCESS & commonattr) {
		u_int32_t user_access = 0;

		user_access = getuseraccess(zp, aip->ai_context);

		/* Also consider READ-ONLY file system. */
		if (vfs_flags(mp) & MNT_RDONLY) {
			user_access &= ~W_OK;
		}
		/* Locked objects are not writable either */
		if (pzp && (pzp->zp_flags & ZFS_IMMUTABLE) &&
		    (vfs_context_suser(aip->ai_context) != 0)) {
			user_access &= ~W_OK;
		}

		*((u_int32_t *)attrbufptr) = user_access;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_FILEID & commonattr) {
		/*
		 * On Mac OS X we always export the root directory id as 2
		 */
		if (objnum == zfsvfs->z_root)
			objnum = 2;

		*((u_int64_t *)attrbufptr) = objnum;
		attrbufptr = ((u_int64_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_PARENTID & commonattr) {
		u_int64_t parentid;

		/*
		 * On Mac OS X we always export the root
		 * directory id as 2 and its parent as 1
		 */
		if (zp && zp->z_id == zfsvfs->z_root)
			parentid = 1;
		else if (pzp && pzp->zp_parent == zfsvfs->z_root)
			parentid = 2;
		else
			parentid = pzp ? pzp->zp_parent : 0;
		ASSERT(parentid != 0);
		
		*((u_int64_t *)attrbufptr) = parentid;
		attrbufptr = ((u_int64_t *)attrbufptr) + 1;
	}
	
	*aip->ai_attrbufpp = attrbufptr;
	*aip->ai_varbufpp = varbufptr;
}

static void
dirattrpack(attrinfo_t *aip, znode_t *zp)
{
	attrgroup_t dirattr = aip->ai_attrlist->dirattr;
	void *attrbufptr = *aip->ai_attrbufpp;
	znode_phys_t *pzp = zp ? zp->z_phys : NULL;
	u_int32_t entries;

	if (ATTR_DIR_LINKCOUNT & dirattr) {
		*((u_int32_t *)attrbufptr) = 1;  /* no dir hard links */
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_DIR_ENTRYCOUNT & dirattr && pzp) {
		*((u_int32_t *)attrbufptr) = pzp->zp_size;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_DIR_MOUNTSTATUS & dirattr && zp) {
		struct vnode *vp = ZTOV(zp);

		if (vp != NULL && vnode_mountedhere(vp) != NULL)
			*((u_int32_t *)attrbufptr) = DIR_MNTSTATUS_MNTPOINT;
		else
			*((u_int32_t *)attrbufptr) = 0;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	*aip->ai_attrbufpp = attrbufptr;
}

static void
fileattrpack(attrinfo_t *aip, zfsvfs_t *zfsvfs, znode_t *zp)
{
	attrgroup_t fileattr = aip->ai_attrlist->fileattr;
	void *attrbufptr = *aip->ai_attrbufpp;
	void *varbufptr = *aip->ai_varbufpp;
	znode_phys_t *pzp = zp ? zp->z_phys : NULL;
	uint64_t allocsize = 0;
	cred_t  *cr = (cred_t *)vfs_context_ucred(aip->ai_context);

	if ((ATTR_FILE_ALLOCSIZE | ATTR_FILE_DATAALLOCSIZE) & fileattr && zp) {
		uint32_t  blksize;
		u_longlong_t  nblks;

		dmu_object_size_from_db(zp->z_dbuf, &blksize, &nblks);
		allocsize = (uint64_t)512LL * (uint64_t)nblks;
	}
	if (ATTR_FILE_LINKCOUNT & fileattr && pzp) {
		*((u_int32_t *)attrbufptr) = pzp->zp_links;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_TOTALSIZE & fileattr && pzp) {
		*((off_t *)attrbufptr) = pzp->zp_size;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_ALLOCSIZE & fileattr) {
		*((off_t *)attrbufptr) = allocsize;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_IOBLOCKSIZE & fileattr && zp) {
		*((u_int32_t *)attrbufptr) =
				zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_DEVTYPE & fileattr && pzp) {
		if (S_ISBLK(pzp->zp_mode) || S_ISCHR(pzp->zp_mode))
			*((u_int32_t *)attrbufptr) = (u_int32_t)pzp->zp_rdev;
		else
			*((u_int32_t *)attrbufptr) = 0;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_DATALENGTH & fileattr && pzp) {
		*((off_t *)attrbufptr) = pzp->zp_size;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_DATAALLOCSIZE & fileattr) {
		*((off_t *)attrbufptr) = allocsize;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	if ((ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE) & fileattr && pzp) {
		uint64_t rsrcsize = 0;

		if (pzp->zp_xattr) {
			struct vnode  *xdvp = NULLVP;
			struct vnode  *xvp = NULLVP;
			struct componentname  cn;

			bzero(&cn, sizeof (cn));
			cn.cn_nameiop = LOOKUP;
			cn.cn_flags = ISLASTCN;
			cn.cn_nameptr = XATTR_RESOURCEFORK_NAME;
			cn.cn_namelen = strlen(cn.cn_nameptr);

			/* Grab the hidden attribute directory vnode. */
			if (zfs_get_xattrdir(zp, &xdvp, cr, 0) == 0 &&
			    zfs_dirlook(VTOZ(xdvp), &cn, &xvp) == 0) {
				rsrcsize = VTOZ(xvp)->z_phys->zp_size;
			}
			if (xvp)
				vnode_put(xvp);
			if (xdvp)
				vnode_put(xdvp);
		}
		if (ATTR_FILE_RSRCLENGTH & fileattr) {
			*((off_t *)attrbufptr) = rsrcsize;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
		if (ATTR_FILE_RSRCALLOCSIZE & fileattr) {
			*((off_t *)attrbufptr) = roundup(rsrcsize, 512);
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
	}
	*aip->ai_attrbufpp = attrbufptr;
	*aip->ai_varbufpp = varbufptr;
}

static void
nameattrpack(attrinfo_t *aip, const char *name, int namelen)
{
	void *varbufptr;
	struct attrreference * attr_refptr;
	u_int32_t attrlen;
	size_t nfdlen, freespace;

	varbufptr = *aip->ai_varbufpp;
	attr_refptr = (struct attrreference *)(*aip->ai_attrbufpp);

	freespace = (char*)aip->ai_varbufend - (char*)varbufptr;
	/*
	 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
	 * so convert to NFD before exporting them.
	 */
	namelen = strlen(name);
	if (is_ascii_str(name) ||
	    utf8_normalizestr((const u_int8_t *)name, namelen,
			      (u_int8_t *)varbufptr, &nfdlen,
			      freespace, UTF_DECOMPOSED) != 0) {
		/* ASCII or normalization failed, just copy zap name. */
		strncpy((char *)varbufptr, name, MIN(freespace, namelen+1));
	} else {
		/* Normalization succeeded (already in buffer). */
		namelen = nfdlen;
	}
	attrlen = namelen + 1;
	attr_refptr->attr_dataoffset = (char *)varbufptr - (char *)attr_refptr;
	attr_refptr->attr_length = attrlen;
	/*
	 * Advance beyond the space just allocated and
	 * round up to the next 4-byte boundary:
	 */
	varbufptr = ((char *)varbufptr) + attrlen + ((4 - (attrlen & 3)) & 3);
	++attr_refptr;

	*aip->ai_attrbufpp = attr_refptr;
	*aip->ai_varbufpp = varbufptr;
}

static int
getpackedsize(struct attrlist *alp, boolean_t user64)
{
	attrgroup_t attrs;
	int timespecsize;
	int size = 0;

	timespecsize = user64 ? sizeof(timespec_user64_t) :
	                        sizeof(timespec_user32_t);

	if ((attrs = alp->commonattr) != 0) {
		if (attrs & ATTR_CMN_NAME)
			size += sizeof(struct attrreference);
		if (attrs & ATTR_CMN_DEVID)
			size += sizeof(dev_t);
		if (attrs & ATTR_CMN_FSID)
			size += sizeof(fsid_t);
		if (attrs & ATTR_CMN_OBJTYPE)
			size += sizeof(fsobj_type_t);
		if (attrs & ATTR_CMN_OBJTAG)
			size += sizeof(fsobj_tag_t);
		if (attrs & ATTR_CMN_OBJID)
			size += sizeof(fsobj_id_t);
		if (attrs & ATTR_CMN_OBJPERMANENTID)
			size += sizeof(fsobj_id_t);
		if (attrs & ATTR_CMN_PAROBJID)
			size += sizeof(fsobj_id_t);
		if (attrs & ATTR_CMN_SCRIPT)
			size += sizeof(text_encoding_t);
		if (attrs & ATTR_CMN_CRTIME)
			size += timespecsize;
		if (attrs & ATTR_CMN_MODTIME)
			size += timespecsize;
		if (attrs & ATTR_CMN_CHGTIME)
			size += timespecsize;
		if (attrs & ATTR_CMN_ACCTIME)
			size += timespecsize;
		if (attrs & ATTR_CMN_BKUPTIME)
			size += timespecsize;
		if (attrs & ATTR_CMN_FNDRINFO)
			size += 32 * sizeof(u_int8_t);
		if (attrs & ATTR_CMN_OWNERID)
			size += sizeof(uid_t);
		if (attrs & ATTR_CMN_GRPID)
			size += sizeof(gid_t);
		if (attrs & ATTR_CMN_ACCESSMASK)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_CMN_FLAGS)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_CMN_USERACCESS)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_CMN_FILEID)
			size += sizeof(u_int64_t);
		if (attrs & ATTR_CMN_PARENTID)
			size += sizeof(u_int64_t);
	}
	if ((attrs = alp->dirattr) != 0) {
		if (attrs & ATTR_DIR_LINKCOUNT)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_DIR_ENTRYCOUNT)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_DIR_MOUNTSTATUS)
			size += sizeof(u_int32_t);
	}
	if ((attrs = alp->fileattr) != 0) {
		if (attrs & ATTR_FILE_LINKCOUNT)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_FILE_TOTALSIZE)
			size += sizeof(off_t);
		if (attrs & ATTR_FILE_ALLOCSIZE)
			size += sizeof(off_t);
		if (attrs & ATTR_FILE_IOBLOCKSIZE)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_FILE_DEVTYPE)
			size += sizeof(u_int32_t);
		if (attrs & ATTR_FILE_DATALENGTH)
			size += sizeof(off_t);
		if (attrs & ATTR_FILE_DATAALLOCSIZE)
			size += sizeof(off_t);
		if (attrs & ATTR_FILE_RSRCLENGTH)
			size += sizeof(off_t);
		if (attrs & ATTR_FILE_RSRCALLOCSIZE)
			size += sizeof(off_t);
	}
	return (size);
}

static void
getfinderinfo(znode_t *zp, znode_phys_t *pzp, cred_t *cr, finderinfo_t *fip)
{
	struct vnode	*xdvp = NULLVP;
	struct vnode	*xvp = NULLVP;
	uio_t		auio = NULL;
	struct componentname  cn;
	int		error;

	if (pzp->zp_xattr == 0) {
		goto nodata;
	}
	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	if (auio == NULL) {
		goto nodata;
	}
	uio_addiov(auio, CAST_USER_ADDR_T(fip), sizeof (finderinfo_t));

	/*
	 * Grab the hidden attribute directory vnode.
	 *
	 * XXX - switch to embedded Finder Info when it becomes available
	 */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = XATTR_FINDERINFO_NAME;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	if ((error = zfs_dirlook(VTOZ(xdvp), &cn, &xvp))) {
		goto out;
	}
	error = dmu_read_uio(zp->z_zfsvfs->z_os, VTOZ(xvp)->z_id, auio,
	                     sizeof (finderinfo_t));
out:
	if (auio)
		uio_free(auio);
	if (xvp)
		vnode_put(xvp);
	if (xdvp)
		vnode_put(xdvp);
	if (error == 0)
		return;
nodata:
	bzero(fip, sizeof (finderinfo_t));
}


#define KAUTH_DIR_WRITE     (KAUTH_VNODE_ACCESS | KAUTH_VNODE_ADD_FILE | \
                             KAUTH_VNODE_ADD_SUBDIRECTORY | \
                             KAUTH_VNODE_DELETE_CHILD)

#define KAUTH_DIR_READ      (KAUTH_VNODE_ACCESS | KAUTH_VNODE_LIST_DIRECTORY)

#define KAUTH_DIR_EXECUTE   (KAUTH_VNODE_ACCESS | KAUTH_VNODE_SEARCH)

#define KAUTH_FILE_WRITE    (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA)

#define KAUTH_FILE_READ     (KAUTH_VNODE_ACCESS | KAUTH_VNODE_READ_DATA)

#define KAUTH_FILE_EXECUTE  (KAUTH_VNODE_ACCESS | KAUTH_VNODE_EXECUTE)

/*
 * Compute the same user access value as getattrlist(2)
 */
static u_int32_t
getuseraccess(znode_t *zp, vfs_context_t ctx)
{
	struct vnode	*vp;
	znode_phys_t	*pzp = zp->z_phys;
	u_int32_t	user_access = 0;

	/* Only take the expensive vnode_authorize path when we have an ACL */
	if (pzp->zp_acl.z_acl_count == 0) {
		kauth_cred_t	cred = vfs_context_ucred(ctx);
		uid_t		obj_uid;
		mode_t		obj_mode;
		
		/* User id 0 (root) always gets access. */
		if (!vfs_context_suser(ctx)) {
			return (R_OK | W_OK | X_OK);
		}
		obj_uid = pzp->zp_uid;
		obj_mode = pzp->zp_mode & MODEMASK;
		if (obj_uid == UNKNOWNUID) {
			obj_uid = kauth_cred_getuid(cred);
		}
		if ((obj_uid == kauth_cred_getuid(cred)) ||
		    (obj_uid == UNKNOWNUID)) {
			return (((u_int32_t)obj_mode & S_IRWXU) >> 6);
		}
		/* Otherwise, settle for 'others' access. */
		return ((u_int32_t)obj_mode & S_IRWXO);
	}
	vp = ZTOV(zp);
	if (vnode_isdir(vp)) {
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_WRITE, ctx) == 0)
			user_access |= W_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_READ, ctx) == 0)
			user_access |= R_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_EXECUTE, ctx) == 0)
			user_access |= X_OK;
	} else {
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_WRITE, ctx) == 0)
			user_access |= W_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_READ, ctx) == 0)
			user_access |= R_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_EXECUTE, ctx) == 0)
			user_access |= X_OK;
	}
	return (user_access);
}

