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
 */

#ifndef	_SYS_DMU_TX_H
#define	_SYS_DMU_TX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/inttypes.h>
#include <sys/dmu.h>
#include <sys/txg.h>
#include <sys/refcount.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct dmu_buf_impl;
struct dmu_tx_hold;
struct dnode_link;
struct dsl_pool;
struct dnode;
struct dsl_dir;

struct dmu_tx {
	/*
	 * No synchronization is needed because a tx can only be handled
	 * by one thread.
	 */
	list_t tx_holds; /* list of dmu_tx_hold_t */
	objset_t *tx_objset;
	struct dsl_dir *tx_dir;
	struct dsl_pool *tx_pool;
	uint64_t tx_txg;
	uint64_t tx_lastsnap_txg;
	uint64_t tx_lasttried_txg;
	txg_handle_t tx_txgh;
	void *tx_tempreserve_cookie;
	struct dmu_tx_hold *tx_needassign_txh;
	uint8_t tx_anyobj;
	int tx_err;
#ifdef ZFS_DEBUG
	uint64_t tx_space_towrite;
	uint64_t tx_space_tofree;
	uint64_t tx_space_tooverwrite;
	refcount_t tx_space_written;
	refcount_t tx_space_freed;
#endif
};

enum dmu_tx_hold_type {
	THT_NEWOBJECT,
	THT_WRITE,
	THT_BONUS,
	THT_FREE,
	THT_ZAP,
	THT_SPACE,
	THT_NUMTYPES
};

typedef struct dmu_tx_hold {
	dmu_tx_t *txh_tx;
	list_node_t txh_node;
	struct dnode *txh_dnode;
	uint64_t txh_space_towrite;
	uint64_t txh_space_tofree;
	uint64_t txh_space_tooverwrite;
#ifdef ZFS_DEBUG
	enum dmu_tx_hold_type txh_type;
	uint64_t txh_arg1;
	uint64_t txh_arg2;
#endif
} dmu_tx_hold_t;


/*
 * These routines are defined in dmu.h, and are called by the user.
 */
dmu_tx_t *dmu_tx_create(objset_t *dd);
int dmu_tx_assign(dmu_tx_t *tx, uint64_t txg_how);
void dmu_tx_commit(dmu_tx_t *tx);
void dmu_tx_abort(dmu_tx_t *tx);
uint64_t dmu_tx_get_txg(dmu_tx_t *tx);
void dmu_tx_wait(dmu_tx_t *tx);

/*
 * These routines are defined in dmu_spa.h, and are called by the SPA.
 */
extern dmu_tx_t *dmu_tx_create_assigned(struct dsl_pool *dp, uint64_t txg);

/*
 * These routines are only called by the DMU.
 */
dmu_tx_t *dmu_tx_create_dd(dsl_dir_t *dd);
int dmu_tx_is_syncing(dmu_tx_t *tx);
int dmu_tx_private_ok(dmu_tx_t *tx);
void dmu_tx_add_new_object(dmu_tx_t *tx, objset_t *os, uint64_t object);
void dmu_tx_willuse_space(dmu_tx_t *tx, int64_t delta);
void dmu_tx_dirty_buf(dmu_tx_t *tx, struct dmu_buf_impl *db);
int dmu_tx_holds(dmu_tx_t *tx, uint64_t object);
void dmu_tx_hold_space(dmu_tx_t *tx, uint64_t space);

#ifdef ZFS_DEBUG
#define	DMU_TX_DIRTY_BUF(tx, db)	dmu_tx_dirty_buf(tx, db)
#else
#define	DMU_TX_DIRTY_BUF(tx, db)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DMU_TX_H */
