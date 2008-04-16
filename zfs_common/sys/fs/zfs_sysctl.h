/*
* Copyright (c) 2007 Apple Inc. All rights reserved.
* Use is subject to license terms stated below.
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License v. 1.0 (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://www.opensolaris.org/os/licensing <http://www.opensolaris.org/os/licensing> .
* See the License for the specific language governing permissions
* and limitations under the License.
*
* THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _SYS_ZFS_SYSCTL_H
#define	_SYS_ZFS_SYSCTL_H

#ifdef	__cplusplus
extern "C" {
#endif


#define ZFS_SYSCTL_FOOTPRINT	1
#define ZFS_SYSCTL_READONLY	2
#define ZFS_SYSCTL_CONFIG_DEBUGMSG 3
#define ZFS_SYSCTL_CONFIG_DPRINTF 4


#define ZFS_FOOTPRINT_VERSION	1


/*
 * ZFS Footprint Statistics
 */
 
typedef struct memory_stats {
	uint32_t	current;
	uint32_t	target;
	uint32_t	highest;
	uint32_t	maximum;
} zfs_memory_stats_t;

typedef struct kmem_cache_stats {
	char		cache_name[32];
	uint32_t	cache_obj_size;
	uint32_t	cache_obj_count;
	uint32_t	cache_obj_inuse;
	uint32_t	cache_obj_peak;
	uint32_t	cache_slab_size;
	uint32_t	spare[3];
} kmem_cache_stats_t;

typedef struct zfs_footprint_stats {
	uint32_t		version;
	uint32_t		thread_count;
	zfs_memory_stats_t	memory_stats;
	zfs_memory_stats_t	arc_stats;
	uint32_t		spare;
	uint32_t		caches_count;
	kmem_cache_stats_t	cache_stats[1];
} zfs_footprint_stats_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_SYSCTL_H */
