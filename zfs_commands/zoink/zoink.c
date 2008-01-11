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


#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysctl.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curses.h>

#include <sys/fs/zfs_sysctl.h>


#define ONEMEGABYTE	(1024*1024)


int kmem_cache_total;
int kmem_cache_inuse;

char linebuf[1024];
int row;


void
print_memory_info(const char *mem_name, zfs_memory_stats_t *mem_stats)
{
	sprintf(linebuf, " %s: %4dM used, %4dM peak, %4dM goal",
		mem_name,
		mem_stats->current / ONEMEGABYTE,
		mem_stats->highest / ONEMEGABYTE,
		mem_stats->target / ONEMEGABYTE);
	mvaddstr(row++, 0, linebuf);
}

void
print_cache_info(kmem_cache_stats_t *cache_stats)
{
	kmem_cache_stats_t *twin_stats;

	/*
	 * Combine same-sized zio_buf and zio_data_buf stats
	 * to save screen real estate.
	 *
	 * XXX - assumes these always occur in pairs
	 */
	if (strstr(cache_stats->cache_name, "zio") != NULL) {
		if (strstr(cache_stats->cache_name, "data") != NULL)
			return;

		twin_stats = cache_stats + 1;
		if ((cache_stats->cache_obj_peak + twin_stats->cache_obj_peak) <= 1)
			return;

		sprintf(linebuf, " zio_bufs %d", cache_stats->cache_obj_size);
		mvaddstr(row, 0, linebuf);

		sprintf(linebuf, "%9d %9d %9d %9d %9d %7d%K",
			cache_stats->cache_obj_size,
			cache_stats->cache_slab_size,
			cache_stats->cache_obj_inuse + twin_stats->cache_obj_inuse,
			cache_stats->cache_obj_count + twin_stats->cache_obj_count,
			cache_stats->cache_obj_peak + twin_stats->cache_obj_peak,
			(cache_stats->cache_obj_size * cache_stats->cache_obj_count) / 1024);

		kmem_cache_total += twin_stats->cache_obj_size * twin_stats->cache_obj_count;
		kmem_cache_inuse += twin_stats->cache_obj_size * twin_stats->cache_obj_inuse;
	} else {
		if (cache_stats->cache_obj_peak <= 1)
			return;

		sprintf(linebuf, " %s", cache_stats->cache_name);
		mvaddstr(row, 0, linebuf);

		sprintf(linebuf, "%9d %9d %9d %9d %9d %7d%K",
			cache_stats->cache_obj_size,
			cache_stats->cache_slab_size,
			cache_stats->cache_obj_inuse,
			cache_stats->cache_obj_count,
			cache_stats->cache_obj_peak,
			(cache_stats->cache_obj_size * cache_stats->cache_obj_count) / 1024);

	}

	mvaddstr(row++, 18, linebuf);
	kmem_cache_total += cache_stats->cache_obj_size * cache_stats->cache_obj_count;
	kmem_cache_inuse += cache_stats->cache_obj_size * cache_stats->cache_obj_inuse;
}

int
main(void)
{
	zfs_footprint_stats_t *footprint;
	size_t buflen = 8192;
	struct vfsconf vfc;
	int name[3];
	int i;

	if (getvfsbyname("zfs", &vfc) < 0)
		errx(1, "ZFS not loaded into kernel");

	footprint = (zfs_footprint_stats_t *) malloc(buflen);

	name[0] = CTL_VFS;
	name[1] = vfc.vfc_typenum;
	name[2] = ZFS_SYSCTL_FOOTPRINT;
	if (sysctl(name, 3, footprint, &buflen, (void *)0, (size_t)0) < 0)
		err(1, "sysctl");

	if (footprint->version != ZFS_FOOTPRINT_VERSION)
		errx(1, "ZFS footprint sysctl version mismatch");

	(void) initscr();

	while (1) {
		kmem_cache_total = kmem_cache_inuse = 0;
		row = 0;
	
		name[0] = CTL_VFS;
		name[1] = vfc.vfc_typenum;
		name[2] = ZFS_SYSCTL_FOOTPRINT;
		if (sysctl(name, 3, footprint, &buflen, (void *)0, (size_t)0) < 0)
			err(1, "sysctl");

		clear();
		print_memory_info("ZFS footprint", &footprint->memory_stats);
		print_memory_info("ARC footprint", &footprint->arc_stats);
		row++;

		sprintf(linebuf, "%3d threads", footprint->thread_count);
		mvaddstr(0, 65, linebuf);
	
		sprintf(linebuf, "%9s %9s %9s %9s %9s %8s", "obj", "slab", "active", "total", "peak", "total");
		mvaddstr(row++, 18, linebuf);

		sprintf(linebuf, " kmem_cache name");
		mvaddstr(row, 0, linebuf);

		sprintf(linebuf, "%9s %9s %9s %9s %9s %8s", "size", "size", "objs", "objs", "objs", "mem");
		mvaddstr(row++, 18, linebuf);

		sprintf(linebuf, "-----------------------------------------------------------------------------");
		mvaddstr(row++, 0, linebuf);

		for (i = 0; i < footprint->caches_count; ++i) {
			print_cache_info(&footprint->cache_stats[i]);
		}
	
		sprintf(linebuf, "-----------------------------------------------------------------------------");
		mvaddstr(row++, 0, linebuf);

		sprintf(linebuf, " kmem_cache total:                      %6dM   %6dM",
			kmem_cache_inuse / ONEMEGABYTE, kmem_cache_total / ONEMEGABYTE);
		mvaddstr(row++, 0, linebuf);

		move(row, 0);

	//	clrtobot();
		refresh();
		sleep(1);
	}
	endwin();

	exit(0);
}

