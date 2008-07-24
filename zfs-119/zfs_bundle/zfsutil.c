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

/*	@(#)zfsutil.c   (c) 2007 Apple Inc.	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/loadable_fs.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/nvpair.h>
#include <sys/fs/zfs.h>


#define RAWDEV_PREFIX		"/dev/r"


const char *progname;


static void
usage(void)
{
	fprintf(stderr, "usage: %s -p device\n", progname);
        exit(FSUR_INVAL);
}

#define ZFS_COMMAND	"/usr/sbin/zfs"
#define ZPOOL_COMMAND	"/usr/sbin/zpool"


static void
zfs_create_pool(const char *poolname, const char *devpath)
{
	int pid;
	union wait status;

	pid = fork();
	if (pid == 0) {
		(void) execl(ZPOOL_COMMAND, ZPOOL_COMMAND, "create", poolname, devpath, NULL);
	} else if (pid != -1) {
		(void) wait4(pid, (int *)&status, 0, NULL);
	}
}


static void
zpool_import(uint64_t guid)
{
	int pid;
	union wait status;

	pid = fork();
	if (pid == 0) {
		char idstr[64];

		sprintf(idstr, "%llu", (u_longlong_t)guid);

		(void) execl(ZPOOL_COMMAND, ZPOOL_COMMAND, "import", "-f", idstr, NULL);
	} else if (pid != -1) {
		(void) wait4(pid, (int *)&status, 0, NULL);
	}
}


static void
zfs_mount(const char *filesystem)
{
	int pid;
	union wait status;

	pid = fork();
	if (pid == 0) {
		(void) execl(ZFS_COMMAND, ZFS_COMMAND, "mount", filesystem, NULL);
	} else if (pid != -1) {
		(void) wait4(pid, (int *)&status, 0, NULL);
	}
}


static int
zfs_probe(const char *devpath)
{
	nvlist_t *config = NULL;
	char *poolname;
	uint64_t guid;
	int result = FSUR_UNRECOGNIZED;
	int fd;

	if ((fd = open(devpath, O_RDONLY)) < 0) {
		return (result);
	}
	if (zpool_read_label(fd, &config) != 0) {
		(void) close(fd);
		goto out;
	}
	if (config == NULL) {
		goto out;
	}
	if (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &poolname) != 0) {
		goto out;
	}

	/* Write the volume name to standard output */
	(void) fwrite(poolname, sizeof(char), strlen(poolname), stdout);

	result = FSUR_RECOGNIZED;
#if 1
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) == 0) {
		zpool_import(guid);
		if (poolname[0] != '\0') {
			zfs_mount(poolname);
		}
	}
#endif
out:
	(void) close(fd);
	if (config) {
		nvlist_free(config);
	}
	return (result);
}


int
main(int argc, char **argv)
{
	char  blkdevice[MAXPATHLEN];
	char  what;
	char  *cp;
	char  *devname;
	char  *poolname;
	struct stat  sb;
	int  ret = FSUR_INVAL;

	/* save & strip off program name */
	progname = argv[0];
	argc--;
	argv++;

	if (argc < 2 || argv[0][0] != '-')
		usage();
 
	what = argv[0][1];

	/*
	 * -v is used for our newfs_zfs simulation
	 *
	 * arguments will look like: "-v poolname /dev/rdisk1s2"
	 *
	 * we'll turn around and call "zpool create poolname /dev/disk1s2"
	 */
	if (what == 'v') {
		poolname = argv[1];
		argc--;
		argv++;
	}

	devname = argv[1];
	cp = strrchr(devname, '/');
	if (cp != 0)
		devname = cp + 1;
	if (*devname == 'r')
		devname++;
	(void) sprintf(blkdevice, "%s%s", _PATH_DEV, devname);

	if (stat(blkdevice, &sb) != 0) {
		fprintf(stderr, "%s: stat %s failed, %s\n", progname, blkdevice, strerror(errno));
		exit(FSUR_INVAL);
	}

	switch (what) {
	case FSUC_PROBE:
		ret = zfs_probe(blkdevice);
		break;

	case 'v':
 		zfs_create_pool(poolname, blkdevice);
 		exit(0);
 		break;

	default:
		usage();
	}

	exit(ret);
}

