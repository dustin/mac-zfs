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


#include <stdio.h>
#include <stdlib.h>
#include <sys/zfs_ioctl.h>

/*
 * In OSX, data is not copied out of the kernel if the ioctl call returns 
 * an error.  ZFS relies on data *always* being returned from ther kernel since
 * data is always copied out of the kernel in the Solaris ioctl implementation.
 * So we need to have zfsdev_ioctl always return 0 and set zc_ioc_error 
 * to be the real ioctl error.
 */
int app_ioctl(int, unsigned long, zfs_cmd_t *);

#define ioctl(fd, zioc, zcmdt)  app_ioctl(fd, zioc, zcmdt)
