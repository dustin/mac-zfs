#include <mach/mach_types.h>
 
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t zfs_module_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t zfs_module_stop(kmod_info_t *ki, void *data);
 
KMOD_EXPLICIT_DECL(com.apple.filesystems.zfs.readonly, "6.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = zfs_module_start;
__private_extern__ kmod_stop_func_t *_antimain = zfs_module_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
