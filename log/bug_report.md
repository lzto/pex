#Reported Bugs


# Summary

| CAP    | comments          | DAC    | Comments          | LSM    | Comments          |
| ------ | ----------------- | ------ | ----------------- | ------ | ----------------- |
| CAP-2  | confirmed/fixing  | DAC-1  | confirmed/ignored | LSM-12 | confirmed/fixing  |
| CAP-3  | confirmed/ignored | DAC-12 | confirmed/fixing  | LSM-13 | reported          |
| CAP-4  | confirmed/ignored |        |                   | LSM-14 | reported/ignored  |
| CAP-5  | reported          |        |                   | LSM-15 | reported/ignored  |
| CAP-6  | confirmed/ignored |        |                   | LSM-16 | reported          |
| CAP-7  | confirmed/ignored |        |                   | LSM-17 | confirmed/ignored |
| CAP-8  | reported/ignored  |        |                   | LSM-18 | reported          |
| CAP-9  | reported/ignored  |        |                   |        |                   |
| CAP-10 | reported/ignored  |        |                   |        |                   |
| CAP-11 | reported          |        |                   |        |                   |

# DAC-1 btrfs send snapshot bypass DAC check
btrfs with proper capability can allow non-root to read snapshot contains file
not accessible to the user, thus can bypass DAC check

https://bugs.launchpad.net/ubuntu/+source/linux-signed/+bug/1785687

# CAP-2 ```/dev/random``` driver missing ```capable()``` check

```/dev/random``` file have 666 permission, all user can write pool by calling into

```
random_write()->write_pool()
```

However, this ```write_pool()``` is protected by ```CAP_SYS_ADMIN``` in
```random_ioctl()```, ```random_ioctl()``` also calls ```credit_entropy_bits()```
to credit entropy bits.

Also, there are other paths that can reach ```credit_entropy_bits()```, such as

```
evdev_write()
    ->input_inject_event()
    ->input_handle_event()
    ->add_input_randomness()
    ->add_timmer_randomness()
    ->credit_entropy_bits()
```

User can combine ```write_pool()``` and a path eventually call
 ```credit_entropy_bits``` to achieve similar goal.

# CAP-3 sg driver missing capable() check

In ```drivers/scsi/sg.c```, ```sg_ioctl(SCSI_IOCTL_SEND_COMMAND)``` calls
 ```sg_scsi_ioctl()``` to send command to device without capability check,
 however, such check exists in ```drivers/scsi/scsi_ioctl.c```,
 ```scsi_ioctl()``` also calls ```sg_scsi_ioctl()``` and check for ```CAP_SYS_ADMIN```,
 ```CAP_RAW_IO```

# CAP-4 bsg driver missing capable() check

This one is similar to 3, and this problem exists in block/bsg.c

# CAP-5 nvram driver missing ```capable()``` check

In ```drivers/char/nvram.c```, call ```nvram_ioctl()``` with NVRAM_INIT can wipe
the nvram,

```
nvram_ioctl(NVRAM_INIT)->__nvram_write_byte(0,i);
                       ->__nvram_set_checksum();
```

This path is protected by capable(CAP_SYS_ADMIN).

However, in ```nvram_write()``` user can also wipe it by just issuing ```write(0)```
without CAP_SYS_ADMIN capability.

```
nvram_write(0)->__nvram_write_byte(0,i);
              ->__nvram_set_checksum();
```

(assuming that the checksum is correct at the beginning)

# CAP-6 ```efivar_entry_set``` in ```efivar.c```, missing ```capable()``` check

in ```drivers/firmware/efi/efivars.c```

It requires ```CAP_SYS_ADMIN``` in ```efivar_create()``` to create new efi variable,

```
efivar_create()->efivar_entry_set()
                 efivar_create_sysfs_entry()
```

However it allows user without such capability to modify it through ```efivar_store_raw()```

```
efivar_store_raw()->efivar_entry_set()
```

user might want to drop capability later in time and don’t want to allow modify
 of such variable.

# CAP-7 missing ```capable()``` check for ```rfkill_set_block()```

In file ```net/rfkill/core.c```,
```rfkill_set_block()``` is checked for ```CAP_NET_ADMIN``` in ```state_store()```
and ```soft_store()```. However, in ```rfkill_fop_write()```, user can also call
```rfkill_set_block()``` without ```CAP_NET_ADMIN```.


# CAP-8 missing ```capable()/blk_verify_command()``` check in ```mmc_rpmb_ioctl()```

in ```sg_scsi_ioctl()``` (file: ```block/scsi_ioctl.c```)
```blk_execute_rq()``` is protected by ```blk_verify_command()```,

```
sg_scsi_ioctl()-> blk_verify_command()
                        `-> blk_execute_rq()
```

However, such check does not exist in ```mmc_rpmb_ioctl()```, file: ```drivers/mmc/core/block.c```

```
mmc_rpmb_ioctl()->mmc_blk_ioctl_cmd()->blk_execute_rq()
                            `->mmc_blk_ioctl_multi_cmd()->blk_execute_rq()
```

We speculate that similar check need to be added to this path also.

# CAP-9 Possible ```missing capable()``` check in ```thinkpad_acpi.c```

In file ```drivers/platform/x86/thinkpad_acpi.c```,

```acpi_evalf()``` is called by multiple wrapper functions like 
```video_read()/video_write()/hotkey_mask_get()/kbdlight_set_level()``` etc.

In ```video_read()/video_write()```, use of ```acpi_evalf()``` is protected by
```capable(CAP_SYS_ADMIN)```,

However, in other path like ```kbdlight_set_level()/light_set_status()```,
the check is missing.

We speculate that there should have been checks along other paths.

# CAP-10 Possible missing ```capable()``` check in ```dm_blk_ioctl()```

We noticed that ```__blkdev_driver_ioctl()``` is called by ```dm_blk_ioctl()``` in
```drivers/md/dm.c```, and there’s a check for ```CAP_SYS_RAWIO``` only when ```r>0```,
in case of ```r==0```, there’s no capability check.

We also noticed the use of ```__blkdev_driver_ioctl()``` requires ```CAP_SYS_ADMIN```
privilege in other places, (see ```blkdev_roset(), block/ioctl.c```)

We suspect that those places should have required same privilege.

# CAP-11 Possible missing capable() check in ```add_store()/remove_store()```

We noticed that in ```drivers/block/pktcdvd.c```, ```pkt_setup_dev/pkt_remove_dev```
are used in ```pkt_ctl_ioctl()``` and protected by ```capable(CAP_SYS_ADMIN)```,

However, these two functions are also used in ```add_store()``` and ```remove_store()```,
where there are no requirement for ```CAP_SYS_ADMIN```.

# DAC-12 LSM-12 Possible missing check(DAC/LSM) in ecryptfs

We noticed an inconsistency in ```ecryptfs_xattr_set(), (fs/ecryptfs/inode.c)```

The callgraph is shown below:

```
ecryptfs_xattr_set()
         |-> ecryptfs_setxattr() -> vfs_setxattr()
         `-> ecryptfs_removexattr()-> __vfs_removexattr()
```

In ```ecryptfs_setxattr()```, it calls ```vfs_setxattr()```, which checks
lower_dentry permission(DAC and LSM), using ```xattr_permission()``` and 
```security_inode_removexattr()```,

In ```ecryptfs_removexattr()```, it calls ```__vfs_removexattr()```,
which does not have such check.



# LSM-13 security_mmap_file() in remap_file_pages syscall 

We noticed ```remap_file_pages syscall``` uses ```do_mmap_pgoff``` without LSM check: ```security_mmap_file()```.  This system call passed user controllable parameters to ```do_mmap_pgoff()```.  We think that this LSM check should be added in order to be consistent with other cases, for example: in system call ```mmap_pgoff()```, ```shmat()```, they all have ```security_mmap_file()``` check before calling ```do_mmap_pgoff()```. 



# LSM-14 Possible missing LSM check in load_elf_binary() 

We noticed a use of ```kernel_read()``` in ```load_elf_binary()```, which doesn’t have LSM check ```security_kernel_read_file()/kernel_post_read_file()``` along the path. 

 callgraph:

```
   load_elf_binary()->kernel_read()
              `->load_elf_phdrs()->kernel_read()  
```

We think that these LSM checks should exist because the file may be specified by userspace. Note that this is different from other LSM checks, each LSM check has its own purpose. 

# LSM-15 Possible missing LSM check in load_elf_library() 

We noticed a use of ```kernel_read()``` in ```load_elf_library()```, which doesn’t have LSM check ```security_kernel_read_file()/kernel_post_read_file()``` along the path. 

 callgraph: 

```
  load_elf_library()->kernel_read()  
```

We think that these LSM checks should exist because the file may be specified by userspace. Note that this is different from other LSM checks, each LSM check has its own purpose.  

# LSM-16 Missing security_inode_readlink() in xfs_file_ioctl() 

We noticed a use of ```vfs_readlink()``` in ```xfs_file_ioctl()```, which should have been checked by  ```security_inode_readlink()```. 

The callgraph is:

```
 	xfs_file_ioctl()->xfs_readlink_by_handle()->vfs_readlink()
```

  This path allows user to do things similar to ```SyS_readlinkat()```, and the parameters are user controllable.  



# LSM-17 Missing security_task_setnice() check in wq_nice_store() 

We noticed a path which calls ```set_user_nice()``` (the nice value is user controllable), and this path does not have ```security_task_setnice()``` check.  The problematic functions and call graph is shown below:  

```
wq_nice_store()  ->apply_wqattrs_prepare()  ->alloc_unbound_pwq()  ->create_worker()  ->set_user_nice()  
```

Similar check exists in: ```kernel/sched/core.c```, ```SYSCALL_DEFINE1(nice, int, increment) set_user_nice() ```function is guarded by ```security_task_setnice()```  We think this LSM hook is necessary because this behavior should have been checked LSM hook(even for root), however, this is the one that definitely escaped the check. 

#LSM-18 Possible missing check LSM in ecryptfs 

While looking at the code, we found out more inconsistencies in ecryptfs, please see below:  ```ecryptfs_listxattr()```

calls lower listxattr() no check.  

```ecryptfs_do_unlink/do_create/link/symlink/mkdir/rmdir/mknod/rename/getlink/getattr/setxattr/unlink    ```

calls vfs_* and have checks for lower LSM permission. 