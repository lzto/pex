#reported bugs


# Summary

| No.  | comments         |
|------|------------------|
| 1    | confirmed/ignored|
| 2    | confirmed/fixing |
| 3    | confirmed/ignored|
| 4    | confirmed/ignored|
| 5    | reported         |
| 6    | confirmed/ignored|
| 7    | confirmed/ignored|
| 8    | reported/ignored |
| 9    | reported/ignored |
| 10   | reported/ignored |
| 11   | reported         |
| 12   | confirmed/fixing |

# 1 btrfs send snapshot bypass DAC check
btrfs with proper capability can allow non-root to read snapshot contains file
not accessible to the user, thus can bypass DAC check

https://bugs.launchpad.net/ubuntu/+source/linux-signed/+bug/1785687

# 2 ```/dev/random``` driver missing ```capable()``` check

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

# 3 sg driver missing capable() check

In ```drivers/scsi/sg.c```, ```sg_ioctl(SCSI_IOCTL_SEND_COMMAND)``` calls
 ```sg_scsi_ioctl()``` to send command to device without capability check,
 however, such check exists in ```drivers/scsi/scsi_ioctl.c```,
 ```scsi_ioctl()``` also calls ```sg_scsi_ioctl()``` and check for ```CAP_SYS_ADMIN```,
 ```CAP_RAW_IO```

# 4 bsg driver missing capable() check

This one is similar to 3, and this problem exists in block/bsg.c

# 5 nvram driver missing ```capable()``` check

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

# 6 ```efivar_entry_set``` in ```efivar.c```, missing ```capable()``` check

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

# 7 missing ```capable()``` check for ```rfkill_set_block()```

In file ```net/rfkill/core.c```,
```rfkill_set_block()``` is checked for ```CAP_NET_ADMIN``` in ```state_store()```
and ```soft_store()```. However, in ```rfkill_fop_write()```, user can also call
```rfkill_set_block()``` without ```CAP_NET_ADMIN```.


# 8 missing ```capable()/blk_verify_command()``` check in ```mmc_rpmb_ioctl()```

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

# 9 Possible ```missing capable()``` check in ```thinkpad_acpi.c```

In file ```drivers/platform/x86/thinkpad_acpi.c```,

```acpi_evalf()``` is called by multiple wrapper functions like 
```video_read()/video_write()/hotkey_mask_get()/kbdlight_set_level()``` etc.

In ```video_read()/video_write()```, use of ```acpi_evalf()``` is protected by
```capable(CAP_SYS_ADMIN)```,

However, in other path like ```kbdlight_set_level()/light_set_status()```,
the check is missing.

We speculate that there should have been checks along other paths.

# 10 Possible missing ```capable()``` check in ```dm_blk_ioctl()```

We noticed that ```__blkdev_driver_ioctl()``` is called by ```dm_blk_ioctl()``` in
```drivers/md/dm.c```, and there’s a check for ```CAP_SYS_RAWIO``` only when ```r>0```,
in case of ```r==0```, there’s no capability check.

We also noticed the use of ```__blkdev_driver_ioctl()``` requires ```CAP_SYS_ADMIN```
privilege in other places, (see ```blkdev_roset(), block/ioctl.c```)

We suspect that those places should have required same privilege.

# 11 Possible missing capable() check in ```add_store()/remove_store()```

We noticed that in ```drivers/block/pktcdvd.c```, ```pkt_setup_dev/pkt_remove_dev```
are used in ```pkt_ctl_ioctl()``` and protected by ```capable(CAP_SYS_ADMIN)```,

However, these two functions are also used in ```add_store()``` and ```remove_store()```,
where there are no requirement for ```CAP_SYS_ADMIN```.

# 12 Possible missing check(DAC/LSM) in ecryptfs

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




