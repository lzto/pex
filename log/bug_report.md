#reported bugs


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



