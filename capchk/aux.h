#ifndef _AUX_H_
#define _AUX_H_

#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_KILL             5
#define CAP_SETGID           6
#define CAP_SETUID           7
#define CAP_SETPCAP          8
#define CAP_LINUX_IMMUTABLE  9
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_ADMIN        12
#define CAP_NET_RAW          13
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_SYS_MODULE       16
#define CAP_SYS_RAWIO        17
#define CAP_SYS_CHROOT       18
#define CAP_SYS_PTRACE       19
#define CAP_SYS_PACCT        20
#define CAP_SYS_ADMIN        21
#define CAP_SYS_BOOT         22
#define CAP_SYS_NICE         23
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_SYS_TTY_CONFIG   26
#define CAP_MKNOD            27
#define CAP_LEASE            28
#define CAP_AUDIT_WRITE      29
#define CAP_AUDIT_CONTROL    30
#define CAP_SETFCAP	         31
#define CAP_MAC_OVERRIDE     32
#define CAP_MAC_ADMIN        33
#define CAP_SYSLOG           34
#define CAP_WAKE_ALARM       35
#define CAP_BLOCK_SUSPEND    36
#define CAP_AUDIT_READ       37
#define CAP_LAST_CAP         CAP_AUDIT_READ

static char cap2string[][32] = 
{
"CAP_CHOWN",
"CAP_DAC_OVERRIDE",
"CAP_DAC_READ_SEARCH",
"CAP_FOWNER",
"CAP_FSETID",
"CAP_KILL",
"CAP_SETGID",
"CAP_SETUID",
"CAP_SETPCAP",
"CAP_LINUX_IMMUTABLE",
"CAP_NET_BIND_SERVICE",
"CAP_NET_BROADCAST",
"CAP_NET_ADMIN",
"CAP_NET_RAW",
"CAP_IPC_LOCK",
"CAP_IPC_OWNER",
"CAP_SYS_MODULE",
"CAP_SYS_RAWIO",
"CAP_SYS_CHROOT",
"CAP_SYS_PTRACE",
"CAP_SYS_PACCT",
"CAP_SYS_ADMIN",
"CAP_SYS_BOOT",
"CAP_SYS_NICE",
"CAP_SYS_RESOURCE",
"CAP_SYS_TIME",
"CAP_SYS_TTY_CONFIG",
"CAP_MKNOD",
"CAP_LEASE",
"CAP_AUDIT_WRITE",
"CAP_AUDIT_CONTROL",
"CAP_SETFCAP	",
"CAP_MAC_OVERRIDE",
"CAP_MAC_ADMIN",
"CAP_SYSLOG",
"CAP_WAKE_ALARM",
"CAP_BLOCK_SUSPEND",
"CAP_AUDIT_READ",
"CAP_LAST_CAP",
};


#endif
