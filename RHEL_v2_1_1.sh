#!/bin/bash

echo "1 Initial Setup"
echo "1.1 Filesystem Configuration . 18"
echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled   19"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"


echo "output of command"
modprobe -n -v cramfs



echo "output of command"
lsmod | grep cramfs


echo "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled  21"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"


echo "output of command"
modprobe -n -v freevxfs


echo "output of command"
lsmod | grep freevxfs

echo "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled  . 22"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"


echo "output of command"
modprobe -n -v jffs2


echo "output of command"
lsmod | grep jffs2


echo "1.1.1.4 Ensure mounting of hfs filesystems is disabled   23"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"


echo "output of command"
modprobe -n -v hfs


echo "output of command"
lsmod | grep hfs


echo "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled  . 24"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"

echo "output of command"
modprobe -n -v hfsplus


echo "output of command"
lsmod | grep hfsplus


echo "1.1.1.6 Ensure mounting of squashfs filesystems is disabled   25"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"

echo "output of command"
modprobe -n -v squashfs


echo "output of command"
lsmod | grep squashfs


echo "1.1.1.7 Ensure mounting of udf filesystems is disabled  . 26"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"

echo "output of command"
modprobe -n -v udf


echo "output of command"
lsmod | grep udf


echo "1.1.1.8 Ensure mounting of FAT filesystems is disabled  . 27"
echo "Run the following commands and verify the output is as indicated: install /bin/true and <No output>"


echo "output of command"
modprobe -n -v vfat


echo "output of command"
lsmod | grep vfat


echo "1.1.2 Ensure separate partition exists for /tmp   28 i.e. tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)"


echo "output of command"
mount | grep /tmp


echo "1.1.3 Ensure nodev option set on /tmp partition  . 30 eg: tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)"


echo "output of command"
mount | grep /tmp


echo "1.1.4 Ensure nosuid option set on /tmp partition   31"

echo "output of command"
mount | grep /tmp


echo "1.1.5 Ensure noexec option set on /tmp partition  . 32"


echo "output of command"
mount | grep /tmp


echo "1.1.6 Ensure separate partition exists for /var  . 33 i.e. /dev/xvdg1 on /var type ext4 (rw,relatime,data=ordered)"


echo "output of command"
mount | grep /var

echo "1.1.7 Ensure separate partition exists for /var/tmp  . 34
1.1.8 Ensure nodev option set on /var/tmp partition   36
1.1.9 Ensure nosuid option set on /var/tmp partition  . 37
1.1.10 Ensure noexec option set on /var/tmp partition   38
output should be : tmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)"


echo "output of command"
mount | grep /var/tmp


echo "1.1.11 Ensure separate partition exists for /var/log   39
output should be /dev/xvdh1 on /var/log type ext4 (rw,relatime,data=ordered)"

echo "output of command"
mount | grep /var/log


echo "1.1.12 Ensure separate partition exists for /var/log/audit  . 41
output should be /dev/xvdi1 on /var/log/audit type ext4 (rw,relatime,data=ordered)"


echo "output of command"
mount | grep /var/log/audit


echo "1.1.13 Ensure separate partition exists for /home   43
1.1.14 Ensure nodev option set on /home partition  . 44"
echo "output should be : /dev/xvdf1 on /home type ext4 (rw,nodev,relatime,data=ordered)"


echo "output of command"
mount | grep /home


echo "1.1.15 Ensure nodev option set on /dev/shm partition   45
1.1.16 Ensure nosuid option set on /dev/shm partition  . 46
1.1.17 Ensure noexec option set on /dev/shm partition   47
outut should be: /dev/xvdf1 on /home type ext4 (rw,nodev,relatime,data=ordered)"

echo "output of command"
mount | grep /dev/shm


echo "1.1.18 Ensure nodev option set on removable media partitions  . 48
1.1.19 Ensure nosuid option set on removable media partitions   49
1.1.20 Ensure noexec option set on removable media partitions  . 50
Run the following command and verify that the nodev and nosuid and noexec option is set on all removable media partitions."

echo "output of command"
mount

echo "1.1.21 Ensure sticky bit is set on all world-writable directories   51
Run the following command to verify no world writable directories exist without the sticky
bit set:"


echo "output of command"
df --local -P | awk 'if (NR!=1) print $6' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null


echo "1.1.22 Disable Automounting  . 52
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled autofs


echo "1.2 Configure Software Updates . 54
1.2.1 Ensure package manager repositories are configured  . 54
Run the following command and verify repositories are configured correctly:"

echo "output of command"
yum repolist

echo "1.2.2 Ensure gpgcheck is globally activated  . 56
Run the following command and verify gpgcheck is set to ' 1 ':"

echo "output of command"
grep ^gpgcheck /etc/yum.conf

echo "1.2.3 Ensure GPG keys are configured   57 
Run the following command and verify GPG keys are configured correctly:"

echo "output of command"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'


echo "1.2.4 Ensure Red Hat Network or Subscription Manager connection is configured
Verify your system is connected to the Red Hat Network or Red Hat Subscription Manager."

echo "output of command"
subscription-manager identity

echo "1.2.5 Disable the rhnsd Daemon  . 59 
Run the following command and verify all runlevels are listed as 'off' or rhnsd is not
Available:"

echo "output of command"
chkconfig --list rhnsd


echo "1.3 Filesystem Integrity Checking  60"

echo "1.3.1 Ensure AIDE is installed   60 
Run the following command and verify aide is installed:"


echo "output of command"
rpm -q aide


echo "1.3.2 Ensure filesystem integrity is regularly checked  . 62
Run the following commands to determine if there is a cron job scheduled to run the aide Check."


echo "output of command"
crontab -u root -l | grep aide


echo "output of command"
grep -r aide /etc/cron.* /etc/crontab


echo "1.4 Secure Boot Settings  64
1.4.1 Ensure permissions on bootloader config are configured  . 64
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other"


echo "output of command"
stat /boot/grub2/grub.cfg


echo "1.4.2 Ensure bootloader password is set  . 66
Run the following commands and verify output matches:
set superusers=<username>"


echo "output of command"
grep "^set superusers" /boot/grub2/grub.cfg


echo "password_pbkdf2 <username> <encrypted-password>"


echo "output of command"
grep "^password" /boot/grub2/grub.cfg


echo "1.4.3 Ensure authentication required for single user mode   68
Run the following commands and verify that /sbin/sulogin is used as shown:"


echo "output of command"
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service

echo "output of command"
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service


echo "1.5 Additional Process Hardening . 69
1.5.1 Ensure core dumps are restricted  . 69
Run the following commands and verify output matches:hard core 0
fs.suid_dumpable = 0*****"

echo "output of command"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*

echo "output of command"
sysctl fs.suid_dumpable


echo "1.5.2 Ensure XD/NX support is enabled   71
Run the following command and verify your kernel has identified and activated NX/XD Protection."


echo "output of command"
dmesg | grep NX


echo "1.5.3 Ensure address space layout randomization (ASLR) is enabled  . 73
Run the following command and verify output matches:kernel.randomize_va_space = 2"


echo "output of command"
sysctl kernel.randomize_va_space

echo "1.5.4 Ensure prelink is disabled   74
Run the following command and verify prelink is not installed:"


echo "output of command"
rpm -q prelink


echo "Mandatory Access Control . 75
1.6.1.1 Ensure SELinux is not disabled in bootloader configuration   77"
echo "Run the following command and verify that no linux line has the selinux=0 or enforcing=0 parameters set:"


echo "output of command"
grep "^\s*linux" /boot/grub2/grub.cfg

echo "1.6.1.2 Ensure the SELinux state is enforcing   79
Run the following commands and ensure output matches:SELINUX=enforcing, SELinux status: enabled, Current mode: enforcing, Mode from config file: enforcing"


echo "output of command"
grep SELINUX=enforcing /etc/selinux/config

echo "output of command"
sestatus

echo "1.6.1.3 Ensure SELinux policy is configured  . 80 
Run the following commands and ensure output matches either ' targeted ' or ' mls ':"


echo "output of command"
grep SELINUXTYPE=targeted /etc/selinux/config


echo "output of command"
sestatus


echo "1.6.1.4 Ensure SETroubleshoot is not installed  . 81
Run the following command and verify setroubleshoot is not installed:"


echo "output of command"
rpm -q setroubleshoot

echo "1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed  . 82
Run the following command and verify mcstrans is not installed:"


echo "output of command"
rpm -q mcstrans

echo "1.6.1.6 Ensure no unconfined daemons exist  . 83
Run the following command and verify not output is produced:"


echo "output of command"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' |awk '{ print $NF }'


echo "1.6.2 Ensure SELinux is installed   84
Run the following command and verify libselinux is installed:"


echo "output of command"
rpm -q libselinux


echo "1.7 Warning Banners. 84
1.7.1.1 Ensure message of the day is configured properly  . 86
Run the following command and verify that the contents match site policy:"


echo "output of command"
cat /etc/motd

echo "1.7.1.2 Ensure local login warning banner is configured properly  . 88
Run the following command and verify that the contents match site policy:"


echo "output of command"
cat /etc/issue

echo "1.7.1.3 Ensure remote login warning banner is configured properly   90
Run the following command and verify that the contents match site policy:"


echo "output of command"
cat /etc/issue.net


echo "1.7.1.4 Ensure permissions on /etc/motd are configured  . 92
Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"


echo "output of command"
stat /etc/motd

echo "1.7.1.5 Ensure permissions on /etc/issue are configured   93
Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"


echo "output of command"
stat /etc/issue

echo "1.7.1.6 Ensure permissions on /etc/issue.net are configured   94
Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"

echo "output of command"
stat /etc/issue.net

echo "1.7.2 Ensure GDM login banner is configured   95
If GDM is installed on the system verify that /etc/dconf/profile/gdm exists and contains the following:
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults"

echo "output of command"
cat /etc/dconf/profile/gdm

echo "1.8 Ensure updates, patches, and additional security software are installed (Not
Scored) . 97
Run the following command and verify there are no updates or patches to install:"

echo "output of command"
yum check-update

echo "2 Services  98
2.1 inetd Services  99
2.1.1 Ensure chargen services are not enabled  . 99
Run the following command and verify chargen-dgram and chargen-stream are off or Missing:"

echo "output of command"
chkconfig --list


echo "2.1.2 Ensure daytime services are not enabled  . 100
Run the following command and verify daytime-dgram and daytime-stream are off or Missing"


echo "output of command"
chkconfig --list


echo "2.1.3 Ensure discard services are not enabled   101
Run the following command and verify discard-dgram and discard-stream are off or Missing:"

echo "output of command"
chkconfig --list


echo "2.1.4 Ensure echo services are not enabled   102
Run the following command and verify echo-dgram and echo-stream are off or missing:"


echo "output of command"
chkconfig --list


echo "2.1.5 Ensure time services are not enabled   103”
echo Run the following command and verify time-dgram and time-stream are off or missing:"


echo "output of command"
chkconfig --list


echo "2.1.6 Ensure tftp server is not enabled  . 104 Run the following command and verify tftp is off or missing:"

echo "output of command"
chkconfig --list

echo "2.1.7 Ensure xinetd is not enabled  . 105
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled xinetd


echo "2.2 Special Purpose Services  105
2.2.1.1 Ensure time synchronization is in use  . 106
On physical systems or virtual systems where host based time synchronization is not available run the following commands and verify either ntp or chrony is installed:"


echo "output of command"
rpm -q ntp

echo "output of command"
rpm -q chrony


echo "2.2.1.2 Ensure ntp is configured   108
Run the following command and verify output matches:
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery"

echo "output of command"
grep "^restrict" /etc/ntp.conf

echo "Run the following command and verify remote server is configured properly:"

echo "output of command"
grep "^server" /etc/ntp.conf

echo "Run the following commands and verify that ' -u ntp:ntp ' is included in OPTIONS or ExecStart as listed:"


echo "output of command"
grep "^OPTIONS" /etc/sysconfig/ntpd

echo "output of command"
grep "^ExecStart" /usr/lib/systemd/system/ntpd.service


echo "2.2.1.3 Ensure chrony is configured   110
Run the following command and verify remote server is configured properly:"

echo "output of command"
grep "^server" /etc/chrony.conf

echo "Run the following command and verify OPTIONS includes ' -u chrony ':"

echo "output of command"
grep ^OPTIONS /etc/sysconfig/chronyd

echo "2.2.2 Ensure X Window System is not installed   112
Run the following command and verify no output is returned:"

echo "output of command"
rpm -qa xorg-x11*

echo "2.2.3 Ensure Avahi Server is not enabled   113
Run the following command and verify result is not enabled:"

echo "output of command"
systemctl is-enabled avahi-daemon

echo "2.2.4 Ensure CUPS is not enabled  . 114
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled cups

echo "2.2.5 Ensure DHCP Server is not enabled   116
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled dhcpd

echo "2.2.6 Ensure LDAP server is not enabled  . 117
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled slapd

echo "2.2.7 Ensure NFS and RPC are not enabled  . 118
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled nfs

echo "output of command"
systemctl is-enabled rpcbind

echo "2.2.8 Ensure DNS Server is not enabled  . 119
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled named

echo "2.2.9 Ensure FTP Server is not enabled   120
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled vsftpd

echo "2.2.10 Ensure HTTP server is not enabled   121
Run the following command and verify result is not enabled"


echo "output of command"
systemctl is-enabled httpd

echo "2.2.11 Ensure IMAP and POP3 server is not enabled   122
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled dovecot

echo "2.2.12 Ensure Samba is not enabled   123
Run the following command and verify result is not enabled"

echo "output of command"
systemctl is-enabled smb

echo "2.2.13 Ensure HTTP Proxy Server is not enabled  . 124"

echo "output of command"
systemctl is-enabled squid

echo "2.2.14 Ensure SNMP Server is not enabled  . 125"

echo "output of command"
systemctl is-enabled snmpd

echo "2.2.15 Ensure mail transfer agent is configured for local-only mode . 126
Run the following command and verify that the MTA is not listening on any non-loopback
address ( 127.0.0.1 or ::1 ):"

echo "output of command"
netstat -an | grep LIST | grep ":25[[:space:]]"

echo "2.2.16 Ensure NIS Server is not enabled   128"

echo "output of command"
systemctl is-enabled ypserv

echo "2.2.17 Ensure rsh server is not enabled  . 129"

echo "output of command"
systemctl is-enabled rsh.socket

echo "output of command"
systemctl is-enabled rlogin.socket

echo "output of command"
systemctl is-enabled rexec.socket

echo "2.2.18 Ensure talk server is not enabled   130"

echo "output of command"
systemctl is-enabled ntalk

echo "2.2.19 Ensure telnet server is not enabled   131"


echo "output of command"
systemctl is-enabled telnet.socket

echo "2.2.20 Ensure tftp server is not enabled   132"

echo "output of command"
systemctl is-enabled tftp.socket

echo "2.2.21 Ensure rsync service is not enabled  . 133"

echo "output of command"
systemctl is-enabled rsyncd

echo "2.3 Service Clients  134
2.3.1 Ensure NIS Client is not installed  . 134"

echo "output of command"
rpm -q ypbind

echo "2.3.2 Ensure rsh client is not installed   136"

echo "output of command"
rpm -q rsh

echo "2.3.3 Ensure talk client is not installed  . 138"

echo "output of command"
rpm -q talk

echo "2.3.4 Ensure telnet client is not installed  . 139"

echo "output of command"
rpm -q telnet

echo "2.3.5 Ensure LDAP client is not installed  . 141"

echo "output of command"
rpm -q openldap-clients

echo "3 Network Configuration  141
3.1 Network Parameters (Host Only) . 142
3.1.1 Ensure IP forwarding is disabled  . 142"

echo "output of command"
sysctl net.ipv4.ip_forward

echo "3.1.2 Ensure packet redirect sending is disabled  . 144"

echo "output of command"
sysctl net.ipv4.conf.all.send_redirects

echo "output of command"
sysctl net.ipv4.conf.default.send_redirects

echo "3.2 Network Parameters (Host and Router)  146
3.2.1 Ensure source routed packets are not accepted   146"

echo "output of command"
sysctl net.ipv4.conf.all.accept_source_route

echo "output of command"
sysctl net.ipv4.conf.default.accept_source_route


echo "3.2.2 Ensure ICMP redirects are not accepted  . 148"

echo "output of command"
sysctl net.ipv4.conf.all.accept_redirects

echo "output of command"
sysctl net.ipv4.conf.default.accept_redirects

echo "3.2.3 Ensure secure ICMP redirects are not accepted   150"

echo "output of command"
sysctl net.ipv4.conf.all.secure_redirects

echo "output of command"
sysctl net.ipv4.conf.default.secure_redirects

echo "3.2.4 Ensure suspicious packets are logged   152 result should be 1"

echo "output of command"
sysctl net.ipv4.conf.all.log_martians

echo "output of command"
sysctl net.ipv4.conf.default.log_martians


echo "3.2.5 Ensure broadcast ICMP requests are ignored  . 153 result 1"

echo "output of command"
sysctl net.ipv4.icmp_echo_ignore_broadcasts

echo "3.2.6 Ensure bogus ICMP responses are ignored   155 result 1"

echo "output of command"
sysctl net.ipv4.icmp_ignore_bogus_error_responses

echo "3.2.7 Ensure Reverse Path Filtering is enabled  . 156 res 1"

echo "output of command"
sysctl net.ipv4.conf.all.rp_filter

echo "output of command"
sysctl net.ipv4.conf.default.rp_filter

echo "3.2.8 Ensure TCP SYN Cookies is enabled  158 res 1"

echo "output of command"
sysctl net.ipv4.tcp_syncookies

echo "3.3 IPv6 . 160
3.3.1 Ensure IPv6 router advertisements are not accepted  . 160 result should be 0"

echo "output of command"
sysctl net.ipv6.conf.all.accept_ra

echo "output of command"
sysctl net.ipv6.conf.default.accept_ra


echo "3.3.2 Ensure IPv6 redirects are not accepted  "

echo "output of command"
sysctl net.ipv6.conf.all.accept_redirects

echo "output of command"
sysctl net.ipv6.conf.default.accept_redirects

echo "3.3.3 Ensure IPv6 is disabled"
echo " output should be 'options ipv6 disable=1'"

echo "output of command"
modprobe -c | grep ipv6

echo "3.4 TCP Wrappers" 
echo "3.4.1 Ensure TCP Wrappers is installed   "
echo "Run the following command and verify tcp_wrappers is installed"

echo "output of command"
rpm -q tcp_wrappers

echo "Run the following command and verify libwrap.so is installed"

echo "output of command"
rpm -q tcp_wrappers-libs

echo "3.4.2 Ensure /etc/hosts.allow is configured"
echo "Run the following command and verify the contents of the /etc/hosts.allow file, whitelisted IPs should be there"

echo "output of command"
cat /etc/hosts.allow

echo "3.4.3 Ensure /etc/hosts.deny is configured"
echo "Run the following command and verify the contents of the /etc/hosts.deny file: ALL: ALL"

echo "output of command"
cat /etc/hosts.deny


echo "3.4.4 Ensure permissions on /etc/hosts.allow are configured  . 169"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"

echo "output of command"
stat /etc/hosts.allow

echo "3.4.5 Ensure permissions on /etc/hosts.deny are 644   170"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"

echo "output of command"
stat /etc/hosts.deny

echo "3.5 Uncommon Network Protocols . 171"
echo "3.5.1 Ensure DCCP is disabled  . 171"
echo "Run the following commands and verify the output is as indicated: i.e. install /bin/true and <No output>"

echo "output of command"
modprobe -n -v dccp

echo "output of command"
lsmod | grep dccp

echo "3.5.2 Ensure SCTP is disabled   173"
echo "Run the following commands and verify the output is as indicated: i.e. install /bin/true and <No output>"

echo "output of command"
modprobe -n -v sctp

echo "output of command"
lsmod | grep sctp

echo "3.5.3 Ensure RDS is disabled   174"
echo "Run the following commands and verify the output is as indicated: i.e. install /bin/true and <No output>"

echo "output of command"
modprobe -n -v rds

echo "output of command"
lsmod | grep rds

echo "3.5.4 Ensure TIPC is disabled  . 175"
echo "Run the following commands and verify the output is as indicated: i.e. install /bin/true and <No output>"

echo "output of command"
modprobe -n -v tipc

echo "output of command"
lsmod | grep tipc

echo "3.6 Firewall Configuration  176"
echo "3.6.1 Ensure iptables is installed  . 176"
echo "Run the following command and verify iptables is installed:"

echo "output of command"
rpm -q iptables

echo "3.6.2 Ensure default deny firewall policy   178"
echo "Run the following command and verify that the policy for the INPUT , OUTPUT , and FORWARD chains is DROP or REJECT i.e. Chain INPUT (policy DROP), Chain FORWARD (policy DROP), Chain OUTPUT (policy DROP)"

echo "output of command"
iptables -L

echo "3.6.3 Ensure loopback traffic is configured   180"
echo "Run the following commands and verify output includes the listed rules in order (packet and byte counts may differ):"

echo "for input"
echo "output of command"
iptables -L INPUT -v -n

echo "for output"
echo "output of command"
iptables -L OUTPUT -v -n

echo "3.6.4 Ensure outbound and established connections are configured  182"
echo "Run the following command and verify all rules for new outbound, and established connections match site policy:"

echo "output of command"
iptables -L -v -n

echo "3.6.5 Ensure firewall rules exist for all open ports   "
echo "Verify all open ports listening on non-localhost addresses have at least one firewall rule."
echo "Run the following command to determine open ports:"

echo "output of command"
netstat -ln

echo "Run the following command to determine firewall rules:"

echo "output of command"
iptables -L INPUT -v -n

echo "3.7 Ensure wireless interfaces are disabled  . 186"
echo "Run the following command to determine wireless interfaces on the system:"

echo "output of command"
iwconfig

echo "Run the following command and verify wireless interfaces are active:"

echo "output of command"
ip link show up

echo "4 Logging and Auditing . 187"
echo "4.1 Configure System Accounting (auditd) . 188"
echo "4.1.1.1 Ensure audit log storage size is configured  . 189"
echo "Run the following command and ensure output is in compliance with site policy: i.e. max_log_file = <MB>"

echo "output of command"
grep max_log_file /etc/audit/auditd.conf

echo "4.1.1.2 Ensure system is disabled when audit logs are full   191"
echo "Run the following commands and verify output matches: i.e. space_left_action = email, action_mail_acct = root, admin_space_left_action = halt"

echo "output of command"
grep space_left_action /etc/audit/auditd.conf

echo "output of command"
grep action_mail_acct /etc/audit/auditd.conf

echo "output of command"
grep admin_space_left_action /etc/audit/auditd.conf


echo "4.1.1.3 Ensure audit logs are not automatically deleted   192"
echo "Run the following command and verify output matches: i.e. max_log_file_action = keep_logs"

echo "output of command"
grep max_log_file_action /etc/audit/auditd.conf


echo "4.1.2 Ensure auditd service is enabled  . 193"
echo "Run the following command and verify result is enabled'"

echo "output of command"
systemctl is-enabled auditd

echo "4.1.3 Ensure auditing for processes that start prior to auditd is enabled  194"
echo "Run the following command and verify that each linux line has the audit=1 parameter set:"

echo "output of command"
grep "^\s*linux" /boot/grub2/grub.cfg

echo "4.1.4 Ensure events that modify date and time information are collected 
. 196"
echo "On a 32 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-
change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change"


echo "output of command"
grep time-change /etc/audit/audit.rules

echo "On a 64 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-
change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change"


echo "output of command"
grep time-change /etc/audit/audit.rules


echo "4.1.5 Ensure events that modify user/group information are collected  . 198"
echo "Run the following command and verify output matches:"
echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity"

echo "output of command"
grep identity /etc/audit/audit.rules


echo "4.1.6 Ensure events that modify the system's network environment are collected"
echo "On a 32 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale"

echo "On a 64 bit system run the following command and verify the output matches"
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale"

echo "output of command"
grep system-locale /etc/audit/audit.rules


echo "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected   202"
echo "Run the following command and verify output matches: i.e. -w /etc/selinux/ -p wa -k MAC-policy"


echo "output of command"
grep MAC-policy /etc/audit/audit.rules


echo "4.1.8 Ensure login and logout events are collected   203"
echo "Run the following command and verify output matches: i.e. -w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins"

echo "output of command"
grep logins /etc/audit/audit.rules


echo "4.1.9 Ensure session initiation information is collected   205"
echo "Run the following command and verify output matches:-w /var/run/utmp -p wa -k session, -w /var/log/wtmp -p wa -k session, -w /var/log/btmp -p wa -k session"

echo "output of command"
grep session /etc/audit/audit.rules

echo "4.1.10 Ensure discretionary access control permission modification events are collected   207"
echo "On a 32 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid !=4294967295 -k perm_mod"

echo "output of command"
grep perm_mod /etc/audit/audit.rules

echo "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected"
echo "On a 64 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"


echo "output of command"
grep access /etc/audit/audit.rules
 
echo "4.1.12 Ensure use of privileged commands is collected . 211"
echo "Verify all resulting lines are in the /etc/audit/audit.rules file."

echo "output of command"
find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged" }'

echo "/etc/audit/audit.rules file"
echo "output of command"

cat /etc/audit/audit.rules

echo "4.1.13 Ensure successful file system mounts are collected   213"
echo "On a 64 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"


echo "output of command"
grep mounts /etc/audit/audit.rules


echo "4.1.14 Ensure file deletion events by users are collected  215"
echo "On a 64 bit system run the following command and verify the output matches:"
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F
auid>=1000 -F auid!=4294967295 -k delete"


echo "output of command"
grep delete /etc/audit/audit.rules


echo "4.1.15 Ensure changes to system administration scope (sudoers) is collected"
echo "Run the following command and verify output matches: i.e. -w /etc/sudoers -p wa -k scope and -w /etc/sudoers.d -p wa -k scope"

echo "output of command"
grep scope /etc/audit/audit.rules

echo "4.1.16 Ensure system administrator actions (sudolog) are collected   218"
echo "Run the following command and verify output matches: i.e. -w /var/log/sudo.log -p wa -k actions"

echo "output of command"
grep actions /etc/audit/audit.rules

echo "4.1.17 Ensure kernel module loading and unloading is collected   220"
echo "On a 64 bit system run the following command and verify the output matches:"
echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b64 -S init_module -S delete_module -k modules"

echo "output of command"
grep modules /etc/audit/audit.rules


echo "4.1.18 Ensure the audit configuration is immutable  . 222"
echo "Run the following command and verify output matches: i.e. -e 2"


echo "output of command"
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1

echo "4.2 Configure Logging . 222
4.2.1.1 Ensure rsyslog Service is enabled   224"
echo "Run the following command and verify result is 'enabled':"

echo "output of command"
systemctl is-enabled rsyslog


echo "4.2.1.2 Ensure logging is configured  . 226"
echo "Review the contents of the /etc/rsyslog.conf file to ensure appropriate logging is set. In
addition, run the following command and verify that the log files are logging information:"

echo "rsyslog.conf"

echo "output of command"
cat /etc/rsyslog.conf

echo "contents of log files"

echo "output of command"
ls -l /var/log/

echo "4.2.1.3 Ensure rsyslog default file permissions configured   228"
echo "Run the following command and verify that $FileCreateMode is 0640 or more restrictive:"

echo "output of command"
grep ^\$FileCreateMode /etc/rsyslog.conf

echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host  . 229"
echo "Review the /etc/rsyslog.conf file and verify that logs are sent to a central host (where loghost.example.com is the name of your central log host): i.e. *.* @@loghost.example.com"

echo "output of command"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf


echo "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts."
echo "Run the following commands and verify the resulting lines are uncommented on designated log hosts and commented or removed on all others: \$ModLoad imtcp.so, \$InputTCPServerRun 514"

echo "output of command"
grep '$ModLoad imtcp.so' /etc/rsyslog.conf

echo "output of command"
grep '$InputTCPServerRun' /etc/rsyslog.conf


echo "4.2.2.1 Ensure syslog-ng service is enabled   233"
echo "Run the following command and verify result is 'enabled':"


echo "output of command"
systemctl is-enabled syslog-ng


echo "4.2.2.2 Ensure logging is configured  . 235"
echo "Review the contents of the /etc/syslog-ng/syslog-ng.conf file to ensure appropriate
logging is set. In addition, run the following command and ensure that the log files are
logging information:"
echo "/etc/syslog-ng/syslog-ng.conf files"


echo "output of command"
cat /etc/syslog-ng/syslog-ng.conf


echo "output of command"
ls -l /var/log/

echo "4.2.2.3 Ensure syslog-ng default file permissions configured  . 237"
echo "Run the following command and verify the perm option is 0640 or more restrictive:"

echo "output of command"
grep ^options /etc/syslog-ng/syslog-ng.conf

echo "4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host"
echo "Review the /etc/syslog-ng/syslog-ng.conf file and verify that logs are sent to a central host (where logfile.example.com is the name of your central log host): destination logserver"


echo "output of command"
cat /etc/syslog-ng/syslog-ng.conf


echo "4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts"
echo "Review the /etc/syslog-ng/syslog-ng.conf file and verify the following lines are configured appropriately on designated log hosts:"


echo "output of command"
cat /etc/syslog-ng/syslog-ng.conf

echo "4.2.3 Ensure rsyslog or syslog-ng is installed   242"
echo "Run the following commands and verify at least one indicates the package is installed:"

echo "output of command"
rpm -q rsyslog


echo "output of command"
rpm -q syslog-ng

echo "4.2.4 Ensure permissions on all logfiles are configured   244"
echo "Run the following command and verify that other has no permissions on any files and group does not have write or execute permissions on any files:"


echo "output of command"
find /var/log -type f -ls


echo "4.3 Ensure logrotate is configured  . 245"
echo "Review /etc/logrotate.conf and /etc/logrotate.d/ * and verify logs are rotated according to site policy."

echo "logrotate.conf"
echo "output of command"
cat /etc/logrotate.conf

echo "logrotate.d/*"
echo "output of command"
ls -l /etc/logrotate.d/


echo "5 Access, Authentication and Authorization . 245"
echo "5.1 Configure cron  246"
echo "5.1.1 Ensure cron daemon is enabled  . 246"
echo "Run the following command and verify result is 'enabled':"

echo "output of command"
systemctl is-enabled crond


echo "5.1.2 Ensure permissions on /etc/crontab are configured   247"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"

echo "output of command"
stat /etc/crontab

echo "5.1.3 Ensure permissions on /etc/cron.hourly are configured . 248"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"

echo "output of command"
stat /etc/cron.hourly


echo "5.1.4 Ensure permissions on /etc/cron.daily are configured   249"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"

echo "output of command"
stat /etc/cron.daily


echo "5.1.5 Ensure permissions on /etc/cron.weekly are configured  . 250"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"


echo "output of command"
stat /etc/cron.weekly


echo "5.1.6 Ensure permissions on /etc/cron.monthly are configured  . 251"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"

echo "output of command"
stat /etc/cron.monthly


echo "5.1.7 Ensure permissions on /etc/cron.d are configured  . 252"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"

echo "output of command"
stat /etc/cron.d


echo "5.1.8 Ensure at/cron is restricted to authorized users   253"
echo "Run the following commands and ensure /etc/cron.deny and /etc/at.deny do not exist:"

echo "output of command"
stat /etc/cron.deny

echo "output of command"
stat /etc/at.deny


echo "5.2 SSH Server Configuration . 255
5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured   255"
echo "Run the following command and verify Uid and Gid are both 0/root and Access does not
grant permissions to group or other (0600)"


echo "output of command"
stat /etc/ssh/sshd_config


echo "5.2.2 Ensure SSH Protocol is set to 2  . 257"

echo "output of command"
grep "^Protocol" /etc/ssh/sshd_config


echo "5.2.3 Ensure SSH LogLevel is set to INFO   258"
echo "Run the following command and verify that output matches:i.e. LogLevel INFO"

echo "output of command"
grep "^LogLevel" /etc/ssh/sshd_config


echo "5.2.4 Ensure SSH X11 forwarding is disabled   259"
echo "Run the following command and verify that output matches:i.e. X11Forwarding no"


echo "output of command"
grep "^X11Forwarding" /etc/ssh/sshd_config



echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less  . 260"
echo "Run the following command and verify that output MaxAuthTries is 4 or less:"

echo "output of command"
grep "^MaxAuthTries" /etc/ssh/sshd_config


echo "5.2.6 Ensure SSH IgnoreRhosts is enabled   261"
echo "Run the following command and verify that output matches: i.e. IgnoreRhosts yes"

echo "output of command"
grep "^IgnoreRhosts" /etc/ssh/sshd_config

echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled   262"
echo "Run the following command and verify that output matches:i.e. HostbasedAuthentication no"

echo "output of command"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config


echo "5.2.8 Ensure SSH root login is disabled   263"
echo "Run the following command and verify that output matches:PermitRootLogin no"

echo "output of command"
grep "^PermitRootLogin" /etc/ssh/sshd_config



echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled  . 264"
echo "Run the following command and verify that output matches: i.e. PermitEmptyPasswords no"

echo "output of command"
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config


echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled  . 265"
echo "Run the following command and verify that output matches: i.e. PermitUserEnvironment no"

echo "output of command"
grep PermitUserEnvironment /etc/ssh/sshd_config


echo "5.2.11 Ensure only approved ciphers are used  . 266"
echo "Run the following command and verify that output does not contain any cipher block
chaining (-cbc) algorithms:"

echo "output of command"
grep "Ciphers" /etc/ssh/sshd_config


echo "5.2.12 Ensure only approved MAC algorithms are used   268"
echo "Run the following command and verify that output does not contain any unlisted MAC
algorithms:"

echo "output of command"
grep "MACs" /etc/ssh/sshd_config


echo "5.2.13 Ensure SSH Idle Timeout Interval is configured  . 270"
echo "Run the following commands and verify ClientAliveInterval is 300 or less and ClientAliveCountMax is 3 or less:"

echo "output of command"
grep "^ClientAliveInterval" /etc/ssh/sshd_config

echo "output of command"
grep "^ClientAliveCountMax" /etc/ssh/sshd_config


echo "5.2.14 Ensure SSH LoginGraceTime is set to one minute or less  272"
echo "Run the following command and verify that output LoginGraceTime is 60 or less:"

echo "output of command"
grep "^LoginGraceTime" /etc/ssh/sshd_config


echo "5.2.15 Ensure SSH access is limited  . 273"
echo "Run the following commands and verify that output matches for at least one: i.e. AllowUsers <userlist>, AllowGroups <grouplist>, DenyUsers <userlist>, DenyGroups <grouplist>"


echo "output of command"
grep "^AllowUsers" /etc/ssh/sshd_config

echo "output of command"
grep "^AllowGroups" /etc/ssh/sshd_config

echo "output of command"
grep "^DenyUsers" /etc/ssh/sshd_config

echo "output of command"
grep "^DenyGroups" /etc/ssh/sshd_config


echo "5.2.16 Ensure SSH warning banner is configured   275"
echo "Run the following command and verify that output matches: Banner /etc/issue.net"


echo "output of command"
grep "^Banner" /etc/ssh/sshd_config

echo "5.3 Configure PAM  276
5.3.1 Ensure password creation requirements are configured   276, password requisite pam_pwquality.so try_first_pass retry=3, password requisite pam_pwquality.so try_first_pass retry=3, minlen=14, dcredit=-1, lcredit=-1, ocredit=-1, ucredit=-1"


echo "output of command"
grep pam_pwquality.so /etc/pam.d/password-auth


echo "output of command"
grep pam_pwquality.so /etc/pam.d/system-auth

echo "output of command"
grep ^minlen /etc/security/pwquality.conf

echo "output of command"
grep ^dcredit /etc/security/pwquality.conf

echo "output of command"
grep ^lcredit /etc/security/pwquality.conf

echo "output of command"
grep ^ocredit /etc/security/pwquality.conf


echo "output of command"
grep ^ucredit /etc/security/pwquality.conf



echo "5.3.2 Ensure lockout for failed password attempts is configured  278"
echo "Review the /etc/pam.d/password-auth and /etc/pam.d/system-auth files and verify the following pam_faillock.so lines appear surrounding a pam_unix.so line and the pam_unix.so is [success=1 default=bad] as listed in both:"


echo "output of command"
cat /etc/pam.d/password-auth


echo "output of command"
cat /etc/pam.d/system-auth


echo "5.3.3 Ensure password reuse is limited  280"
echo "Run the following commands and ensure the remember option is ' 5 ' or more and included in all results:"

echo "output of command"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth

echo "output of command"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth




echo "5.3.4 Ensure password hashing algorithm is SHA-512   281"
echo "Run the following commands and ensure the sha512 option is included in all results:"


echo "output of command"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth

echo "output of command"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth


echo "5.4 User Accounts and Environment  282
5.4.1.1 Ensure password expiration is 90 days or less  . 283"
echo "Run the following command and verify PASS_MAX_DAYS is 90 or less:"

echo "output of command"
grep PASS_MAX_DAYS /etc/login.defs


echo "5.4.1.2 Ensure minimum days between password changes is 7 or more  . 285"
echo "Run the following command and verify PASS_MIN_DAYS is 7 or more:"


echo "output of command"
grep PASS_MIN_DAYS /etc/login.defs


echo "5.4.1.3 Ensure password expiration warning days is 7 or more   287"
echo "Run the following command and verify PASS_WARN_AGE is 7 or more:"

echo "output of command"
grep PASS_WARN_AGE /etc/login.defs


echo "5.4.1.4 Ensure inactive password lock is 30 days or less   289"
echo "Run the following command and verify INACTIVE is 30 or less:"


echo "output of command"
useradd -D | grep INACTIVE

echo "Verify all users with a password have Password inactive no more than 30 days after
password expires:"


echo "output of command"
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1


echo "5.4.2 Ensure system accounts are non-login   291"
echo "Run the following script and verify no results are returned:"

echo "output of command"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'


echo "5.4.3 Ensure default group for the root account is GID 0   293"
echo "Run the following command and verify the result is 0 :"


echo "output of command"
grep "^root:" /etc/passwd | cut -f4 -d:


echo "5.4.4 Ensure default user umask is 027 or more restrictive   294"
echo "Run the following commands and verify all umask lines returned are 027 or more restrictive."


echo "output of command"
grep "^umask" /etc/bashrc

echo "output of command"
grep "^umask" /etc/profile


echo "5.5 Ensure root login is restricted to system console . 296"


echo "output of command"
cat /etc/securetty



echo "5.6 Ensure access to the su command is restricted  . 297"
echo "Run the following command and verify output includes matching line:auth required pam_wheel.so use_uid"


echo "output of command"
grep pam_wheel.so /etc/pam.d/su


echo "6 System Maintenance . 298
6.1 System File Permissions . 299
6.1.1 Audit system file permissions  . 299"
echo "Run the following command to review all installed packages."


echo "output of command"
rpm -Va --nomtime --nosize --nomd5 --nolinkto > audit_system_file_perm.txt

echo "6.1.2 Ensure permissions on /etc/passwd are configured  . 301"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"


echo "output of command"
stat /etc/passwd

echo "6.1.3 Ensure permissions on /etc/shadow are configured   302"
echo "Run the following command and verify Uid and Gid are 0/root , and Access is 000 :"

echo "output of command"
stat /etc/shadow


echo "6.1.4 Ensure permissions on /etc/group are configured   303"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 644 :"

echo "output of command"
stat /etc/group


echo "6.1.5 Ensure permissions on /etc/gshadow are configured   304"
echo "Run the following command and verify Uid and Gid are 0/root , and Access is 000 :"


echo "output of command"
stat /etc/gshadow


echo "6.1.6 Ensure permissions on /etc/passwd- are configured  . 305"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 600 or"


echo "output of command"
stat /etc/passwd-


echo "6.1.7 Ensure permissions on /etc/shadow- are configured  . 306"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:"


echo "output of command"
stat /etc/shadow-


echo "6.1.8 Ensure permissions on /etc/group- are configured   307"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:"


echo "output of command"
stat /etc/group-


echo "6.1.9 Ensure permissions on /etc/gshadow- are configured   308"
echo "Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:"


echo "output of command"
stat /etc/gshadow-


echo "6.1.10 Ensure no world writable files exist   309"
echo "Run the following command and verify no files are returned:"

echo "output of command"
df --local -P | awk 'if (NR!=1) print $6' | xargs -I '{}' find '{}' -xdev -type f -perm -0002

echo "6.1.11 Ensure no unowned files or directories exist  . 310"
echo "Run the following command and verify no files are returned:"


echo "output of command"
df --local -P | awk 'if (NR!=1) print $6' | xargs -I '{}' find '{}' -xdev -nouser


echo "6.1.12 Ensure no ungrouped files or directories exist   311"
echo "Run the following command and verify no files are returned:"

echo "output of command"
df --local -P | awk 'if (NR!=1) print $6' | xargs -I '{}' find '{}' -xdev -nogroup

echo "6.1.13 Audit SUID executables  . 312"
echo "Run the following command to list SUID files:"

echo "output of command"
df --local -P | awk 'if (NR!=1) print $6' | xargs -I '{}' find '{}' -xdev -type f -perm -4000


echo "6.1.14 Audit SGID executables  . 313"
echo "Run the following command to list SGID files:"

echo "output of command"
df --local -P | awk 'if (NR!=1) print $6' | xargs -I '{}' find '{}' -xdev -type f -perm -2000


echo "6.2 User and Group Settings . 315
6.2.1 Ensure password fields are not empty   315"
echo "Run the following command and verify that no output is returned:"


echo "output of command"
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'

echo "6.2.2 Ensure no legacy "+" entries exist in /etc/passwd  . 316"
echo "Run the following command and verify that no output is returned:"

echo "output of command"
grep '^+:' /etc/passwd


echo "6.2.3 Ensure no legacy '+' entries exist in /etc/shadow  . 317"
echo "Run the following command and verify that no output is returned:"

echo "output of command"
grep '^+:' /etc/shadow


echo "6.2.4 Ensure no legacy + entries exist in /etc/group   318"
echo "Run the following command and verify that no output is returned:"


echo "output of command"
grep '^+:' /etc/group



echo "6.2.5 Ensure root is the only UID 0 account   319"
echo "Run the following command and verify that only root is returned:"


echo "output of command"
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'


echo "6.2.6 Ensure root PATH Integrity  . 320"
echo "Run the following script and verify no results are returned:"


if [ "`echo $PATH | grep ::`" != "" ]; then
	echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`" != "" ]; then
	echo "Trailing : in PATH"
fi

p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
	if [ "$1" = "." ]; then
		echo "PATH contains ."
		shift
		continue
	fi
if [ -d $1 ]; then
	dirperm=`ls -ldH $1 | cut -f1 -d" "`
	if [ `echo $dirperm | cut -c6` != "-" ]; then
		echo "Group Write permission set on directory $1"
	fi
	if [ `echo $dirperm | cut -c9` != "-" ]; then
		echo "Other Write permission set on directory $1"
	fi
	dirown=`ls -ldH $1 | awk '{print $3}'`
	if [ "$dirown" != "root" ] ; then
		echo $1 is not owned by root
	fi
	else
		echo $1 is not a directory
	fi
	shift
done
echo "6.2.7 Ensure all users' home directories exist  . 322"
echo "Run the following script and verify no results are returned:"


cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
	if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	fi
done


echo "6.2.8 Ensure users' home directories permissions are 750 or more restrictive"
echo "Run the following script and verify no results are returned:"

for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F:'($7 != "/sbin/nologin") { print $6 }'`; do
	dirperm=`ls -ld $dir | cut -f1 -d" "`
	if [ `echo $dirperm | cut -c6` != "-" ]; then
		echo "Group Write permission set on directory $dir"
	fi
	if [ `echo $dirperm | cut -c8` != "-" ]; then
		echo "Other Read permission set on directory $dir"
	fi
	if [ `echo $dirperm | cut -c9` != "-" ]; then
		echo "Other Write permission set on directory $dir"
	fi
	if [ `echo $dirperm | cut -c10` != "-" ]; then
		echo "Other Execute permission set on directory $dir"
	fi
done



echo "6.2.9 Ensure users own their home directories   325"
echo "Run the following script and verify no results are returned:"

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
	if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
	owner=$(stat -L -c "%U" "$dir")
	if [ "$owner" != "$user" ]; then
	echo "The home directory ($dir) of user $user is owned by $owner."
	fi
	fi
done



echo "6.2.10 Ensure users' dot files are not group or world writable   326"
echo "Run the following script and verify no results are returned:"


for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
	for file in $dir/.[A-Za-z0-9]*; do
		if [ ! -h "$file" -a -f "$file" ]; then
			fileperm=`ls -ld $file | cut -f1 -d" "`
			if [ `echo $fileperm | cut -c6` != "-" ];then
				echo "Group Write permission set on file $file"
			fi
			if [ `echo $fileperm | cut -c9` != "-" ]; then
				echo "Other Write permission set on file $file"
			fi
		fi
	done
done



echo "6.2.11 Ensure no users have .forward files  . 328"
echo "Run the following script and verify no results are returned:"


for dir in `cat /etc/passwd |\
	awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
		echo ".forward file $dir/.forward exists"
	fi
done


echo "6.2.12 Ensure no users have .netrc files  . 329"
echo "Run the following script and verify no results are returned:"


for dir in `cat /etc/passwd |\
	awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
		echo ".netrc file $dir/.netrc exists"
	fi
done


echo "6.2.13 Ensure users' .netrc Files are not group or world accessible  . 330"
echo "Run the following script and verify no results are returned:"


for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: 
'($7 != "/sbin/nologin") { print $6 }'`; do
	for file in $dir/.netrc; do
		if [ ! -h "$file" -a -f "$file" ]; then
			fileperm=`ls -ld $file | cut -f1 -d" "`
			if [ `echo $fileperm | cut -c5` != "-" ]; then
				echo "Group Read set on $file"
			fi	
			if [ `echo $fileperm | cut -c6` != "-" ]; then
				echo "Group Write set on $file"
			fi
			if [ `echo $fileperm | cut -c7` != "-" ]; then
				echo "Group Execute set on $file"
			fi
			if [ `echo $fileperm | cut -c8` != "-" ]; then
				echo "Other Read set on $file"
			fi
			if [ `echo $fileperm | cut -c9` != "-" ]; then
				echo "Other Write set on $file"
			fi
			if [ `echo $fileperm | cut -c10` != "-" ]; then
				echo "Other Execute set on $file"
			fi
		fi
	done
done


		

echo "6.2.14 Ensure no users have .rhosts files  . 332"
echo "Run the following script and verify no results are returned:"
	


for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F:'($7 != "/sbin/nologin") { print $6 }'`; do
		for file in $dir/.rhosts; do
			if [ ! -h "$file" -a -f "$file" ]; then
				echo ".rhosts file in $dir"
			fi
		done
done



echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group  . 333"
echo "Run the following script and verify no results are returned:"


for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
	grep -q -P "^.*?:[^:]*:$i:" /etc/group
	if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done



echo "6.2.16 Ensure no duplicate UIDs exist   334"
echo "Run the following script and verify no results are returned:"


cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
		echo "Duplicate UID ($2): ${users}"
	fi
done


echo "6.2.17 Ensure no duplicate GIDs exist  . 335"
echo "Run the following script and verify no results are returned:"


cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
		echo "Duplicate GID ($2): ${groups}"
	fi
done


echo "6.2.18 Ensure no duplicate user names exist  . 336"
echo "Run the following script and verify no results are returned:"


cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
		echo "Duplicate User Name ($2): ${uids}"
	fi
done



echo "6.2.19 Ensure no duplicate group names exist"
echo "Run the following script and verify no results are returned:"


cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
		echo "Duplicate Group Name ($2): ${gids}"
	fi
done


