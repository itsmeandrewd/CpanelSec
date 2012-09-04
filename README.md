Cpanel Security
===============

About
-----

Bash functions to help when administering cpanel servers, I found
them helpful when doing abuse/security work. Simply source the file
and you should be good to go, auto-complete offered by most.


Usage
-----

**pwnmail**: Requires exim, deletes  emails based on string match
from the queue, in the case of a a huge queue (100k+) I'd suggest using exim
stats + exiqsum and seeing if its all from one or two users and then just
deleting and recreating /var/spool/exim/input and msglog as its
faster.

**cmscheck**: Checks recursively for cms software in use and lists
installed version and latest version. Helpful to show clients who are running
Wordpres 2.0 and keep getting hacked.

**addspf**: Adds SPF records from the command line, helps in cases
where emails are not being blocked by blacklists but are ending
up in the spam folder

**injectcleaner**. Be _VERY_ careful with this. Make sure your regular expressions are
spot on. Uses a perl hack to handle multiline injections (sed won't do it).
Is designed with work with individual files (use -b flag to make a  backup in case). Or
-l mean to work with a textfile contained a list of files (generally grep -rl output).

**sysinfo**: Quick glance at CSF settings, exim queue size, external connections and disk
quotas for users.

**inodebreakdown**: If inode restrictions are in place this will give a pretty accurate listing
of folders containing to most inodes for abuse notices.

**secimgdir**: I've found that /images directories are a very popular spot for shells, running this
in a directory creates a .htaccess with rules preventing any script execution.

**grepuser**: Find domains owned by user or vice versa

**trafficstats**: Auto-completes based on domains on server, gives you the number of hits
in the last 24 hours.

**chkmailabuse**: Shows scripts sending out mail, useful for finding malicious
files blasting out spam.

**owner**: Which accounts resellers own

**pwn**: For disabling access to a file

**fixperms**: Oh the permission settings used by clients... get those 777s out of there,
it's rather brute force though and certain files (such as wp-config.php) should be 600. Defaults
to 644 for files and 755 for dirs.

**rmsymlinks**: Deletes symlinks recursively, useful in symlink attacks (patch Apache!)

**www**: Jump to publichtml folder of user, autocompletes user names

**chpass**: Generates random password for given user and updates passwd, also runs ftpupdate
script to make cpanel happy

**beachheadfinder**: A systemwide symlink scanner, checks /home for possible symlink attacks

**qgrep**: Uses find to fine-tune checking for shells when grep -Ir is slow due to
server load or resellers with 8 billion accounts

**cpanel**: Checks for 'interesting' entires in cpanel logs for a given user

**chkbackup**: Determines if a given files has changes from daily and weekly backups and
offers to restore if so. Useful when only index.html has been hacked.

**lsandrew**: Shows all the functions and usages if you forget
