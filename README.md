Cpanel Security
===============

About
-----

Bash functions to help when administering cpanel servers, I found
them helpful when doing abuse/security work. Simply source the file
and you should be good to go, auto-complete offered in many cases.

Includes several other tools written in PHP and Python for tasks 
such as CMS password changing, injection removal, server audits,
and checking IPs against email blacklistings


Requirements
------------

+ CentOS
+ Cpanel
+ CSF Firewall (recommended)
+ [The Silver Surfer](https://github.com/ggreer/the_silver_searcher) (recommended)

To use simple clone repo into a folder. Edit the `INSTALLDIR` bash variable at the top of cpanelsec.sh  and checkrbl.py to reflect this location.
Then just `source cpanelsec.sh`. Note if using silver surfer please install it into `$INSTALLDIR/ag/`

Documentation
-------------

Mail Functions
--------------

**pwnmail [STRING]**: Removes email from exim mail queue given string, matches recipient, sender, or ID.
Can remove frozen emails with "frozen" and old emails with the command `pwnoldmail`

**addspf [USER]**: adds a 'strong' SPF record (-all) to the given cpanel user name's domains

**adddkim [USER]**: adds domain keys (or DKIM) to given cpanel user's domain

**chkmailabuse**: Shows scripts sending out mail, useful for finding malicious
files blasting out spam.

**check_rbl**: command line RBL checker, no argument checks current IPs, -a checks all. 
Or you can give it a specific IP as an argument. List of rbls is in rblist

**switchmailip**: provides a list of all server IPs and prompts for which IP to send mail from

**rdns_check**: does a check to ensure rDNS is properly configured

**scramble_emaili [EMAIL ADDRESS]**: inserts !!ABUSE!! into the email hash for the address, 
allows user to reset the email password after a compromise while preventing further spam

**train_sa [USER]**: Trains SpamAssassin for a given cpanel user, must have user create two email folders: 
HAM-TRAIN (with 200+ non-spam emails) and SPAM-TRAIN (200+ spam emails).

**checkmail**: checks exim and prompts if recommended anti-spam settings are not enabled. Checks for SPF checking, 
Spamhaus RBL, and Spamcop RBL


Malware Search/Cleanup
----------------------

**injectcleaner**: Uses the pyclean Python script to remove malicious injections.
Given a regex pattern this allows you to visually see what will be matched before
you remove it. Can be run without verification using -f and against a list of files
with -l

```
Usage: injectcleaner [options] REGEX FILE

Options:
  -h, --help       show this help message and exit
  -l, --list-file  use a list file
  -b, --backup     make backup files
  -f, --force      supress confirmation notice
```

**pwn [FILE]**: 'disables' file(s), sets targets to permissions 000 and owner root:root. Can be undone with `unpwn`

**qgrep [-l -s -p] [-c CUSTOM]**: (quick)grep, searches for  common base64 injections and shells across code files only. Flags are below:

+ no arguments defaults to base64 injection search
+ -l list files (analagous to grep -l)
+ -s shellsearch (searches for list on shells found in shell_patterns file)
+ -p ignores files with perm 000
+ -c CUSTOM, looks for custom string

**qgrep_ag**: same as qgrep but uses silver surfer to search

**shellscan**: searches across public_html folders for all cpanel users looking for shells, places results in
$INSTALLDIR/possible_shells.txt. `shellscan_ag` is the ag version.

**phishing_scams**: greps for common phishing words in all domain names

**mitigate_ddos**: Uses a python script that automatically temp bans (using CSF) IPs with over 30 connections

Account/System Maintenance
--------------------------

**secimgdir**: modifies (or creates) .htaccess file in current directory to prevent script execution. 
Useful for folders such as "/images" or "/uploads" which shouldn't be executing anything

**sysinfo**: Quick glance at CSF settings, exim queue size, external connections and disk
quotas for users.

**inodebreakdown**: If inode restrictions are in place this will give a pretty accurate listing
of folders containing the most inodes for abuse notices.

**grepuser [USER/DOMAIN]**: searches a string in userdomains and cpanel account names

**trafficstats [DOMAIN]**: given a domain it returns the number of hits in the last 24 hours, autocompletes
based on domain names in /etc/httpd/domlogs

**lshtaccess**: find and prints .htaccess files recursively, useful for finding malicious redirects

**chpass [USER]**: Generates random password for given user, also runs ftpupdate
script to make cpanel happy

**cmspass**: Automatically find and detect Joomla/WordPress installations and change
all admin passwords to random 10 character strings

**owner [USER]**: finds owner of cpanel account, auto-completes cpanel names

**fixperms**: recursively sets files to 644 and folders to 755. Leaves cms config files as 600

**rmsymlinks**: recursively removes symlinks (safely). For use in symlink attacks

**www USER**: jumps to cpanel user's public_html folder, autocompletes cpanel account names

**chkbackup [FILE]**: compares FILE with copies in daily, weekly, and monthly backups. Helpful when only a single file
 needs to be restore, avoids full account backup.

**vzsuspend [VEID]**: suspends OpenVZ container, can be unsuspended with `vzunsuspend`

**lscpanelsec**: lists all commands and arguments for easy reference
