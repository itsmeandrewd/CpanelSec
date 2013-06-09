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


Some of the functions include:
------------------------------

**injectcleaner**. Uses my pyClean Python script to remove malicious injections.
Given a regex pattern this allows you to visually see what will be matched before
you remove it. Can be run without verification using -f and against a list of files
with -l

**sysinfo**: Quick glance at CSF settings, exim queue size, external connections and disk
quotas for users.

**inodebreakdown**: If inode restrictions are in place this will give a pretty accurate listing
of folders containing to most inodes for abuse notices.

**chkmailabuse**: Shows scripts sending out mail, useful for finding malicious
files blasting out spam.

**chpass**: Generates random password for given user, also runs ftpupdate
script to make cpanel happy

**qgrep**: Find shells, base64 code, or other content when grep -r is slow due to
server load or accounts with a million inodes

**cmspass**: Automatically find and detect Joomla/WordPress installations and change
all admin passwords to random 10 character strings

**hazexploit**: search for exploits on the command line using the exploitDB API
