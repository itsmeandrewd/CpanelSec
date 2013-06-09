#!/usr/bin/env python
# Andrew De Stefano

from commands import getstatusoutput
import os
import sys

data = ""

def gs(cmd):
    return getstatusoutput(cmd)[1]

# remove me, the formatting was previously a bit more complex, now just replace \n with \line
# don't really need a function
def rtfstring(text):
    return text.replace("\n", "\\line ")

def green(text):
    return '\033[92m' + text + '\033[0m'

def yellow(text):
    return '\033[93m' + text + '\033[0m'

def main():

    if len(sys.argv) < 2:
        sys.stderr.write('Usage: ' + sys.argv[0] +' EMAIL\n')
        sys.exit(1)

    print "Generating audit...",

    email = sys.argv[1].lower()

    date        = gs('date +%m/%d/%Y')
    hostname    = gs('hostname')
    ipaddress   = gs('hostname -i')
    osver       = gs('cat /etc/redhat-release')
    cpanelver   = gs('cat /usr/local/cpanel/version')
    kernelver   = '\t' + gs('uname -r')
    mqueue      = gs('exim -bpc')
    freespace   = rtfstring(gs('df -H'))
    inodeaudit  = rtfstring(gs("cat /etc/domainusers | cut -f1 -d: | sort -nk1 | while read USER; do quota -s $USER; done | grep '[0-9]k' -B 2 | grep -v '-' | grep '[0-9]k' -B 2"))
    backupusers = rtfstring(gs('echo "Users in cpbackup-userskip";if [ -z /etc/cpbackup-userskip.conf ];then echo "None"; else cat /etc/cpbackup-userskip.conf;fi'))

    resources   = rtfstring(gs('sh res.sh'))

    mount       = rtfstring(gs('mount | column -t'))

    global data
    infile = open('ServerAuditTemplate.rtf', 'r')
    data = infile.read()
    infile.close()

    # when adding new vars just make sure stubs[x] = osdata[x]
    stubs = [ '#DATE#', '#HOSTNAME#', '#NAME#', '#IPADDRESS#', '#OSVER#', '#CPANELVER#', '#KERNELVER#', '#MQUEUE#',
            '#FREESPACE#', '#INODEAUDIT#', '#BACKUPUSERS#', '#RESOURCES#', '#MOUNT#' ]
    osdata = [ date, hostname, name, ipaddress, osver, cpanelver, kernelver, mqueue, 
            freespace, inodeaudit, backupusers, resources, mount ]

    def func(a, b):
        global data
        data = data.replace(a, b)

    map(func, stubs, osdata)

    outfile = open('ServerAuditTemplate.rtf', 'w')
    outfile.write(data)
    outfile.close()

    os.system('bash sendattach.sh ' + email)
    os.system('rm ServerAuditTemplate.rtf -f;rm sendattach.sh -f;rm audit.py -f;rm res.sh -f')

    print green("DONE!")
    print "Server audit template emailed!"


if __name__ == "__main__":
    main()
