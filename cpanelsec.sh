#!/bin/bash


# Deletes mail from exim queue based on regex pattern match of sender
pwnmail() {
    if [ -z "$1" ]; then
        echo "Usage: pwnmail STRING"
        return
    fi

    exim -bp | grep -B1 "$1" | grep '<.*>' | awk '{print $3}' | while read line; do exim -Mrm $line; done
}


# adds SPF record to all domains under a user account, uses -all hard fail record
addspf() {
    if [ -z "$1" ]; then
        echo "Usage: addspf USER"
        return
    fi
    /usr/local/cpanel/bin/spf_installer "$1" '' 1 1
    echo "Added SPF records for account $1"
}


# uses exploitdb API to allow for command line search of exploits
hazexploit() {
  php exploitdb.php "$@"
}


# change WordPress/Joomla admin passwords via terminal
cmspass() {
 
    php cmspass.php "$@"
}


# tool to remove malicious code injections
injectcleaner() {
    python pyClean.py "$@"
}


# provide useful system stats
sysinfo() {
    echo '[===SYSTEM BUILD===]'; uname -a; echo '[===LANGUAGE HANDLERS===]'; /usr/local/cpanel/bin/rebuild_phpconf --current; echo '[===PHP CONFIG===]'; egrep -i "(disable_fun)"  /usr/local/lib/php.ini | sed 's/;//'; echo '[===FIREWALL STATUS===]'; egrep "(SMTP_BLOCK|SMTP_ALLOWLOCAL|SMTP_PORTS)[[:space:]]?=" /etc/csf/csf.conf; csf -v; echo '[===EMAIL STATUS===]'; echo Emails per Hour: $(cat /var/cpanel/maxemailsperhour); echo Emails in Queue: $(exim -bpc); echo '[===RESOURCE ALLOCATION===]'; OUT=$(/usr/local/cpanel/bin/dcpumonview | grep -v Top | sed -e 's#<[^>]*># #g' | while read i ; do NF=`echo $i | awk {'print NF'}` ; if [[ "$NF" == "5" ]] ; then USER=`echo $i | awk '{print $1}'`; OWNER=`grep -e "^OWNER=" /var/cpanel/users/$USER | cut -d= -f2` ; echo "$OWNER $i"; fi ; done) ; (echo "USER CPU" ; echo "$OUT" | sort -nrk4 | awk '{print $2,$4}' | head -5) | column -t ; echo; (echo -e "USER MEMORY" ; echo "$OUT" | sort -nrk5 | awk '{print $2,$5}' | head -5) | column -t; echo '[===ESTABLISHED CONNECTIONS===]'; PORTS=([80]=Apache [110]=POP3 [143]=IMAP [25]=SMTP [26]=SMTP [21]=FTP); netstat -plan > /root/stats.txt; for port in ${!PORTS[*]}; do echo "$(tput bold)${PORTS[$port]}($port):$(tput sgr0)"; grep $port /root/stats.txt | awk {'print $5'} | grep -Po "\d{1,3}(?:\.\d{1,3}){3}" | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq -c | sort -nk 1 | grep -v "0.0.0.0" | tail -5 | awk '{ if ( $1 > 35 ) { printf "\033[1;31m" } else if ( $1 > 25 ) { printf "\033[1;33m" } else { printf "\033[1;32m" } ; print " ", $1, "\033[0;39m", $2 }'; done; rm -f /root/stats.txt; echo '[===CONNECTIONS BY DOMAIN===]';  lynx -dump -width=200 localhost/whm-server-status | grep 'POST\|GET' | awk '{print $12}' | sort | uniq -c; echo '[===DISK ALLOCATION===]'; df -h; echo '[===INODE AUDIT===]'; cat /etc/domainusers | cut -f1 -d: | sort -nk1 | while read USER; do quota -s $USER; done | grep '[0-9]k' -B 2 | grep -v "-" | grep '[0-9]k' -B 2; echo '[===EXCLUDED USERS===]'; cat /etc/cpbackup-userskip.conf; screen -ls; cat /etc/cpspamd.conf;

}


# useful for providing inode counts
inodebreakdown() {
    find . -maxdepth 1 -type d | while read line ; do echo "$( find "$line"| wc -l) $line" ; done | sort -rn
}


# add or edit a .htaccess in current dir to prevent exection of code
secimgdir() {
    if [ ! -f .htaccess ];then
        echo -e "AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi .php5 .php4 .php3 .phps .txt .bat .cmd .rb\nOptions -ExecCGI -Indexes" > .htaccess
        chattr +ai .htaccess
    else
        sed -i '1s/^/AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi .php5 .php4 .php3 .phps .txt .bat .cmd .rb\nOptions -ExecCGI -Indexes\n/' .htaccess
        chattr +ai .htaccess
    fi
    echo ".htaccess edited."
}


# show rough number of 'hits' for a given domain
trafficstats() {
    if [ -z "$1" ];then
        echo "Usage: trafficstats [-f] DOMAIN"
        return
    fi
    if [ ! -f /etc/httpd/domlogs/"$1" ];then
        echo "Domain $1 not found."
        return
    fi
    
	local BEGIN=`head -n1 /etc/httpd/domlogs/"$1" | awk '{print $4$5}'`
	local END=`tail -n1 /etc/httpd/domlogs/"$1" | awk '{print $4$5}'`
	local HITS=`wc -l /etc/httpd/domlogs/"$1"| awk '{print $1}'`
	echo "From $BEGIN to $END there were $HITS hits for $1"
}

_trafficstats() {
    local cur
    cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=( $( compgen -f /etc/httpd/domlogs/$cur | perl -pi -e 's/.*\/(.*)/$1/g' ) )
}

complete -o nospace -F _trafficstats trafficstats 
alias dcpumonview="/usr/local/cpanel/bin/dcpumonview" 


# shorcuts for viewing exim queue and queue size
alias mc="exim -bpc" 
alias m="exim -bp" 


# check for scripts which have sent emails (useful for find spam)
alias chkmailabuse='less /var/log/exim_mainlog | grep sendmail | grep -vE "csf|FCron"' 


alias grep="grep --color=auto" 
alias ll='ls -Alh --color=tty' 


# shortcuts for checking logs, headers, and bodies of email
alias vb='exim -Mvb' 
alias vh='exim -Mvh' 
alias vl='exim -Mvl' 


# list content in all .htaccess files, common location for malicious code
alias lshtaccess='find -type f -name .htaccess -printf "\n\n=== %p ===\n" -exec cat {} \;' 


# find account which owns a given domain/account
owner() {
    if [ -z "$1" ];then
        echo "Usage: owner USER"
        return
    fi
    grep "$1" /etc/trueuserowners
}
complete -o nospace -F _www owner 


# 'disable' access to file/dir, sets permission to 000 and owner to root
# useful for disabling content on shared servers
pwn() {
    if [ -z "$1" ];then
        echo "Usage: pwn FILES"
        return
    fi
    until [ -z "$1" ];do
        chmod 000 "$1"
        chown 0:0 "$1"
        shift
    done
}


# restore access to file/dir
unpwn() {
    if [ -z "$1" ];then
        echo "Usage: unpwn FILES"
        return
    fi
    until [ -z "$1" ];do
        if [ -d "$1" ];then
            chmod 755 "$1"
        else
            chmod 644 "$1"
        fi
        chown `pwd | cut -d/ -f3`:`pwd | cut -d/ -f3` "$1"
        shift
    done
}


# for accounts on shared servers only! restore 'sane' permissions. Set files to
# 644 and directories to 755, set cms config files to 600
fixperms() {
    find -type f ! -perm 000 -exec bash -c 'if [[ "$1" =~ "wp-config.php" || "$1" =~ "configuration.php" ]];then chmod 600 "$1";else chmod 644 "$1";fi' bash '{}' \;
    find -type d ! -perm 000 -exec chmod 755 {} \;
}


# recursively remove all symlinks (usually upon find malicious symlinks on account)
rmsymlinks() {
    find -type l -exec unlink {} \;
}


# go to public_html folder of given username, a bit lazy but in conjunction
# with tab completion I find it helpful :P
www() {
    if [ -z "$1" ];then
        echo "Usage: www USER"
        return
    fi
    if [ ! -d /home/"$1"/public_html ];then
        echo "Public html directory for user $1 not found."
        return
    fi
    cd /home/"$1"/public_html
}


# tabcompletion of cpanel usernames
_www() {
    local cur
    cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=( $( compgen -f /var/cpanel/users/$cur | perl -pi -e 's/.*\/(.*)/$1/g' ) )
}

complete -o nospace -F _www www 
complete -o nospace -F _www addspf 


# change account password to random 10 character string
chpass() {
    if [ -z "${ALLOW_PASSWORD_CHANGE+xxx}" ];then
        export ALLOW_PASSWORD_CHANGE=1
    fi
    if [ -z "$1" ];then
        echo "Usage: chpass USER"
        return
    fi
    
    local NEWPW=`cat /dev/urandom| tr -dc 'a-zA-Z0-9' | head -c 10`
    echo "Changing password for user $1 to: $NEWPW"
    /scripts/chpass "$1" "$NEWPW"
    if [ $? -ne 0 ];then
        return
    fi
    /scripts/ftpupdate
}

complete -o nospace -F _www chpass 


# 'Quick' grep, greps for base64_encode references (commonly used in malware)
# using find and xargs which is quicker (but less comprehensive) than a grep -r
# can also find 'shells' if given the -s option, custom target with -c and
# ignores perm 000 files with -p
qgrep() {
    local OPTIND
    local OPTARG
    while getopts ":plsc:" opt; do
        case $opt in
            p ) local NONULL='! -perm 000' ;;
            l ) local LFILES='-EHil' ;;
        s ) local SHLLSRCH="(c3284|psbt|mjdu|gdsg|filesman|system.file.do.not.delete|2e922c|r57shell|default_action|tryag_vb|priv8|@error_reporting\(0\))";;
            c ) local SHLLSRCH="($OPTARG)";;
	    : ) echo "-$OPTARG requires an argument";return 1;;
            \? ) echo "Usage: qgrep [-l (list files)] [-s (shells) ] [-p (no perm 000) ] [-c SEARCHSTR]"
                return 1;;
        esac
    done
    GREPARGS=${LFILES:-'-EHi'}
    ARGS1=${NONULL:-''}
    SEARCH=${SHLLSRCH:-"(gzinflate|base64_decode|strrev)"}
    find -type f $ARGS1 -regex ".*\.\(htm\|html\|php\|inc\|tmp\|js\|htaccess\|pl\)" -print0 | xargs -0 grep $GREPARGS $SEARCH --color=auto
    return 0
}


# very simple 'shell' scanner to find malicious files in accounts
shellscan() {
    for user in /var/cpanel/users/*;do
        account=$(basename $user)
        echo -e "\n===\n$account\n===\n"
        www $account

        if [ $? -eq 0 ];then
            qgrep -ps
        fi
    done
}


# check individual files against copies in backup and restores if desired
# I find this helpful when only a single file like index.php was hacked
chkbackup() {
    if [ -z "$1" ];then
        echo "Usage: chkbackup FILE"
        return
    fi
    local ACCOUNT=$(readlink -f "$1" | cut -d/ -f3)
    local TARGET=$(readlink -f "$1" | awk -F "public_html/" '{print $2}')
    diff /backup/cpbackup/daily/"$ACCOUNT"/homedir/public_html/"$TARGET" /home/"$ACCOUNT"/public_html/"$TARGET" 2> /dev/null
    if [ $? -ne 0 ];then
        echo "Restore file? (y or n): "
        read option
        if [ "$option" == "y" ];then
            cp /backup/cpbackup/daily/"$ACCOUNT"/homedir/public_html/"$TARGET" $(dirname /home/"$ACCOUNT"/public_html/"$TARGET")
            return
        fi
    else
        echo "No changes in daily copy"
    fi
    diff /backup/cpbackup/weekly/"$ACCOUNT"/homedir/public_html/"$TARGET" /home/"$ACCOUNT"/public_html/"$TARGET" 2> /dev/null
    if [ $? -ne 0 ];then
        echo "Restore file? (y or n): "
        read option
        if [ "$option" == "y" ];then
            cp /backup/cpbackup/weekly/"$ACCOUNT"/homedir/public_html/"$TARGET" $(dirname /home/"$ACCOUNT"/public_html/"$TARGET")
            return
        fi
    else
        echo "No changes in weekly copy"
    fi
    diff /backup/cpbackup/monthly/"$ACCOUNT"/homedir/public_html/"$TARGET" /home/"$ACCOUNT"/public_html/"$TARGET" 2> /dev/null
    if [ $? -ne 0 ];then
        echo "Restore file? (y or n): "
        read option
        if [ "$option" == "y" ];then
            cp /backup/cpbackup/monthly/"$ACCOUNT"/homedir/public_html/"$TARGET" $(dirname /home/"$ACCOUNT"/public_html/"$TARGET")
            return
        fi
    else
        echo "No changes in monthly copy"
    fi
}


# Add Domain Keys or DKIM records to all domains under an account
adddkim() {
    if [ -z "$1" ];then
        echo "Usage: adddkim USER"
        return
    fi
    if [ -e /usr/local/cpanel/bin/domain_keys_installer ];then
        /usr/local/cpanel/bin/domain_keys_installer "$1"
        echo "Added domain keys for user $1"
    else
        /usr/local/cpanel/bin/dkim_keys_install "$1"
        echo "Added DKIM for user $1"
    fi
}

complete -o nospace -F _www adddkim 


# Audit CentOS server and send report via email
ServerAudit() {
    python audit/audit.py "$1"
}


# check for RBL listings on major blacklists
check_rbl() {
    python checkrbl.py
}


# Lists all OpenVZ containers and associated load
alias vzusage="vzlist -o ctid,laverage,hostname"


# lists all functions for easy reference
lsandrew() {
    echo -e "pwnmail STRING\naddspf USER\ninjectcleaner [-l] [-b] PATTERN [FILE|LIST]\nsysinfo\ninodebreakdown\nsecimgdr"
    echo -e "trafficstats [-f] DOMAIN\npwn FILE\nfixperms\nrmsymlinks\nwww USER\nchpass USER\nchkmailabuse"
    echo -e "qgrep [-f (full)] [-l (list)] [-h (hack|shell) ] [-p (no perm 000) ] [search str]"
    echo -e "chkbackup FILE\nowner USER\n"
    echo -e "adddkim USER\nunpwn USERS\nvzusage\ncheck_rbl"
}
