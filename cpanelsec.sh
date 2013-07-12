#!/bin/bash

PS1='╭─\[\033[01m\][ \[\033[01;34m\]\u@\h \[\033[00m\]\[\033[01m\]] \[\033[01;32m\]\w\[\033[00m\]\n╰─➤ ' 
unalias cp 
unalias vi 

pwnmail() {
    if [ -z "$1" ]; then
        echo "Usage: pwnmail STRING"
        return
    fi

    if [ "$1" == "frozen" ];then
        exiqgrep -z -i | xargs exim -Mrm
        return
    fi

    exim -bp | grep -B1 "$1" | grep '<.*>' | awk '{print $3}' | while read line; do exim -Mrm $line; done
}


addspf() {
    if [ -z "$1" ]; then
        echo "Usage: addspf USER"
        return
    fi
    /usr/local/cpanel/bin/spf_installer "$1" '' 1 1
    echo "Added SPF records for account $1"
}


hazexploit() {
    php exploitdb.php "$@"
}


cmspass() {
 
    if [ "$1" = "-r" ];then
        find -maxdepth 4 -type d -exec php cmspass {} 2> /dev/null \;
    else
        php cmspass.php "$@"
    fi

}


injectcleaner() {
    python pyclean.py "$@"
}


sysinfo() {
    echo '[===SYSTEM BUILD===]'; uname -a; echo '[===LANGUAGE HANDLERS===]'; /usr/local/cpanel/bin/rebuild_phpconf --current; echo '[===PHP CONFIG===]'; egrep -i "(disable_fun)"  /usr/local/lib/php.ini | sed 's/;//'; echo '[===FIREWALL STATUS===]'; egrep "(SMTP_BLOCK|SMTP_ALLOWLOCAL|SMTP_PORTS)[[:space:]]?=" /etc/csf/csf.conf; csf -v; echo '[===EMAIL STATUS===]'; echo Emails per Hour: $(cat /var/cpanel/maxemailsperhour); echo Emails in Queue: $(exim -bpc); echo '[===RESOURCE ALLOCATION===]'; OUT=$(/usr/local/cpanel/bin/dcpumonview | grep -v Top | sed -e 's#<[^>]*># #g' | while read i ; do NF=`echo $i | awk {'print NF'}` ; if [[ "$NF" == "5" ]] ; then USER=`echo $i | awk '{print $1}'`; OWNER=`grep -e "^OWNER=" /var/cpanel/users/$USER | cut -d= -f2` ; echo "$OWNER $i"; fi ; done) ; (echo "USER CPU" ; echo "$OUT" | sort -nrk4 | awk '{print $2,$4}' | head -5) | column -t ; echo; (echo -e "USER MEMORY" ; echo "$OUT" | sort -nrk5 | awk '{print $2,$5}' | head -5) | column -t; echo '[===ESTABLISHED CONNECTIONS===]'; PORTS=([80]=Apache [110]=POP3 [143]=IMAP [25]=SMTP [26]=SMTP [21]=FTP); netstat -plan > /root/stats.txt; for port in ${!PORTS[*]}; do echo "$(tput bold)${PORTS[$port]}($port):$(tput sgr0)"; grep $port /root/stats.txt | awk {'print $5'} | grep -Po "\d{1,3}(?:\.\d{1,3}){3}" | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq -c | sort -nk 1 | grep -v "0.0.0.0" | tail -5 | awk '{ if ( $1 > 35 ) { printf "\033[1;31m" } else if ( $1 > 25 ) { printf "\033[1;33m" } else { printf "\033[1;32m" } ; print " ", $1, "\033[0;39m", $2 }'; done; rm -f /root/stats.txt; echo '[===CONNECTIONS BY DOMAIN===]';  lynx -dump -width=200 localhost/whm-server-status | grep 'POST\|GET' | awk '{print $12}' | sort | uniq -c; echo '[===DISK ALLOCATION===]'; df -h; echo '[===INODE AUDIT===]'; cat /etc/domainusers | cut -f1 -d: | sort -nk1 | while read USER; do quota -s $USER; done | grep '[0-9]k' -B 2 | grep -v "-" | grep '[0-9]k' -B 2; echo '[===EXCLUDED USERS===]'; cat /etc/cpbackup-userskip.conf; screen -ls; cat /etc/cpspamd.conf;

}


inodebreakdown() {
    find . -maxdepth 1 -type d | while read line ; do echo "$( find "$line"| wc -l) $line" ; done | sort -rn
}


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


grepuser() {
    if [ -z "$1" ];then
        echo "Usage: grepuser USER"
        return
    fi
    grep "$1" /etc/userdomains
}


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
alias mc="exim -bpc" 
alias m="exim -bp" 
alias chkmailabuse='less /var/log/exim_mainlog | grep sendmail | grep -vE "csf|FCron"' 
alias grep="grep --color=auto" 
alias ll='ls -Alh --color=tty' 
alias vb='exim -Mvb' 
alias vh='exim -Mvh' 
alias vl='exim -Mvl' 
alias lshtaccess='find -type f -name .htaccess -printf "\n\n=== %p ===\n" -exec cat {} \;' 
alias pwnoldmail='exiqgrep -i -o 86400 | xargs exim -Mrm'


owner() {
    if [ -z "$1" ];then
        echo "Usage: owner USER"
        return
    fi
    grep "$1" /etc/trueuserowners
}
complete -o nospace -F _www owner 


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


fixperms() {
    find -type f ! -perm 000 -exec bash -c 'if [[ "$1" =~ "wp-config.php" || "$1" =~ "configuration.php" ]];then chmod 600 "$1";else chmod 644 "$1";fi' bash '{}' \;
    find -type d ! -perm 000 -exec chmod 755 {} \;
}


rmsymlinks() {
    find -type l -exec unlink {} \;
}


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

_www() {
    local cur
    cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=( $( compgen -f /var/cpanel/users/$cur | perl -pi -e 's/.*\/(.*)/$1/g' ) )
}

complete -o nospace -F _www www 
complete -o nospace -F _www addspf 


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

beachheadfinder() {
    screen -A -a -d -m -L -t 'Beach-Head Finder' -S 'bhfinder' /bin/bash -c "find /home* -type d \( -path '/home*/virtfs' -or -path '/home*/.cpan' -or -path '/home*/.cpanm' -or 
-path '/home*/cpeasyapache' -or -path '/home*/cpapachebuild' -or -path '/home*/cpphpbuild' -or -path '/home*/cpzendinstall' \) -prune -false -or -type l -not -lname 
'public_html' -not -lname '/usr/local/apache/domlogs/*' -not -path '/home*/*/mail/.*' -not -lname '/home*/*/.rvsitebuilder/projects/*' -not -lname 
'/var/cpanel/rvglobalsoft/rvsitebuilder/*' -not -lname '/var/netenberg/click_be/*' -not -lname '*/.click_be/database/' -not -lname '*/.click_be/advertisements/' -not -lname 
'*/.click_be/click_be/' -not -lname '*/.click_be/backup/' -not -lname '/usr/local/urchin/*' -not \( -path '/home*/*/wp-content/advanced-cache.php' -and -lname 
'/home*/wp-content/plugins/*' \) -not \( -path '/home*/rvadmin/public_html/rvadmin/themeimages/tran' -and -lname '/usr/local/cpanel/base/frontend/*/themeimages/tran' \) -printf 
'%p => %l\n\c' -fprintf '/dev/stderr' '%p => %l\n\c' 2>> /root/found_links.txt"
}


qgrep() {

    local OPTIND
    local OPTARG
    while getopts ":plsc:" opt; do
        case $opt in
            p ) local NONULL='! -perm 000' ;;
            l ) local LFILES='-EHil' ;;
            s ) local SHLLSRCH="(c3284|psbt|iframe.name.twitter.scrolling|mjdu|gdsg|filesman|system.file.do.not.delete|2e922c|r57shell|default_use_ajax|tryag_vb|priv8|@error_reporting\(0\))";;
            c ) local SHLLSRCH="($OPTARG)";;
            : ) echo "-$OPTARG requires an argument";return 1;;
            \? ) echo "Usage: qgrep [-l (list files)] [-s (shells) ] [-p (no perm 000) ] [-c SEARCHSTR]"
                return 1;;
        esac
    done

    GREPARGS=${LFILES:-'-EHi'}
    ARGS1=${NONULL:-''}
    SEARCH=${SHLLSRCH:-"(gzinflate|base64_decode)"}
    find -type f $ARGS1 -regex ".*\.\(htm\|html\|shtml\|asp\|php\|inc\|tmp\|js\|htaccess\|pl\)" -print0 | xargs -0 grep $GREPARGS $SEARCH --color=auto
    return 0
}


shellscan() {

    if [ -f /root/possible_shells.txt ];then
        rm /root/possible_shells.txt -f
    fi

    SCAN_ARGS="-ps"
    if [ ! -z "$1" ];then
        if [ "$1" == "base64" ];then
            SCAN_ARGS="-p"
        else
            SCAN_ARGS="-c $1"
        fi
    fi

    for i in /var/cpanel/users/*;do
        echo -e "\n===\n$(basename $i)\n===\n" | tee -a /root/possible_shells.txt
        cd /home/$(basename $i)/public_html
        if [ $? -eq 0 ];then
            qgrep $SCAN_ARGS | tee -a /root/possible_shells.txt
        fi
    done
}


complete -o nospace -F _www d7monview 


chkbackup() {

    if [ -z "$1" ];then
        echo "Usage: chkbackup FILE"
        return
    fi
    local ACCOUNT=$(readlink -f "$1" | cut -d/ -f3)
    local TARGET=$(readlink -f "$1" | awk -F "public_html/" '{print $2}')

    BACKUPS=('daily' 'weekly' 'monthly')
    for i in ${BACKUPS[@]}; do
        if [ ! -f /backup/cpbackup/"$i"/"$ACCOUNT"/homedir/public_html/"$TARGET" ];then
            echo "No $i backup"
        else
            diff /backup/cpbackup/"$i"/"$ACCOUNT"/homedir/public_html/"$TARGET" /home/"$ACCOUNT"/public_html/"$TARGET" 2> /dev/null
            if [ $? -ne 0 ];then
                echo "Restore file? (y or n): "
                read option
                if [ "$option" == "y" ];then
                    cp /backup/cpbackup/"$i"/"$ACCOUNT"/homedir/public_html/"$TARGET" $(dirname /home/"$ACCOUNT"/public_html/"$TARGET")
                    return
                fi
            else
                echo "No changes in $i copy"
            fi
        fi
    done


}


vzsuspend() {
    if [ -z "$1" ];then
        echo "Usage: vzsuspend VEID"
        return
    fi

    vzlist -a | grep "$1" 1> /dev/null
    if [ "$?" -ne 0 ];then
        echo "VEID $1 not found!"
        return
    fi

    local HOSTNAME=$(vzlist -a | grep "$1" | awk '{print $5}')
    vzctl set "$1" --hostname "$HOSTNAME":SUSPENDED --save
    vzctl stop "$1" --fast
    vzctl set "$1" --disabled yes --save
}


vzunsuspend() {
    if [ -z "$1" ];then
        echo "Usage: vzunsuspend VEID"
        return
    fi

    vzlist -a | grep "$1" 1> /dev/null
    if [ "$?" -ne 0 ];then
        echo "VEID $1 not found!"
        return
    fi

    vzctl set "$1" --disabled no --save
    local HOSTNAME=$(vzlist -a | grep "$1" | awk '{print $5}' | awk -F':SUSPENDED' '{print $1}')
    vzctl set "$1" --hostname "$HOSTNAME" --save
    vzctl start "$1"
}


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


ServerAudit() {
    python audit.py "$!"
}


check_rbl() {
    
    python checkrbl.py "$1"
}


alias vzusage="vzlist -o ctid,laverage,hostname"


mitigate_ddos() {
    python mitigate_ddos.py
}


checkmail() {

    CHANGES=0
    RBLS=('acl_spf_bl' 'acl_spamcop_rbl' 'acl_spamhaus_rbl')
    NOT_USING=('NOT using SPF checking!' 'NOT using Spamcop RBL!' 'NOT using Spamhaus RBL!')
    USING=('SPF checking is enabled.' 'Spamcop RBL is enabled.' 'Spamhaus RBL is enabled.')

    index=0
    for bl in ${RBLS[@]};do
        local HAS_BL=$(grep "$bl" /etc/exim.conf.localopts | cut -d'=' -f2)
        grep acl_spf_bl /etc/exim.conf.localopts 1> /dev/null
        if [[ $? -ne 0 || $HAS_BL -ne 1 ]];then
            echo "${NOT_USING[$index]} Would you like to enable this feature? (y or n): "
            read choice
            if [ "$choice" == "y" ];then
                sed -i "/$bl/d" /etc/exim.conf.localopts
                echo "$bl=1" >> /etc/exim.conf.localopts
                CHANGES=1
            fi
        else
            echo ${USING[$index]}
        fi
        index=$[ $index + 1 ]
    done

    if [ $CHANGES -eq 1 ];then
        /scripts/buildeximconf 1> /dev/null
        service exim restart
    fi

}


switchmailip() {

    IPs=($(ifconfig | grep 'inet addr' | awk '{print $2}'| sed 's#addr:##g' | grep -v 127.0.0.1 | sed 's/^/ /' | tr '\n' ' '))
    index=1
    mainIP=${IPs[0]}
    curIP=$mainIP

    altIP=$(grep -E "^\*:" /etc/mailips | cut -d':' -f2)
    if [ ! -z $altIP ];then
        curIP=$altIP
    fi

    echo -e "Current mailing IP is: $curIP\n"

    for ip in ${IPs[@]};do
        echo "$index.) $ip ----> $(host $ip | cut -d' ' -f5 | sed 's/.$//')"
        index=$[ $index + 1 ]
    done

    echo -e "Enter new mailing IP: "
    read choice

    newip=${IPs[$[ $choice - 1 ]]}
    echo "new IP is $newip"

    sed -i '/^\*:/d' /etc/mailips
    sed -i '/per_domain_mailips/d' /etc/exim.conf.localopts
    if [ "$newip" == "$mainIP" ];then
        echo "per_domain_mailips=0" >> /etc/exim.conf.localopts
    else
        echo "per_domain_mailips=1" >> /etc/exim.conf.localopts
        echo -e "*: $newip\n$(cat /etc/mailips)" > /etc/mailips
        grep $newip /etc/mail_reverse_dns 1> /dev/null
        if [ $? -ne 0 ];then
            echo "$newip: $(host $ip | cut -d' ' -f5 | sed 's/.$//')" >> /etc/mail_reverse_dns
        fi
    fi

    /scripts/buildeximconf 1> /dev/null
    service exim restart
}

rdns_check() {

    ERRORS=0

    host $(hostname) 1> /dev/null
    if [ $? -ne 0 ];then
        echo "$(hostname) ----> Invalid domain name!"
        ERRORS=1
    else
        echo "$(hostname) ----> $(host $(hostname) | grep address | cut -d' ' -f4)"
    fi

    PTR=$(host $(hostname -i) | cut -d' ' -f5 | sed 's/.$//')
    echo "$(hostname -i) ----> $PTR"

    if [ "$PTR" != "$(hostname)" ];then
        ERRORS=1
    fi

    if [ $ERRORS -eq 1 ];then
        echo -e "rDNS check: \033[0;31mFAILED\033[m\017"
    else
        echo -e "rDNS check: \033[0;32mPASSED\033[m\017"
    fi
}

alias phishing_scams='grep -iE "ebay|chase|hotmail|yahoo|gmail|google|remax|fidelity|santander|visa|amazon|paypal|mastercard|signin" /etc/userdomains'

scramble_email() {
    
    if [ -z "$1" ];then
        echo "Usage: scramble_email user@domain.com"
        return
    fi

    USER=$(echo "$1" | cut -d'@' -f1)
    DOMAIN=$(echo "$1" | cut -d'@' -f2)
    ACCT=$(grep "^$DOMAIN" /etc/userdomains | awk -F": " '{print $2}')

    grep "^$USER" /home/"$ACCT"/etc/"$DOMAIN"/shadow | grep -viE "ABUSE|LOCKED" 1> /dev/null
    if [ $? -ne 0 ];then
        echo "Error: $1 may be suspended, already locked, or does not exist"
        return
    fi

    sed -i "s/^$USER:/$USER:!!ABUSE!!/" /home/"$ACCT"/etc/"$DOMAIN"/shadow

    echo "Scrambled password for $1 under '$ACCT'"
    service exim restart
}


train_sa() {

    if [ -z "$1" ];then
        echo "Usage: train_sa USER"
        return
    fi

    su "$1" -s /bin/bash -c "sa-learn --dump magic"
    su "$1" -s /bin/bash -c "sa-learn --clear"
    su "$1" -s /bin/bash -c "sa-learn --sync"
    rm auto-whitelist 2> /dev/null

    echo "Please enter the email account with SPAM-TRAIN and HAM-TRAIN folder"
    read email

    USER=$(echo $email | cut -d'@' -f1)
    DOMAIN=$(echo $email | cut -d'@' -f2)

    if [[ ! -d /home/"$1"/mail/"$DOMAIN"/"$USER"/.SPAM-TRAIN || ! -d /home/"$1"/mail/"$DOMAIN"/"$USER"/.HAM_TRAIN ]];then
        echo "Could not find HAM-TRAIN or SPAM-TRAIN folders!"
        return
    fi

    su "$1" -s /bin/bash -c "sa-learn --progress --spam /home/$1/mail/$DOMAIN/$USER/.SPAM-TRAIN/cur"
    su "$1" -s /bin/bash -c "sa-learn --progress --ham /home/$1/mail/$DOMAIN/$USER/.HAM-TRAIN/cur"

    sed -i '/use_auto_whitelist/d' /home/"$1"/.spamassassin/user_prefs
    sed -i '/URIBL_DBL_SPAM/d' /home/"$1"/.spamassassin/user_prefs
    sed -i '/URIBL_JP_SURBL/d' /home/"$1"/.spamassassin/user_prefs
    sed -i '/URIBL_WS_SURBL/d' /home/"$1"/.spamassassin/user_prefs

    echo "use_auto_whitelist 0" >> /home/"$1"/.spamassassin/user_prefs
    echo "URIBL_DBL_SPAM 6.0" >> /home/"$1"/.spamassassin/user_prefs
    echo "URIBL_JP_SURBL 4.0" >> /home/"$1"/.spamassassin/user_prefs
    echo "URIBL_WS_SURBL 4.0" >> /home/"$1"/.spamassassin/user_prefs
}

complete -o nospace -F _www train_sa

lsandrew() {
    echo -e "pwnmail STRING\ncmscheck\naddspf USER\nupdatemodsec\ninjectcleaner [-l] [-b] PATTERN [FILE|LIST]\nsysinfo\ninodebreakdown\nsecimgdr"
    echo -e "grepuser USER\ntrafficstats [-f] DOMAIN\npwn FILE\nfixperms\nrmsymlinks\nwww USER\nchpass USER\nchkmailabuse\nbeachheadfinder"
    echo -e "qgrep [-f (full)] [-l (list)] [-h (hack|shell) ] [-p (no perm 000) ] [search str]"
    echo -e "jsecure\nchkbackup FILE\nowner USER\nvzsuspend VEID\nvzunsuspend VEID"
    echo -e "adddkim USER\nunpwn USERS\nvzusage\nmitigate_ddos\ncheck_rbl\npwnoldmail\ncheckmail"
    echo -e "phishing_scams\nrdns_check\nswitchmailip\nscramble_email EMAIL\ntrain_sa USER"
}
