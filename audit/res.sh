#!/bin/bash

# slightly more structured script showing data provided by
# 'sysinfo'
OUT=$(/usr/local/cpanel/bin/dcpumonview | grep -v Top | sed -e 's#<[^>]*># #g' | while read i ;do NF=`echo $i | awk {'print NF'}` ;if [[ "$NF" == "5" ]] ; then USER=`echo $i | awk '{print $1}'`;OWNER=`grep -e "^OWNER=" /var/cpanel/users/$USER | cut -d= -f2` ; echo "$OWNER $i"; fi ; done) ; 

(echo "USER CPU" ; echo "$OUT" | sort -nrk4 | awk '{print $2,$4}' | head -5) | column -t  
echo; 
(echo -e "USER MEMORY" ; echo "$OUT" | sort -nrk5 | awk '{print $2,$5}' | head -5) | column -t;
echo;
(echo -e "USER MYSQL" ; echo "$OUT" | sort -nrk6 | awk '{print $2,$6}' | head -5) | column -t;
