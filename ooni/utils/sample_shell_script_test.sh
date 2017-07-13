#!/bin/bash
# Get hostname
hostname=`hostname` 2> /dev/null

# Get distro
distro=`python -c 'import platform ; print platform.linux_distribution()[0] + " " +        platform.linux_distribution()[1]'` 2> /dev/null

# Get uptime
if [ -f "/proc/uptime" ]; then
uptime=`cat /proc/uptime`
uptime=${uptime%%.*}
seconds=$(( uptime%60 ))
minutes=$(( uptime/60%60 ))
hours=$(( uptime/60/60%24 ))
days=$(( uptime/60/60/24 ))
uptime="$days days, $hours hours, $minutes minutes, $seconds seconds"
else
uptime=""
fi
echo -e "{\"hostname\":\""$hostname"\", \"distro\":\""$distro"\", \"uptime\":\""$uptime"\"}"
