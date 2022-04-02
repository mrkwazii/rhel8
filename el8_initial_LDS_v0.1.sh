#!/bin/bash

# Created By hjunlee@linuxdata.co.kr
# 2022.04.01 build on Linuxdatasystem | OTS 

######################################################
##                                                  ##
##                    For RHEL8                     ##
##                                                  ##
##              LinuxDataSystem Inc.                ##
##             Initial Script - v0.1    	    ##
##                                                  ##
######################################################

function color()
{
        case $1 in
                NORMAL) printf "\033[m";;
                   RED) printf "\033[31m";;
                 GREEN) printf "\033[32m";;
                YELLOW) printf "\033[33m";;
                  BLUE) printf "\033[34m";;
                PURPLE) printf "\033[35m";;
                   SKY) printf "\033[36m";;
                 WHITE) printf "\033[37m";;
        esac
}

CUR_DATE=`date +'%Y%m%d'`
BACK_DIR=/root/LDS/backup_initial

#중복 실행여부 확인
#두번 실행하게 되면 백업파일이 덮어 씌어지기 때문에 문제가 된다.
if [ -d "$BACK_DIR/$CUR_DATE" ];
then
     color "RED"
     echo "backup directory already exist"
     color "NORMAL"
    exit 1
fi

mkdir -p /root/LDS/backup_initial/$CUR_DATE

function initial_sar()
{
  echo "#################### sysstat timer config  ####################"
  cp /usr/lib/systemd/system/sysstat-collect.timer /etc/systemd/system/
  sed -i 's/OnCalendar\=\*\:00\/10/OnCalendar\=\*\:00\/01/' /etc/systemd/system/sysstat-collect.timer
  systemctl daemon-reload
  systemctl enable --now sysstat
}

function initial_parameter()
{
echo "##### sysctl Configure  #####"
cp -a /etc/sysctl.d/99-sysctl.conf $BACK_DIR/$CUR_DATE
cat >> /etc/sysctl.conf << EOF
# Parameter Tuning

kernel.sysrq = 1
kernel.panic_on_io_nmi=1
kernel.panic_on_unrecovered_nmi=1
kernel.panic_on_stackoverflow=1
kernel.softlockup_panic=1
kernel.unknown_nmi_panic=1

vm.swappiness = 1
EOF
sysctl -p
}

function initial_ulimit()
{
echo "##### Configure ulimit #####"
cp -a /etc/security/limits.conf $BACK_DIR/$CUR_DATE
cat >> /etc/security/limits.conf << EOF
*        soft    nofile       8192
*        hard    nofile       65535
*        soft    nproc        8192
*        hard    nproc        16384
EOF
}

function initial_histtime()
{
echo "##### Set bash history timestamp #####"
echo 'export HISTTIMEFORMAT="%F %T "' >> ~/.bashrc
}


function main()
{
	initial_sar 			## Change the sar log collection cycle to 1 minute
	initial_parameter		## Set initial parameter
	initial_ulimit			## Set initial parameter
	initial_histtime		## Set bash history timestamp
}


main
color "NORMAL"
