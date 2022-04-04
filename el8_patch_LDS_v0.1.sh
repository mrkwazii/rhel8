#!/bin/bash

# Created By hjunlee@linuxdata.co.kr
# 2019.05.27 build on Linuxdatasystem | OTS 
# 2022.04.01 Added RHEL8 support

##########################################################
##						      	##
##		      For RHEL7, RHEL8 			##
##						      	##
##		    LinuxDataSystem Inc.		##
## 		Security Patch Script - v0.2	    	##
##						 	##
##########################################################

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

# SET Global variable 
CUR_DATE=`date +'%Y%m%d'`
BACK_DIR=/root/LDS/backup
RHEL_VERSION=`cat /etc/redhat-release | cut -d. -f 1 | awk '{print $NF}'`
RHEL_MINOR_VERSION=`cat /etc/redhat-release | cut -d. -f 2 | awk '{print $1}'`

#중복 실행여부 확인
#두번 실행하게 되면 백업파일이 덮어 씌어지기 때문에 문제가 된다.
if [ -d "$BACK_DIR/$CUR_DATE" ];
then
	 color "RED"
	 echo "backup directory already exist"
	 color "NORMAL"
	exit 1
fi

mkdir -p /root/LDS/backup/$CUR_DATE


function u01()
{

	echo "##### u01 root 계정 원격 접속 제한 #####"
cp -an /etc/ssh/sshd_config $BACK_DIR/$CUR_DATE

if [ "$RHEL_VERSION" == 8 ];
then
	sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config;
else
	sed -i "s/#PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config;
fi
	systemctl restart sshd
		
chk=$(cat /etc/ssh/sshd_config | grep ^PermitRootLogin | awk '{print $2}')
	if [ "$chk" = no ];
	then
	color "GREEN"
	echo "successed"
	else	
	color "RED"
	echo "Not successed"
	fi

color "NORMAL"
echo ""
echo "##### u01 root 계정 원격 접속 제한 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u02()
{
	echo "##### u02 패스워드 복잡성 설정 #####"
# 숫자와 특수문자가 혼합된 패스워드 복잡도 설정
#echo "minlen=8 (비밀번호의 최소길이 8)"
#echo "lcredit=-1 (포함될 소문자의 최소 개수)"
#echo "ucredit=-1 (포함될 대문자의 최소 개수)"
#echo "dcredit=-1 (포함될 숫자의 최소 개수)"
#echo "ocredit=-1 (포함될 특수 문자의 최소 개수)"
cp -an /etc/security/pwquality.conf $BACK_DIR/$CUR_DATE

if [ "$RHEL_VERSION" == 8 ];
  then
sed -i "s/# dcredit = 0/dcredit = -1/g" /etc/security/pwquality.conf;
sed -i "s/# ocredit = 0/ocredit = -1/g" /etc/security/pwquality.conf;
sed -i "s/# lcredit = 0/lcredit = -1/g" /etc/security/pwquality.conf;
sed -i "s/# ucredit = 0/ucredit = -1/g" /etc/security/pwquality.conf;
  else
sed -i "s/# dcredit = 1/dcredit = -1/g" /etc/security/pwquality.conf;
sed -i "s/# ocredit = 1/ocredit = -1/g" /etc/security/pwquality.conf;
sed -i "s/# lcredit = 1/lcredit = -1/g" /etc/security/pwquality.conf;
sed -i "s/# ucredit = 1/ucredit = -1/g" /etc/security/pwquality.conf;
fi


chk=$(cat /etc/security/pwquality.conf | egrep "dcredit|ocredit" | grep "\-1" | wc -l)
	if [ "$chk" -eq 2 ]
	then
	color "GREEN"
        echo "successed"
        else
        color "RED"
        echo "Not successed"
        fi
	
color "NORMAL"
echo ""
echo "##### u02 패스워드 복잡성 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u03()
{

	echo "##### u03 계정 잠금 임계값 설정 #####"


if [ "$RHEL_VERSION" == 8 ];
  then
  cp -an /etc/authselect/system-auth $BACK_DIR/$CUR_DATE
  cp -an /etc/authselect/password-auth $BACK_DIR/$CUR_DATE
  authselect apply-changes -b --backup=sssd.backup
  authselect create-profile password-policy -b sssd
  authselect select custom/password-policy
  authselect enable-feature with-mkhomedir
  authselect enable-feature with-faillock
  authselect apply-changes
	if [ "$RHEL_MINOR_VERSION" -le 2 ]
		then
			sed -i -e 's/deny=4/deny=10/g' -e 's/unlock_time=1200/unlock_time=3600/g' /etc/authselect/custom/password-policy/system-auth
			sed -i -e 's/deny=4/deny=10/g' -e 's/unlock_time=1200/unlock_time=3600/g' /etc/authselect/custom/password-policy/password-auth
			authselect apply-changes
		else
			sed -i -e 's/pam_faillock.so preauth silent/pam_faillock.so preauth silent deny=10 unlock_time=3600/g' -e 's/pam_faillock.so authfail/pam_faillock.so authfail deny=10 unlock_time=3600/g' /etc/authselect/custom/password-policy/system-auth
			sed -i -e 's/pam_faillock.so preauth silent/pam_faillock.so preauth silent deny=10 unlock_time=3600/g' -e 's/pam_faillock.so authfail/pam_faillock.so authfail deny=10 unlock_time=3600/g' /etc/authselect/custom/password-policy/password-auth
			authselect apply-changes
	fi	
  else
cp -an /etc/pam.d/system-auth $BACK_DIR/$CUR_DATE
cp -an /etc/pam.d/password-auth $BACK_DIR/$CUR_DATE
sed -i '5i\auth        required      pam_tally2.so deny=10 unlock_time=3600' /etc/pam.d/system-auth
sed -i '11i\account     required      pam_tally2.so' /etc/pam.d/system-auth
sed -i '5i\auth        required      pam_tally2.so deny=10 unlock_time=3600' /etc/pam.d/password-auth
sed -i '10i\account     required      pam_tally2.so' /etc/pam.d/password-auth

## check
chk1=$(cat /etc/pam.d/system-auth | grep "pam_tally2"  | wc -l)
chk2=$(cat /etc/pam.d/password-auth | grep "pam_tally2" | wc -l)

        if [ "$chk1" -eq 2 ] && [ "$chk2" -eq 2 ]
        then
        color "GREEN"
        echo "successed"
        else
        color "RED"
        echo "Not successed"
        fi
fi

#deny=10  : 패스워드 잠금 횟수 10회
#unlock_time=3600 (1시간) : 계정이 잠김 후 해제 될 때까지의 시간(단위 : 초) 
#onerr=fail : /etc/loginusers 파일 자체가 없다든지 할 때 거부할 것인가 아닌가를 결정 success|fail
#로그인 성공시 잠금횟수 초기화
#no_magic_root reset  root계정에 한해선 예외처리 (이 옵션 없어졌으니까 사용하지 마세요)


color "NORMAL"
echo ""
echo "##### u03 계정 잠금 임계값 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u04()
{
      echo " ##### u04 패스워드 파일 보호 #####"
	# 기본적으로 shadow파일을 사용하게 되어 있다.
}


function u05()
{
      echo "##### u05 root 이외의 UID가 '0' 금지#####"
	# 수동으로 확인 필요. 
     	# cat /etc/passwd | grep -v root | cut -d: -f3 | grep ^0
}

function u06()
{
      echo " ##### u06 root 계정 su 제한 #####"
	cp -an /etc/pam.d/su $BACK_DIR/$CUR_DATE

# wheel 그룹에 사용할 유저명/패스워드 지정
#user_name=suser
#passwd=suser

	# wheel그룹에 포함된 사용자 su사용 가능하게 설정
sed -i '/#auth\t\trequired\tpam_wheel.so/  s/.// ' /etc/pam.d/su

	# wheel그룹에 포함되는 user생성
#	useradd $user_name
#	echo "$passwd" | passwd $user_name --stdin


usermod -aG wheel hjun

chk=$(cat /etc/pam.d/su | grep "pam_wheel.so use_uid" | grep -v ^# | wc -l)
        if [ "$chk" -eq 1 ]
        then
        color "GREEN"
        echo "successed"
        else
        color "RED"
        echo "Not successed"
        fi

color "NORMAL"
echo ""
echo " ##### u06 root 계정 su 제한 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u07()
{
		# u07 u08 u09
## 유저가 생성될때 해당 설정을 가져 오기 때문에 이미 생성된 유저에 대해서는 ##
## chage 명령을 이용하여 설정을 변경하여야 한다. 예) chage  hjun -m 1 -M 90 ##
      echo "##### u07,08,09 패스워드 최소 길이,최대 길이, 최소 사용기간 설정 #####"

	cp -ap /etc/login.defs $BACK_DIR/$CUR_DATE

        cat /etc/login.defs |grep -v "^PASS_WARN_AGE" | grep -v "^PASS_MIN_LEN" | grep -v "^PASS_MAX_DAYS" | grep -v "^PASS_MIN_DAYS" > $BACK_DIR/login.tmp
        echo "" >> login.tmp
        echo "# Add passwd rule" >> $BACK_DIR/login.tmp
        echo "PASS_MIN_LEN    9" >> $BACK_DIR/login.tmp
        echo "PASS_MAX_DAYS  70" >> $BACK_DIR/login.tmp
        echo "PASS_MIN_DAYS   7" >> $BACK_DIR/login.tmp
	echo "PASS_WARN_AGE   7" >> $BACK_DIR/login.tmp
  cat $BACK_DIR/login.tmp > /etc/login.defs
  rm -f $BACK_DIR/login.tmp

# 결과를 확인하기 위해 PASS_MIN_LEN 값보다 하나 작은 숫자를 입력한다. 
if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN"| grep -v "#" | egrep [0-7]| awk '{print $2}'| wc -l` -eq 0 ]
then
	color "GREEN"
        echo "successed"
else
	color "RED"
	echo "Not successed"
fi

color "NORMAL"
echo " "
echo "##### u07,08,09 패스워드 최소 길이,최대 길이, 최소 사용기간 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt

# 이미 생성된 사용자 셋팅정보 확인
echo " ** use \"chage\" command to change current user rule **"
for i in $( cat /etc/passwd | egrep -v "nologin|root|sync|shutdown|halt" | cut -d: -f1)
do
echo $i
chage -l $i| tail -3
echo " "
done

}

# function u08()
      # 07에서 설정됨.
# function u09()
      # 07에서 설정됨.


function u10()
{
      echo "##### u10 불필요한 계정 제거 #####"
	# lp 계정 삭제 (uucp ,nuucp 계정은 default로 생성 안됨)

cp -ap /etc/passwd $BACK_DIR/$CUR_DATE
cp -ap /etc/group $BACK_DIR/$CUR_DATE
cp -ap /etc/shadow $BACK_DIR/$CUR_DATE
cp -ap /etc/gshadow $BACK_DIR/$CUR_DATE

	for i in $(cat /etc/passwd | grep "^lp:" | cut -d: -f1 )
	do
		userdel $i
	done

chk=$(cat /etc/passwd | grep "^lp:" | cut -d: -f1 | wc -l)
if [ "$chk" -eq 0 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "
echo "##### u10 불필요한 계정 제거 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u11()
{
      echo "##### u11 관리자 그룹에 최소한의 계정 포함 #####"
	# root 그룹에 다른 유저가 등록 되어 있는지 수동으로 점검 
	# groups root

}

function u12()
{
      echo "##### u12 계정이 존재하지 않는 GID 금지 #####"
	# 점검시 발생되는 그룹에 대해 수동으로 삭제
	# 해당 스크립트는 점검만 한다
	
# 기본 생성된 그룹에 대해서는 제외하고 검색
chk_list=$(cat /etc/group | egrep -v "^root|^bin|^daemon|^sys|^adm|^tty|^disk|^lp|^mem|^kmem|^wheel|^cdrom|^mail|^man|^dialout|^floppy|^games|^tape|^video|^ftp|^lock|^audio|^nobody|^users|^utmp|^utempter|^ssh_keys|^input|^systemd-journal|^systemd-bus-proxy|^systemd-network|^dbus|^polkitd|^cgred|^unbound|^tss|^libstoragemgmt|^rpc|^colord|^usbmuxd|^dip|^saslauth|^geoclue|^libvirt|^abrt|^setroubleshoot|^rtkit|^radvd|^rpcuser|^nfsnobody|^kvm|^qemu|^chrony|^pulse-access|^pulse-rt|^pulse|^gdm|^gnome-initial-setup|^avahi|^slocate|^postdrop|^postfix|^ntp|^sshd|^stapusr|^stapsys|^stapdev|^tcpdump" | cut -d: -f1)

for i in $chk_list
do
groups $i &>> /tmp/tmp_u12_file.txt
done

chk=$(cat /tmp/tmp_u12_file.txt |grep "no such user"| wc -l)
if [ "$chk" -eq 0 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

rm -f /tmp/tmp_u12_file.txt
color "NORMAL"
echo " "

echo "##### u12 계정이 존재하지 않는 GID 금지 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt

}

function u13()
{
      echo "##### u13 동일한 UID 금지 #####"
	# 동일한 UID사용하는지 직접 확인
	# cat /etc/passwd  | cut -d: -f3 | uniq -c | awk '{print $1}'

}

function u14()
{
      echo "##### u14 사용자 shell 점검 #####"
	# nologin설정이 되지 않은 계정 수동으로 점검
	# cat /etc/passwd | grep -v nologin

}

function u15()
{
      echo "##### u15 Session Timeout 설정 #####"
	cp -ap /etc/profile $BACK_DIR/$CUR_DATE
	
#TIME OUT값 입력
set_num=300

if [ `cat /etc/profile | grep ^TMOUT | wc -l` -eq 0 ]
then
echo "TMOUT=$set_num" >> /etc/profile
echo "export TMOUT" >> /etc/profile
fi	

cur_num=$(cat /etc/profile | grep ^TMOUT | cut -d= -f2)
chk_act=$(cat /etc/profile | grep ^TMOUT | wc -l)

#입력한 시간과 설정된 시간이 틀리다면 Not successed가 나온다.
if [ "$chk_act" -gt 0 ] && [ "$cur_num" -eq "$set_num" ]
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "

echo "##### u15 Session Timeout 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt

}

function u16()
{
      echo "##### u16 root 홈, 패스 디렉터리 권한 및 패스 설정 #####"
	# 수동으로 점검, .이 포함되지 않은 경우 정상
	# echo $PATH
}

function u17()
{
      echo "##### u17 파일 및 디렉터리 소유자 설정 #####"
	# 수동으로 점검, 소유자가 없는 파일
	# find / -nouser -print 2> /dev/null
}

function u18()
{
      echo "##### u18 /etc/passwd 파일 소유자 및 권한 설정 #####"
	# passwd 파일 소유자: root 권한: 644 로 변경
	ls -al /etc/passwd >> $BACK_DIR/$CUR_DATE/file_info.txt	

	
cur_chk=$(find /etc/passwd -perm 644 -user root | wc -l)
	if [ "$cur_chk" -eq 0 ];
	then
		chown root.root /etc/passwd
		chmod 644 /etc/passwd
	fi

cur_chk2=$(find /etc/passwd -perm 644 -user root | wc -l)
	if [ "$cur_chk2" -eq 1 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "	

echo "##### u18 /etc/passwd 파일 소유자 및 권한 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt

}

function u19()
{
      echo "##### u19 /etc/shadow 파일 소유자 및 권한 설정 #####"
	# shadow 파일은 default로 root 에 000으로 되어 있다.
	# ls -al /etc/shadow 로 직접 확인


}

function u20()
{
      echo "##### u20 /etc/hosts 파일 소유자 및 권한 설정 #####"

	# hosts 파일 소유자: root 권한: 600 로 변경
        ls -al /etc/hosts >> $BACK_DIR/$CUR_DATE/file_info.txt


cur_chk=$(find /etc/hosts -perm 600 -user root | wc -l)
        if [ "$cur_chk" -eq 0 ];
        then
                chown root.root /etc/hosts
                chmod 600 /etc/hosts
        fi

cur_chk2=$(find /etc/hosts -perm 600 -user root | wc -l)
        if [ "$cur_chk2" -eq 1 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "        
echo "##### u20 /etc/hosts 파일 소유자 및 권한 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u21()
{
      echo "##### u21 /etc/(x)inetd.conf 파일 소유자 및 권한 설정 #####"
	# RHEL7 버전부터 inetd파일 사용 안함
}

function u22()
{
      echo "##### u22 /etc/syslog.conf 파일 소유자 및 권한 설정 #####"	
     # rsyslog.conf 파일 소유자: root 권한: 644 로 변경
        ls -al /etc/rsyslog.conf >> $BACK_DIR/$CUR_DATE/file_info.txt


cur_chk=$(find /etc/rsyslog.conf -perm 644 -user root | wc -l)
        if [ "$cur_chk" -eq 0 ];
        then
                chown root.root /etc/rsyslog.conf
                chmod 644 /etc/rsyslog.conf
        fi

cur_chk2=$(find /etc/rsyslog.conf -perm 644 -user root | wc -l)
        if [ "$cur_chk2" -eq 1 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "        
      
echo "##### u22 /etc/syslog.conf 파일 소유자 및 권한 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
	
}

function u23()
{
      echo "##### u23 /etc/services 파일 소유자 및 권한 설정 #####"
     # services 파일 소유자: root 권한: 644 로 변경
        ls -al /etc/services >> $BACK_DIR/$CUR_DATE/file_info.txt


cur_chk=$(find /etc/services -perm 644 -user root | wc -l)
        if [ "$cur_chk" -eq 0 ];
        then
                chown root.root /etc/services
                chmod 644 /etc/services
        fi

cur_chk2=$(find /etc/services -perm 644 -user root | wc -l)
        if [ "$cur_chk2" -eq 1 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "    
      
echo "##### u23 /etc/services 파일 소유자 및 권한 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u24()
{
      echo "##### u24 SUID, SGID, Sticky bit 설정 파일 점검 #####"
	# FILES에 나열된 파일중에 SUID등이 설정된 파일을 제거한다.
	# 백업은 setid_file_info.txt로 확인 가능
	# 수동으로 확인은 find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al {} \;

FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /bin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"
for check_file in $FILES
do
        if [ -f $check_file ]
        then
                if [ -g $check_file -o -u $check_file ]
                then
                        echo `ls $check_file` >> list.tmp
                fi
        fi
done


if [ -f list.tmp ]
then
for i in $(cat list.tmp)
do
ls -al $i >> $BACK_DIR/$CUR_DATE/setid_file_info.txt
done

        for chfile in $(cat list.tmp)
        do
                chmod u-s $chfile
                chmod g-s $chfile
        done
fi
/bin/rm -rf list.tmp


#여기부터는 확인용
for check_file in $FILES
do
        if [ -f $check_file ]
        then
                if [ -g $check_file -o -u $check_file ]
                then
                        echo `ls $check_file` >> list.tmp
                fi
        fi
done

# 조치가 완료되면 목록이 확인되지 않는다. 
if [ -f list.tmp ]; 
then
        color "RED"
        echo "Not successed"
else
        color "GREEN"
        echo "successed"
fi

color "NORMAL"
echo " "   
      
echo "##### u24 SUID, SGID, Sticky bit 설정 파일 점검 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u25()
{
      echo "##### u25 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 #####"
	# 사용자의 홈 디렉토리에서 디렉토리를 제외한 파일중 other에 write권한이 있는 파일을 찾아서 삭제.

chk_list=$(cat /etc/passwd | egrep -v "^root|^bin|^daemon|^adm|^lp|^sync|^shutdown|^halt|^mail|^operator|^games|^ftp|^nobody|^avahi-autoipd|^systemd-bus-proxy|^systemd-network|^dbus|^polkitd|^unbound|^tss|^colord|^usbmuxd|^geoclue|^saslauth|^libstoragemgmt|^abrt|^setroubleshoot|^rpc|^rtkit|^chrony|^radvd|^qemu|^rpcuser|^nfsnobody|^pulse|^gdm|^gnome-initial-setup|^avahi|^postfix|^ntp|^sshd|^tcpdump|nologin"| cut -d: -f6 )

for i in $chk_list
do
find $i/ -type f -perm -o=w >> /tmp/u25_tmp.perm.txt
done



mod_list=$(cat /tmp/u25_tmp.perm.txt 2> /dev/null)
for i in $mod_list
do
ls -al $i >> $BACK_DIR/$CUR_DATE/home_ww_file_info.txt 
chmod o-w $i
done
rm -f /tmp/u25_tmp.perm.txt


#확인
for i in $chk_list
do
find $i -type f -perm -o=w >> /tmp/final_u25_chk.txt
done


if [ -s "/tmp/final_u25_chk.txt" ];
then
        color "RED"
        echo "Not successed"
else
        color "GREEN"
        echo "successed"
fi

color "NORMAL"
echo " "   
rm -f /tmp/final_u25_chk.txt

      
echo "##### u25 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt


}

function u26()
{
      echo "##### u26 world writable 파일 점검 #####"
	# /proc 와 /sys/fs 에 있는 파일을 제외한 일반파일들의 world writable 권한을 검사하고 조치한다.

#현재 정보 백업
find / -type f -perm -002 -ls | awk '{print $3 ":" $5 ":" $6 ":" $11}' | grep -v "/proc/" | grep -v "/sys/fs/" > $BACK_DIR/$CUR_DATE/all_ww_file_info.txt


find / -type f -perm -002 -ls | awk '{print $11}' | grep -v "/proc/" | grep -v "/sys/fs/" > /tmp/u26_tmp.perm.txt

# world wriatble파일이 검출 되었다면 o=w 퍼미션 제거
if [ -s /tmp/u26_tmp.perm.txt ];
then
for i in $(cat /tmp/u26_tmp.perm.txt) 
do
chmod o-w $i
done
rm -f /tmp/u26_tmp.perm.txt
fi

# 확인용 find다시 실행
find / -type f -perm -002 -ls | awk '{print $11}' | grep -v "/proc/" | grep -v "/sys/fs/" > /tmp/u26_tmp.perm2.txt

if [ -s /tmp/u26_tmp.perm2.txt ];
then
        color "RED"
        echo "Not successed"
else
        color "GREEN"
        echo "successed"
fi

color "NORMAL"
echo " "   
rm -f /tmp/u26_tmp.perm2.txt

      
echo "##### u26 world writable 파일 점검 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u27()
{
      echo "##### u27 /dev에 존재하지 않는 device 파일 점검 #####"
	# 파일을 확인하여 수동으로 점검
	# find /dev -type f -exec ls -l {} \; | grep -v "/dev/shm/"
      
	
}

function u28()
{
      echo "##### u28 \$HOME/.rhosts, hosts.equiv 사용 금지 #####"
	# 수동으로 점검 할 것

# hosts.equiv확인
ls -al /etc/ | grep hosts.equiv

# rhosts파일 확인
chk_list=$(cat /etc/passwd | egrep -v "nologin|root|sync|shutdown|halt" | cut -d: -f6)
for i in $chk_list
do
ls -al $i | grep rhosts
done


echo "##### u28 \$HOME/.rhosts, hosts.equiv 사용 금지 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u29()
{
      echo "##### u29 접속 IP 및 포트 제한 #####"
	# 협의 후 설정	

	# 예)
	# hosts.deny
	# ALL : ALL
	# hosts.allow
	# ALL : 192.168.0.10 192.169.0.11
	# ALL : 10.
 
}

function u30()
{
      echo "##### u30 host.lpd 파일 소유자 및 권한 설정 #####"
	# 기본적으로 파일이 없다
	# ls -al /etc/host.lpd
	# chown 600 /etc/host.lpd

}

function u31()
{
      echo "##### u31 NIS 서비스 비활성화 #####"
	# ypserv 및 ypbind 패키지 및 서비스 확인	
	# rpm -qa | grep ^yp
	# ps -ef | grep  yp | grep -v abrt | grep -v grep | grep -v crypto
}

function u32()
{
      echo "##### u32 UMASK 설정 관리 #####"
# 백업
cp -ap /etc/bashrc $BACK_DIR/$CUR_DATE
	
# u15번에서 백업 하므로 확인 후 없다면 백업 진행
if [ -s "$BACK_DIR/$CUR_DATE/profile" ];
then
echo ""
else
cp -ap /etc/profile $BACK_DIR/$CUR_DATE
fi
 
sed -i "s/umask 002/umask 022/g" /etc/profile
sed -i "s/umask 002/umask 022/g" /etc/bashrc


# 확인
chk1_u32=$(cat /etc/profile | grep -v "^#" | grep umask | awk '{print $2}')
chk2_u32=$(cat /etc/bashrc | egrep -v "^*#" | grep umask | awk '{print $2}')

a=0
for i in $chk1_u32
do
if [ "$i" -ne 022 ];
then
a=1
fi
done

for i in $chk2_u32
do
if [ "$i" -ne 022 ];
then
a=1
fi
done

if [ "$a" -eq 0 ];
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " " 
	
      
echo "##### u32 UMASK 설정 관리 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u33()
{
      echo "##### u33 홈 디렉터리 소유자 및 권한 설정 #####"
	# 수동으로 점검, 홈디렉토리 소유자가 해당 계정이고 일반사용자 쓰기권한 제거 확인
	# ls -l /home

}

function u34()
{
      echo "##### u34 홈 디렉터리로 지정한 디렉터리의 존재 관리 #####"
	# 수동으로 점검, 계정별 홈 디렉토리가 있는지 확인.
	# cat /etc/passwd | egrep -v "nologin|root|sync|shutdown|halt"| cut -d: -f1,6
}

function u35()
{
      echo "##### u35 숨겨진 파일 및 디렉터리 검색 및 제거 #####"
	# 수동으로 점검, 의심스러운 파일을 찾아 삭제
	#  find / -xdev -name ".*" -print
}

function u36()
{
      echo "##### u36 Finger 서비스 비활성화 #####"
	# 수동으로 점검,  finger 서비스 사용 여부 확인
	# rpm -qa | grep finger
	 	
}

function u37()
{
      echo "##### u37 Anonymous FTP 비활성화 #####"
	# ftp계정 제거,
	# vsftpd 사용중일 경우 vsftpd.conf 에서 anonymous_enable=NO진행

# 백업파일 생성, # u10번에서 백업 하므로 확인 후 없다면 백업 진행
if [ -s "$BACK_DIR/$CUR_DATE/passwd" ];
then
echo -n ""
else
cp -ap /etc/passwd $BACK_DIR/$CUR_DATE
fi

if [ -s "$BACK_DIR/$CUR_DATE/group" ];
then
echo -n ""
else
cp -ap /etc/group $BACK_DIR/$CUR_DATE
fi

if [ -s "$BACK_DIR/$CUR_DATE/shadow" ];
then
echo -n ""
else
cp -ap /etc/shadow $BACK_DIR/$CUR_DATE
fi

if [ -s "$BACK_DIR/$CUR_DATE/gshadow" ];
then
echo -n ""
else
cp -ap /etc/gshadow $BACK_DIR/$CUR_DATE
fi


        for i in $(cat /etc/passwd | grep "^ftp:" | cut -d: -f1 )
        do
                userdel $i
        done

# vsftpd anonymous_enabled=No설정
chk_conf=$(cat /etc/vsftpd/vsftpd.conf | grep ^anonymous | cut -d= -f2)
cp -ap /etc/vsftpd/vsftpd.conf $BACK_DIR/$CUR_DATE

if [ -s "/etc/vsftpd/vsftpd.conf" ] && [ "$chk_conf" = "YES" ]
then
sed -i "s/anonymous_enable=YES/anonymous_enable=No/g" /etc/vsftpd/vsftpd.conf
fi


#확인
chk=$(cat /etc/passwd | grep "^ftp:" | cut -d: -f1 | wc -l)
chk2=$(cat /etc/vsftpd/vsftpd.conf | grep ^anonymous | cut -d= -f2)
if [ "$chk" -eq 0 ] && [ "$chk2" = "No" ]
then
        color "GREEN"
        echo "successed"
else
        color "RED"
        echo "Not successed"
fi

color "NORMAL"
echo " "

echo "##### u37 Anonymous FTP 비활성화 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt

}

function u38()
{
      echo "##### u38 r 계열 서비스 비활성화 #####"
	# 수동 점검, rlogin, rsh, rcp
	# # rpm -qa | grep rsh

}

function u39()
{
      echo "##### u39 cron 파일 소유자 및 권한 설정 #####"
	# 수동 점검
	# /etc/cron.allow 및 /etc/cron.deny 파일이 존재할 경우
	# 소유자 root, 퍼미션 640이하로 설정
}

function u40()
{
      echo "##### u40 DoS 공격에 취약한 서비스 비활성화 #####"
	# RHEL7 해당사항 없음
}

function u41()
{
      echo "##### u41 NFS 서비스 비활성화 #####"
	# 서비스 사용여부 수동 점검
}

function u42()
{
      echo "##### u42 NFS 접근통제 #####"
	# 서비스 사용시 everyone지정 제한
	# /etc/exports 파일 확인
}

function u43()
{
      echo "##### u43 automountd 제거 #####"
	# 수동점검
	# 패키지확인: rpm -qa | grep autofs
 	# 서비스확인: systemctl status autofs
}

function u44()
{
      echo "##### u44 RPC 서비스 확인 #####"
	# 수동점검, nfs를 사용하고 있는지 확인
	# 패키지확인: rpm -qa | grep rpcbind
 	# 서비흐확인: systemctl status rpcbind	
	
}

function u45()
{
      echo "##### u45 NIS, NIS+ 점검 #####"
	# 수동점검, ypserv, ypbind 확인
	# 패키지확인: rpm -qa | egrep "ypserv|ypbind"
}

function u46()
{
      echo "##### u46 tftp, talk 서비스 비활성화 #####"
	# 수동점검 
	# 패키지확인: rpm -qa | egrep "tftp|talk"
}

function u47()
{
      echo "Sendmail 버전 점검"
	# 수동점검 
	# 패키지확인: rpm -qa |grep sendmail"
	
}

function u48()
{
      echo "스팸 메일 릴레이 제한"
	# 수동 점검
	# 메일서버 사용여부 확인
	# sendmail 8.9.0부터는 디폴트로 메일 릴레이 기능을 제한 하도록 설정되어 있다.
}

function u49()
{
      echo "일반사용자의 Sendmail 실행 방지" 
	# 수동 점검
	# sendmail사용여부 확인
	# 아래와 같이 sendmail.cf 에 이미 되어 있다.
	# O PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun
}

function u50()
{
      echo "DNS 보안 버전 패치"
	# N/A
}

function u51()
{
      echo "DNS ZoneTransfer 설정"
	# N/A
}

function u52()
{
      echo "Apache 디렉터리 리스팅 제거"
	# N/A
}

function u53()
{
      echo "Apache 웹 프로세스 권한 제한"
	# N/A
}

function u54()
{
      echo "Apache 상위 디렉터리 접근 금지"
	# N/A
}

function u55()
{
      echo "Apache 불필요한 파일 제거"
	# N/A
}

function u56()
{
      echo "Apache 링크 사용금지"
	# N/A
}

function u57()
{
      echo "Apache 파일 업로드 및 다운로드 제한"
	# N/A
}

function u58()
{
      echo "Apache 웹 서비스 영역의 분리"
	# N/A
}

function u59()
{
      echo "ssh 원격접속 허용"
	# 수동점검
	# 기본값으로 ssh사용
}

function u60()
{
      echo "##### u60 ftp 서비스 확인 #####"
	# 수동점검, ftp서비스 확인

}

function u61()
{
      echo "ftp 계정 shell 제한"
	# 수동점검, ftp계정은 기본적으로 nologin이다.
	# cat /etc/passwd | grep ftp
}

function u62()
{
      echo "##### u62 Ftpusers 파일 소유자 및 권한 설정 #####"
	# 수동점검, /etc/ftpusers파일이 존재한다면
	# 소유자: root, 권한: 640
}

function u63()
{
      echo "Ftpusers 파일 설정"
	# 수동점검
#	- vsftp를 사용하는 경우

# vsftpd.conf 파일에서 userlist_enable=YES 인경우 : /etc/vsftpd/user_list 또는 /etc/vsftpd.user_list 파일에 root 계정을 넣어줌 (root 앞에 #이 있을 경우 제거)

# vsftpd.conf 파일에서 userlist_enable=NO 혹은 옵션이 존재하지 않을 경우 : /etc/vsftpd/ftpusers 또는 /etc/vsftpd.ftpusers 파일에 root 계정을 넣어줌 (root 앞에 #이 있을 경우 제거)

}

function u64()
{
      echo "at 파일 소유자 및 권한 설정"
	# 수동점검, at.deny파일 640미만으로 변경
	# at.allow파일은 기본적으로 없으며
	# at.allow파일이 존재할 경우 at.deny는 무시되며
	# at.allow에 명시된 유저만 at,batct커맨드를 사용할 수 있다.
}

function u65()
{
      echo "SNMP 서비스 구동 점검"
	# 수동점검, 패키지확인및 서비스 종료 net-snmp
	# rpm -qa | grep net-snmp
}

function u66()
{
      echo "SNMP 서비스 커뮤니티스트링의 복잡성 설정"
	# 수동점검	
	# 아래 커뮤니티값 public에서 다른걸로 교체
	# Server/Client에 모두 같은 Community String사용하여야 함 	
	# cat /etc/snmp/snmpd.conf | grep com2sec | grep public
	# com2sec notConfigUser  default       public
	
}

function u67()
{
      echo "##### u67 로그온 시 경고 메시지 제공 #####"

	# vsftpd일경우 
	# cat /etc/vsftpd/vsftpd.conf | grep ^ftpd_banner
	# ftpd_banner="This system is for the use of authorized users only."



echo "
 #####################################################################
 #  This system is for the use of authorized users only.             #
 #  Individuals using this computer system without authority, or in  #
 #  excess of their authority, are subject to having all of their    #
 #  activities on this system monitored and recorded by system       #
 #  personnel.                                                       #
 #                                                                   #
 #  In the course of monitoring individuals improperly using this    #
 #  system, or in the course of system maintenance, the activities   #
 #  of authorized users may also be monitored.                       #
 #                                                                   #
 #  Anyone using this system expressly consents to such monitoring   #
 #  and is advised that if such monitoring reveals possible          #
 #  evidence of criminal activity, system personnel may provide the  #
 #  evidence of such monitoring to law enforcement officials.        #
 #####################################################################
" > /etc/motd

echo "##### u67 로그온 시 경고 메시지 제공 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u68()
{
      echo "NFS 설정 파일 접근 권한"
	# NFS파일 소유자가 root이고 권한이 644이하인 경우
}

function u69()
{
      echo "expn, vrfy 명령어 제한"
}

function u70()
{
      echo "Apache 웹서비스 정보 숨김"
}

function u71()
{
      echo "최신 보안패치 및 벤더 권고사항 적용"
}

function u72()
{
      echo "로그의 정기적 검토 및 보고"

}

function u73()
{
      echo "##### u73 정책에 따른 시스템 로깅 설정 #####"

cp -ap /etc/rsyslog.conf $BACK_DIR/$CUR_DATE

chk=$(cat /etc/rsyslog.conf  | grep ".alert" | wc -l)

if [ "$chk" -eq 0 ];
then
sed -i '65i\*.alert                  /dev/console' /etc/rsyslog.conf
systemctl restart rsyslog
fi

chk2=$(cat /etc/rsyslog.conf  | grep ".alert" | wc -l)
        if [ "$chk2" -eq 1 ];
        then
        color "GREEN"
        echo "successed"
        else
        color "RED"
        echo "Not successed"
        fi

color "NORMAL"
echo ""
echo "##### u73 정책에 따른 시스템 로깅 설정 #####" &>> /$BACK_DIR/$CUR_DATE/result.txt
}

function u74()
{
chmod o-w /etc/crontab 
chmod o-w /etc/cron.daily/
chmod o-w /etc/cron.hourly/
chmod o-w /etc/cron.monthly/
chmod o-w /etc/cron.weekly/
}

function u75()
{
sed -i "s/rotate 4/rotate 24/g" /etc/logrotate.conf
}

function u76()
{
systemctl disable spice-vdagentd.service
systemctl disable abrt-vmcore.service
systemctl disable abrt-xorg.service
systemctl disable mdmonitor.service
systemctl disable spice-vdagentd.service
systemctl disable cups.socket
systemctl disable cups.service
systemctl disable bluetooth.service
systemctl disable ksm.service
systemctl disable ksmtuned.service
systemctl disable libvirtd.service
}

function main()
{
	u01 	# root계정 원격 접속 제한
	u02 	# 패스워드 복잡성 설정
	u03 	# 계정 잠금 임계값 설정
#	u04 	# 패스워드 파일 보호(기본적으로 shadow파일 사용됨)
#	u05	# root 이외의 UID가 '0' 금지 (수동으로 점검)
	u06	# root 계정 su 제한
	u07	# 패스워드 최소 길이,최대 길이, 최소 사용기간 설정
	#u08	 u07과 동일 (u07에서 같이 적용됨)
	#u09	 u07과 동일 (u07에서 같이 적용됨)
	u10	# 불필요한 계정 제거
#	u11	# 관리자 그룹에 최소한의 계정 포함 (수동으로 점검)
#	u12	# 계정이 존재하지 않는 GID 금지 (점검만 가능)
#	u13	# 동일한 UID 금지 (수동으로 점검)
#	u14	# 사용자 shell 점검 (수동으로 점검)
	u15	# Session Timeout 설정
#	u16	# root 홈, 패스 디렉터리 권한 및 패스 설정 (수동으로 점검)
#	u17	# 파일 및 디렉터리 소유자 설정 (수동으로 점검)
#	u18	# /etc/passwd 파일 소유자 및 권한 설정
#	u19	# /etc/shadow 파일 소유자 및 권한 설정 (default설정이 root/000)
	u20	# /etc/hosts 파일 소유자 및 권한 설정
#	u21	# /etc/(x)inetd.conf 파일 소유자 및 권한 설정 (RHEL7에서 사용안함)
#	u22	# /etc/syslog.conf 파일 소유자 및 권한 설정
#	u23	# /etc/services 파일 소유자 및 권한 설정
	u24	# SUID, SGID, Sticky bit 설정 파일 점검
#	u25	# 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
#	u26	# world writable 파일 점검
#	u27	# /dev에 존재하지 않는 device 파일 점검(수동으로 점검)
#	u28	# $HOME/.rhosts, hosts.equiv 사용 금지(수동으로 점검)
#	u29	# 접속 IP 및 포트 제한(수동으로 점검)
#	u30	# hosts.lpd 파일 소유자 및 권한 설정(기본적으로 파일이  없다)
#	u31	# NIS 서비스 비활성화(수동점검)
	u32	# UMASK 설정 관리
#	u33	# 홈 디렉터리 소유자 및 권한 설정(수동점검)
#	u34	# 홈 디렉터리로 지정한 디렉터리의 존재 관리(수동점검)
#	u35	# 숨겨진 파일 및 디렉터리 검색 및 제거(수동점검)
#	u36	# Finger 서비스 비활성화(수동점검)
#	u37	# Anonymous FTP 비활성화
#	u38	# r 계열 서비스 비활성화(수동점검)
#	u39	# cron 파일 소유자 및 권한 설정(수동 점검)
#	u40	# DoS 공격에 취약한 서비스 비활성화(N/A)
#	u41	# NFS 서비스 비활성화(수동 점검)
#	u42	# NFS 접근통제(수동 점검) 
#	u43	# automountd 제거(수동 점검)
#	u44	# RPC 서비스 확인(수동 점검)
#	u45	# NIS, NIS+ 점검(수동 점검)
#	u46	# tftp, talk 서비스 비활성화(수동 점검)
#	u47	# Sendmail 버전 점검(수동점검)
#	u48	# 스팸 메일 릴레이 제한(수동점검)
#	u49	# 일반사용자의 Sendmail 실행 방지(수동점검)
#	u50	# DNS 보안 버전 패치(N/A)
#	u51	# DNS ZoneTransfer 설정(N/A)
#	u52	# Apache 디렉터리 리스팅 제거(N/A)
#	u53	# Apache 웹 프로세스 권한 제한(N/A)
#	u54	# Apache 상위 디렉터리 접근 금지(N/A)
#	u55	# Apache 불필요한 파일 제거(N/A)
#	u56	# Apache 링크 사용금지(N/A)
#	u57	# Apache 파일 업로드 및 다운로드 제한(N/A)
#	u58	# Apache 웹 서비스 영역의 분리(N/A)
#	u59	# ssh 원격접속 허용(수동점검)
#	u60	# ftp 서비스 확인(수동점검)
#	u61	# ftp 계정 shell 제한(수동점검)
#	u62	# Ftpusers 파일 소유자 및 권한 설정(수동점검)
#	u63	# Ftpusers 파일 설정(수동점검)
#	u64	# at 파일 소유자 및 권한 설정(수동점검)
#	u65	# SNMP 서비스 구동 점검(수동점검)
#	u66	# SNMP 서비스 커뮤니티스트링의 복잡성 설정(수동점검)
	u67	# 로그온 시 경고 메시지 제공
#	u68	# NFS 설정 파일 접근 권한(수동점검)
#	u69	# expn, vrfy 명령어 제한
#	u70	# Apache 웹서비스 정보 숨김
#	u71	# 최신 보안패치 및 벤더 권고사항 적용
#	u72	# 로그의 정기적 검토 및 보고
#	u73	# 정책에 따른 시스템 로깅 설정
	u74 # crontab 파일 권한 설정
   u75  # 로그저장주기 6개월로 변경
   u76 # 필요없는 서비스 disable
}

u06
color "NORMAL"

