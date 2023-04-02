#!/bin/bash
#by ikuamike

# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;97m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

rm $2/commands.txt 2>/dev/null
# automate quick port scan to feed to thorough port scan with list of ports
printf "\n${BWhite}[+] Running Nmap full port scan: nmap -n -Pn -sS -v -p- --min-rate=1000 $1 ${Color_Off}\n\n"
mkdir -p $2/recon-$2
cd $2
sudo grc nmap -n -Pn -sS -v -p- --min-rate=1000 --open -oA recon-$2/$2_quick_tcp $1 #| /usr/bin/grep --color=always -v "delay"
ports=`grep -v nmap recon-$2/$2_quick_tcp.nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr '\n' ','| head -c -1`

printf "\n${BWhite}[+] Running Nmap thorough scan: nmap -n -Pn -sC -sV -p $ports $1 ${Color_Off}\n\n"
sudo grc nmap -n -Pn -sC -sV -p $ports -oA recon-$2/$2_full_tcp $1

# SMB
if grep -q 445/tcp recon-$2/$2_full_tcp.nmap; then
	#printf "\n${BGreen}[+] Enumerating port 445${Color_Off}\n" > port445.report
	echo "printf \"\n${White}[*] enum4linux-ng -A -R $1 ${Color_Off}\n\n\" > recon-$2/$2-enum4linux-ng.enum; enum4linux-ng -A _target_ >> recon-$2/$2-enum4linux-ng.enum;printf \"${Green}[*] enum4linux-ng done${Color_Off}\"" > commands.txt
	echo "printf \"\n${White}[*] smbmap -R -H $1 ${Color_Off}\n\n\" > recon-$2/$2-smbmap.enum;smbmap -R -H _target_ >> recon-$2/$2-smbmap.enum;printf \"${Green}[*] smbmap done${Color_Off}\"" >> commands.txt
	echo "printf \"\n${White}[*] smbclient -L //$1 -N ${Color_Off}\n\" > recon-$2/$2-smbclient.enum;smbclient -L //_target_ -N >> recon-$2/$2-smbclient.enum;printf \"${Green}[*] smbclient done${Color_Off}\"" >> commands.txt
	echo "printf \"\n${White}[*] smb nmap scripts ${Color_Off}\n\n\" > recon-$2/$2-smbnmap.enum;sudo nmap -n -Pn -T4 -sV -p 139,445 --script smb-ls,smb-enum-shares,vulners,vuln --append-output -oN recon-$2/$2-smbnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port 139,445 smb nmap scripts done${Color_Off}\"" >> commands.txt
fi

# Web
for port in $(grep open recon-$2/$2_full_tcp.nmap | grep -v "#" | grep -v "Microsoft HTTPAPI httpd" | grep http | awk -F/ '{print $1}');do
	echo "printf \"\n${White}[*] Nmap Scripts for http port $port ${Color_Off}\n\n\" > recon-$2/$2-${port}-httpnmap.enum;sudo nmap -n -Pn -T4 -sV -p $port --script 'http-enum,http-backup-finder,http-config-backup,vuln and not vulners' --append-output -oN recon-$2/$2-${port}-httpnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port $port http nmap scripts done ${Color_Off}\"" >> commands.txt
done   

# SSH
for port in $(grep open recon-$2/$2_full_tcp.nmap | grep -v "#" | grep ssh | awk -F/ '{print $1}');do
	echo "printf \"\n${White}[*] ssh nmap scripts ${Color_Off}\n\n\" > recon-$2/$2-sshnmap.enum;sudo nmap -n -Pn -T4 -sV -p $port --script ssh-auth-methods --append-output -oN recon-$2/$2-sshnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port $port ssh nmap scripts done ${Color_Off}\"" >> commands.txt
done

# FTP
if grep open recon-$2/$2_full_tcp.nmap | grep ftp | grep -v "Microsoft ftpd"; then
	echo "printf \"\n${White}[*] FTP Nmap Scripts ${Color_Off}\n\n\" > recon-$2/$2-ftpnmap.enum;sudo nmap -n -Pn -T4 -sV -p 21 --script ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,vulners --script-args mincvss=7 --append-output -oN recon-$2/$2-ftpnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port 21 ftp nmap scripts done${Color_Off}\"" >> commands.txt
fi

# LDAP
if grep -w -q 389 recon-$2/$2_full_tcp.nmap; then
	echo "printf \"\n${White}[*] ldap nmap scripts ${Color_Off}\n\n\" > recon-$2/$2-ldapnmap.enum;sudo nmap -n -Pn -T4 -sV -p 389,636 --script ldap* --append-output -oN recon-$2/$2-ldapnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port 389,636 ldap nmap scripts done${Color_Off}\"" >> commands.txt
fi

# RDP
if grep -w -q 3389 recon-$2/$2_quick_tcp.nmap; then
	echo "printf \"\n${White}[*] bluekeep check nmap script ${Color_Off}\n\n\" > recon-$2/$2-bluekeep.enum;sudo nmap -n -Pn -T4 -sV -p 3389 --script rdp-vuln-ms12-020 --append-output -oN recon-$2/$2-bluekeep.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] bluekeep check nmap script done ${Color_Off}\"" >> commands.txt
fi

# NFS
if grep -w -q 111 recon-$2/$2_quick_tcp.nmap; then
	echo "printf \"\n${White}[*] nfs/rpc nmap scripts ${Color_Off}\n\n\" > recon-$2/$2-rpcnmap.enum;sudo nmap -n -Pn -T4 -sV -p 111 --script nfs* --append-output -oN recon-$2/$2-rpcnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port 111 nmap scripts done ${Color_Off}\"" >> commands.txt
fi

# MSSQL

# SMTP

# RPC

# VNC
for port in $(grep open recon-$2/$2_full_tcp.nmap | grep vnc | awk -F/ '{print $1}');do
	echo "printf \"\n${White}[*] vnc nmap scripts for $port ${Color_Off}\n\n\" > recon-$2/$2-${port}-vncnmap.enum;sudo nmap -n -Pn -T4 -sV -p $port --script vuln --append-output -oN recon-$2/$2-${port}-vncnmap.enum _target_ >/dev/null 2>&1;printf \"${Green}[*] port $port vnc nmap scripts done ${Color_Off}\"" >> commands.txt
done 

interlace -t $1 -cL commands.txt -threads 20 --silent

sleep 3
# Report
printf "\n${BYellow}[*] NMAP ${Color_Off}" > $2.report
printf "\n${BYellow}========================================================= ${Color_Off}\n" >> $2.report
#cat recon-$2/$2_quick_tcp.nmap >> $2.report 2>/dev/null
cat recon-$2/$2_full_tcp.nmap >> $2.report 2>/dev/null
	

if grep -w -q ftp recon-$2/$2_quick_tcp.nmap; then
	printf "\n${BYellow}[*] FTP ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >> $2.report
	cat recon-$2/$2*ftpnmap* | grep -vi "SAINT\|CANVAS\|1337DAY" >> $2.report 2>/dev/null
fi

if grep -w -q ssh recon-$2/$2_full_tcp.nmap; then
	printf "\n${BYellow}[*] SSH ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >> $2.report
	cat recon-$2/$2*sshnmap* >> $2.report 2>/dev/null
fi

if grep -w -q http recon-$2/$2_quick_tcp.nmap; then
	printf "\n${BYellow}[*] HTTP ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >> $2.report
	cat recon-$2/$2*httpnmap* recon-$2/$2*ffuf* recon-$2/$2*nikto* >> $2.report 2>/dev/null
fi

if grep -w -q 389 recon-$2/$2_quick_tcp.nmap; then
	printf "\n${BYellow}[*] LDAP ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >> $2.report
	cat recon-$2/$2*ldapnmap* >> $2.report 2>/dev/null
fi

if grep -w -q 445 recon-$2/$2_quick_tcp.nmap; then
	printf "\n${BYellow}[*] SMB ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >>$2.report
	cat recon-$2/$2*smbnmap* recon-$2/$2*smbmap* recon-$2/$2*smbclient* recon-$2/$2*enum4linux* >> $2.report 2>/dev/null
fi

if grep -w -q 111 recon-$2/$2_quick_tcp.nmap; then
	printf "\n${BYellow}[*] RPC/NFS ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >>$2.report
	cat recon-$2/$2*rpcnmap* >> $2.report 2>/dev/null
fi

if grep -w -q 3389 recon-$2/$2_quick_tcp.nmap; then
	printf "\n${BYellow}[*] RDP ${Color_Off}" >> $2.report
	printf "\n${BYellow}========================================================= ${Color_Off}\n" >>$2.report
	cat recon-$2/$2*bluekeep* >> $2.report 2>/dev/null
fi


less -f -r $2.report 2>/dev/null

# UDP Scan



