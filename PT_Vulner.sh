#!/bin/bash

echo -e '\e[1;33mWelcome to the Vulner Tool\e[0m' & sleep 2
echo ' '
echo -e '\e[1;32mThis script automates the identifying of vulnerabilities inside a network, which can be time costly\e[0m'
echo -e '\e[1;32mUsing this tool allows can help improve the process of identifying vulnerabilities before attackers do\e[0m' & sleep 4
echo ' '
echo -e '\e[1;32mPlease type in your password when prompted as elevated rights are required at some portions\e[0m' & sleep 2
echo ' '

mkdir ~/vulner 2> /dev/null
cd ~/vulner 2> /dev/null
sgtime=$(TZ=Asia/Singapore date)
# To make sure all reports will be in one directory

# THIS PORTION IS TO FIND THE LAN NETWORK RANGE USING THE COMMAND 'IPPR ADDR'
ethorwifi=$(ip addr | grep eth0)

if [ -z "$ethorwifi" ]
then
	networkrange=$(ip addr | grep wlan0 | grep inet | awk '{print $2}')
	echo -e "\e[1;32mYour network range is $networkrange\e[0m"
	
else
	networkrange=$(ip addr | grep eth0 | grep inet | awk '{print $2}')
	echo -e "\e[1;32mYour network range is $networkrange\e[0m"
fi

# IN THIS SEGMENT, WE USE NETDISCOVER TO FIND THE LIVE HOSTS
sleep 2 & echo -e '\e[1;33mPlease wait as we scan your network for live host(s):\e[0m'
sudo netdiscover -P -r $networkrange > ndresults.txt && cat ndresults.txt
cat ndresults.txt | awk '$3=="1"' | awk '{print $1}' | awk -F'.' '!/\.([12]|254)$/' > iplist.txt
# To reduce delays in the nmap scan later, we exclude internal IP addresses ending with 1,2 or 254, which are host machine, NAT device and DHCP server respectively
	#! negative operator | \. treat as literal dot | [12][254] matches either 1,2 or 254 | $ pattern at the end of the line, last octet


# LINES THAT END WITH '>> VULNERREPORT.TXT' IS TO CONSOLIDATE DATA INTO A SINGLE REPORT
echo "$sgtime" >> VULNERreport.txt
echo "**************************************************************************THESE ARE THE IP ADDRESSES(ES) OF THE LIVE HOSTS**************************************************************************" >> VULNERreport.txt
cat iplist.txt >> VULNERreport.txt

echo ' '
sleep 5 & echo -e '\e[1;33mPlease wait as we scan and enumerate the live host(s), this may take awhile:\e[0m' & sleep 2

# THIS SECTION INVOLVES USING A WHILE READ LOOP TO PERFORM NMAP SCANS
while read -r target
do
	sudo nmap --script vuln -sV -p- -T5 -vv "$target" -oN "scanresult_$target"
	echo ' '
	echo -e "\e[1;33mThese are the login services that are available on $target for bruteforcing:\e[0m"
	cat "scanresult_$target" | grep open | grep tcp | grep 'ftp\|ssh\|smb'
	echo "**************************************************************************THESE ARE THE VULNERABILITIES FOR $target**************************************************************************" >> VULNERreport.txt
	cat "scanresult_$target" >> VULNERreport.txt
	echo ' '
	# --script vuln, to run nse scripts to expose vulnerabilities
	# grep 'ftp\|ssh\|smb' allows to grep for mulitple patterns
		# https://phoenixnap.com/kb/grep-multiple-strings
done < iplist.txt


# THIS SECTION IS TO ALLOW USERS TO SPECIFY A USER AND PASS LIST FOR THE BRUTEFORCE ATTACKS
echo ' '
echo -e '\e[1;32mIn order to bruteforce,we will need a user list,\e[0m' & sleep 1
echo -e '\e[1;32mPlease key in the FULL file path of the user list:\e[0m'
read USER_LIST_PATH

echo ' '
echo -e '\e[1;32mWe will also need a password list,\e[0m' & sleep 1
echo ' '
echo -e '\e[1;32mDo you want to specify a list or create one?\e[0m'
echo -e '\e[1;32m[A] Specify  [B] Create one\e[0m'
read PASSOPTION
echo ' '

case $PASSOPTION in
	A|a)
		echo -e '\e[1;32mPlease key in the FULL file path of the password list:\e[0m'
		read PASS_LIST_PATH
		cp "$PASS_LIST_PATH" passlist.txt
	;;
	B|b) 
		echo -e '\e[1;32mPlease type in the passwords, as many as you want, using space as a separator between each user name. E.g. pass 12345 Passw0rd!\e[0m'
		read PASS_WORD
		echo "$PASS_WORD" > typedpass.txt
		tr ' ' '\n' < typedpass.txt > passlist.txt
		rm typedpass.txt
		# Transposing from horizontal data set to vertical
			# credits: https://odin.mdacc.tmc.edu/~ryu/linux.html#:~:text=If%20you%20type%20%22tr%20'%5C,one%20column%20into%20one%20row
	;;
     *)
		exit
     ;;
     esac

echo ' '
sleep 3 & echo -e '\e[1;32mThank you for your input, we will begin the bruteforce ...\e[0m'

echo '**************************************************************************BRUTEFORCING RESULTS**************************************************************************' >> VULNERreport.txt

# IN THIS PORTION, WE USE A WHILE READ LOOP TO IDENTIFY THE LOGIN SERVICES AVAILABLE
	# For the scope of this project, we will be focusing on the top 3 more common login services which are ssh, ftp & smb
	# If more than one login service is available, choose the first service
	# Each service might also have multiple ports, so a randmoniser is applied
	# Hydra will be used as the attack vector

while read -r target
do
	port=$(cat "scanresult_$target" | grep open | grep tcp | grep 'ftp\|ssh\|smb' | head -n1)
	ftpstatus=$(cat "scanresult_$target" | grep open | grep tcp | grep 'ftp\|ssh\|smb' | head -n1 | grep ftp) 2> /dev/null
	sshstatus=$(cat "scanresult_$target" | grep open | grep tcp | grep 'ftp\|ssh\|smb' | head -n1 | grep ssh) 2> /dev/null
	smbstatus=$(cat "scanresult_$target" | grep open | grep tcp | grep 'ftp\|ssh\|smb' | head -n1 | grep smb) 2> /dev/null
	# To check for the presence/status of a certain type of login service
		
	if [ -n "$ftpstatus" ]
	# -n means if not empty
	then	
		cat "scanresult_$target"  | grep open | grep ftp | awk '{print $1}' > ftpport.txt

		counter=$(cat ftpport.txt | wc -l)
		randomnumber=$(echo $(( $RANDOM%$counter+1)))
		ftpport=$(cat ftpport.txt | head -n $randomnumber | tail -n 1)
		# If there are multiple ports, a randomiser is applied

		hydra -L "$USER_LIST_PATH" -P passlist.txt "$target" ftp -s $ftpport 
		# -L, -P, -s to specify user, pass list and port respectively
		hydra -L "$USER_LIST_PATH" -P passlist.txt "$target" ftp -s $ftpport >> "bruteresult_$target"
		cat "bruteresult_$target" >> VULNERreport.txt
		
		rm ftpport.txt 2> /dev/null

	else
		if [ -n "$smbstatus" ]
		then
			cat "scanresult_$target"  | grep open | grep smb | awk '{print $1}' > smbport.txt

			counter=$(cat smbport.txt | wc -l)
			randomnumber=$(echo $(( $RANDOM%$counter+1)))
			smbport=$(cat smbport.txt | head -n $randomnumber | tail -n 1)

			hydra -L "$USER_LIST_PATH" -P passlist.txt "$target" smb -s $smbport
			hydra -L "$USER_LIST_PATH" -P passlist.txt "$target" smb -s $smbport >> "bruteresult_$target"
			cat "bruteresult_$target" >> VULNERreport.txt
			
			rm smbport.txt 2> /dev/null
		else
			cat "scanresult_$target"  | grep open | grep ssh | awk '{print $1}' > sshport.txt

			counter=$(cat sshport.txt | wc -l)
			randomnumber=$(echo $(( $RANDOM%$counter+1)))
			sshport=$(cat sshport.txt | head -n $randomnumber | tail -n 1)

			hydra -L "$USER_LIST_PATH" -P passlist.txt "$target" ssh -s $sshport
			hydra -L "$USER_LIST_PATH" -P passlist.txt "$target" ssh -s $sshport >> "bruteresult_$target"
			cat "bruteresult_$target" >> VULNERreport.txt
			
			rm sshport.txt 2> /dev/null
		fi
	fi
done < iplist.txt


# TO GIVE USER A SUMMARY OF WHAT HAS HAPPENED THUS FAR
echo ' '
sleep 3 & echo -e '\e[1;33mThese are the live hosts we scanned and enumerated:\e[0m' & sleep 2
cat iplist.txt
sleep 2& echo -e '\e[1;32mAll results are consolidated in ~/vulner/VULNERreport.txt\e[0m'

# ALLOW USERS TO SPECIFY AN IP ADDRESS TO RETRIEVE FINDINGS
echo -e '\e[1;32mWould you like to display the findings for a particular host? (y/n)\e[0m'
read OPTION

case $OPTION in
	Y|y)
		echo -e '\e[1;32mPlease choose the IP Address of the live host to display the findings:\e[0m'
		read IPFINDING
		echo -e '\e[1;32mHere are the findings:\e[0m' & sleep 3
		cat "scanresult_$IPFINDING"
		cat "bruteresult_$IPFINDING"
		echo -e '\e[1;32mThank you, we have come to the end of the script!\e[0m'

	;;
	N|n) 
		echo -e '\e[1;32mThank you, we have come to the end of the script!\e[0m'
     ;;
     esac

# CLEANING UP OF FILES
rm ndresults.txt
rm iplist.txt
rm passlist.txt
mkdir individualreports 2> /dev/null
mv scanresult_* individualreports & mv bruteresult_* individualreports
