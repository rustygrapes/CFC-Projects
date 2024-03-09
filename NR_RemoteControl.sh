#!/bin/bash

echo -e '\e[1;33mWelcome to the remote controller\e[0m' && sleep 3
echo ' '
echo -e  '\e[1;32m(1) This remote controller makes your connection anonymous\e[0m' && sleep 3
echo -e '\e[1;32m(2) Thereafter it executes a whois and nmap scan on a target IP on a specificed remote server\e[0m' && sleep 5
echo ' '
echo -e '\e[1;33mBefore we start this process, we must ensure you have all the necessary applications installed\e[0m' && sleep 4

# '\e[1;33m <text> \e[0m' uses color codes to add some visual appeal to your output
	# \e is the escape sequence that tells the terminal emulator that a color code is about to follow.
	# \e[33m: yellow
	# \e[32m: green
	# \e[0m is another escape sequence that tells the terminal emulator to stop interpreting color codes.

echo ' '
geoipapp=$(dpkg -l | grep geoip-bin)
geoipinstall=$(echo $geoipapp)

# geoiplookup helps to give the country of a specified IP adress
# dpkg is a package manager for Debian-based systems
	# dpkg -l lists the installed packages on the system
	# We 'grep geoip-bin' to check if geoiplookup has been installed
# geoipinstall just echoes the status of the geoiplookup installation
# Credits: https://www.baeldung.com/linux/list-installed-packages

if [ -z "$geoipinstall" ]
then	
	echo -e "\e[1;33mInstalling geoiplookup package, please input password if prompted\e[0m" && sleep 2
	sudo apt-get install geoip-bin && sleep 3
	echo -e '\e[1;32mGeoiplookup has been installed\e[0m'
else
	sleep 2
	echo -e '\e[1;32mNice, you have Geoiplookup installed\e[0m'
fi
# -z means 'if empty'
# Therefore if geouplookup is uninstalled, the script will install it.
# If installed, it will not install it again.

sleep 2
echo ' '

nipeapp=$(find ~ -type d -name nipe)
nipeinstall=$(echo $nipeapp)
# nipe helps to anonymise your ip address by using the onion router (Tor) network as a user's default gateway
# find in /home/$user if a directory named nipe exists
# nipeinstall just echoes the directory location

if [ -z "$nipeinstall" ]
then
	echo -e '\e[1;33mInstalling nipe, please input password if prompted\e[0m' && sleep 1
	git clone https://github.com/htrgouvea/nipe && cd nipe
	# We must clone this repository from GitHub
	
	sudo cpan install Try::Tiny Config::Simple JSON
	# To install the libraries and dependencies
	
	sudo perl nipe.pl install && sleep 3
	# To install Nipe dependencies or a Perl script
		# Perl is a family of script programming languages that is similar in syntax to the C language
		
	echo -e '\e[1;32mNipe has been installed\e[0m'
	# Credits: https://www.geeksforgeeks.org/how-to-install-nipe-tool-in-kali-linux/
else
	sleep 2
	echo -e '\e[1;32mNice, you have Nipe installed\e[0m'
fi
# -z means 'if empty'
# Therefore, if nipe directory does not exists, the script will install nipe.
# If directory exists, it will not install it again.

nipedir=$(find ~ -type d -name nipe)
cd $nipedir
# Find in /home/$user to print the nipe directory 
# We then change directories into the nipe folder to start the service

echo ' ' && sleep 1
echo -e '\e[1;33mStarting the nipe service, please input password if prompted\e[0m'
sudo perl nipe.pl stop && sleep 3
sudo perl nipe.pl start && sleep 3
sleep 2 && echo -e '\e[32mPlease wait as we run the service\e[0m'
echo ' '

nipestatus=$(echo "$(sudo perl nipe.pl status)" | grep -i false)
IPX=$(echo "$(sudo perl nipe.pl status)" | grep -i ip | awk -F: '{print $2}' | tr -d "[:blank:]")

# nipestatus checks if the nipe service has not started
	# grep -i ignores case sensitivity
# IPX greps the IP address from the nipestatus output
	# awk -F: "{print $2}' prints the 2nd column with ':' as the separator
	# tr -d "[:blank]" deletes blank spaces

if [ -z $nipestatus ]
then
	echo 'Spoofed country name:'
	geoiplookup "$IPX" | awk -F: '{print $2}'
else
	echo -e '\e[1;33mConnection is not anonymous, please exit\e[0m'
	kill -9 $$
	# The -9 option tells kill to send a SIGKILL signal, which immediately terminates the process.
	# $$ is a variable used to store the PID of a running script.
	# Credits: https://www.javatpoint.com/kill-command-in-linux#:~:text=It%20is%20used%20for%20manually,%24%20type%20%2Da%20kill
fi
# -z means 'if empty'
# Therefore, if the nipe has started, the script will echo the spoofed country
# If nipe service has not started, the script will stop running

sleep 3
echo ' '

echo -e '\e[1;33mTarget IP Address for Whois & Nmap scan:\e[0m'
read targetip
# read allows for users of the script to input a string

echo ' '
echo -e '\e[1;32mConnecting to the remote server, please wait\e[0m' && sleep 1
echo ' ' 
echo -e '\e[1;33mPlease input the remote server IP Address:\e[0m'
read IPadd
echo -e '\e[1;33mPlease input the username of the remote server:\e[0m'
read Username
echo -e '\e[1;33mPlease input the password of the remote server:\e[0m'
read -s Password
# -s does not echo input, credits: https://www.baeldung.com/linux/bash-hide-user-input
sleep 2

echo ' '
date | tee -a ~/remoteseverlog.txt && sleep 1
remoteIP=$(sshpass -p $Password ssh -o StrictHostKeyChecking=no $Username@$IPadd "curl -s ifconfig.me")

# tee prints the output of a command
	# -a appends to a given file, in this case /home/$user/remoteserver.log.txt
	# Credits: https://www.geeksforgeeks.org/tee-command-linux-example/
# Syntax of sshpass -> sshpass -p <Password> ssh <Username>@Ipaddress
	# " " is to specify the commands to execute after entering the remote server
	# -o StrictHostKeyChecking=no skips the host key checking everytime you do a new SSH

echo ' '
echo "Remote Server IP: $remoteIP" | tee -a ~/remoteseverlog.txt && sleep 1
echo ' '
echo "Remote Sever IP Country: $(geoiplookup $remoteIP | awk -F: '{print $2}')" | tee -a ~/remoteseverlog.txt && sleep 1
echo ' '
echo "Remote Sever uptime: $(uptime)" | tee -a ~/remoteseverlog.txt && sleep 1
echo ' '
echo "*****************************************End of session*****************************************" | tee -a ~/remoteseverlog.txt
# geoiplookup finds the country of a particular IP Address
# uptime prints the current time, the length of time the system has been up, the number of users online, and the load average. 
	# The load average is the number of runnable processes over the preceding 1-, 5-, 15-minute intervals.
	# Credits: https://www.ibm.com/docs/en/aix/7.2?topic=u-uptime-command

echo ' ' && sleep 2
echo -e '\e[1;33mRemote server activities are logged\e[0m' && sleep 2
echo -e '\e[32mLogs are stored in remoteseverlog.txt that is saved in your User Directory\e[0m' && sleep 5

echo ' ' & sleep 2
echo -e '\e[1;32mRunning whois and nmap scan, please wait\e[0m'
sshpass -p $Password ssh -o StrictHostKeyChecking=no $Username@$IPadd "whois $targetip > whoisreport.txt"
sshpass -p $Password ssh -o StrictHostKeyChecking=no $Username@$IPadd "nmap $targetip -Pn -T5 -oN nmapscan.txt"
# > whoisreport.txt saves output of whois to a text file
# nmap scans for open ports of a server
	# -Pn used to skip the host discovery stage of the scanning process
		# Assume that the target host(s) are online and available for scanning.
	# -T5 sets the speed of the scan
	# -oN injects output of the scan into a file

echo ' '
echo -e '\e[1;33mSaving Whois & Nmap report, please choose file location:\e[0m'
echo -e '\e[32mA) User Directory B) Downloads C) New Directory\e[0m'
read OPTIONS

case $OPTIONS in
	A|a)
		echo -e '\e[1;33mIf prompted, please input password of remote server to download the whois report:\e[0m'
		scp $Username@$IPadd:/home/$Username/whoisreport.txt ~
		echo -e '\e[1;33mIf prompted, please input password of remote server to download the nmap report:\e[0m'
		scp $Username@$IPadd:/home/$Username/nmapscan.txt ~
		echo ' ' && sleep 1
		echo -e '\e[32mReports are saved in your User Directory\e[0m'
	;;
	B|b) 
		echo -e '\e[1;33mIf prompted, please input password of remote server to download the whois report:\e[0m'
		scp $Username@$IPadd:/home/$Username/whoisreport.txt ~/Downloads
		echo -e '\e[1;33mIf prompted, please input password of remote server to download the nmap report:\e[0m'
		scp $Username@$IPadd:/home/$Username/nmapscan.txt ~/Downloads
		echo ' ' && sleep 1
		echo -e '\e[32mReports are saved in ~/Downloads\e[0m'
	;;
	C|c)
		echo -e '\e[1;33mPlease input name of new directory\e[0m'
		read newdir
		mkdir ~/$newdir
		echo -e '\e[1;33mIf prompted, please input password of remote server to download the whois report:\e[0m'
		scp $Username@$IPadd:/home/$Username/whoisreport.txt ~/$newdir
		echo -e '\e[1;33mIf prompted, please input password of remote server to download the nmap report:\e[0m'
		scp $Username@$IPadd:/home/$Username/nmapscan.txt ~/$newdir
		echo ' ' && sleep 1
		echo -e "\e[32mReports are saved in ~/$newdir\e[0m"
		;;
		esac
# Case allows for the user to choose from a variety of options
# scp copies files or directories between a local and a remote system
	# The syntax is <username>@<remoteserverIP>:<file location> <destination>
		
sshpass -p $Password ssh -o StrictHostKeyChecking=no $Username@$IPadd "rm whoisreport.txt && rm nmapscan.txt"
# Delete files from the remote server

echo ' '  && sleep 2
echo -e '\e[1;33mThank you for using this remote controller\e[0m' && sleep 2
echo -e '\e[1;32mPlease contact Ryan, @rustygrapes via telegram if there are any issues\e[0m' && sleep 4
echo ' '
echo -e '\e[1;35mThank you once again & Goodbye~\e[0m' && sleep 2
