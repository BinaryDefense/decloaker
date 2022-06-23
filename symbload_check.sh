#!/bin/bash

CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
GRAY='\033[0;90m'
LGRAY='\033[0;93m'
MAGE='\033[0;35m'

echo
echo -e "${GRAY}-------------------------------------${NC}${YELLOW}\033[33;5mWARNING\033[0m${NC}${GRAY}-----------------------------------------${NC}"
echo
echo -e "${LGRAY}This script is meant to be supplementary to an investigation into Symbiote or other LD_PRELOAD based rootkits."
echo -e "Due to the nature of rootkits, host based forensics should always be treated with skepticism when investigating."
echo

echo -e "${GRAY}---------------------------${NC}${MAGE}Checking for Syslogk${NC}${GRAY}-------------------------------------${NC}"
echo

echo '1'>/proc/syslogk 2>/dev/null
lsmod | grep -i syslogk
grep_rtrn=$?

if [ $grep_rtrn -eq 0 ]; then
	echo -e "${RED}[!] System is infected with Syslogk rootkit${NC}"
	netstat -tulpn |grep LISTEN|awk '{ print $7 }' |grep -q '^-$'
	payload_rtrn=$?
	if [ $payload_rtrn -eq 0 ]; then
		echo -e "${RED}---> [!] Backdoor payload active"
		bad_procs=$(netstat -tulpn |grep LISTEN|grep ' -'|awk '{ print $4 }')
		backdoor=1
	else
		echo -e "${YELLOW}---> [~] Backdoor payload not currently active"
		backdoor=0
	fi
	while true; do
		echo -e -n "${CYAN}------> [?] Remove Syslogk from memory? (Y/N): ${NC}"
		read confirm
		if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
			find /etc -type f > pre_decloak.txt
			rmmod syslogk
			echo -e "${GREEN}---------> [*] Syslogk removed from memory.${NC}"
			find /etc -type f > post_decloak.txt
			if [ $backdoor -eq 1 ]; then
				bad_pids=$(for x in $bad_procs; do netstat -tulpn | grep $x | awk '{ print $7 }' | cut -d'/' -f1; done)
				bad_files=$(for x in $bad_pids; do ls -l /proc/$x/exe| awk '{ print $11 }'; done|sort|uniq|tr '\n' ' ')
				echo -e -n "${CYAN}-----------> [?] Kill backdoor process? (Y/N): ${NC}"
				read confirm
				if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
					for x in $bad_pids; do kill $x; echo -e "${GREEN}------------> $x killed"; done
                                	p_exist=$(comm -3 <(sort pre_decloak.txt) <(sort post_decloak.txt)|sed -u 's/\t//g'|tr '\n' ' ')
                                	if [[ ! -z $p_exist || ! -z $bad_files ]]; then
						file_array=($(echo $p_exist) $(echo $bad_files))
						empt_array=()
						for x in $file_array; do 
							if printf '%s\0' "${file_array[@]}" | grep -Fxqz $x; then
								empt_array+=$x
							else
								:
							fi;
						done
						echo -e "${RED}------------> [!] Backdoor payload file found in ${empt_array[@]}${NC}"
						echo -e -n "${CYAN}---------------> [?] Remove backdoor payload file? (Y/N): ${NC}"
						read confirm
						if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
							rm -rf ${empt_array[@]}
							echo -e "${GREEN}------------------> [*] Payload removed.${NC}"
							echo -e "${GRAY}                        Note: Payload parent directory remains, in order to ensure this script doesn't delete important directories. Manual cleanup required.${NC}"
							break
						else
							echo -e "${YELLOW}------------------> [~] Leaving $p_exist in place.${NC}"
							break
						fi
                                	else
                                	        echo -e "${RED}------------> [!] Backdoor payload file not found in.${NC}"
						break
                                	fi
				else
					echo -e "${YELLOW}------------> [~] Leaving backdoor process alive. PIDs: $(for x in $bad_pids; do netstat -tulpn | grep $x | awk '{ print $7 }' | cut -d'/' -f1; done|tr '\n' ' ')"
					#for x in $bad_pids; do echo -e "${RED}---------------> $(netstat -tulpn | grep $x | awk '{ print $7 }' | cut -d'/' -f1)${NC}";  done
					break
				fi
			else
				echo -e "${GREEN}---------> [*] No backdoor process found.${NC}"
				echo -e "${YELLOW}------------> [~] Looking for dormant backoor payload file...${NC}"
                                p_exist=$(comm -3 <(sort pre_decloak.txt) <(sort post_decloak.txt)|sed -u 's/\t//g')
                                if [[ ! -z $p_exist || ! -z $bad_files ]]; then
					file_array=($(echo $p_exist) $(echo $bad_files))
                                        empt_array=()
                                        for x in $file_array; do
                                                if printf '%s\0' "${file_array[@]}" | grep -Fxqz $x; then
                                                        empt_array+=$x
                                                else
                                                        :
                                                fi;
                                        done
                                        echo -e "${RED}---------------> [!] Backdoor payload file found in ${empt_array[@]}${NC}"
					echo -e -n "${CYAN}------------------> [?] Remove backdoor payload file? (Y/N): ${NC}"
					read confirm
                                        if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
                                                rm -rf ${empt_array[@]}
						echo -e "${GREEN}------------------> [*] Payload removed.${NC}"
						echo -e "${LGRAY}                        Note: Payload parent directory remains, in order to ensure this script doesn't delete important directories. Manual cleanup required.${NC}"
                                                break
                                        else
                                                echo -e "${YELLOW}------------------> [~] Leaving ${empt_array[@]} in place"
                                                break
                                        fi

                                else
                                        echo -e "${GREEN}---------------> [*] Backdoor payload file not found${NC}"
                                        break
				fi
			fi
		else
			echo -e "${YELLOW}---------> [~] Leaving Syslogk in place.${NC}"
			break
		fi
	done
else
	echo -e "${GRAY}↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑Ignore this↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑"
	echo -e "${GREEN}[*] Syslogk not detected.${NC}"
fi
rm -f *_decloak.txt
echo

echo -e "${GRAY}---------------------------${NC}${MAGE}Checking for Symbiote${NC}${GRAY}-------------------------------------${NC}"
echo
	mkdir -p ./symbiote_test
declare -a SYMB_FILES=("certbotx64" "certbotx86" "javautils" "javaserverx64" "javaclientex64" "javanodex86" "apache2start" "apache2stop" "profiles.php" "404erro.php" "javaserverx64" "javaclientex64" "javanodex86" "liblinux.so" "java.h" "open.h" "mpt86.h" "sqlsearch.php" "indexq.php" "mt64.so" "certbot.h" "cert.h" "certbotx64" "certbotx86" "javautils" "search.so")

for x in ${SYMB_FILES[@]}; do
	touch ./symbiote_test/$x
done
NUM_FILES=$(ls ./symbiote_test/ | wc -l)
if [ $NUM_FILES -lt 20 ]; then
	echo -e "${RED}[!] Symbiote related filenames are being hidden. Potential malware present.${NC}"
	echo
	if [[ $LD_PRELOAD && -s /etc/ld.so.preload ]]; then
		echo -e "${YELLOW}[!] LD_PRELOAD and /etc/ld.so.preload both present.${NC}"
		LD_PRE=$(echo $LD_PRELOAD)

		unset LD_PRELOAD
		mv /etc/ld.so.preload /etc/preload.bak

		base_unset_count=$(ls ./symbiote_test/ | wc -l)
		base_mv_count=$(ls ./symbiote_test/ | wc -l)

		export LD_PRELOAD=$(echo $LD_PRE)
		post_unset_count=$(ls ./symbiote_test/ | wc -l)
		unset LD_PRELOAD
		mv /etc/preload.bak /etc/ld.so.preload
		post_mv_count=$(ls ./symbiote_test/ | wc -l)
		export LD_PRELOAD=$(echo $LD_PRE)

		unset LD_PRELOAD; mv /etc/ld.so.preload /etc/preload.bak; rm -rf ./symbiote_test && export LD_PRELOAD=$(echo $LD_PRE); mv /etc/preload.bak /etc/ld.so.preload

		if [ "$base_unset_count" -gt "$post_unset_count" ] && [ "$base_mv_count" -gt "$post_mv_count" ]; then
			echo -e "${RED}---> [!] LD_PRELOAD env variable matches Symbiote file hiding behavior.${NC}"
			echo -e "${RED}---> [!] /etc/ld.so.preload matches Symbiote file hiding behavior.${NC}"
			echo -e
			echo
		elif [ "$base_unset_count" -gt "$post_unset_count" ]; then
			echo -e "${GREEN}---> [*] /etc/ld.so.preload does not match Symbiote file hiding behavior.${NC}"
			echo -e "${RED}---> [!] LD_PRELOAD env variable matches Symbiote behavior.${NC}"
			echo
		elif [ "$base_mv_count" -gt "$post_mv_count" ]; then
			echo -e "${GREEN}---> [*] LD_PRELOAD env variable does not match Symbiote file hiding behavior.${NC}"
			echo -e "${RED}---> [!] /etc/ld.so.preload matches Symbiote behavior.${NC}"
			echo
		else
			echo -e "${YELLOW}---> [~] No change in file hiding behavior, hooks are likely being intercepted.${NC}"
			echo
		fi
	elif [[ $LD_PRELOAD && ! -s /etc/ld.so.preload ]]; then
		echo -e "${YELLOW}[~] LD_PRELOAD present.${NC}"
		LD_PRE=$(echo $LD_PRELOAD)
		pre_unset_count=$(ls ./symbiote_test/ | wc -l)
                unset LD_PRELOAD
                post_unset_count=$(ls ./symbiote_test/ | wc -l)
                export LD_PRELOAD=$(echo $LD_PRE)
		pre_mv_count=0
		post_mv_count=0

		unset LD_PRELOAD; rm -rf ./symbiote_test; export LD_PRELOAD=$(echo $LD_PRE)

		if [ "$pre_unset_count" -lt "$post_unset_count" ]; then
			echo -e "${RED}---> [!] LD_PRELOAD present and exhibiting Symbiote file hiding behavior.${NC}"
			echo
		else
			echo -e "${YELLOW}---> [~] LD_PRELOAD present but does not exhibit Symbiote file hiding behavior.${NC}"
			echo
		fi
	elif [[ -z $LD_PRELOAD && -s /etc/ld.so.preload ]]; then
		echo -e "${YELLOW}[~] /etc/ld.so.preload present.${NC}"
		pre_mv_count=$(ls ./symbiote_test/ | wc -l)
		mv /etc/ld.so.preload /etc/preload.bak
                post_mv_count=$(ls ./symbiote_test/ | wc -l)
                mv /etc/preload.bak /etc/ld.so.preload
		pre_unset_count=0
		post_unset_count=0

		mv /etc/ld.so.preload /etc/preload.bak; rm -rf ./symbiote_test; mv /etc/preload.bak /etc/ld.so.preload

		if [ "$pre_mv_count" -lt "$post_mv_count" ]; then
                        echo -e "${RED}---> [!] /etc/ld.so.preload present and exhibiting Symbiote file hiding behavior.${NC}"
			echo
                else
                        echo -e "${YELLOW}---> [~] /etc/ld.so.preload present but does not exhibit Symbiote file hiding behavior.${NC}"
			echo
		fi
	else
		echo -e "${YELLOW}[~] No LD_PRELOAD env variable or /etc/ld.so.preload, hooks are likely being intercepted."
		echo -e "${YELLOW}---> [~] ./symbiote_test directory may require manual cleanup."
		echo
		post_unset_count=0
		post_mv_count=0
	fi
else
	echo -e "${GREEN}[*] No Symbiote filename hiding behavior detected in this shell/env.${NC}"
	rm -rf ./symbiote_test
	echo
fi


echo -e "${GRAY}---------------------------${NC}${MAGE}Checking for generic LD_PRELOAD${NC}${GRAY}---------------------------${NC}"
echo

if [ -z $LD_PRELOAD ]; then
        echo -e "${GREEN}[*] No LD_PRELOAD env variable found in this shell/env.${NC}"
        echo
else
        echo -e "${RED}[!] LD_PRELOAD env variable present.\n---> LD_PRELOAD library: https://www.virustotal.com/gui/file/$(sha256sum $(echo $LD_PRELOAD))"
        echo -e "${CYAN}------> [#] Unsetting LD_PRELOAD during analysis...${NC}"
        echo
        UNKNOWN_LD=$(echo $LD_PRELOAD)
        unset LD_PRELOAD
fi

if [ ! -s /etc/ld.so.preload ]; then
        echo -e "${GREEN}[*] No /etc/ld.so.preload file found.${NC}"
        echo
else
        echo -e "${RED}[!] /etc/ld.so.preload has data.\n---> [!] LD_PRELOAD library: https://www.virustotal.com/gui/file/$(sha256sum $(cat /etc/ld.so.preload))${NC}"
        echo -e "${CYAN}------> [#] Removing /etc/ld.so.preload during analysis...${NC}"
        echo
        mv /etc/ld.so.preload /etc/preload.bak
fi

echo -e "${GRAY}---------------------------${NC}${MAGE}Checking processes for LD_PRELOAD${NC}${GRAY}---------------------------${NC}"
echo

RESULTS=$(bash -c 'grep -ao "LD_PRELOAD=.*" /proc/*/environ | tr "\0" "\n" | grep LD_PRELOAD.*|grep -v $PPID')
rtrn_code=$?
if [ $rtrn_code -eq 0 ]; then
	for x in $RESULTS; do echo $x >>./tmpresults; done
	sed -i 's/.*=//g' ./tmpresults
	UNIQ_RES=$(for x in $(cat ./tmpresults | sort | uniq); do echo $x; done)
	rm ./tmpresults
fi

if [ $rtrn_code -gt 0 ]; then
	echo -e "${GREEN}[*] No LD_PRELOAD env variables found in running processes.${NC}"
	echo
else
	echo -e "${RED}[!] LD_PRELOAD env variable found in running processes.\n${NC}"
	echo -e "${RED}-------LD_PRELOAD LIBRARIES\n|${NC}"
	for x in $UNIQ_RES; do
		echo -e "${RED}|${NC}    ${CYAN}LD_PRELOAD library:${NC} https://www.virustotal.com/gui/file/$(sha256sum $x)"
	done
	echo -e "${RED}|\n----------------------------\n${NC}"
	echo -e "${RED}-------POSSIBLE HIJACKED PROCESSES${NC}"
	for x in $RESULTS; do
		BAD_PID=$(echo $x | cut -d '/' -f3)
		BAD_NAME=$(cat /proc/$BAD_PID/cmdline | tr -d '\0')
		echo -e "${RED}|\n|${NC}    ${CYAN}Process name:${NC} $BAD_NAME\n${RED}|${NC}    ${CYAN}Path:${NC} $(echo $x | cut -d':' -f1)\n${RED}|${NC}    ${CYAN}LD_PRELOAD library:${NC} $(echo $x | cut -d':' -f2 | cut -d'=' -f2)"
		echo -e "${RED}|\n----------------------------${NC}"
	done
fi

if [ -z $LD_PRELOAD ] && [ ! -z $UNKNOWN_ID ]; then
	export LD_PRELOAD=$(echo $UNKNOWN_LD)
fi

if [ -s /etc/preload.bak ]; then
	mv /etc/preload.bak /etc/ld.so.preload
fi
