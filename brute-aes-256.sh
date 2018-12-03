#!/bin/sh
numPar="$#"
STARTTIME=$(date +%s)
GREEN='\e[1;32m'
RED='\e[0;31m'
BLUE='\e[0;34m'
YELL='\e[1;33m'
PURPLE='\e[1;35m'
NC='\e[0m' # No Color

if [ $numPar != 2 ]
then
	echo "Error"
	echo "Usage: ./brute-aes-256.sh file.enc wordlist"
	exit
fi

if [ ! -f $1 ]
then
	echo "Aes encrypted file ( $1 ) - not found"
	exit
fi

if [ ! -f $2 ]
then
	echo "Wordlist ( $2 ) - not found"
	exit
fi



echo "${GREEN}
██████╗ ██████╗ ██╗   ██╗████████╗███████╗     █████╗ ███████╗███████╗      ██████╗ ███████╗ ██████╗    ███████╗██╗  ██╗
██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝    ██╔══██╗██╔════╝██╔════╝      ╚════██╗██╔════╝██╔════╝    ██╔════╝██║  ██║
██████╔╝██████╔╝██║   ██║   ██║   █████╗█████╗███████║█████╗  ███████╗█████╗ █████╔╝███████╗███████╗    ███████╗███████║
██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝╚════╝██╔══██║██╔══╝  ╚════██║╚════╝██╔═══╝ ╚════██║██╔═══██╗   ╚════██║██╔══██║
██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗    ██║  ██║███████╗███████║      ███████╗███████║╚██████╔╝██╗███████║██║  ██║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝    ╚═╝  ╚═╝╚══════╝╚══════╝      ╚══════╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝
                                                                                                                        
														${RED}by @manulqwerty 
                                                                       
${BLUE}--------------------------------------------------------------------------------${NC}
"


for password in $(cat $2)
do
 decrypted=$( openssl enc -d -aes-256-cbc -a -in $1 -pass pass:$password 2>/dev/null )
 if echo $decrypted | grep -q "password" ; then
  echo "${YELL}[+] Found!: $password${NC}"
  openssl enc -d -aes-256-cbc -a -in $1 -pass pass:$password -out output.txt 2>/dev/null
  echo "${YELL}[+] Output file: output.txt${NC}"
  ENDTIME=$(date +%s)
  echo "${PURPLE}Time elapsed: $((ENDTIME-STARTTIME))s ${NC}"
break;
fi

done
