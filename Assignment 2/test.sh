#!/bin/bash

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
TRUE_BOOL="True"
VERBOSITY="-v"
MATCHES=0
SAMPLES=19

#Signature Test:

for counter in {0..19}; do
	echo -e "SIGN TEST NUMBER "$counter": \n"
	OUTPUT="$(./vault.py -s samples/${counter}.clear private.pem)"
	if [ "$1" = "$VERBOSITY" ] ; then
		echo -e ${YELLOW}"YOUR OUTPUT: "${NC} " "$OUTPUT" \n"
	fi
	EXPECTED="$(cat samples/${counter}.sig)"
	if [ "$1" = "$VERBOSITY" ] ; then
		echo -e ${CYAN}"EXPECTED OUTPUT: "${NC} ""$EXPECTED" \n"
	fi

	if [ "$OUTPUT" = "$EXPECTED" ] ;
       	then
		((MATCHES++))
		echo -e ${GREEN}"MATCH :)\n" ${NC}
	else
		echo -e ${RED}"NOT MATCHED :(\n" ${NC}
	fi

done

if [ "$MATCHES" -gt "$SAMPLES" ] ; then
	echo -e ${GREEN} "ALL SIGNATURE TESTS PASSED!!!\n"${NC}
fi

#Verify Test:

((MATCHES=0))
for counter in {0..19}; do
	echo -e "VERIFY TEST NUMBER "$counter": \n"
	SIGN_OUTPUT="$(./vault.py -s samples/${counter}.clear private.pem > sign)"
	VERIFY_OUTPUT="$(./vault.py -v samples/${counter}.clear public.pem sign)"
	if [ "$1" = "$VERBOSITY" ] ; then
		echo -e ${YELLOW}"YOUR OUTPUT: "${NC} ""$VERIFY_OUTPUT"\n"
		echo -e ${CYAN}"EXPECTED OUTPUT: "${NC} ""$TRUE_BOOL"\n"
	fi

	if [ "$VERIFY_OUTPUT" = "$TRUE_BOOL" ] ;
	then
		((MATCHES++))
		echo -e ${GREEN}"MATCH :)\n" ${NC}
        else
                echo -e ${RED}"NOT MATCHED :(\n" ${NC}
        fi

done	

if [ "$MATCHES" -gt "$SAMPLES" ] ; then
        echo -e ${GREEN} "ALL VERIFICATION TESTS PASSED!!!\n"${NC}
fi

