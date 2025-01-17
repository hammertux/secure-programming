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
TESTS_PASSED=0

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
	((TESTS_PASSED++))
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
		echo -e ${CYAN}"EXPECTED OUTPUT: "${NC} "\n"
	fi
	
	./vault.py -v samples/${counter}.clear public.pem sign
	RETURN=$?
	if [ $RETURN -eq 0 ] ;
	then
		((MATCHES++))
		echo -e ${GREEN}"MATCH :)\n" ${NC}
        else
                echo -e ${RED}"NOT MATCHED :(\n" ${NC}
        fi

done	

if [ "$MATCHES" -gt "$SAMPLES" ] ; then
	((TESTS_PASSED++))
        echo -e ${GREEN} "ALL VERIFICATION TESTS PASSED!!!\n"${NC}
fi


#Encrypt/Decrypt Test:

((MATCHES=0))
for counter in {0..19}; do
	echo -e "ENCRYPT TEST NUMBER "$counter": \n"
	./vault.py -e samples/${counter}.clear 0xdeadbeef 0xae70254a174e0d4677b9ce5393eb00c1 > encrypted
	DECRYPTED="$(./vault.py -d encrypted 0xdeadbeef 0xae70254a174e0d4677b9ce5393eb00c1 > tmp)"
	EXPECTED="$(cat samples/${counter}.clear)"
	TMP="$(cat tmp)"
	if [ "$1" = "$VERBOSITY" ] ; then
                echo -e ${YELLOW}"YOUR OUTPUT: "${NC} ""$TMP"\n"
                echo -e ${CYAN}"EXPECTED OUTPUT: "${NC} ""$EXPECTED"\n"
        fi

	if [ "$TMP" = "$EXPECTED" ] ; then
		((MATCHES++))
		echo -e ${GREEN}"MATCH :)\n" ${NC}
        else
                echo -e ${RED}"NOT MATCHED :(\n" ${NC}
        fi
done

if [ "$MATCHES" -gt "$SAMPLES" ] ; then
	((TESTS_PASSED++))
        echo -e ${GREEN} "ALL ENCRYPTION/DECRYPTION TESTS PASSED!!!\n"${NC}
fi


if [ "$TESTS_PASSED" -eq 3 ] ; then
	echo -e ${GREEN} "ALL TESTS PASSED!!!\n"${NC}
fi

rm tmp
rm encrypted
rm sign
