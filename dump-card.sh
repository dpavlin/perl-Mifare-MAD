#!/bin/sh -x

# http://code.google.com/p/nfc-tools/wiki/mfoc

uid=`nfc-list | grep UID | cut -d: -f2 | sed 's/ //g'`

if [ -z "$uid" ] ; then
	echo "No card on reader"
	nfc-list
	exit 1
fi

#mfoc -O $uid.mfd | tee $uid.mfoc.txt

md5=`md5sum 32a0ee18.mfd | cut -d" " -f1`
mv $uid.mfd $uid.$md5.mfd
mv $uid.mfoc.txt $uid.$md5.mfoc.txt
ls -al $uid.*
