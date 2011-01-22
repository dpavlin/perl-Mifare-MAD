#!/bin/sh -x

# http://code.google.com/p/nfc-tools/wiki/mfoc
mfoc -O $1 $keys.dump | tee $1-keys.txt
