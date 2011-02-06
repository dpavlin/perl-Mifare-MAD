#!/bin/sh -x

o=`basename $1`
n=`basename $2`
./mifare-mad.pl $1 > /tmp/$o
./mifare-mad.pl $2 > /tmp/$n
vi -d /tmp/$o /tmp/$n
