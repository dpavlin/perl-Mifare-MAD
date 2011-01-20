#!/usr/bin/perl

use warnings;
use strict;

# based on AN10787
# MIFARE Application Directory (MAD)


use Data::Dump qw(dump);

# http://www.nxp.com/acrobat_download2/other/identification/MAD_overview.pdf
my $mad_id = {
	0x0000 => 'sector free',
	0x0001 => 'sector defective',
	0x0002 => 'sector reserved',
	0x0003 => 'DIR continuted',
	0x0004 => 'card holder',
	# ...
	0x0015 => 'card administration - MIKROELEKTRONIKA spol.s.v.M',

	0x071D => 'miscellaneous applications - ZAGREBACKI Holding d.o.o. [1] Customer profile',
	0x071E => 'miscellaneous applications - ZAGREBACKI Holding d.o.o. [1] Bonus counter',

	0x1837 => 'city traffic - ZAGREBACKI Holding d.o.o. [1] Prepaid coupon',

	0x2062 => 'bus services - ZAGREBACKI Holding d.o.o. [1] electronic ticket',

	0x887B => 'electronic purse - ZAGREBACKI Holding d.o.o. [4]',
};

local $/ = undef;
my $card = <>;

die "expected 4096 bytes, got ",length($card), " bytes\n"
	unless length $card == 4096;

foreach my $i ( 0 .. 15 ) {
	my $v = unpack('v',(substr($card, 0x10 + ( $i * 2 ), 2)));
	printf "MAD sector %-2d %04x %s\n", $i, $v, $mad_id->{$v} || '?';

	foreach my $j ( 0 .. 3 ) {
		my $offset = 0x40 * $i + $j * 0x10;
		my $block = substr($card, $offset, 0x10);
		printf "%04x %s\n", $offset, unpack('H*',$block);
	}

	if ( $v == 0x0004 ) {
		# RLE encoded card holder information
		my $data = substr( $card, 0x40 * $i, 0x30);
		my $o = 0;
		my $types = {
			0b00 => 'surname',
			0b01 => 'given name',
			0b10 => 'sex',
			0b11 => 'any',
		};
		while ( substr($data,$o,1) ne "\x00" ) {
			my $len = ord(substr($data,$o,1));
			my $type = ( $len & 0b11000000 ) >> 6;
			$len     =   $len & 0b00111111;
			my $dump = substr($data,$o+1,$len-1);
			$dump = '0x' . unpack('H*', $dump) if $type == 0b11; # any
			printf "%-10s %2d %s\n", $types->{$type}, $len, $dump;
			$o += $len + 1;
		}
	}

}
