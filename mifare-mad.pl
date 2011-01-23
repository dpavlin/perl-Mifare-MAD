#!/usr/bin/perl

use warnings;
use strict;

# based on AN10787
# MIFARE Application Directory (MAD)
# http://www.nxp.com/acrobat_download2/other/identification/MAD_overview.pdf

use Data::Dump qw(dump);

my $debug = $ENV{DEBUG} || 0;

my $function_clusters;
my $mad_id;

while(<DATA>) {
	chomp;
	next if m/^#?\s*$/;
	my ( $code, $function ) = split(/\s+/,$_,2);
	my $h = '[0-9A-F]';
	if ( $code =~ m/^($h{2})-($h{2})$/ ) {
		foreach my $c ( hex($1) .. hex($2) ) {
			$function_clusters->{ unpack('HH',$c) } = $function;
		}
	} elsif ( $code =~ m/^($h{2})$/ ) {
		$function_clusters->{ lc $code } = $function;
	} elsif ( $code =~ m/^($h{4})$/ ) {
		$mad_id->{ lc $1 } = $function;
	} else {
		die "can't parse __DATA__ line $.\n$_\n";
	}
}

my $access_condition_data = {
0b000 => 'R:AB W:AB I:AB DTR:AB transport conf',
0b010 => 'R:AB W:-- I:-- DTR:-- r/w block',
0b100 => 'R:AB W:-B I:-- DTR:-- r/w block', 
0b110 => 'R:AB W:-B I:-B DTR:AB r/w block',
0b001 => 'R:AB W:-- I:-- DTR:AB value block',
0b011 => 'R:-B W:-B I:-- DTR:-- value block',
0b101 => 'R:-B W:-- I:-- DTR:-- r/w block',
0b111 => 'R:-- W:-- I:-- DTR:-- r/w block',
};

my $access_condition_trailer = {
0b000 => 'R/W: KEYA:-/A ACCESS:A-/- DATB:A/A ?',
0b010 => 'R/W: KEYA:-/- ACCESS:A-/- DATB:A/- ?'.
0b100 => 'R/W: KEYA:-/B ACCESS:AB/- KEYB:-/B',
0b110 => 'R/W: KEYA:-/- ACCESS:AB/- KEYB:-/-',
0b001 => 'R/W: KEYA:-/A ACCESS:A-/A DATB:A/A ? transport conf',
0b011 => 'R/W: KEYA:-/B ACCESS:AB/B KEYB:-/B',
0b101 => 'R/W: KEYA:-/- ACCESS:AB/B KEYB:-/-',
0b111 => 'R/W: KEYA:-/- ACCESS:AB/- KEYB:-/-',
};


if ( $debug ) {
	warn "# function_clusters ",dump($function_clusters);
	warn "# mad_id ", dump($mad_id);
}

local $/ = undef;
my $card = <>;

die "expected 4096 bytes, got ",length($card), " bytes\n"
	unless length $card == 4096;

my ( $ADV, $MA, $DA );

my $pos = 0;

foreach my $sector ( 0 .. 39 ) {

	my $blocks = $sector < 32 ? 4 : 16;

	next if substr($card,$pos,$blocks * 0x10) eq "\x00" x ($blocks * 0x10);

	# General purpose byte (GPB)
	my $GBP = ord(substr($card,0x39,1));

	if ( $sector == 0 ) {
		printf "manufacturer block\nSerial number: %s\nCB: %s\nmanufacturer data: %s\n"
			, unpack('H*',substr($card,0,4))
			, unpack('H*',substr($card,4,1))
			, unpack('H*',substr($card,5,11))
			;

		# MAD
		$ADV = $GBP & 0b00000011;
		$MA  = $GBP & 0b01000000;
		$DA  = $GBP & 0b10000000;
		printf "ADV (MAD version code): %d %s\n", $ADV;
		printf "MA (multiapplication): %s\n", $MA ? 'yes' : 'monoaplication';
		printf "DA (MAD available): %s%s\n",  $DA ? 'yes' : 'no',
			substr($card,$pos+0x30,6) eq "\xA0\xA1\xA2\xA3\xA4\xA5" ? ' public' : '';

		printf "Info byte (publisher sector): %x\n", ord(substr($card,0x11,1));
	} elsif ( $DA ) {
		my $mad_offset = 0x10 + ( $sector * 2 );
		my $v = unpack('v',(substr($card, $mad_offset, 2)));
		my $cluster_id = unpack('HH', (( $v & 0xff00 ) >> 8) );
		my $full_id = sprintf "%04x",$v;
		printf "MAD sector %-2d@%x %04x [%s]\n%s\n", $sector, $mad_offset, $v
			, $function_clusters->{ $cluster_id }
			, $mad_id->{$full_id} || "FIXME: add $full_id from MAD_overview.pdf to __DATA__ at end of $0"
			;

		if ( $v == 0x0004 ) {
			# RLE encoded card holder information
			my $data = substr( $card, $pos, 0x30);
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
		} elsif ( $v == 0x0015 ) {
			printf "Card number: %s\n", unpack('h*',substr($card,$pos + 0x04,6));
		}

	} else {
		printf "# sector %-2d with %d blocks\n", $sector, $blocks;
	}

	my $trailer_pos = $pos + $blocks * 0x10 - 0x10;
	my $c1 = ( ord(substr($card,$trailer_pos+7,1)) & 0xf0 ) >> 4;
	my $c2 = ( ord(substr($card,$trailer_pos+8,1)) & 0x0f );
	my $c3 = ( ord(substr($card,$trailer_pos+8,1)) & 0xf0 ) >> 4;

	printf "# trailer @%x c1:%d c2:%d c3:%d [%016b]\n"
		, $trailer_pos, $c1, $c2, $c3
		, unpack('n',(substr($card,$trailer_pos+7,2)))
		;

	foreach my $j ( 0 .. $blocks - 1 ) {
		my $offset = $pos + $j * 0x10;
		my $block = substr($card, $offset, 0x10);
		my $mask = 1 << $j;
		my $cond
			= ( ( $c1 & $mask ) * 4 )
			+ ( ( $c2 & $mask ) * 2 )
			+ ( ( $c3 & $mask ) * 1 )
			;
		$cond >>= $j;

		my $hex = unpack('H*',$block);
		$hex =~ s/(....)/$1 /g;

		if ( $ENV{SWAP} ) {
			my $hex_sw = unpack('h*',$block);
			$hex_sw =~ s/(....)/$1 /g;
			$hex .= " | $hex_sw";
		}

		printf "%04x  %s %03b %s\n", $offset, $hex
			, $cond
			, $j < 3 ? $access_condition_data->{$cond} : $access_condition_trailer->{$cond}
			;
	}


	printf "KEY A:%s | %s GDP: %s | B:%s\n"
		,unpack('H*',substr($card,$trailer_pos   ,6))
		,unpack('H*',substr($card,$trailer_pos+6 ,3))
		,unpack('H*',substr($card,$trailer_pos+9 ,1))
		,unpack('H*',substr($card,$trailer_pos+10,6))
		;

	print "\n";

	$pos += $blocks * 0x10;
}

__DATA__
00    card administration
01-07 miscellaneous applications
08    airlines
09    ferry trafic
10    railway services
12    transport
18    city traffic
19    Czech Railways
20    bus services
21    multi modal transit
28    taxi
30    road toll
38    company services
40    city card services
47-48 access control & security
49    VIGIK
4A    Ministry of Defence, Netherlands
4B    Bosch Telecom, Germany
4A    Ministry of Defence, Netherlands
4C    European Union Institutions
50    ski ticketing
51-54 access control & security
58    academic services
60    food
68    non food trade
70    hotel
75    airport services
78    car rental
79    Dutch government
80    administration services
88    electronic purse
90    television
91    cruise ship
95    IOPTA
97    Metering
98    telephone
A0    health services
A8    warehouse
B0    electronic trade
B8    banking
C0    entertainment & sports
C8    car parking
C9    Fleet Management
D0    fuel, gasoline
D8    info services
E0    press
E1    NFC Forum
E8    computer
F0    mail
F8-FF miscellaneous applications

0000	sector is free
0001	sector is defect, e.g. access keys are destroyed or unknown
0002	sector is reserved
0003	sector contains additional directory info (useful only for future cards)
0004	sector contains card holder information in ASCII format.
0005	sector not applicable (above memory size)

0015 - card administration MIKROELEKTRONIKA spol.s.v.MIKROELEKTRONIKA spol.s.v.o. worldwide 1 01.02.2007 Card publisher info
0016 - card administration Mikroelektronika spol.s.r.o., Kpt.Mikroelektronika spol.s.r.o., Kpt. PoEurope    1 10.10.2007 Issuer information

071C - miscellaneous applications MIKROELEKTRONIKA spol.s.r. MIKROELEKTRONIKA spol.s.r.o., Europe       1 01.12.2008 Customer profile
071D - miscellaneous applications ZAGREBACKI Holding d.o.o. MIKROELEKTRONIKA spol.s.r.o. EUROPE,Croatia 1 01.04.2009 Customer profile
071E - miscellaneous applications ZAGREBACKI Holding d.o.o. MIKROELEKTRONIKA spol.s.r.o. EUROPE,Croatia 1 01.04.2009 Bonus counter

1835 - city traffic KORID LK, spol.s.r.o.       KORID LK, spol.s.r.o.        Europe         2 08.09.2008 Eticket
1836 - city traffic MIKROELEKTRONIKA spol.s.r. MIKROELEKTRONIKA spol.s.r.o., Europe         1 01.12.2008 Prepaid coupon 1S
1837 - city traffic ZAGREBACKI Holding d.o.o. MIKROELEKTRONIKA spol.s.r.o.   EUROPE,Croatia 1 01.04.2009 Prepaid coupon
1838 - city traffic MIKROELEKTRONIKA spol.s.r. MIKROELEKTRONIKA spol.s.r.o.  Europe         1 01.05.2009 Prepaid coupon
1839 - city traffic Mikroelektronika spol.s r.o Mikroelektronika spol.s r.o  EUROPE,Czech R 1 01.08.2009 Prepaid coupon
183B - city traffic UNICARD S.A.                UNICARD S.A.                 Poland        15 01.01.2010 city traffic services

2061 - bus services Mikroelektronika spol.s r.o. Mikroelektronika spol.s r.o. Europe     1 01.08.2008 Electronic ticket
2062 - bus services ZAGREBACKI Holding d.o.o. MIKROELEKTRONIKA spol.s.r.o EUROPE,Croatia 1 01.04.2009 Electronic tiicket
2063 - bus services MIKROELEKTRONIKA spol.s.r. MIKROELEKTRONIKA spol.s.r.o. Europe       3 01.05.2009 electronic ticket

887B - electronic purse ZAGREBACKI Holding d.o.o. MIKROELEKTRONIKA spol.s.r.o. EUROPE,Croatia  4 01.04.2009 Electronic purse
887C - electronic purse MIKROELEKTRONIKA spol.s.r. MIKROELEKTRONIKA spol.s.r.o. Europe         4 01.05.2009 electronic purse
887D - electronic purse Mikroelektronika spol.s r.o Mikroelektronika spol.s r.o EUROPE,Czech R 4 01.08.2009 Electronic purse

