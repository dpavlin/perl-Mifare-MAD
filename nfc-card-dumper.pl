#!/usr/bin/perl
use warnings;
use strict;

use RFID::Libnfc::Reader;
use RFID::Libnfc::Constants;
use File::Slurp;
use Digest::MD5 qw(md5_hex);

use Data::Dump qw(dump);

my $debug = $ENV{DEBUG} || 0;
my $keyfile = shift @ARGV;

my $r = RFID::Libnfc::Reader->new(debug => $debug);
if ($r->init()) {
    warn "reader: %s\n", $r->name;
    my $tag = $r->connect(IM_ISO14443A_106);

    if ($tag) {
        $tag->dump_info;
    } else {
        warn "No TAG";
        exit -1;
    }

	my $uid = sprintf "%02x%02x%02x%02x", @{ $tag->uid };

	my $card_key_file = "cards/$uid.key";
	$keyfile ||= $card_key_file;

	if ( -e $keyfile ) {
		warn "# loading keys from $keyfile";
	    $tag->load_keys($keyfile);
		warn "## _keys = ", dump($tag->{_keys}) if $debug;
	}

    $tag->select if ($tag->can("select")); 

	my $card;

	print STDERR "$uid reading blocks ";
    for (my $i = 0; $i < $tag->blocks; $i++) {
        if (my $data = $tag->read_block($i)) {
            # if we are dumping an ultralight token, 
            # we receive 16 bytes (while a block is 4bytes long)
            # so we can skip next 3 blocks
            $i += 3 if ($tag->type eq "ULTRA");
			$card .= $data;
			print STDERR "$i ";
		} elsif ( $tag->error =~ m/auth/ ) {
			warn $tag->error,"\n";

			# disconnect from reader so we can run mfoc
			RFID::Libnfc::nfc_disconnect($r->{_pdi});

			print "Dump this card with mfoc? [y] ";
			my $yes = <STDIN>; chomp $yes;
			exit unless $yes =~ m/y/i || $yes eq '';

			my $file = "cards/$uid.keys";
			unlink $file;
			warn "# finding keys for card $uid with: mfoc -O $file\n";
			exec "mfoc -O $file" || die $!;
        } else {
            die $tag->error."\n";
        }
    }
	print STDERR "done\n";

	# re-insert keys into dump
	my $keys = $tag->{_keys} || die "can't find _keys";
	foreach my $i ( 0 .. $#$keys ) {
		my $o = $i * 0x40 + 0x30;
		last if $o > length($card);
		$card
			= substr($card, 0,   $o) . $keys->[$i]->[0]
			. substr($card, $o+6, 4) . $keys->[$i]->[1]
			. substr($card, $o+16)
			;
		warn "# sector $i keys re-inserted at $o\n" if $debug;
	}

	if ( my $padding = 4096 - length($card) ) {
		warn "# add $padding bytes up to 4k dump (needed for keys loading)\n" if $debug;
		$card .= "\x00" x $padding;
	}

	my $md5 = md5_hex($card);
	my $out_file = "cards/$uid.$md5";
	if ( -e $out_file ) {
		warn "$out_file allready exists, not overwriting\n";
	} else {
		write_file $out_file, $card;
		warn "$out_file ", -s $out_file, " bytes key: $card_key_file\n";
		if ( ! -e $card_key_file ) {
			$out_file =~ s{^cards/}{} || die "can't strip directory from out_file";
			symlink $out_file, $card_key_file || die "$card_key_file: $!";
			warn "$card_key_file symlink created as default key for $uid\n";
		}
	}

	# view dump
	system "./mifare-mad.pl $out_file > $out_file.txt";
	$ENV{MAD} && system "vi $out_file.txt";
}

