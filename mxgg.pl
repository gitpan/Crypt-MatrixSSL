#!/usr/bin/perl

=head1 NAME

mxgg.pl - Sample MatrixSSL client which grabs the google.com https home page

=head1 SYNOPSIS

	perl mxpp.pl

=head1 DESCRIPTION

  "Opens" MatrixSSL
  Opens a socket to google
  Establishes SSL session
  Issues an HTTP "GET /"
  Reads response
  exits.

=head1 BUGS

  doesn't check certificate validity
  lots of stuff is hard-coded.
  ignores return codes mostly.

=cut


use Crypt::MatrixSSL;
use IO::Socket;

$rc=Crypt::MatrixSSL::matrixSslOpen(); if($rc){die "open fail";} # Let MatrixSSL initialize

# Expects the key files to be in the current directory.  Get the key files from
# either the MatrixSSL.com download, or our Crypt-MatrixSSL package (eg: from CPAN)
# (They *should* have been in the same place you got this sample code from)
$rc=Crypt::MatrixSSL::matrixSslReadKeys( $cmxkeys,
				     'certCln.pem', 
				     'privkeyCln.pem',undef,
				     'CAcertSrv.pem'); if($rc){die "readkeys fail";}

Crypt::MatrixSSL::matrixSslNewSession($cssl, $cmxkeys, 0,0); if($rc){die "newsession fail";}

# This is the bit that would let us run custom cert validation if we needed
# We don't: MatrixSSL already can validate for us (if you've got the right cert files installed)
# Crypt::MatrixSSL::matrixSslSetCertValidator($cssl,0,0);

$host="www.google.com:443";
$remote=new IO::Socket::INET(PeerAddr=>$host,Proto=>'tcp') || die "sock:$!"; # Connect to a server

$rc=Crypt::MatrixSSL::matrixSslEncodeClientHello($cssl,$cout,0);if($rc){die "hello fail";} # in SSL, Clients talk 1st

# SSL connections require some back-and-forth chatskis - this loop feeds MatrixSSL with the data until it says we're connected OK.
while(($hc=Crypt::MatrixSSL::matrixSslHandshakeIsComplete($cssl))!=1) {
  print "hc=$hc\n";
  if(length($cout)) {
    syswrite($remote,$cout); print "wrote bytes=" . length($cout) . "\n";
    $b=sysread($remote,$cin,17000);
    print "Read bytes=$b '${\showme($cin)}'\n";
  }
  $rc=Crypt::MatrixSSL::matrixSslDecode($cssl, $cin, $cout, $error, $alertLevel, $alertDescription);
  # Need to end if $rc hit an error
  print "dec=$rc\n";
  die "oops" if($l++>10);
}


# Our client is now going to send a message to the server
$rc=Crypt::MatrixSSL::matrixSslEncode($cssl, "GET / HTTP/1.1\r\nAccept: */*\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\nHost: $host\r\n\r\n", $cout);
syswrite($remote,$cout); print "wrote bytes=" . length($cout) . "\n" if(length($cout));


# Wait for google to talk back to us:-
$b=sysread($remote,$cin,17000); print "Read bytes=$b '${\showme($cin)}'\n";

# Decrypt what it said:-
$rc=Crypt::MatrixSSL::matrixSslDecode($cssl, $cin, $cout, $error, $alertLevel, $alertDescription);
print "Read($rc): '$cout'\n";

# Tell google we're about to go away now
$rc=Crypt::MatrixSSL::matrixSslEncodeClosureAlert($cssl, $cout);
syswrite($remote,$cout); print "wrote bytes=" . length($cout) . "\n" if(length($cout));


# Clear up the finished session now
$rc=Crypt::MatrixSSL::matrixSslDeleteSession($cssl);

# Free our keys
$rc=Crypt::MatrixSSL::matrixSslFreeKeys($cmxkeys);

# Tidy up
Crypt::MatrixSSL::matrixSslClose();

# End!
exit(0);

# Display (possibly binary) data on-screen
sub showme {
  no warnings;
  my($buf,$col2,$src)=@_;
  my $col=$col2; my($red)=''; my($norm)='';

  $buf =~ s/[\000-\011\013-\014\016-\037\177-\377]/"\\$red".unpack("H*",$&)."$col"/esmg; # Do every non-ascii char too
  $buf=~s/\r/$red\\r$col/g;
  #$buf=~s/\n/$red\\n$col\n/g;
  $buf=~s/\n/$red\\n$col/g;
  # &printa("$col$buf$norm\n")  unless($switch{'quiet'});
  return "$col$buf$norm";

}

