#! /opt/perl5/bin/perl
use ExtUtils::testlib;


use Crypt::MatrixSSL;
use IO::Socket;

$rc=Crypt::MatrixSSL::matrixSslOpen(); if($rc){die "open fail";} # Let MatrixSSL initialize

$rc=Crypt::MatrixSSL::matrixSslReadKeys($smxkeys,
				     '/tmp/mxcertSrv.pem',
				     '/tmp/mxprivkeySrv.pem', undef,
				     '/tmp/mxCAcertCln.pem'); if($rc){die "readkeys fail";}

Crypt::MatrixSSL::matrixSslNewSession($sssl, $smxkeys, 0,1); if($rc){die "newsession fail";}

# Crypt::MatrixSSL::matrixSslSetCertValidator($cssl,0,0);

$local=new IO::Socket::INET(LocalHost => "0.0.0.0:4433", Proto => 'tcp', Listen => 1, Reuse => 1) || die "listen fail";

my $sock=$local->accept || die "problem accepting incoming connection: $!";

$b=sysread($sock,$sin,17000);
print "Read bytes=$b '${\showme($sin)}'\n";

$sout=$error=$alertLevel=$alertDescription='';

while(($hc=Crypt::MatrixSSL::matrixSslHandshakeIsComplete($sssl))!=1) {
  print "hc=$hc\n";
  # $p=<STDIN>;
  if(length($sout)) {
    syswrite($sock,$sout); print "wrote bytes=" . length($sout) . "\n";
    $b=sysread($sock,$sin,17000);
    print "Read bytes=$b '${\showme($sin)}'\n";
  }
  $rc=Crypt::MatrixSSL::matrixSslDecode($sssl, $sin, $sout, $error, $alertLevel, $alertDescription);
  die "rc=$rc, $error, $alertLevel, $alertDescription" if($rc==-1);
  print "dec=$rc\n";
  die "oops" if($l++>10);
}
    syswrite($sock,$sout); print "wrote bytes=" . length($sout) . "\n";

# Clients speak 1st when we're a server
$b=sysread($sock,$sin,17000);	# NB: if we get 0 bytes, it's coz client dropped con, like browsers do when they hate your server cert
print "Read bytes=$b '${\showme($sin)}'\n";
$rc=Crypt::MatrixSSL::matrixSslDecode($sssl, $sin, $sout, $error, $alertLevel, $alertDescription);
print "Got '$sout'\n";

$rc=Crypt::MatrixSSL::matrixSslEncode($sssl, "HTTP/1.1 200 OK\r\nServer: My PeerSec Networks MatrixSSL\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nContent-type: text/html\r\n\r\n<H1>Good One MatrixSSL!</H1>\r\n", $sout);
    syswrite($sock,$sout); print "wrote bytes=" . length($sout) . "\n";


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

