package Crypt::MatrixSSL;

use 5.00001;
use strict;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $AUTOLOAD);
@ISA = qw(Exporter
	DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Crypt::MatrixSSL ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
%EXPORT_TAGS = ( 'all' => [ qw(
	
mxSSL_SUCCESS mxSSL_ERROR mxSSL_FULL mxSSL_PARTIAL mxSSL_SEND_RESPONSE mxSSL_PROCESS_DATA mxSSL_ALERT mxSSL_FILE_NOT_FOUND
matrixSslHandshakeIsComplete

) ] );

@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

@EXPORT = qw(
	
);

$VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Crypt::MatrixSSL::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

bootstrap Crypt::MatrixSSL $VERSION;

# Preloaded methods go here.

use constant mxSSL_SUCCESS	=>  0;	#/* Generic success */
use constant mxSSL_ERROR		=> -1;	#/* generic ssl error, see error code */
use constant mxSSL_FULL		=> -2;	#/* must call sslRead before decoding */
use constant mxSSL_PARTIAL	=> -3;	#/* more data reqired to parse full msg */
use constant mxSSL_SEND_RESPONSE	=> -4;	#/* decode produced output data */
use constant mxSSL_PROCESS_DATA	=> -5;	#/* succesfully decoded application data */
use constant mxSSL_ALERT		=> -6;	#/* we've decoded an alert */
use constant mxSSL_FILE_NOT_FOUND	=> -7;	#/* File not found */

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Crypt::MatrixSSL - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Crypt::MatrixSSL;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for Crypt::MatrixSSL.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for Crypt::MatrixSSL, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -C
	-b
	5.0.1
	-n
	Crypt::MatrixSSL
	--use-old-tests
	-p
	mx_

=back



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

A. U. Thor, E<lt>cnd@localdomaE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2005 by A. U. Thor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
