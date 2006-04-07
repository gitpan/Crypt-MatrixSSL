package Crypt::MatrixSSL;

use 5.006;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Crypt::MatrixSSL ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

mxSSL_SUCCESS mxSSL_ERROR mxSSL_FULL mxSSL_PARTIAL mxSSL_SEND_RESPONSE mxSSL_PROCESS_DATA mxSSL_ALERT mxSSL_FILE_NOT_FOUND
mxSSL_ALERT_CODES mxSSL_RETURN_CODES

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '1.8';

require XSLoader;
XSLoader::load('Crypt::MatrixSSL', $VERSION);

# Preloaded methods go here.
# Return codes from public apis. Not all apis return all codes.  See documentation for more details.
use constant mxSSL_SUCCESS		=>  0;	#/* Generic success */
use constant mxSSL_ERROR		=> -1;	#/* generic ssl error, see error code */
use constant mxSSL_FULL			=> -2;	#/* must call sslRead before decoding */
use constant mxSSL_PARTIAL		=> -3;	#/* more data reqired to parse full msg */
use constant mxSSL_SEND_RESPONSE	=> -4;	#/* decode produced output data */
use constant mxSSL_PROCESS_DATA		=> -5;	#/* succesfully decoded application data */
use constant mxSSL_ALERT		=> -6;	#/* we've decoded an alert */
use constant mxSSL_FILE_NOT_FOUND	=> -7;	#/* File not found */
use constant mxSSL_MEM_ERROR		=> -8;	#/* Memory allocation failure */


# SSL Alert levels and descriptions. This implementation treats all alerts as fatal.
our %mxSSL_ALERT_CODES=(1 => 'SSL_ALERT_LEVEL_WARNING',
			2 => 'SSL_ALERT_LEVEL_FATAL',
			0 => 'SSL_ALERT_CLOSE_NOTIFY',
			10=> 'SSL_ALERT_UNEXPECTED_MESSAGE',
			20=> 'SSL_ALERT_BAD_RECORD_MAC',
			30=> 'SSL_ALERT_DECOMPRESSION_FAILURE',
			40=> 'SSL_ALERT_HANDSHAKE_FAILURE',
			41=> 'SSL_ALERT_NO_CERTIFICATE',
			42=> 'SSL_ALERT_BAD_CERTIFICATE',
			43=> 'SSL_ALERT_UNSUPPORTED_CERTIFICATE',
			44=> 'SSL_ALERT_CERTIFICATE_REVOKED',
			45=> 'SSL_ALERT_CERTIFICATE_EXPIRED',
			46=> 'SSL_ALERT_CERTIFICATE_UNKNOWN',
			47=> 'SSL_ALERT_ILLEGAL_PARAMETER',
			67=> 'SSL_ALLOW_ANON_CONNECTION'); # 67= /* Use as return code in user validation callback to allow anonymous connections to proceed */

our %mxSSL_RETURN_CODES=( 0 => 'SSL_SUCCESS	Generic success',
			 -1 => 'SSL_ERROR	generic ssl error, see error code',
			 -2 => 'SSL_FULL	must call sslRead before decoding',
			 -3 => 'SSL_PARTIAL	more data reqired to parse full msg',
			 -4 => 'SSL_SEND_RESPONSE	decode produced output data',
			 -5 => 'SSL_PROCESS_DATA	succesfully decoded application data',
			 -6 => 'SSL_ALERT	weve decoded an alert',
			 -7 => 'SSL_FILE_NOT_FOUND	File not found',
			 -8 => 'SSL_MEM_ERROR	Memory allocation failure');


# Old:-
# BEGIN {
# 
#   our %MX_RC=( # /* Return codes from public apis. Not all apis return all codes.  See documentation for more details.  */
# 	  'SSL_SUCCESS'		=>  0,	#/* Generic success */
# 	  'SSL_ERROR'		=> -1,	#/* generic ssl error, see error code */
# 	  'SSL_FULL'		=> -2,	#/* must call sslRead before decoding */
# 	  'SSL_PARTIAL'		=> -3,	#/* more data reqired to parse full msg */
# 	  'SSL_SEND_RESPONSE'	=> -4,	#/* decode produced output data */
# 	  'SSL_PROCESS_DATA'	=> -5,	#/* succesfully decoded application data */
# 	  'SSL_ALERT'		=> -6,	#/* we've decoded an alert */
# 	  'SSL_FILE_NOT_FOUND'	=> -7	#/* File not found */
# 	 );
# }

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Crypt::MatrixSSL - Perl extension for SSL and TLS using MatrixSSL.org 

=head1 SYNOPSIS

  use Crypt::MatrixSSL;

  (See the MatrixSSL documentation, or the mxgg.pl sample script 
   included in this package)

  Some documentation is also included in POD format in the .xs file. 

=head1 DESCRIPTION

Crypt::MatrixSSL lets you use the MatrixSSL crypto library (see
http://matrixssl.org/) from Perl.  With this module, you will be
able to easily write SSL and TLS client and server programs.

MatrixSSL includes everything you need, all in under 50KB.

You will need a "C" compiler to build this, unless you're getting
the ".ppm" prebuilt Win32 version.  Crypt::MatrixSSL builds cleanly
on (at least) Windows, Linux, and Macintosh machines.

MatrixSSL is an Open Source (GNU Public License) product, and is
also available commercially if you need freedom from GNU rules.

Everything you need is included here, but check the MatrixSSL.org
web site to make sure you've got the latest version of the 
MatrixSSL "C" code if you like (it's in the directory "./matrixssl"
of this package if you want to replace the included version from
the MatrixSSL.org download site.)

=head2 EXPORT

None by default.



=head1 SEE ALSO

http://www.MatrixSSL.org - the download from this site includes
simple yet comprehensive documentation in PDF format.

=head1 AUTHOR

C. N. Drake, E<lt>christopher@pobox.comE<gt>

=head1 COPYRIGHT AND LICENSE

MatrixSSL is distrubed under the GNU Public License:-
http://www.gnu.org/copyleft/gpl.html

Crypt::MatrixSSL uses MatrixSSL, and so inherits the same License.

Copyright (C) 2005 by C. N. Drake.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
