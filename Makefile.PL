use 5.00001;
use ExtUtils::MakeMaker;
#
#  WARNING: Do not try to "make dist" under Windows; it destroys the Upper/lower CaSe of some files.
#
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
#
# Many thanks to Randy Kobes for helping me figure out how to make this work on Win32, which
# also laid the foundation for me getting it to work nicely on Linux and Macintosh
#
use Config;
my $os_src = ($^O =~ /Win32/) ? 'win/win' : 'linux/linux';
my $o = $Config{obj_ext};
my $c='.c';


# NOTE: For future versions of MatrixSSL (this is v1-1-4) - you might need to do this;
#       1. cd matrixssl
#       2. make all
#       3. find . -name '*.o' -print >/tmp/objs
#       4. vi ../Makefile.PL
#       5. include the file /tmp/objs - eg:   ":r /tmp/objs"
#	6. change all the ".o" endings to "$mxext"
#	7. remove the leading "./" if any
#	8. join them all on to one line and assign them all to "$mxfiles"; be careful NOT to expand the "$mxext" (eg: use single quotes)
#	9. replace the os/linux/linux$mxext one with os/$os_src$mxext

my $mxfiles='matrixssl/src/crypto/peersec/arc4$mxext matrixssl/src/crypto/peersec/asn1$mxext matrixssl/src/crypto/peersec/base64$mxext matrixssl/src/crypto/peersec/des3$mxext matrixssl/src/crypto/peersec/md5$mxext matrixssl/src/crypto/peersec/md2$mxext matrixssl/src/crypto/peersec/mpi$mxext matrixssl/src/crypto/peersec/rsa$mxext matrixssl/src/crypto/peersec/sha1$mxext matrixssl/src/os/$os_src$mxext matrixssl/src/cipherSuite$mxext matrixssl/src/matrixSsl$mxext matrixssl/src/sslDecode$mxext matrixssl/src/sslEncode$mxext matrixssl/src/sslv3$mxext';

$mxext=$o; my $mxobjs;eval('$mxobjs="' . $mxfiles . '"');	# These are all the object files we need for our release

# my $mxobjs="matrixssl/src/matrixSsl$o matrixssl/src/sslEncode$o matrixssl/src/sslDecode$o matrixssl/src/sslv3$o matrixssl/src/cipherSuite$o matrixssl/src/crypto/peersec/arc4$o matrixssl/src/crypto/peersec/asn1$o matrixssl/src/crypto/peersec/base64$o matrixssl/src/crypto/peersec/des3$o matrixssl/src/crypto/peersec/md5$o matrixssl/src/crypto/peersec/md2$o matrixssl/src/crypto/peersec/mpi$o matrixssl/src/crypto/peersec/rsa$o matrixssl/src/crypto/peersec/sha1$o matrixssl/src/os/psMalloc$o matrixssl/src/os/$os_src$o";

$mxext=$c; my $mxc;eval('$mxc="' . $mxfiles . '"');		# These are the .c files that built the above objects. Note that the peersec "Makefile" did this for us, via "make all" in the "./matrixssl" subdirectory

# my $mxc   ="matrixssl/src/matrixSsl$c matrixssl/src/sslEncode$c matrixssl/src/sslDecode$c matrixssl/src/sslv3$c matrixssl/src/cipherSuite$c matrixssl/src/crypto/peersec/arc4$c matrixssl/src/crypto/peersec/asn1$c matrixssl/src/crypto/peersec/base64$c matrixssl/src/crypto/peersec/des3$c matrixssl/src/crypto/peersec/md5$c matrixssl/src/crypto/peersec/md2$c matrixssl/src/crypto/peersec/mpi$c matrixssl/src/crypto/peersec/rsa$c matrixssl/src/crypto/peersec/sha1$c matrixssl/src/os/psMalloc$c matrixssl/src/os/$os_src$c";

sub MY::postamble {

return '';

        return "

libmatrixssl.lib: matrixssl/src/Makefile $mxc
	cd matrixssl/src && \$(MAKE) all
	ar -rc libmatrixssl.lib $mxobjs

";
#     'OBJECT'		=> 'matrixssl/src/libmatrixssl.so matrixssl/src/cipherSuite.c matrixssl/src/matrixSsl.c matrixssl/src/sslEncode.c matrixssl/src/sslDecode.c matrixssl/src/sslv3.c matrixssl/src/crypto/peersec/base64.c matrixssl/src/crypto/peersec/arc4.c matrixssl/src/crypto/peersec/asn1.c matrixssl/src/crypto/peersec/des3.c matrixssl/src/crypto/peersec/md2.c matrixssl/src/crypto/peersec/md5.c matrixssl/src/crypto/peersec/mpi.c matrixssl/src/crypto/peersec/rsa.c matrixssl/src/crypto/peersec/sha1.c matrixssl/src/os/psMalloc.c matrixssl/src/os/linux/linux.c', # link all the C files too

}

# The MatrixSSL code requires _WIN32_WINNT=0x0400 in order to correctly pick up the wincrypt.h header
my $defines = ($^O =~ /Win32/) ? '/D_WIN32_WINNT=0x0400' : '-DLINUX';
# Some Linicies seem to require '-lpthread' - if you're having problems, try removing this:-
my $libs = ($^O =~ /Win32/) ? '' : '-lpthread';

=for comment

Win32 inline mod snippet

=cut

=head1 NAME

matrixssl_win32_inline - win32 compiler support script

=head1 SYNOPSIS

	reads  < ./matrixssl/matrixSsl.h  writes > ./mxSsl.h

=head1 DESCRIPTION

Converts the MatrixSSL header file so that Win32 compilations work "inline"
(that is: so they don't need a "perl" loading DLL and a MatrixSSL functions
DLL - everything is instead put all inside the one DLL)

=head2 diff -C2 -b -B -w ./matrixssl/matrixSsl.h ./mxSsl.h

*** ./matrixssl/matrixSsl.h	2004-09-21 00:33:22.000000000 +0000
--- ./mxSsl.h	2005-01-17 14:10:14.000000000 +0000
***************
*** 35,41 ****
  #define _h_MATRIXSSL
  
- #ifdef __cplusplus
- extern "C" {
- #endif
  
  /******************************************************************************/
--- 35,38 ----
***************
*** 145,153 ****
  */
  #ifdef WIN32
! #define SSLPUBLIC extern __declspec(dllimport)
  #endif /* WIN */
  #else /* _h_MATRIXINTERNAL */
  #ifdef WIN32
! #define SSLPUBLIC extern __declspec(dllexport)
  #endif /* WIN */
  #endif /* _h_MATRIXINTERNAL */
--- 142,152 ----
  */
  #ifdef WIN32
! #define SSLPUBLIC extern
! /* __declspec(dllimport) */
  #endif /* WIN */
  #else /* _h_MATRIXINTERNAL */
  #ifdef WIN32
! #define SSLPUBLIC extern
! /*__declspec(dllexport) */
  #endif /* WIN */
  #endif /* _h_MATRIXINTERNAL */
***************
*** 202,208 ****
  /******************************************************************************/
  
- #ifdef __cplusplus
- }
- #endif
  
  #endif /* _h_MATRIXSSL */
--- 201,204 ----

=head1 BUGS

  searches for hardcoded stuff instead of "parsing the header file"; should be OK,
  but might one day fail if peersec make dramatic changes to their header files.

=cut


my($win32)=0;		# Switch so we know if we're inside a win32-specific part of the header file
my($line);

open(MXIN,"<./matrixssl/matrixSsl.h") || die "./matrixssl/matrixSsl.h: $!";
open(MXOUT,">./mxSsl.h") || die "./mxSsl.h: $!";

while($line=<MXIN>) {	# Read the incoming header file
  if($line=~/^#ifdef __cplusplus/) {
    print MXOUT " /* $line */ ";
    $line=<MXIN>;		# extern "C" { or }
    print MXOUT " /* $line */ ";
    $line=<MXIN>;		# #endif
    print MXOUT " /* $line */ \n";
    $line=<MXIN>;		# process next line now
  }

  $win32=1 if($line=~/^#ifdef WIN32/);
  $win32=0 if($line=~/^#endif/);

  if($win32) {
    if($line=~/(.*#define SSLPUBLIC extern)( __declspec\(dll[^\)]+\).*)/sm) {
      # Comment out the dllexport/dllimport declaration
      $line=$1; my $tmp=$2; $tmp=~s/\// \/ /g; $line .= " /* $tmp */ \n";
    }
  }
  print MXOUT $line;
}

close(IN); close(OUT);

=for comment

End of Win32 inline mod snippet

=cut

WriteMakefile(
    'NAME'		=> 'Crypt::MatrixSSL',
    'VERSION_FROM'	=> 'MatrixSSL.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'MatrixSSL.pm', # retrieve abstract from module
       AUTHOR     => 'C. N. Drake <christopher@pobox.com>') : ()),
    'LIBS'		=> [$libs], # e.g., '-lm'
    'DEFINE'		=> $defines, # e.g., '-DHAVE_SOMETHING'
    'INC'		=> '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # 'OBJECT'		=> 'libmatrixssl.lib matrixssl/src/*.o MatrixSSL.o',
    # 'OBJECT'		=> "libmatrixssl.lib $mxobjs MatrixSSL.o", # link all the C files too
    'OBJECT'		=> "$mxobjs MatrixSSL$o", # link all the C files too
    # 'OBJECT'		=> '$(O_FILES)', # link all the C files too
    clean               => {FILES => "$mxobjs Matrixssl$o"},
);



if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw());
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'Crypt::MatrixSSL',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}

package MY;

sub c_o {
  my $inherited = shift->SUPER::c_o(@_);
  if($^O =~ /darwin/) {	# Mac
    # cc -Os -DLINUX -DOSX -isystem -I/usr/include   -c -o sslv3.o sslv3.c
    $inherited =~ s{\$\*.c\n}{\$\*.c -DOSX -isystem -I/usr/include -o\$\*.o\n}mg;
  } elsif($^O =~ /Win32/) {	# Microsoft
    $inherited =~ s{\$\*.c\n}{\$\*.c -Fo\$\*.obj\n}mg;
  } else {			# linux/other unicies: Tell the Makefile to put the .o files with the .c ones
    $inherited =~ s{\$\*.c\n}{\$\*.c -o\$\*.o\n}mg;
  }
  return $inherited;
}


