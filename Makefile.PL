use 5.00001;
use ExtUtils::MakeMaker;
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

my $mxobjs="matrixssl/src/matrixSsl$o matrixssl/src/sslEncode$o matrixssl/src/sslDecode$o matrixssl/src/sslv3$o matrixssl/src/cipherSuite$o matrixssl/src/crypto/peersec/arc4$o matrixssl/src/crypto/peersec/asn1$o matrixssl/src/crypto/peersec/base64$o matrixssl/src/crypto/peersec/des3$o matrixssl/src/crypto/peersec/md5$o matrixssl/src/crypto/peersec/md2$o matrixssl/src/crypto/peersec/mpi$o matrixssl/src/crypto/peersec/rsa$o matrixssl/src/crypto/peersec/sha1$o matrixssl/src/os/malloc$o matrixssl/src/os/$os_src$o";

my $mxc="matrixssl/src/matrixSsl$c matrixssl/src/sslEncode$c matrixssl/src/sslDecode$c matrixssl/src/sslv3$c matrixssl/src/cipherSuite$c matrixssl/src/crypto/peersec/arc4$c matrixssl/src/crypto/peersec/asn1$c matrixssl/src/crypto/peersec/base64$c matrixssl/src/crypto/peersec/des3$c matrixssl/src/crypto/peersec/md5$c matrixssl/src/crypto/peersec/md2$c matrixssl/src/crypto/peersec/mpi$c matrixssl/src/crypto/peersec/rsa$c matrixssl/src/crypto/peersec/sha1$c matrixssl/src/os/malloc$c matrixssl/src/os/$os_src$c";

sub MY::postamble {

return '';

        return "

libmatrixssl.lib: matrixssl/src/Makefile $mxc
	cd matrixssl/src && \$(MAKE) all
	ar -rc libmatrixssl.lib $mxobjs

";
#     'OBJECT'		=> 'matrixssl/src/libmatrixssl.so matrixssl/src/cipherSuite.c matrixssl/src/matrixSsl.c matrixssl/src/sslEncode.c matrixssl/src/sslDecode.c matrixssl/src/sslv3.c matrixssl/src/crypto/peersec/base64.c matrixssl/src/crypto/peersec/arc4.c matrixssl/src/crypto/peersec/asn1.c matrixssl/src/crypto/peersec/des3.c matrixssl/src/crypto/peersec/md2.c matrixssl/src/crypto/peersec/md5.c matrixssl/src/crypto/peersec/mpi.c matrixssl/src/crypto/peersec/rsa.c matrixssl/src/crypto/peersec/sha1.c matrixssl/src/os/malloc.c matrixssl/src/os/linux/linux.c', # link all the C files too

}

my $defines = ($^O =~ /Win32/) ? '' : '-DLINUX';
WriteMakefile(
    'NAME'		=> 'Crypt::MatrixSSL',
    'VERSION_FROM'	=> 'MatrixSSL.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'MatrixSSL.pm', # retrieve abstract from module
       AUTHOR     => 'C. N. Drake <christopher@pobox.com>') : ()),
    'LIBS'		=> [''], # e.g., '-lm'
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


