# Microsoft Developer Studio Generated NMAKE File, Based on matrixssl.dsp
!IF "$(CFG)" == ""
CFG=matrixssl - Win32 Debug
!MESSAGE No configuration specified. Defaulting to matrixssl - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "matrixssl - Win32 Release" && "$(CFG)" != "matrixssl - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "matrixssl.mak" CFG="matrixssl - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "matrixssl - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "matrixssl - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "matrixssl - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\matrixssl.lib"


CLEAN :
	-@erase "$(INTDIR)\arc4.obj"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\base64.obj"
	-@erase "$(INTDIR)\cipherSuite.obj"
	-@erase "$(INTDIR)\des3.obj"
	-@erase "$(INTDIR)\malloc.obj"
	-@erase "$(INTDIR)\matrixSsl.obj"
#	-@erase "$(INTDIR)\mxSsl.obj"
	-@erase "$(INTDIR)\md2.obj"
	-@erase "$(INTDIR)\md5.obj"
	-@erase "$(INTDIR)\mpi.obj"
	-@erase "$(INTDIR)\rsa.obj"
	-@erase "$(INTDIR)\sha1.obj"
	-@erase "$(INTDIR)\sslDecode.obj"
	-@erase "$(INTDIR)\sslEncode.obj"
	-@erase "$(INTDIR)\sslv3.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\win.obj"
	-@erase "$(OUTDIR)\matrixssl.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\matrixssl.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\matrixssl.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\matrixssl.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\matrixssl.lib" 
LIB32_OBJS= \
	"$(INTDIR)\cipherSuite.obj" \
	"$(INTDIR)\matrixSsl.obj" \
#	"$(INTDIR)\mxSsl.obj" \
	"$(INTDIR)\sslDecode.obj" \
	"$(INTDIR)\sslEncode.obj" \
	"$(INTDIR)\sslv3.obj" \
	"$(INTDIR)\sha1.obj" \
	"$(INTDIR)\arc4.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\base64.obj" \
	"$(INTDIR)\des3.obj" \
	"$(INTDIR)\md2.obj" \
	"$(INTDIR)\md5.obj" \
	"$(INTDIR)\mpi.obj" \
	"$(INTDIR)\rsa.obj" \
	"$(INTDIR)\malloc.obj" \
	"$(INTDIR)\win.obj"

"$(OUTDIR)\matrixssl.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    type <<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "matrixssl - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\matrixssl.lib"


CLEAN :
	-@erase "$(INTDIR)\arc4.obj"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\base64.obj"
	-@erase "$(INTDIR)\cipherSuite.obj"
	-@erase "$(INTDIR)\des3.obj"
	-@erase "$(INTDIR)\malloc.obj"
	-@erase "$(INTDIR)\matrixSsl.obj"
	-@erase "$(INTDIR)\mxSsl.obj"
	-@erase "$(INTDIR)\md2.obj"
	-@erase "$(INTDIR)\md5.obj"
	-@erase "$(INTDIR)\mpi.obj"
	-@erase "$(INTDIR)\rsa.obj"
	-@erase "$(INTDIR)\sha1.obj"
	-@erase "$(INTDIR)\sslDecode.obj"
	-@erase "$(INTDIR)\sslEncode.obj"
	-@erase "$(INTDIR)\sslv3.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\win.obj"
	-@erase "$(OUTDIR)\matrixssl.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\matrixssl.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ  /c 
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\matrixssl.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ  /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\matrixssl.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\matrixssl.lib" 
LIB32_OBJS= \
	"$(INTDIR)\cipherSuite.obj" \
	"$(INTDIR)\matrixSsl.obj" \
#	"$(INTDIR)\mxSsl.obj" \
	"$(INTDIR)\sslDecode.obj" \
	"$(INTDIR)\sslEncode.obj" \
	"$(INTDIR)\sslv3.obj" \
	"$(INTDIR)\sha1.obj" \
	"$(INTDIR)\arc4.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\base64.obj" \
	"$(INTDIR)\des3.obj" \
	"$(INTDIR)\md2.obj" \
	"$(INTDIR)\md5.obj" \
	"$(INTDIR)\mpi.obj" \
	"$(INTDIR)\rsa.obj" \
	"$(INTDIR)\malloc.obj" \
	"$(INTDIR)\win.obj"

"$(OUTDIR)\matrixssl.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    type <<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("matrixssl.dep")
!INCLUDE "matrixssl.dep"
!ELSE 
!MESSAGE Warning: cannot find "matrixssl.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "matrixssl - Win32 Release" || "$(CFG)" == "matrixssl - Win32 Debug"
SOURCE=.\src\crypto\peersec\arc4.c

"$(INTDIR)\arc4.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\asn1.c

"$(INTDIR)\asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\base64.c

"$(INTDIR)\base64.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\cipherSuite.c

"$(INTDIR)\cipherSuite.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\des3.c

"$(INTDIR)\des3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\os\malloc.c

"$(INTDIR)\malloc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\matrixSsl.c

"$(INTDIR)\matrixSsl.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)

SOURCE=.\src\mxSsl.c

# "$(INTDIR)\matrixSsl.obj" : $(SOURCE) "$(INTDIR)"
"$(INTDIR)\mxSsl.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\md2.c

"$(INTDIR)\md2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\md5.c

"$(INTDIR)\md5.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\mpi.c

"$(INTDIR)\mpi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\rsa.c

"$(INTDIR)\rsa.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\crypto\peersec\sha1.c

"$(INTDIR)\sha1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\sslDecode.c

"$(INTDIR)\sslDecode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\sslEncode.c

"$(INTDIR)\sslEncode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\sslv3.c

"$(INTDIR)\sslv3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\src\os\win\win.c

"$(INTDIR)\win.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

