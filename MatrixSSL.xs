#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "mxSsl.h"




MODULE = Crypt::MatrixSSL		PACKAGE = Crypt::MatrixSSL		



##############################################################################################	

=head2 matrixSslOpen

Prototype
int matrixSslOpen();

Context
Client and Server

Description
This function performs the one-time initialization for MatrixSSL. Applications
should call this function once as part of their own initialization to load the cipher
suite and perform any operating system specific set up.

Parameters
None

Return Value
0 Success
< 0 Failure

=cut

int
matrixSslOpen()
    CODE:
        RETVAL = matrixSslOpen();
    OUTPUT:
        RETVAL











##############################################################################################	

=head2 matrixSslClose

Prototype
void matrixSslClose();

Context
Client and Server

Description
This function performs the one-time final cleanup for MatrixSSL. Applications
should call this function as part of their own final cleanup.

Parameters
None

Return Value
None

=cut

void matrixSslClose()
    CODE:
        matrixSslClose();










##############################################################################################	

=head2 matrixSslReadKeys

Prototype
int matrixSslReadKeys(sslKeys_t **keys, char *certFile, char *privFile,
char *privPass, char *trustedCAcertFiles);

Context
Client and Server

Description
This function is called to load the certificates and private key files from disk that
are needed for server authentication. The key material is loaded into the keys
output parameter. The GNU MatrixSSL supports one-way authentication (server)
so the parameters to this function are specific to the client/server role of the
application. The certFile, privFile, and privPass parameters are server specific
and should identify the certificate and private key file for that server. The
trustedCAcertFiles is client specific and should identify the trusted root
certificates that will be used to validate the certificates received from a server.
Multiple trusted root certificates can be passed to this parameter as a semicolon
delimited list of file names. Any key file or password parameter that does not
apply to the application context should be passed in as NULL.
It is possible to identify a certificate chain (server side only) by using a semicolon
delimited list of certificate names in the certFile paramter. The list must be
given in child/parent order with the first certificate being the server certificate.
The private key file specified in the privFile parameter must correspond with the
first certificate in the list.
The sslKeys_t output parameter from this function is used as the input parameter
when starting a new SSL session via matrixSslNewSession. The sslKeys_t type
has been defined in the public matrixSsl.h file to simply be an opaque integer type
since applications do not need access to any of the structure members.
Calling this function is a relatively expensive operation because of the file access
and parsing required to extract the key material. For this reason, it is typical that
this function is only called once per set of key files for a given application. All
new sessions associated with that certificate can reuse the returned key pointer.
This function is separate from matrixSslOpen because some Web servers support
virtual servers that each have different key pairs. The user must free the key
structure using matrixSslFreeKeys.
A buffered memory version of this function is included in the library for
environments where the certificate material is not stored on disk. That version
can be found by searching for matrixSslReadKeysMem in the source code.

Parameters
keys Output parameter for storing the key material
certFile The filename (including path) of the certificate. Server only.
privKeyFile The filename (including path) of the private key file. Server
only.
privKeyPass The password used to encrypt the private key file if used.
Only 3DES CBC encryption is supported. Server only.
trustedCAcertFile The filename (including path) of a trusted root certificate.
Multiple files may be passed in a semicolon delimited list.  Client only.

Return Value
0 Success. A valid key pointer will be returned in the keys
parameter for use in a subsequent call to matrixSslNewSession
<0 Failure

=cut

int
matrixSslReadKeys(mxkeys, certFile, privFile, privPass, trustedCAcertFiles)
	int mxkeys
       	SV *certFile
	SV *privFile
	SV *privPass
	SV *trustedCAcertFiles
    CODE:
       	char *icertFile=SvPV_nolen(certFile);
	char *iprivFile=SvPV_nolen(privFile);
	char *iprivPass=SvPV_nolen(privPass);
	char *itrustedCAcertFiles=SvPV_nolen(trustedCAcertFiles);
	if(strlen(icertFile)==0) { icertFile=NULL; }
	if(strlen(iprivFile)==0) { iprivFile=NULL; }
	if(strlen(iprivPass)==0) { iprivPass=NULL; }
	if(strlen(itrustedCAcertFiles)==0) { itrustedCAcertFiles=NULL; }
	/* Note: This takes advantage of perl's inbuilt string null-termination feature */
        RETVAL = matrixSslReadKeys((sslKeys_t **)&mxkeys, icertFile, iprivFile, iprivPass, itrustedCAcertFiles);
    OUTPUT:
    	mxkeys
        RETVAL










##############################################################################################	

=head2 matrixSslFreeKeys

Prototype
void matrixSslFreeKeys(sslKeys_t *keys);

Context
Client and Server

Description
This function is called to free the key structure and elements allocated from a
previous call to matrixSslReadKeys.

Parameters
keys A pointer to an sslKeys_t value returned from a previous call
to matrixSslReadKeys

Return Value
None

=cut

void
matrixSslFreeKeys(mxkeys)
	int mxkeys
    CODE:
        matrixSslFreeKeys((sslKeys_t *)mxkeys);
	mxkeys=0; /* gone now, so lets remove it from the callers variable too */
    OUTPUT:
    	mxkeys










##############################################################################################	

=head2 matrixSslNewSession

Prototype
int matrixSslNewSession(ssl_t **ssl, sslKeys_t *keys, sslSessionId_t *sesssionId, int flags);

Context
Client and Server

Description
This function is called to start a new SSL session, or resume a previous one, with
a client or server. The session is returned in the output parameter ssl. This
function requires a pointer to an sslKeys_t value returned from a previous call to
matrixSslReadKeys and the flags parameter to specify whether this is a server side
usage. MatrixSSL supports client initiated SSL sessions and the sessionId
parameter is specific to client implementations only. If the client is resuming a
prior session, this parameter will be the value returned from a call to
matrixSslGetSessionId. Otherwise, this parameter must be NULL. The client
must pass 0 as the flags parameter. A client will make a call to this function prior
to calling matrixSslEncodeClientHello.
When a server application has received notice that a client is requesting a secure
socket connection (a socket accept on a secure port), this function should be
called to initialize the new session structure. The sessionId parameter must be set
to NULL for server side implementations.
The output parameter is an ssl_t structure that will be used as input parameters to
the matrixSslDecode and matrixSslEncode family of APIs for decrypting and
encrypting messages. The ssl_t type has been defined in the public matrixSsl.h
file to simply be an opaque integer type since users do not need access to any of
the structure members. The user must free the ssl_t structure using
matrixSslDeleteSession.

Parameters
ssl Output. The new SSL session created by this call
keys The opaque key material pointer returned from a call to
matrixSslReadKeys
sessionId Prior session id obtained from matrixSslGetSessionId if
client is resuming a session. NULL otherwise.
flags SSL_FLAGS_SERVER for server and 0 for client.

Return Value
0 Success. A newly allocated session structure will be returned
in the ssl parameter for use as the input parameter on session
related decoding and encoding APIs
<0 Failure

=cut

int
matrixSslNewSession(ssl, mxkeys, sessionId, flags)
	int ssl
	int mxkeys
	int sessionId
	int flags
    CODE:
        if(flags!=0) {flags=SSL_FLAGS_SERVER;sessionId=NULL;}
	RETVAL = matrixSslNewSession((ssl_t **)&ssl, (sslKeys_t *)mxkeys, (sslSessionId_t *)sessionId, flags);
    OUTPUT:
    	ssl
        RETVAL










##############################################################################################	

=head2 matrixSslDeleteSession

Prototype
void matrixSslDeleteSession(ssl_t *session);

Context
Client and Server

Description
This function is called at the conclusion of an SSL session that was created using
matrixSslNewSession. This function will free the allocated memory associated
with the session. It should be called after the corresponding socket has been
closed.
A client wishing to reconnect later to the same server may choose to call
matrixSslGetSessionId prior to calling this delete session function to save aside
the session id for later use with matrixSslNewSession.

Parameters
session The ssl_t session pointer returned from the call to
matrixSslNewSession

Return Value
None

=cut

void
matrixSslDeleteSession(session)
	int session
    CODE:
	matrixSslDeleteSession((int *)session);
	session=0; /* gone now, so lets remove it from the callers variable too */
    OUTPUT:
    	session










##############################################################################################	

=head2 matrixSslDecode

Prototype
int matrixSslDecode(ssl_t *session, sslBuf_t *in, sslBuf_t *out,
unsigned char *error, unsigned char *alertLevel,
unsigned char *alertDescription);

Context
Client and Server

Description
This is a powerful function used to decode all messages received from a peer,
including handshake and alert messages. The input parameters include the ssl_t
session from the previous call to matrixSslNewSession and an sslBuf_t input
buffer containing the message received from the client or server. This function is
typically called in a loop during the handshake process. The return value
indicates the type of message received and the out buffer parameter may contain
an encoded message to send to the other side or a decoded message for the
application to process. The in buffer may have its start pointer moved forward to
indicate the bytes that were successfully decoded. The out buffer end pointer may
be modified to reflect the output data written to the buffer.
API Documentation MatrixSSL 1.2

Parameters
session The ssl_t session structure associated with this instance.
Created by the call to matrixSslNewSession
in The sslBuf_t buffer containing the input message from the
other side of the client/server communication channel
out The output buffer after returned to the application
error On SSL_ERROR conditions, this output parameter specifies
the error description associated with the error
alertLevel On SSL_ALERT conditions, this output parameter specifies
the alert level associated with the client alert message
alertDescription On SSL_ALERT conditions, this output parameter specifies
the alert description associated with the client alert message

Return Value
SSL_SUCCESS A handshake message was successfully decoded and
handled. No additional action is required for this
message. matrixSslDecode can be called again
immediately if more data is expected. This return
code gives visibility into the handshake process and
can be used in conjunction with
matrixSslHandshakeIsComplete to determine when
the handshake is complete and application data can
be sent.
SSL_SEND_RESPONSE This value indicates the input message was part of the
SSLv3 internal protocol and a reply is expected. The
application should send the data in the out buffer to
the other side and then call matrixSslDecode again to
see if any more message data needs to be decoded.
SSL_ERROR This value indicates there has been an error while
attempting to decode the data or that a bad message
was sent. The application should attempt to send the
contents of out buffer, if any (likely an error alert) to
the other side as a reply and then close the
communication layer (i.e. close the socket).
SSL_ALERT This value indicates the message was an alert sent
from the other side and the application should close
the communication layer (i.e. close the socket).
SSL_PARTIAL This value indicates that the input buffer was an
incomplete message or record. The application must
retrieve more data from the communications layer
(socket) and call matrixSslDecode again when more
data is available.
SSL_FULL This value indicates the output buffer was too small
to hold the output message. The application should
grow the output buffer and call matrixSslDecode
again with the same input buffer. The maximum size
of the buffer output buffer will never exceed 16K per
the SSLv3 standard.
SSL_PROCESS_DATA This value indicates that the message is application
specific data that does not require a response from the
server. This message is an implicit indication that
SSLv3 handshaking is complete. The decoded data
has been written to the output buffer for application
consumption.

=cut

int
matrixSslDecode(session, in, out, error, alertLevel, alertDescription)
	int session
	SV *in
	SV *out
	SV *error
	SV *alertLevel
	SV *alertDescription
    CODE:
	unsigned char oerror=0; /* SvIV(error); */
	unsigned char oalertLevel=0; /* SvIV(alertLevel); */
	unsigned char oalertDescription=0; /* SvIV(alertDescription); */
	sslBuf_t mxin;
	sslBuf_t mxout;
	int mylen=0;
	
	SvGROW(out, 18500);	/* allocate room for output data */
	mxout.size=18500;
	mxout.buf=SvPV(out, mylen);
	mxout.start=mxout.buf;
	mxout.end=mxout.buf;
	
	mxin.buf=SvPV(in, mylen);
	mxin.size=mylen; /* SvCUR(in); */
	mxin.start=mxin.buf;
	mxin.end=mxin.buf+mylen;

	RETVAL = matrixSslDecode((ssl_t *)session, (sslBuf_t *)&mxin, &mxout, &oerror, &oalertLevel, &oalertDescription);

	sv_setpvn(out,mxout.start, mxout.end-mxout.start);	/* Copy the answer */
	sv_setpvn(in,mxin.start, mxin.end-mxin.start);		/* remove from the input whatever got processed */
	sv_setiv(error,oerror);
	sv_setiv(alertLevel,oalertLevel);
	sv_setiv(alertDescription,oalertDescription);
    OUTPUT:
    	in
	out
    	error
	alertLevel
	alertDescription
        RETVAL











##############################################################################################	

=head2 matrixSslEncode

Prototype
int matrixSslEncode(ssl_t *session, unsigned char *in, int inLen, sslBuf_t *out);

Context
Client and Server

Description
This function is used by the application to generate encrypted messages to be sent
to the other side of the client/server communication channel. Only application
level messages should be generated with this API. Handshake messages are
generated internally as part of matrixSslDecode. It is the responsibility of the
application to actually transmit the generated output buffer to the other side.

Parameters
session The ssl_t session identifier for this
session.
in The plain-text message buffer to encrypt
inLen The length of valid data in the input
buffer to encrypt
out The encrypted message to be passed to
the other side

Return Value
>= 0 Success. The value is the length of the
encrypted data.
SSL_ERROR Error. The connection should be closed,
and session deleted.
SSL_FULL The output buffer is not big enough to
hold the encrypted data. Grow the
buffer and retry.

=cut

int
matrixSslEncode(session, in, out)
	int session
	SV *in
	SV *out
    CODE:
    	int inLen=0;
	unsigned char *ptr;
	sslBuf_t mxout;
	if(!(SvOK(out))) {
	  sv_setpvn(out,(char *)&inLen,1);	/* Add any old junk into the SV so that the upcoming GROW will work */
	}
	if(!(SvOK(in))) {
	  sv_setpvn(in,(char *)&inLen,1);	/* "Define" it */
	  SvCUR_set(in, 0);		/* chop off the unused buffers ending */
	}
	/* __asm int 3; // force break point */
	SvGROW(out, 18500);	/* allocate room for output data (some extra above inLen is prolly more efficient) */
	mxout.size=18500;
	mxout.buf=SvPV(out, inLen);	/* inLen not used here presently */
	mxout.start=mxout.buf;
	mxout.end=mxout.buf;
	ptr=SvPV(in, inLen);
	RETVAL = matrixSslEncode((ssl_t *)session, ptr, inLen, &mxout);
	SvCUR_set(out, mxout.end-mxout.start); /* chop off the unused buffers ending */
	/* sv_setpvn(out,mxout.start, mxout.end-mxout.start);	// Copy the answer */
    OUTPUT:
    	out
	RETVAL










##############################################################################################	

=head2 matrixSslEncodeClosureAlert

Prototype
int matrixSslEncodeClosureAlert(ssl_t *session, sslBuf_t * out);

Context
Client and Server

Description
An optional function call made before closing the communication channel with a
peer. This function alerts the peer that the connection is about to close. Some
implementations simply close the connection without an alert, but per spec, this
message should be sent first.

Parameters
session The ssl_t session identifier for this session
out The output alert closure message to be passed along to the client.
Return Value
0 Success
SSL_FULL The output buffer is not big enough to
hold the encrypted data. Grow the
buffer and retry.
SSL_ERROR Failure
=cut

int
matrixSslEncodeClosureAlert(session, out)
	int session
	SV *out
    CODE:
	sslBuf_t mxout;
	int inLen;
	if(!(SvOK(out))) {
	  sv_setpvn(out,(char *)&inLen,1);	/* Add any old junk into the SV so that the upcoming GROW will work */
	}

	SvGROW(out, 18500);
	mxout.size=18500;
	mxout.buf=SvPV(out, inLen);	/* inLen not used here presently */
	mxout.start=mxout.buf;
	mxout.end=mxout.buf;

	RETVAL = matrixSslEncodeClosureAlert((ssl_t *)session, &mxout);
	SvCUR_set(out, mxout.end-mxout.start); /* chop off the unused buffers ending */
    OUTPUT:
    	out
	RETVAL










##############################################################################################	

=head2 matrixSslEncodeClientHello

Prototype
int matrixSslEncodeClientHello(ssl_t *session, sslBuf_t * out,
unsigned short cipherSuite);

Context
Client

Description
This function builds the initial CLIENT_HELLO message to be passed to a server
to begin SSL communications. This function is called once by the client before
entering into the matrixSslDecode handshake loop.
The cipherSuite parameter can be used to force the client to send a single cipher
to the server rather than the entire set of supported ciphers. Set this value to 0 to
send the entire cipher suite list. Otherwise the value is the two byte value of the
cipher suite specified in the standards. The supported values can be found in
matrixInternal.h.
This function may also be called by a client at the conclusion of the initial
handshake at any time to initiate a re-handshake. A re-handshake is a complete
SSL handshake protocol performed on an existing connection to derive new
symmetric key material and/or to change the cipher spec of the communications.
All re-handshake messages will be encrypted using the previously negotiated
cipher suite. If the caller wants to assure that a new session id is used for the rehandshake,
the function matrixSslDeleteCurrentSessionId should be called prior
to calling matrixSslEncodeClientHello. It is always at the discretion of the server
whether or not to resume on a session id passed in by the client in the
CLIENT_HELLO message. However, the client can force a new session if the
session id is not passed in originally.

Parameters
session The ssl_t session identifier for this session
out The output alert closure message to be passed along to the client.
cipherSuite The two byte cipher suite identifier

Return Value
0 Success
SSL_FULL The output buffer is not big enough to
hold the encrypted data. Grow the
buffer and retry.
SSL_ERROR Failure
=cut

int
matrixSslEncodeClientHello(session, out, cipherSuite)
	int session
	SV *out
	unsigned short cipherSuite
    CODE:
	sslBuf_t mxout;
	int inLen;
	if(!(SvOK(out))) {
	  sv_setpvn(out,(char *)&inLen,1);	/* Add any old junk into the SV so that the upcoming GROW will work */
	}
	SvGROW(out, 4100);		/* Make room for our output */
	mxout.size=4100;
	mxout.buf=SvPV(out, inLen);	/* inLen not used here presently */
	mxout.start=mxout.buf;
	mxout.end=mxout.buf;

        RETVAL = matrixSslEncodeClientHello((ssl_t *)session, &mxout, cipherSuite);
	/* Warning: need to monitor the RETVAL and grow the buffer if there was not room? */
	/* printf("\nsize=%d buf='%s'\n",mxout.end-mxout.start, mxbuf); */
	//sv_setpvn(out,mxout.start, mxout.end-mxout.start);	/* Copy the answer */
	SvCUR_set(out, mxout.end-mxout.start); /* chop off the unused buffers ending */
    OUTPUT:
    	out
        RETVAL









##############################################################################################	

=head2 matrixSslEncodeHelloRequest

Prototype
int matrixSslEncodeHelloRequest(ssl_t *session, sslBuf_t * out);

Context
Server

Description
This function builds a HELLO_REQUEST message to be passed to a client to
initiate a re-handshake. This is the only mechanism in the SSL protocol that
allows the server to initiate a handshake. A re-handshake can be done on an
existing session to derive new symmetric cryptographic keys or to change the
cipher spec. All messages exchanged during a re-handshake are encrypted under
the currently negotiated cipher suite.
If the server wishes to change the session option for the re-handshake it should
call matrixSslSetSessionOption to modify the handshake behavior.
Note: The SSL specification allows clients to ignore a HELLO_REQUEST
message. The MatrixSSL client does not ignore this message and will send a
CLIENT_HELLO message with the current session id.

Parameters
session The ssl_t session identifier for this session
out The output alert closure message to be passed along to the
client.

Return Value
0 Success
SSL_FULL The output buffer is not big enough to
hold the data. Grow the buffer and
retry.
SSL_ERROR Failure


=cut

int
matrixSslEncodeHelloRequest(session, out)
	int session
	SV *out
    CODE:
	sslBuf_t mxout;
	int myLen=0;
	
	if(!(SvOK(out))) {
	  sv_setpvn(out,(char *)&myLen,1);	/* Add any old junk into the SV so that the upcoming GROW will work */
	}
	SvGROW(out, 18500);	/* allocate room for output data */
	mxout.size=18500;
	mxout.buf=SvPV(out, myLen);
	mxout.start=mxout.buf;
	mxout.end=mxout.buf;
	
        RETVAL = matrixSslEncodeHelloRequest((ssl_t *)session, &mxout);
	/* Warning: need to monitor the RETVAL and grow the buffer if there was not room? */
	/* printf("\nsize=%d buf='%s'\n",mxout.end-mxout.start, mxbuf); */
	// sv_setpvn(out,mxout.start, mxout.end-mxout.start);	/* Copy the answer */
	SvCUR_set(out, mxout.end-mxout.start); /* chop off the unused buffers ending */
    OUTPUT:
    	out
        RETVAL










##############################################################################################	

=head2 matrixSslSetSessionOption

Prototype
void matrixSslSetSessionOption(ssl_t *session, int option, void *arg);

Context
Client and Server

Description
The matrixSslSetSessionOption function is used to modify the behavior of the
SSL handshake protocol for a re-handshake. This function is only meaningful to
call on an existing SSL session before a re-handshake to give the server control
over which handshake type to perform (full or resumed).
A server initiated re-handshake is done by sending the HELLO_REQUEST
message which can be constructed by calling matrixSslEncodeHelloRequest.
Prior to sending this message, the server may wish to disallow a resumed rehandshake
by passing the option of SSL_OPTION_DELETE_SESSION as the
option parameter to this function. This will delete the current session information
from the local cache so it will not be found if the client passes a session id in the
subsequent CLIENT_HELLO message.
A client initiated re-handshake is done by simply sending a new
CLIENT_HELLO message over an existing connection. If the client application
wishes a full re-handshake to be performed, it should call this function with
SSL_OPTION_DELETE_SESSION as the option parameter.
A resumed re-handshake may be performed by excluding any calls to this
function before sending the HELLO_REQUEST message.
For more information about re-handshaking, see the Re-handshake section of the
MatrixSSL Developers Guide.

Parameters
session The ssl_t session identifier for a currently connected
session
option SSL_OPTION_DELETE_SESSION
arg NULL. Reserved for future use.

Return Value
None

=cut

void
matrixSslSetSessionOption(session, option, arg)
	int session
       	int option
	char *arg
    CODE:
	if(arg!=NULL) {
	  arg=NULL;	/* reserved for future - must be null */
	}
	matrixSslSetSessionOption((ssl_t *)session, option, (void *)arg);










##############################################################################################	

=head2 matrixSslHandshakeIsComplete

Prototype
int matrixSslHandshakeIsComplete(ssl_t *session);

Context
Client and Server

Description
This function returns whether or not the handshake portion of the session is
complete. This API can be used to test when it is OK to send the first application
data record on an SSL connection.

Parameters
session The ssl_t session identifier for this session

Return Value
1 Handshake is complete
0 Handshake is NOT complete

=cut

int
matrixSslHandshakeIsComplete(session)
	int session
    CODE:
	RETVAL=matrixSslHandshakeIsComplete((ssl_t *)session);
    OUTPUT:
    	RETVAL










##############################################################################################	

=head2 matrixSslGetSessionId

Prototype
int matrixSslGetSessionId(ssl_t *session, sslSessionId_t **sessionId);

Context
Client

Description
This function is used by a client application to extract the session id from an
existing session for use in a subsequent call to matrixSslNewSession wishing to
resume a session. A resumed session is much faster to negotiate because the
public key encryption process does not need to be performed and two handshake
messages are avoided. The sessionId return parameter of this function is valid
even after matrixSslDeleteSession has been called on the current session. This
function should only be called by a client SSL session after the handshake is
complete (session id is established).
The sslSessionId_t structure has been defined in the public header as an opaque
integer type since the contents of the structure do not need to be accessed by the
application. The session id must be freed with a call to matrixSslFreeSessionId.

Parameters
session The ssl_t session identifier for this session
sessionId Output. The returned session id for the given SSL session

Return Value
0 Success. An allocated session id is returned in
sessionId
<0 Failure (sessionId unavailable)

=cut

int
matrixSslGetSessionId(session, sessionId)
	int session
	int sessionId
    CODE:
	RETVAL= matrixSslGetSessionId((ssl_t *)session,(sslSessionId_t **)&sessionId);
    OUTPUT:
    	sessionId
    	RETVAL










##############################################################################################	

=head2 matrixSslFreeSessionId

Prototype
void matrixSslFreeSessionId(sslSessionId_t *sessionId);

Context
Client

Description
This function is used by a client application to free a session id returned from a
previous call to matrixSslGetSessionId..

Parameters
sessionId The sslSession_t identifier

Return Value
None

=cut

void
matrixSslFreeSessionId(sessionId)
	int sessionId
    CODE:
	matrixSslFreeSessionId((sslSessionId_t *)sessionId);










##############################################################################################	

=head2 matrixSslSetCertValidator

Prototype
void matrixSslSetCertValidator(ssl_t *session,
int (*certValidator)(sslCertInfo_t*, void *arg), void *arg);

Context
Client

Description
This function is used by client applications to register a callback routine that will
be invoked during the certificate validation process. This optional registration
will enable the application to perform custom validation checks or to pass
certificate information on to end users wishing to manually validate certificates.
The registered function must have the following prototype:
int appCertValidator(sslCertInfo_t *certInfo, void *arg);
The certInfo parameter is the incoming sslCertInfo_t structure containing
information about the certificate chain. This certificate information is read-only
from the perspective of the validating callback function. The structure members
are available in the Structures section in this document and in the matrixSsl.h
public header file.
The verified member of certInfo will indicate whether or not the certificate passed
the default MatrixSSL validation checks. A typical callback implementation
might be to check the value of the verified member and pass the certificate
information along to the user if it had not passed the default validation checks.
The arg parameter is a user specific argument that was specified in the arg
parameter to the matrixSslSetCertValidator routine. This argument can be used to
give session context to the callback if needed.

The callback function should return a value >= 0 if the custom validation check is
successful and the certificate is determined to be acceptable. The callback
function must return a negative value if the validation checks fails for any reason.
The negative return code will be passed back to the MatrixSSL library and the
handshake process will terminate.

=cut

void 
matrixSslSetCertValidator(session, callback, arg)
	int session
	int callback
	int arg
    CODE:
        printf("Warning: not implimented: matrixSslSetCertValidator(ssl_t *session, int (*certValidator)(sslCertInfo_t*, void *arg), void *arg);\n");
        printf("See http://aspn.activestate.com/ASPN/docs/ActivePerl/lib/Pod/perlcall.html for instructions on writing this\n");
	matrixSslSetCertValidator((ssl_t *)session, 0, 0);

	/* Here's the prototype we'll need:	int appCertValidator(sslCertInfo_t *certInfo, void *arg) */






=head3 testing

void
hello()
    CODE:
        printf("Hello, world!\n");

=cut



##############################################################################################	

=head2 The end

That's the end of this .xs file.

=cut
