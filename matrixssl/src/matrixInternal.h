/*
 *	matrixInternal.h
 *	Release $Name: MATRIXSSL_1_2_2_OPEN $
 *
 *	Internal header file used for the MatrixSSL implementation.
 *	Only modifiers of the library should be intersted in this file
 */
/*
 *	Copyright (c) PeerSec Networks, 2002-2004. All Rights Reserved.
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from PeerSec Networks
 *	at http://www.peersec.com
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#ifndef _h_MATRIXINTERNAL
#define _h_MATRIXINTERNAL

/*
	Include the configuration header to define the features we're using
*/
#include "matrixConfig.h"

#include "os/osLayer.h"
#include "crypto/cryptoLayer.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#if WIN32
#define				fcntl(A, B, C)
#define				MSG_NOSIGNAL	0
#endif /* WIN32 */

#define	SSL_FLAGS_SERVER		0x1		/* Must match value in matrixSsl.h */
#define	SSL_FLAGS_READ_SECURE	0x2
#define	SSL_FLAGS_WRITE_SECURE	0x4
#define SSL_FLAGS_PUBLIC_SECURE	0x8
#define SSL_FLAGS_RESUMED		0x10	
#define SSL_FLAGS_CLOSED		0x20
#define SSL_FLAGS_NEED_ENCODE	0x40
#define SSL_FLAGS_ERROR			0x80
	
/*
	matrixSslSetSessionOption defines
*/
#define	SSL_OPTION_DELETE_SESSION		0	/* Must match matrixSsl.h */

#define SSL2_HEADER_LEN				2
#define SSL3_HEADER_LEN				5
#define SSL3_HANDSHAKE_HEADER_LEN	4

/*
	These are defines rather than enums because we want to store them as char,
	not int (enum size)
*/
#define SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC	20
#define SSL_RECORD_TYPE_ALERT				21
#define SSL_RECORD_TYPE_HANDSHAKE			22
#define SSL_RECORD_TYPE_APPLICATION_DATA	23

#define SSL_HS_HELLO_REQUEST		0
#define SSL_HS_CLIENT_HELLO			1
#define SSL_HS_SERVER_HELLO			2
#define SSL_HS_CERTIFICATE			11
#define SSL_HS_SERVER_KEY_EXCHANGE	12
#define SSL_HS_CERTIFICATE_REQUEST	13
#define SSL_HS_SERVER_HELLO_DONE	14
#define SSL_HS_CERTIFICATE_VERIFY	15
#define SSL_HS_CLIENT_KEY_EXCHANGE	16
#define SSL_HS_FINISHED				20
#define SSL_HS_DONE					255	/* Handshake complete (internal) */

#define	INIT_ENCRYPT_CIPHER		0
#define INIT_DECRYPT_CIPHER		1

#define RSA_SIGN	1

/*
	Additional ssl alert value, indicating no error has ocurred.
*/
#define SSL_ALERT_NONE					255	/* No error */

#define SSL_HS_RANDOM_SIZE		32
#define SSL_HS_PREMASTER_SIZE	48

#define SSL2_MAJ_VER	2
#define SSL3_MAJ_VER	3
#define SSL3_MIN_VER	0
#define TLS_MIN_VER		1


/*
	SSL cipher suite values
*/
#define SSL_NULL_WITH_NULL_NULL			0x0000
#define SSL_RSA_WITH_NULL_MD5			0x0001
#define SSL_RSA_WITH_NULL_SHA			0x0002
#define SSL_RSA_WITH_RC4_128_MD5		0x0004
#define SSL_RSA_WITH_RC4_128_SHA		0x0005
#define SSL_RSA_WITH_3DES_EDE_CBC_SHA	0x000A

/*
	Master secret is 48 bytes, sessionId is 32 bytes max
*/
#define		SSL_HS_MASTER_SIZE		48
#define		SSL_MAX_SESSION_ID_SIZE	32


/*
	Return the length of padding bytes required for a record of 'LEN' bytes
	The name Pwr2 indicates that calculations will work with 'BLOCKSIZE'
	that are powers of 2.
	Because of the trailing pad length byte, a length that is a multiple
	of the pad bytes
	FUTURE TLS - Could support random length additions to the pad to obfuscate
	true pad length.
*/
#define sslPadLenPwr2(LEN, BLOCKSIZE) \
	BLOCKSIZE <= 1 ? (unsigned char)0 : \
	(unsigned char)(BLOCKSIZE - ((LEN) & (BLOCKSIZE - 1)))

/*
	Round up the given length to the correct length with SSLv3 padding
*/
#define sslRoundup018(LEN, BLOCKSIZE) \
	BLOCKSIZE <= 1 ? BLOCKSIZE : (((LEN) + 8) & ~7)

#ifndef max
#define max(a,b)	(((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)	(((a) < (b)) ? (a) : (b))
#endif

/******************************************************************************/
#if FUTURE
/*
	Buffer arithmetic
*/
#define BUFLEN(B)			(int)(B.end - B.start)
#define BUFREMAINING(B)		(int)((B.buf + B.size) - B.end)
/*
	Buffer conditionals
*/
#define BUFHASDATA(B)		(B.start < B.end)
#define BUFHASROOM(B, L)	(BUFREMAINING(B) >= L)
/*
	Buffer actions
*/
#define BUFALLOC(B, L)		B.buf = psMalloc(L); B.size = L; BUFRESET(B);
#define BUFFREE(B)			free(B.buf); B.buf = B.start = B.end = NULL;
#define BUFRESET(B)			(B.start = B.end = B.buf);
#define BUFPACK(B)			if (B.start > B.buf) { \
								if (BUFHASDATA(B)) { \
									memmove(B.buf, B.start, BUFLEN(B));\
								} \
								BUFRESET(B); \
							}
#endif
/******************************************************************************/

#ifndef sslBuf_t
/*
	Empty buffer:
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	|.|.|.|.|.|.|.|.|.|.|.|.|.|.|.|.|
	 ^
	 \end
	 \start
	 \buf
	 size = 16
	 len = (end - start) = 0

	Buffer with data:

     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	|.|.|a|b|c|d|e|f|g|h|i|j|.|.|.|.|
	 ^   ^                   ^
	 |   |                   \end
	 |   \start
	 \buf
	size = 16
	len = (end - start) = 10

	Read from start pointer
	Write to end pointer
*/
typedef struct {
	unsigned char	*buf;	/* Pointer to the start of the buffer */
	unsigned char	*start;	/* Pointer to start of valid data */
	unsigned char	*end;	/* Pointer to first byte of invalid data */
	int		size;			/* Size of buffer in bytes */
} sslBuf_t;
#endif

typedef struct {
	unsigned short	len;
	unsigned char	majVer;
	unsigned char	minVer;
	unsigned char	type;
	unsigned char	pad[3];		/* Padding for 64 bit compat */
} sslRec_t;

typedef struct {
	unsigned char	clientRandom[SSL_HS_RANDOM_SIZE];	/* From ClientHello */
	unsigned char	serverRandom[SSL_HS_RANDOM_SIZE];	/* From ServerHello */
	unsigned char	premaster[SSL_HS_PREMASTER_SIZE];	/* From ClientKeyExchange */
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];

	unsigned char	*keyBlock;	/* Storage for the next six items */
	unsigned char	*wMACptr;
	unsigned char	*rMACptr;
	unsigned char	*wKeyptr;
	unsigned char	*rKeyptr;
	unsigned char	*wIVptr;
	unsigned char	*rIVptr;

	/*	All maximum sizes for current cipher suites */
	unsigned char	writeMAC[SSL_MAX_MAC_SIZE];
	unsigned char	readMAC[SSL_MAX_MAC_SIZE];
	unsigned char	writeKey[SSL_MAX_SYM_KEY_SIZE];
	unsigned char	readKey[SSL_MAX_SYM_KEY_SIZE];
	unsigned char	writeIV[SSL_MAX_IV_SIZE];
	unsigned char	readIV[SSL_MAX_IV_SIZE];

	unsigned char	seq[8];
	unsigned char	remSeq[8];

#ifdef USE_CLIENT_SIDE_SSL
	sslRsaCert_t	*cert;
	int (*validateCert)(sslCertInfo_t *certInfo, void *arg);
	void			*validateCertArg;
#endif /* USE_CLIENT_SIDE_SSL */

	sslMd5Context_t		msgHashMd5;
	sslSha1Context_t	msgHashSha1;

	sslCipherContext_t	encryptCtx;
	sslCipherContext_t	decryptCtx;
} sslSec_t;

typedef struct {
	unsigned int	id;
	unsigned char	macSize;
	unsigned char	keySize;
	unsigned char	ivSize;
	unsigned char	blockSize;
	/* Init function */
	int (*init)(sslSec_t *sec, int type);
	/* Cipher functions */
	int (*encrypt)(sslCipherContext_t *ctx, unsigned char *in,
		unsigned char *out, int len);
	int (*decrypt)(sslCipherContext_t *ctx, unsigned char *in,
		unsigned char *out, int len);
	int (*encryptPub)(sslRsaKey_t *key, unsigned char *in, int inlen,
		unsigned char *out, 
		int outlen);
	int (*decryptPriv)(sslRsaKey_t *key, unsigned char *in, int inlen,
		unsigned char *out, 
		int outlen);
	int (*generateMac)(void *ssl, unsigned char type, unsigned char *data,
		int len, unsigned char *mac);
	int (*verifyMac)(void *ssl, unsigned char type, unsigned char *data,
		int len, unsigned char *mac);
} sslCipherSpec_t;

typedef struct sslLocalCert {
	sslRsaKey_t			*privKey;
	unsigned char		*certBin;
	unsigned int		certLen;
	struct sslLocalCert	*next;
} sslLocalCert_t;

typedef struct {
	sslLocalCert_t		cert;
#ifdef USE_CLIENT_SIDE_SSL
	sslRsaCert_t		*caCerts;
#endif /* USE_CLIENT_SIDE_SSL */
} sslKeys_t;

typedef struct ssl {
	sslRec_t		rec;			/* Current SSL record information*/
									
	sslSec_t		sec;			/* Security structure */

	sslKeys_t		*keys;			/* SSL public and private keys */

	unsigned char	sessionIdLen;
	char			sessionId[SSL_MAX_SESSION_ID_SIZE];

	/* Pointer to the negotiated cipher information */
	sslCipherSpec_t	*cipher;

	/* 	Symmetric cipher callbacks

		We duplicate these here from 'cipher' because we need to set the
		various callbacks at different times in the handshake protocol
		Also, there are 64 bit alignment issues in using the function pointers
		within 'cipher' directly
	*/
	int (*encrypt)(sslCipherContext_t *ctx, unsigned char *in,
		unsigned char *out, int len);
	int (*decrypt)(sslCipherContext_t *ctx, unsigned char *in,
		unsigned char *out, int len);
	/* Public key ciphers */
	int (*encryptPub)(sslRsaKey_t *key, unsigned char *in, int inlen,
		unsigned char *out, int outlen);
	int (*decryptPriv)(sslRsaKey_t *key, unsigned char *in, int inlen,
		unsigned char *out, int outlen);
	/* Message Authentication Codes */
	int (*generateMac)(void *ssl, unsigned char type, unsigned char *data,
		int len, unsigned char *mac);
	int (*verifyMac)(void *ssl, unsigned char type, unsigned char *data,
		int len, unsigned char *mac);

	/* Current encryption/decryption parameters */
	unsigned char	enMacSize;
	unsigned char	enIvSize;
	unsigned char	enBlockSize;
	unsigned char	deMacSize;
	unsigned char	deIvSize;
	unsigned char	deBlockSize;

	int				flags;
	int				hsState;		/* Next expected handshake message type */
	int				err;			/* SSL errno of last api call */
	int				ignoredMessageCount;

	unsigned char	reqMajVer;
	unsigned char	reqMinVer;
	unsigned char	majVer;
	unsigned char	minVer;
	int				recordHeadLen;
	int				hshakeHeadLen;
} ssl_t;

typedef struct {
	unsigned char	id[SSL_MAX_SESSION_ID_SIZE];
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	unsigned int	cipherId;
} sslSessionId_t;

typedef struct {
	unsigned char	id[SSL_MAX_SESSION_ID_SIZE];
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	sslCipherSpec_t	*cipher;
	unsigned char	majVer;
	unsigned char	minVer;
	sslTime_t		startTime;
	sslTime_t		accessTime;
	int				inUse;
} sslSessionEntry_t;

/*
	Include the public header here to define the public api calls
	and public defines used internally.
	Some of the types in the public header are duplicately defined, but
	they are predicated on _h_MATRIXINTERNAL, which is defined by this file.
*/
#include "../matrixSsl.h"

/******************************************************************************/
/*
	No file system
*/
extern int matrixSslReadKeysMem(sslKeys_t **keys, char *certBuf, int certLen, 
								char *privBuf, int privLen, char *privPass,
								char *trustedCABuf, int trustedCALen);
/******************************************************************************/
/*
	sslEncode.c and sslDecode.c
*/
extern int psWriteRecordInfo(ssl_t *ssl, unsigned char type, int len,
							 unsigned char *c);
extern int psWriteHandshakeHeader(ssl_t *ssl, unsigned char type, int len, 
								int seq, int fragOffset, int fragLen,
								unsigned char *c);
extern int sslEncodeResponse(ssl_t *ssl, sslBuf_t *out);
extern int sslActivateReadCipher(ssl_t *ssl);
extern int sslActivateWriteCipher(ssl_t *ssl);
extern int sslActivatePublicCipher(ssl_t *ssl);
extern int sslUpdateHSHash(ssl_t *ssl, unsigned char *in, int len);
extern int sslInitHSHash(ssl_t *ssl);
extern int sslSnapshotHSHash(ssl_t *ssl, unsigned char *out, int senderFlag);

extern void sslResetContext(ssl_t *ssl);

#ifdef USE_SERVER_SIDE_SSL
extern int matrixRegisterSession(ssl_t *ssl);
extern int matrixResumeSession(ssl_t *ssl);
extern int matrixClearSession(ssl_t *ssl, int remove);
extern int matrixUpdateSession(ssl_t *ssl);
#endif /* USE_SERVER_SIDE_SSL */


/*
	cipherSuite.c
*/
extern sslCipherSpec_t *sslGetCipherSpec(int id);
extern int sslGetCipherSpecListLen();
extern int sslGetCipherSpecList(unsigned char *c, int len);

/******************************************************************************/
/*
	sslv3.c
*/
extern int sslGenerateFinishedHash(sslMd5Context_t *md5, sslSha1Context_t *sha1,
								unsigned char *masterSecret,
								unsigned char *out, int sender);

extern int sslDeriveKeys(ssl_t *ssl);

#ifdef USE_SHA1_MAC
extern int ssl3HMACSha1(unsigned char *key, unsigned char *seq, 
						unsigned char type, unsigned char *data, int len,
						unsigned char *mac);
#endif /* USE_SHA1_MAC */

#ifdef USE_MD5_MAC
extern int ssl3HMACMd5(unsigned char *key, unsigned char *seq, 
						unsigned char type, unsigned char *data, int len,
						unsigned char *mac);
#endif /* USE_MD5_MAC */


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _h_MATRIXINTERNAL */

/******************************************************************************/



