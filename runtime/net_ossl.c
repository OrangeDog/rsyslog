/* net.c
 * Implementation of network-related stuff.
 *
 * File begun on 2023-08-29 by Alorbach (extracted from net.c)
 *
 * Copyright 2023 Andre Lorbach and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <strings.h>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "rsyslog.h"
#include "syslogd-types.h"
#include "module-template.h"
#include "parse.h"
#include "srUtils.h"
#include "obj.h"
#include "errmsg.h"
#include "net_ossl.h"
#include "prop.h"
#include "rsconf.h"

// MODULE_TYPE_LIB
// MODULE_TYPE_NOKEEP

/* static data */
DEFobjStaticHelpers
DEFobjCurrIf(glbl)

/*--------------------------------------MT OpenSSL helpers ------------------------------------------*/
static MUTEX_TYPE *mutex_buf = NULL;
static sbool openssl_initialized = 0; // Avoid multiple initialization / deinitialization

void locking_function(int mode, int n,
	__attribute__((unused)) const char * file, __attribute__((unused)) int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}


struct CRYPTO_dynlock_value * dyn_create_function(
	__attribute__((unused)) const char *file, __attribute__((unused)) int line)
{
	struct CRYPTO_dynlock_value *value;
	value = (struct CRYPTO_dynlock_value *)malloc(sizeof(struct CRYPTO_dynlock_value));
	if (!value)
		return NULL;

	MUTEX_SETUP(value->mutex);
	return value;
}

void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
	__attribute__((unused)) const char *file, __attribute__((unused)) int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(l->mutex);
	else
		MUTEX_UNLOCK(l->mutex);
}

void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
	__attribute__((unused)) const char *file, __attribute__((unused)) int line)
{
	MUTEX_CLEANUP(l->mutex);
	free(l);
}

/* set up support functions for openssl multi-threading. This must
 * be done at library initialisation. If the function fails,
 * processing can not continue normally. On failure, 0 is
 * returned, on success 1.
 */
int opensslh_THREAD_setup(void)
{
	int i;
	if (openssl_initialized == 1) {
		DBGPRINTF("openssl: multithread setup already initialized\n");
		return 1;
	}

	mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks( ) * sizeof(MUTEX_TYPE));
	if (mutex_buf == NULL)
		return 0;
	for (i = 0; i < CRYPTO_num_locks( ); i++)
		MUTEX_SETUP(mutex_buf[i]);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_set_id_callback(id_function);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	CRYPTO_set_locking_callback(locking_function);
	/* The following three CRYPTO_... functions are the OpenSSL functions
	for registering the callbacks we implemented above */
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);

	DBGPRINTF("openssl: multithread setup finished\n");
	openssl_initialized = 1;
	return 1;
}

/* shut down openssl - do this only when you are totally done
 * with openssl.
 */
int opensslh_THREAD_cleanup(void)
{
	int i;
	if (openssl_initialized == 0) {
		DBGPRINTF("openssl: multithread cleanup already done\n");
		return 1;
	}
	if (!mutex_buf)
		return 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_set_id_callback(NULL);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	for (i = 0; i < CRYPTO_num_locks( ); i++)
		MUTEX_CLEANUP(mutex_buf[i]);

	free(mutex_buf);
	mutex_buf = NULL;

	DBGPRINTF("openssl: multithread cleanup finished\n");
	openssl_initialized = 0;
	return 1;
}
/*-------------------------------------- MT OpenSSL helpers -----------------------------------------*/


/*--------------------------------------OpenSSL helpers ------------------------------------------*/

/* globally initialize OpenSSL
 */
void
osslGlblInit(void)
{
	DBGPRINTF("openssl: entering osslGlblInit\n");

	if((opensslh_THREAD_setup() == 0) ||
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		/* Setup OpenSSL library  < 1.1.0 */
		!SSL_library_init()
#else
		/* Setup OpenSSL library >= 1.1.0 with system default settings */
		OPENSSL_init_ssl(0, NULL) == 0
#endif
		) {
		LogError(0, RS_RET_NO_ERRCODE, "Error: OpenSSL initialization failed!");
	}

	/* Load readable error strings */
	SSL_load_error_strings();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	/*
	* ERR_load_*(), ERR_func_error_string(), ERR_get_error_line(), ERR_get_error_line_data(), ERR_get_state()
	* OpenSSL now loads error strings automatically so these functions are not needed.
	* SEE FOR MORE:
	*	https://www.openssl.org/docs/manmaster/man7/migration_guide.html
	*
	*/
#else
	/* Load error strings into mem*/
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
#endif
}

/* globally de-initialize OpenSSL */
void
osslGlblExit(void)
{
	DBGPRINTF("openssl: entering osslGlblExit\n");
	ENGINE_cleanup();
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}


/* initialize openssl context; called on
 * - listener creation
 * - outbound connection creation
 * Once created, the ctx object is used by-subobjects (accepted inbound connections)
 */
static rsRetVal
net_ossl_osslCtxInit(net_ossl_t *pThis, const SSL_METHOD *method)
{
	DEFiRet;
	int bHaveCA;
	int bHaveCRL;
	int bHaveCert;
	int bHaveKey;
	int bHaveExtraCAFiles;
	const char *caFile, *crlFile, *certFile, *keyFile;
	char *extraCaFiles, *extraCaFile;
	/* Setup certificates */
	caFile = (char*) ((pThis->pszCAFile == NULL) ? glbl.GetDfltNetstrmDrvrCAF(runConf) : pThis->pszCAFile);
	if(caFile == NULL) {
		LogMsg(0, RS_RET_CA_CERT_MISSING, LOG_WARNING,
			"Warning: CA certificate is not set");
		bHaveCA = 0;
	} else {
		dbgprintf("osslCtxInit: OSSL CA file: '%s'\n", caFile);
		bHaveCA	= 1;
	}
	crlFile = (char*) ((pThis->pszCRLFile == NULL) ? glbl.GetDfltNetstrmDrvrCRLF(runConf) : pThis->pszCRLFile);
	if(crlFile == NULL) {
		bHaveCRL = 0;
	} else {
		dbgprintf("osslCtxInit: OSSL CRL file: '%s'\n", crlFile);
		bHaveCRL = 1;
	}
	certFile = (char*) ((pThis->pszCertFile == NULL) ?
		glbl.GetDfltNetstrmDrvrCertFile(runConf) : pThis->pszCertFile);
	if(certFile == NULL) {
		LogMsg(0, RS_RET_CERT_MISSING, LOG_WARNING,
			"Warning: Certificate file is not set");
		bHaveCert = 0;
	} else {
		dbgprintf("osslCtxInit: OSSL CERT file: '%s'\n", certFile);
		bHaveCert = 1;
	}
	keyFile = (char*) ((pThis->pszKeyFile == NULL) ? glbl.GetDfltNetstrmDrvrKeyFile(runConf) : pThis->pszKeyFile);
	if(keyFile == NULL) {
		LogMsg(0, RS_RET_CERTKEY_MISSING, LOG_WARNING,
			"Warning: Key file is not set");
		bHaveKey = 0;
	} else {
		dbgprintf("osslCtxInit: OSSL KEY file: '%s'\n", keyFile);
		bHaveKey = 1;
	}
	extraCaFiles = (char*) ((pThis->pszExtraCAFiles == NULL) ? glbl.GetNetstrmDrvrCAExtraFiles(runConf) :
				pThis->pszExtraCAFiles);
	if(extraCaFiles == NULL) {
		bHaveExtraCAFiles = 0;
	} else {
		dbgprintf("osslCtxInit: OSSL EXTRA CA files: '%s'\n", extraCaFiles);
	        bHaveExtraCAFiles = 1;
	}

	/* Create main CTX Object based on method parameter */
	pThis->ctx = SSL_CTX_new(method);

	if(bHaveExtraCAFiles == 1) {
		while((extraCaFile = strsep(&extraCaFiles, ","))) {
			if(SSL_CTX_load_verify_locations(pThis->ctx, extraCaFile, NULL) != 1) {
				LogError(0, RS_RET_TLS_CERT_ERR, "Error: Extra Certificate file could not be accessed. "
					"Check at least: 1) file path is correct, 2) file exist, "
					"3) permissions are correct, 4) file content is correct. "
					"OpenSSL error info may follow in next messages");
				net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "SSL_CTX_load_verify_locations");
				ABORT_FINALIZE(RS_RET_TLS_CERT_ERR);
			}
		}
	}
	if(bHaveCA == 1 && SSL_CTX_load_verify_locations(pThis->ctx, caFile, NULL) != 1) {
		LogError(0, RS_RET_TLS_CERT_ERR, "Error: CA certificate could not be accessed. "
				"Check at least: 1) file path is correct, 2) file exist, "
				"3) permissions are correct, 4) file content is correct. "
				"OpenSSL error info may follow in next messages");
		net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "SSL_CTX_load_verify_locations");
		ABORT_FINALIZE(RS_RET_TLS_CERT_ERR);
	}
	if(bHaveCRL == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		// Get X509_STORE reference
		X509_STORE *store = SSL_CTX_get_cert_store(pThis->ctx);
		if (!X509_STORE_load_file(store, crlFile)) {
			LogError(0, RS_RET_CRL_INVALID, "Error: CRL could not be accessed. "
					"Check at least: 1) file path is correct, 2) file exist, "
					"3) permissions are correct, 4) file content is correct. "
					"OpenSSL error info may follow in next messages");
			net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "X509_STORE_load_file");
			ABORT_FINALIZE(RS_RET_CRL_INVALID);
		}
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
#else
#	if OPENSSL_VERSION_NUMBER >= 0x10002000L
		// Get X509_STORE reference
		X509_STORE *store = SSL_CTX_get_cert_store(pThis->ctx);
		// Load the CRL PEM file
		FILE *fp = fopen(crlFile, "r");
		if(fp == NULL) {
			LogError(0, RS_RET_CRL_MISSING, "Error: CRL could not be accessed. "
					"Check at least: 1) file path is correct, 2) file exist, "
					"3) permissions are correct, 4) file content is correct. "
					"OpenSSL error info may follow in next messages");
			net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "fopen");
			ABORT_FINALIZE(RS_RET_CRL_MISSING);
		}
		X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		fclose(fp);
		if(crl == NULL) {
			LogError(0, RS_RET_CRL_INVALID, "Error: Unable to read CRL."
					"OpenSSL error info may follow in next messages");
			net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "PEM_read_X509_CRL");
			ABORT_FINALIZE(RS_RET_CRL_INVALID);
		}
		// Add the CRL to the X509_STORE
		if(!X509_STORE_add_crl(store, crl)) {
			LogError(0, RS_RET_CRL_INVALID, "Error: Unable to add CRL to store."
					"OpenSSL error info may follow in next messages");
			net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "X509_STORE_add_crl");
			X509_CRL_free(crl);
			ABORT_FINALIZE(RS_RET_CRL_INVALID);
		}
		// Set the X509_STORE to the SSL_CTX
		// SSL_CTX_set_cert_store(pThis->ctx, store);
		// Enable CRL checking
		X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
		SSL_CTX_set1_param(pThis->ctx, param);
		X509_VERIFY_PARAM_free(param);
#	else
		LogError(0, RS_RET_SYS_ERR, "Warning: TLS library does not support X509_STORE_load_file"
			"(requires OpenSSL 3.x or higher). Cannot use Certificate revocation list (CRL) '%s'.",
			crlFile);
#	endif
#endif
	}
	if(bHaveCert == 1 && SSL_CTX_use_certificate_chain_file(pThis->ctx, certFile) != 1) {
		LogError(0, RS_RET_TLS_CERT_ERR, "Error: Certificate file could not be accessed. "
				"Check at least: 1) file path is correct, 2) file exist, "
				"3) permissions are correct, 4) file content is correct. "
				"OpenSSL error info may follow in next messages");
		net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "SSL_CTX_use_certificate_chain_file");
		ABORT_FINALIZE(RS_RET_TLS_CERT_ERR);
	}
	if(bHaveKey == 1 && SSL_CTX_use_PrivateKey_file(pThis->ctx, keyFile, SSL_FILETYPE_PEM) != 1) {
		LogError(0, RS_RET_TLS_KEY_ERR , "Error: Key could not be accessed. "
				"Check at least: 1) file path is correct, 2) file exist, "
				"3) permissions are correct, 4) file content is correct. "
				"OpenSSL error info may follow in next messages");
		net_ossl_handle_lastOpenSSLErrorMsg(0, NULL, LOG_ERR, "osslCtxInit", "SSL_CTX_use_PrivateKey_file");
		ABORT_FINALIZE(RS_RET_TLS_KEY_ERR);
	}

	/* Set CTX Options */
	SSL_CTX_set_options(pThis->ctx, SSL_OP_NO_SSLv2);		/* Disable insecure SSLv2 Protocol */
	SSL_CTX_set_options(pThis->ctx, SSL_OP_NO_SSLv3);		/* Disable insecure SSLv3 Protocol */
	SSL_CTX_sess_set_cache_size(pThis->ctx,1024);			/* TODO: make configurable? */

	/* Set default VERIFY Options for OpenSSL CTX - and CALLBACK */
	net_ossl_set_ctx_verify_callback(pThis->ctx, SSL_VERIFY_NONE);

	SSL_CTX_set_timeout(pThis->ctx, 30);	/* Default Session Timeout, TODO: Make configureable */
	SSL_CTX_set_mode(pThis->ctx, SSL_MODE_AUTO_RETRY);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#	if OPENSSL_VERSION_NUMBER <= 0x101010FFL
	/* Enable Support for automatic EC temporary key parameter selection. */
	SSL_CTX_set_ecdh_auto(pThis->ctx, 1);
#	else
	/*
	* SSL_CTX_set_ecdh_auto and SSL_CTX_set_tmp_ecdh are depreceated in higher
	* OpenSSL Versions, so we no more need them - see for more:
	* https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_ecdh_auto.html
	*/
#	endif
#else
	dbgprintf("osslCtxInit: openssl to old, cannot use SSL_CTX_set_ecdh_auto."
		"Using SSL_CTX_set_tmp_ecdh with NID_X9_62_prime256v1/() instead.\n");
	SSL_CTX_set_tmp_ecdh(pThis->ctx, EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
#endif
finalize_it:
	RETiRet;
}

/* Helper function to print usefull OpenSSL errors
 */
void net_ossl_handle_lastOpenSSLErrorMsg
	(int ret, SSL *ssl, int severity, const char* pszCallSource, const char* pszOsslApi)
{
	unsigned long un_error = 0;
	int iSSLErr = 0;
	if (ssl == NULL) {
		/* Output Error Info*/
		DBGPRINTF("osslLastSSLErrorMsg: Error in '%s' with ret=%d\n", pszCallSource, ret);
	} else {
		/* if object is set, get error code */
		iSSLErr = SSL_get_error(ssl, ret);
		/* Output Debug as well */
		DBGPRINTF("osslLastSSLErrorMsg: %s Error in '%s': '%s(%d)' with ret=%d, errno=%d, sslapi='%s'\n",
			(iSSLErr == SSL_ERROR_SSL ? "SSL_ERROR_SSL" :
			(iSSLErr == SSL_ERROR_SYSCALL ? "SSL_ERROR_SYSCALL" : "SSL_ERROR_UNKNOWN")),
			pszCallSource, ERR_error_string(iSSLErr, NULL),
			iSSLErr,
			ret,
			errno,
			pszOsslApi);

		/* Output error message */
		LogMsg(0, RS_RET_NO_ERRCODE, severity,
			"%s Error in '%s': '%s(%d)' with ret=%d, errno=%d, sslapi='%s'\n",
			(iSSLErr == SSL_ERROR_SSL ? "SSL_ERROR_SSL" :
			(iSSLErr == SSL_ERROR_SYSCALL ? "SSL_ERROR_SYSCALL" : "SSL_ERROR_UNKNOWN")),
			pszCallSource, ERR_error_string(iSSLErr, NULL),
			iSSLErr,
			ret,
			errno,
			pszOsslApi);
	}

	/* Loop through ERR_get_error */
	while ((un_error = ERR_get_error()) > 0){
		LogMsg(0, RS_RET_NO_ERRCODE, severity,
			"net_ossl:OpenSSL Error Stack: %s", ERR_error_string(un_error, NULL) );
	}
}

/* Verify Callback for X509 Certificate validation. Force visibility as this function is not called anywhere but
   only used as callback!
 */
static int 
verify_callback(int status, X509_STORE_CTX *store)
{
	char szdbgdata1[256];
	char szdbgdata2[256];

	dbgprintf("verify_callback: status %d\n", status);

	if(status == 0) {
		/* Retrieve all needed pointers */
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);
		SSL* ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
		int iVerifyMode = SSL_get_verify_mode(ssl);
		// net_ossl_t *pThis = (net_ossl_t*) SSL_get_ex_data(ssl, 0);
		PermitExpiredCerts *pPermitExpiredCerts = (PermitExpiredCerts*) SSL_get_ex_data(ssl, 0);

		assert(pPermitExpiredCerts != NULL);

		dbgprintf("verify_callback: Certificate validation failed, Mode (%d)!\n", iVerifyMode);

		X509_NAME_oneline(X509_get_issuer_name(cert), szdbgdata1, sizeof(szdbgdata1));
		X509_NAME_oneline(RSYSLOG_X509_NAME_oneline(cert), szdbgdata2, sizeof(szdbgdata2));

		if (iVerifyMode != SSL_VERIFY_NONE) {
			/* Handle expired Certificates **/
			if (err == X509_V_OK || err == X509_V_ERR_CERT_HAS_EXPIRED) {
				if (pPermitExpiredCerts == OSSL_EXPIRED_PERMIT) {
					dbgprintf("verify_callback: EXPIRED cert but PERMITTED at depth: %d \n\t"
						"issuer  = %s\n\t"
						"subject = %s\n\t"
						"err %d:%s\n", depth, szdbgdata1, szdbgdata2,
						err, X509_verify_cert_error_string(err));

					/* Set Status to OK*/
					status = 1;
				}
				else if (*pPermitExpiredCerts == OSSL_EXPIRED_WARN) {
					LogMsg(0, RS_RET_CERT_EXPIRED, LOG_WARNING,
						"Certificate EXPIRED warning at depth: %d \n\t"
						"issuer  = %s\n\t"
						"subject = %s\n\t"
						"err %d:%s",
						depth, szdbgdata1, szdbgdata2,
						err, X509_verify_cert_error_string(err));

					/* Set Status to OK*/
					status = 1;
				}
				else /* also default - if (pPermitExpiredCerts == OSSL_EXPIRED_DENY)*/ {
					LogMsg(0, RS_RET_CERT_EXPIRED, LOG_ERR,
						"Certificate EXPIRED at depth: %d \n\t"
						"issuer  = %s\n\t"
						"subject = %s\n\t"
						"err %d:%s\n\t"
						"not permitted to talk to peer, certificate invalid: "
						"certificate expired",
						depth, szdbgdata1, szdbgdata2,
						err, X509_verify_cert_error_string(err));
				}
			} else if (err == X509_V_ERR_CERT_REVOKED) {
				LogMsg(0, RS_RET_CERT_REVOKED, LOG_ERR,
					"Certificate REVOKED at depth: %d \n\t"
					"issuer  = %s\n\t"
					"subject = %s\n\t"
					"err %d:%s\n\t"
					"not permitted to talk to peer, certificate invalid: "
					"certificate revoked",
					depth, szdbgdata1, szdbgdata2,
					err, X509_verify_cert_error_string(err));
			} else {
				/* all other error codes cause failure */
				LogMsg(0, RS_RET_NO_ERRCODE, LOG_ERR,
					"Certificate error at depth: %d \n\t"
					"issuer  = %s\n\t"
					"subject = %s\n\t"
					"err %d:%s",
					depth, szdbgdata1, szdbgdata2,
					err, X509_verify_cert_error_string(err));
			}
		} else {
			/* do not verify certs in ANON mode, just log into debug */
			dbgprintf("verify_callback: Certificate validation DISABLED but Error at depth: %d \n\t"
				"issuer  = %s\n\t"
				"subject = %s\n\t"
				"err %d:%s\n", depth, szdbgdata1, szdbgdata2,
				err, X509_verify_cert_error_string(err));

			/* Set Status to OK*/
			status = 1;
		}
	}

	return status;
}


#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
static long
RSYSLOG_BIO_debug_callback_ex(BIO *bio, int cmd, const char __attribute__((unused)) *argp,
			   size_t __attribute__((unused)) len, int argi, long __attribute__((unused)) argl,
			   int ret, size_t __attribute__((unused)) *processed)
#else
static long
RSYSLOG_BIO_debug_callback(BIO *bio, int cmd, const char __attribute__((unused)) *argp,
			int argi, long __attribute__((unused)) argl, long ret)
#endif
{
	long ret2 = ret; // Helper value to avoid printf compile errors long<>int
	long r = 1;	
	if (BIO_CB_RETURN & cmd)
		r = ret;
	dbgprintf("openssl debugmsg: BIO[%p]: ", (void *)bio);
	switch (cmd) {
	case BIO_CB_FREE:
		dbgprintf("Free - %s\n", RSYSLOG_BIO_method_name(bio));
		break;
/* Disabled due API changes for OpenSSL 1.1.0+ */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	case BIO_CB_READ:
		if (bio->method->type & BIO_TYPE_DESCRIPTOR)
			dbgprintf("read(%d,%lu) - %s fd=%d\n",
				RSYSLOG_BIO_number_read(bio), (unsigned long)argi,
				RSYSLOG_BIO_method_name(bio), RSYSLOG_BIO_number_read(bio));
		else
			dbgprintf("read(%d,%lu) - %s\n", RSYSLOG_BIO_number_read(bio),
					(unsigned long)argi, RSYSLOG_BIO_method_name(bio));
		break;
	case BIO_CB_WRITE:
		if (bio->method->type & BIO_TYPE_DESCRIPTOR)
			dbgprintf("write(%d,%lu) - %s fd=%d\n",
				RSYSLOG_BIO_number_written(bio), (unsigned long)argi,
				RSYSLOG_BIO_method_name(bio), RSYSLOG_BIO_number_written(bio));
		else
			dbgprintf("write(%d,%lu) - %s\n",
					RSYSLOG_BIO_number_written(bio),
					(unsigned long)argi,
					RSYSLOG_BIO_method_name(bio));
		break;
#else
	case BIO_CB_READ:
		dbgprintf("read %s\n", RSYSLOG_BIO_method_name(bio));
		break;
	case BIO_CB_WRITE:
		dbgprintf("write %s\n", RSYSLOG_BIO_method_name(bio));
		break;
#endif
	case BIO_CB_PUTS:
		dbgprintf("puts() - %s\n", RSYSLOG_BIO_method_name(bio));
		break;
	case BIO_CB_GETS:
		dbgprintf("gets(%lu) - %s\n", (unsigned long)argi,
			RSYSLOG_BIO_method_name(bio));
		break;
	case BIO_CB_CTRL:
		dbgprintf("ctrl(%lu) - %s\n", (unsigned long)argi,
			RSYSLOG_BIO_method_name(bio));
		break;
	case BIO_CB_RETURN | BIO_CB_READ:
		dbgprintf("read return %ld\n", ret2);
		break;
	case BIO_CB_RETURN | BIO_CB_WRITE:
		dbgprintf("write return %ld\n", ret2);
		break;
	case BIO_CB_RETURN | BIO_CB_GETS:
		dbgprintf("gets return %ld\n", ret2);
		break;
	case BIO_CB_RETURN | BIO_CB_PUTS:
		dbgprintf("puts return %ld\n", ret2);
		break;
	case BIO_CB_RETURN | BIO_CB_CTRL:
		dbgprintf("ctrl return %ld\n", ret2);
		break;
	default:
		dbgprintf("bio callback - unknown type (%d)\n", cmd);
		break;
	}

	return (r);
}
/* ------------------------------ end OpenSSL helpers ------------------------------------------*/

/* ------------------------------ OpenSSL Callback set helpers ---------------------------------*/
void
net_ossl_set_ssl_verify_callback(SSL *pSsl, int flags)
{
	/* Enable certificate valid checking */
	SSL_set_verify(pSsl, flags, verify_callback);
}

void
net_ossl_set_ctx_verify_callback(SSL_CTX *pCtx, int flags)
{
	/* Enable certificate valid checking */
	SSL_CTX_set_verify(pCtx, flags, verify_callback);
}

void
net_ossl_set_bio_callback(BIO *conn)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	BIO_set_callback_ex(conn, RSYSLOG_BIO_debug_callback_ex);
#else
	BIO_set_callback(conn, RSYSLOG_BIO_debug_callback);
#endif
}
/* ------------------------------ End OpenSSL Callback set helpers -----------------------------*/


/* Standard-Constructor */
BEGINobjConstruct(net_ossl) /* be sure to specify the object type also in END macro! */
	DBGPRINTF("net_ossl_construct: [%p]\n", pThis);
//	iRet = nsd_ptcp.Construct(&pThis->pTcp);
//	pThis->bReportAuthErr = 1;
ENDobjConstruct(net_ossl)

/* destructor for the net_ossl object */
// PROTOTYPEobjDestruct(net_ossl);
BEGINobjDestruct(net_ossl) /* be sure to specify the object type also in END and CODESTART macros! */
CODESTARTobjDestruct(net_ossl)
	DBGPRINTF("net_ossl_destruct: [%p]\n", pThis);
	/* Free SSL obj also if we do not have a session - or are NOT in TLS mode! */
	if (pThis->ssl != NULL) {
		DBGPRINTF("net_ossl_destruct: [%p] FREE pThis->ssl \n", pThis);
		SSL_free(pThis->ssl);
		pThis->ssl = NULL;
	}
	if(pThis->ctx != NULL && !pThis->ctx_is_copy) {
		SSL_CTX_free(pThis->ctx);
	}
	free((void*) pThis->pszCAFile);
	free((void*) pThis->pszCRLFile);
	free((void*) pThis->pszKeyFile);
	free((void*) pThis->pszCertFile);
	free((void*) pThis->pszExtraCAFiles);
ENDobjDestruct(net_ossl)

/* queryInterface function */
BEGINobjQueryInterface(net_ossl)
CODESTARTobjQueryInterface(net_ossl)
	dbgprintf("netosslQueryInterface");
	if(pIf->ifVersion != net_osslCURR_IF_VERSION) {/* check for current version, increment on each change */
		ABORT_FINALIZE(RS_RET_INTERFACE_NOT_SUPPORTED);
	}
	pIf->Construct		= (rsRetVal(*)(net_ossl_t**)) net_osslConstruct;
	pIf->Destruct		= (rsRetVal(*)(net_ossl_t**)) net_osslDestruct;
	pIf->osslCtxInit	= net_ossl_osslCtxInit;
finalize_it:
ENDobjQueryInterface(net_ossl)


/* exit our class
 */
BEGINObjClassExit(net_ossl, OBJ_IS_CORE_MODULE) /* CHANGE class also in END MACRO! */
CODESTARTObjClassExit(net_ossl)
	dbgprintf("netosslClassExit");
	/* release objects we no longer need */
	objRelease(glbl, CORE_COMPONENT);
	/* shut down OpenSSL */
	osslGlblExit();
ENDObjClassExit(net_ossl)


/* Initialize the net_ossl class. Must be called as the very first method
 * before anything else is called inside this class.
 */
BEGINObjClassInit(net_ossl, 1, OBJ_IS_CORE_MODULE) /* class, version */
	dbgprintf("net_osslClassInit");
	// request objects we use
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	// now do global TLS init stuff
	osslGlblInit();
ENDObjClassInit(net_ossl)


/* --------------- here now comes the plumbing that makes as a library module --------------- */


/* vi:set ai:
 */