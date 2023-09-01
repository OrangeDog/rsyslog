/**
 * The dtls input module.
 *
 * \author  Andre Lorbach <alorbach@adiscon.com>
 *
 * Copyright (C) 2023 Adiscon GmbH.
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
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/errno.h>
#include <assert.h>
#include "rsyslog.h"
#include "dirty.h"
#include "module-template.h"
#include "cfsysline.h"
#include "msg.h"
#include "errmsg.h"
#include "glbl.h"
#include "srUtils.h"
#include "msg.h"
#include "parser.h"
#include "datetime.h"
#include "prop.h"
#include "ruleset.h"
#include "statsobj.h"
#include "net_ossl.h"
#include "unicode-helper.h"

// --- Include openssl headers as well
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
#	include <openssl/bioerr.h>
#endif
#include <openssl/engine.h>
// ---

MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("imdtls")

/* defines */
#define MAX_WRKR_THREADS 32
#define MAX_DTLS_CLIENTS 1024
#define MAX_DTLS_MSGSIZE 65536
#define DTLS_LISTEN_PORT "4433"


/* Module static data */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(datetime)
DEFobjCurrIf(prop)
DEFobjCurrIf(ruleset)
DEFobjCurrIf(statsobj)
DEFobjCurrIf(net_ossl)

#define DTLS_MAX_RCVBUF 1380 /* Maximum DTLS packet 1380 bytes to avoid fragmentation (smaller than the common Ethernet MTU of 1,500 bytes to accommodate potential IP and UDP headers). */

/* config settings */
typedef struct configSettings_s {
	uchar *pszBindRuleset;		/* name of Ruleset to bind to */
} configSettings_t;
static configSettings_t cs;


struct instanceConf_s {
	uchar *pszBindAddr;		/* Listening IP Address */
	uchar *pszBindPort;		/* Port to bind socket to */
	uchar *pszBindRuleset;		/* name of ruleset to bind to */
	uchar *pszInputName;
	prop_t *pInputName;		/* InputName in property format for fast access */
	ruleset_t *pBindRuleset;	/* ruleset to bind listener to (use system default if unspecified) */
	sbool bEnableLstn;		/* flag to permit disabling of listener in error case */
	statsobj_t *stats;		/* listener stats */
	STATSCOUNTER_DEF(ctrSubmit, mutCtrSubmit)

	AuthMode authMode;		/* authenticate peer if no other name given */
	uchar *tlscfgcmd;		/* OpenSSL Config Command used to override any OpenSSL Settings */
	struct {
		int nmemb;
		uchar **name;
	} permittedPeers;

	int bHaveSess;			/* True if DTLS session is established */
	permittedPeers_t *pPermPeers;	/* permitted peers */
	int DrvrVerifyDepth;		/* Verify Depth for certificate chains */

	char *pszRcvBuf;
	int lenRcvBuf;
	/**< -1: empty, 0: connection closed, 1..NSD_OSSL_MAX_RCVBUF-1: data of that size present */
	int ptrRcvBuf;				/**< offset for next recv operation if 0 < lenRcvBuf < NSD_OSSL_MAX_RCVBUF */

	/* OpenSSL and Config Cert vars inside net_ossl_t now */
	net_ossl_t *pNetOssl;			/* OSSL shared Config and object vars are here */
	SSL *sslClients[MAX_DTLS_CLIENTS];	/* Client List of DTSL Clients, TODO Make dynamic with limit */
	int sockfd;				/* UDP Socket used to bind to */

	int id;				/* Thread ID */
	thrdInfo_t *pThrd;		/* Thread Instance Info */
	pthread_t tid;			/* the instances thread ID */

	struct instanceConf_s *next;
	struct instanceConf_s *prev;
};

/* config variables */
struct modConfData_s {
	rsconf_t *pConf;		/* our overall config object */
	instanceConf_t *root, *tail;
	const char *tlslib;
	uchar *pszBindRuleset;		/* default name of Ruleset to bind to */
	AuthMode drvrAuthMode;		/* authenticate peer if no other name given */
};

static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current load process */

static prop_t *pInputName = NULL;

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "ruleset", eCmdHdlrGetWord, 0 },
	{ "tls.authmode", eCmdHdlrString, 0 },
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
	{ "port", eCmdHdlrString, CNFPARAM_REQUIRED },
	{ "address", eCmdHdlrString, 0 },
	{ "name", eCmdHdlrString, 0 },
	{ "ruleset", eCmdHdlrString, 0 },
	{ "tls.permittedpeer", eCmdHdlrArray, 0 },
	{ "tls.authmode", eCmdHdlrString, 0 },
	{ "tls.cacert", eCmdHdlrString, 0 },
	{ "tls.mycert", eCmdHdlrString, 0 },
	{ "tls.myprivkey", eCmdHdlrString, 0 },
	{ "tls.tlscfgcmd", eCmdHdlrString, 0 }
};
static struct cnfparamblk inppblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(inppdescr)/sizeof(struct cnfparamdescr),
	  inppdescr
	};
#include "im-helper.h" /* must be included AFTER the type definitions! */

/* create input instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal
createInstance(instanceConf_t **pinst)
{
	instanceConf_t *inst;
	DEFiRet;
	CHKmalloc(inst = malloc(sizeof(instanceConf_t)));
	inst->next = NULL;

	inst->pszBindAddr = NULL;
	inst->pszBindPort = NULL;
	inst->pszBindRuleset = loadModConf->pszBindRuleset;
	inst->pszInputName = NULL;
	inst->pBindRuleset = NULL;
	inst->bEnableLstn = 0;

	inst->authMode = loadModConf->drvrAuthMode;
	inst->tlscfgcmd = NULL;
	inst->permittedPeers.nmemb = 0;

	/* node created, let's add to config */
	if(loadModConf->tail == NULL) {
		loadModConf->tail = loadModConf->root = inst;
	} else {
		loadModConf->tail->next = inst;
		loadModConf->tail = inst;
	}

	*pinst = inst;
finalize_it:
	RETiRet;
}


/* function to generate an error message if the ruleset cannot be found */
static inline void
std_checkRuleset_genErrMsg(__attribute__((unused)) modConfData_t *modConf, instanceConf_t *inst)
{
	LogError(0, NO_ERRCODE, "imdtls[%s]: ruleset '%s' not found - "
			"using default ruleset instead",
			inst->pszBindPort, inst->pszBindRuleset);
}

static rsRetVal
DTLSCreateSocket(instanceConf_t *inst) {
	DEFiRet;
	int optval = 1;
	int port = atoi((char*)inst->pszBindPort);
	struct in_addr ip_struct;

	// Create UDP Socket
	inst->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (inst->sockfd < 0) {
		LogError(0, NO_ERRCODE, "imdtls: Unable to create DTLS listener,"
				" failed to create socket, "
				" ignoring port %s bind-address %s.",
				inst->pszBindPort, inst->pszBindAddr);
		ABORT_FINALIZE(RS_RET_ERR);
	}
	setsockopt(inst->sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	// Set NON Blcoking Flags
	int flags = fcntl(inst->sockfd, F_GETFL, 0);
	fcntl(inst->sockfd, F_SETFL, flags | O_NONBLOCK);
	
	// Convert IP Address into numeric
	if (inet_pton(AF_INET, (char*) inst->pszBindAddr, &ip_struct) <= 0) {
		LogError(0, NO_ERRCODE, "imdtls: Unable to create DTLS listener,"
				" invalid Bind Address, "
				" ignoring port %s bind-address %s.",
				inst->pszBindPort, inst->pszBindAddr);
		ABORT_FINALIZE(RS_RET_ERR);
	}

	// Set Server Address
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = htonl(ip_struct.s_addr);

	if (bind(inst->sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		LogError(0, NO_ERRCODE, "imdtls: Unable to create DTLS listener,"
				" unable to bind, "
				" ignoring port %s bind-address %s.",
				inst->pszBindPort, inst->pszBindAddr);
		ABORT_FINALIZE(RS_RET_ERR);
	}
finalize_it:
	RETiRet;
}

static rsRetVal
addListner(modConfData_t __attribute__((unused)) *modConf, instanceConf_t *inst)
{
	uchar statname[64];
	DEFiRet;

	if(!inst->bEnableLstn) {
		DBGPRINTF("imdtls: DTLS Listener not started because it is disabled by config error\n");
		FINALIZE;
	}

	inst->pszInputName = ustrdup((inst->pszInputName == NULL) ?  UCHAR_CONSTANT("imrelp") : inst->pszInputName);
	CHKiRet(prop.Construct(&inst->pInputName));
	CHKiRet(prop.SetString(inst->pInputName, inst->pszInputName, ustrlen(inst->pszInputName)));
	CHKiRet(prop.ConstructFinalize(inst->pInputName));

	/* Init defaults */
	if (inst->pszBindPort == NULL) {
		CHKmalloc(inst->pszBindPort = ustrdup((uchar*) DTLS_LISTEN_PORT));
	}

	/* support statistics gathering */
	CHKiRet(statsobj.Construct(&(inst->stats)));
	snprintf((char*)statname, sizeof(statname), "%s(%s)",
		 inst->pszInputName, inst->pszBindPort);
	statname[sizeof(statname)-1] = '\0'; /* just to be on the save side... */
	CHKiRet(statsobj.SetName(inst->stats, statname));
	CHKiRet(statsobj.SetOrigin(inst->stats, (uchar*)"imrelp"));
	STATSCOUNTER_INIT(inst->ctrSubmit, inst->mutCtrSubmit);
	CHKiRet(statsobj.AddCounter(inst->stats, UCHAR_CONSTANT("submitted"),
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &(inst->ctrSubmit)));
	CHKiRet(statsobj.ConstructFinalize(inst->stats));
	/* end stats counters */

	// Construct pNetOssl helper
	CHKiRet(net_ossl.Construct(&inst->pNetOssl));

	// Init OpenSSL Context with DTLS_server_method
	CHKiRet(net_ossl.osslCtxInit(inst->pNetOssl, DTLS_method()));

	// Init Socket
	CHKiRet(DTLSCreateSocket(inst));

	DBGPRINTF("imdtls: DTLS Listener added\n");
finalize_it:
	RETiRet;
}

static rsRetVal
processMsg(instanceConf_t *inst, SSL *sslClient, char *msg, size_t lenMsg)
{
	DEFiRet;
	smsg_t *pMsg = NULL;
	prop_t *pProp = NULL;

	/* Get Gentime */
	time_t ttGenTime = 0;
	struct syslogTime stTime;
	datetime.getCurrTime(&stTime, &ttGenTime, TIME_IN_LOCALTIME);

	/* we now create our own message object and submit it to the queue */
	CHKiRet(msgConstructWithTime(&pMsg, &stTime, ttGenTime));
	MsgSetRawMsg(pMsg, msg, lenMsg);
	MsgSetInputName(pMsg, inst->pInputName);
	MsgSetRuleset(pMsg, inst->pBindRuleset);
	MsgSetFlowControlType(pMsg, eFLOWCTL_NO_DELAY);
	pMsg->msgFlags  = NEEDS_PARSING | PARSE_HOSTNAME;

	// Obtain Sender from BIO
	BIO *wbio = SSL_get_wbio(sslClient);
	BIO_ADDR *peer_addr = BIO_ADDR_new();
	if (BIO_dgram_get_peer(wbio, peer_addr)) {
		char *pHostname = BIO_ADDR_hostname_string(peer_addr, 1);
		printf("imdtls: processMsg Received message from %s: %s\n", pHostname, msg);
		MsgSetRcvFromStr(pMsg, (uchar *)pHostname, strlen(pHostname), &pProp);
		CHKiRet(prop.Destruct(&pProp));
		OPENSSL_free(pHostname);
	} else {
		printf("imdtls: processMsg Received message from UNKNOWN: %s\n", msg);
	}
	BIO_ADDR_free(peer_addr);
	
	// Submit Message
	CHKiRet(submitMsg2(pMsg));
	STATSCOUNTER_INC(inst->ctrSubmit, inst->mutCtrSubmit);
finalize_it:

	RETiRet;
}

static void
DTLSHandleSessions(instanceConf_t *inst) {
	fd_set readfds;
	DBGPRINTF("imdtls: Entering the DTLS session handling loop...\n");

	FD_ZERO(&readfds);
	FD_SET(inst->sockfd, &readfds);

	int max_fd = inst->sockfd;
	for (int i = 0; i < MAX_DTLS_CLIENTS; ++i) {
	    if (inst->sslClients[i] != NULL) {
		int fd = BIO_get_fd(SSL_get_wbio(inst->sslClients[i]), NULL);
		FD_SET(fd, &readfds);
		if (fd > max_fd) {
		    max_fd = fd;
		}
	    }
	}

	DBGPRINTF("imdtls: Waiting for select...\n");
	if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) {
	    perror("select");
	    return;
	}

	if (FD_ISSET(inst->sockfd, &readfds)) {
		// Potential new client
		BIO *bio = BIO_new_dgram(inst->sockfd, BIO_NOCLOSE);
		SSL *ssl = SSL_new(inst->pNetOssl->ctx);
		SSL_set_bio(ssl, bio, bio);
		BIO_ADDR *client_addr = BIO_ADDR_new();
		int new_client_added = 0;

		if (DTLSv1_listen(ssl, client_addr)) {
			for (int i = 0; i < MAX_DTLS_CLIENTS; ++i) {
				if (inst->sslClients[i] == NULL) {
					inst->sslClients[i] = ssl;
					new_client_added = 1;
					DBGPRINTF("imdtls: Client assigned to index %d.\n", i);
					break;
				}
			}

			/* set BIO to connected */
			if (!bio || BIO_connect(inst->sockfd, client_addr, 0) == 0) {
				printf("[ERROR] BIO_connect failed\n");
				ERR_print_errors_fp(stderr);
				BIO_ADDR_free(client_addr);
				return;
			} else {
				DBGPRINTF("imdtls: BIO_connect succeeded.\n");
			}
		} else {
			SSL_free(ssl);
		}
		BIO_ADDR_free(client_addr);

		if (new_client_added) {
			DBGPRINTF("imdtls: New client detected.\n");
		}
	}

	for (int i = 0; i < MAX_DTLS_CLIENTS; ++i) {
		if (inst->sslClients[i] == NULL) {
			return;
		}
		int fd = BIO_get_fd(SSL_get_wbio(inst->sslClients[i]), NULL);
		if (FD_ISSET(fd, &readfds)) {
			DBGPRINTF("imdtls: Read Client activity on index %d.\n", i);

			// Existing client Finish handshake
			int ret = SSL_accept(inst->sslClients[i]);
			if (ret <= 0) {
				int err = SSL_get_error(inst->sslClients[i], ret);
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					// Non-blocking operation did not complete; retry later
					DBGPRINTF("imdtls: SSL_accept didn't complete (%d). Will retry.\n", err);
				} else {
					// An actual error occurred
					DBGPRINTF("imdtls: SSL_accept failed (%d) on index %d, removing client.\n",
						err, i);
					SSL_free(inst->sslClients[i]);
					inst->sslClients[i] = NULL;
					return;
				}
			}

			// If SSL_accept succeeded, proceed to read data
			char buf[MAX_DTLS_MSGSIZE];
			int len = 0;

			do {
				len = SSL_read(inst->sslClients[i], buf, sizeof(buf) - 1);
				if (len > 0) {
					buf[len] = '\0';
					// Process Message
					processMsg(inst, inst->sslClients[i], buf, len);
				} else {
					int err = SSL_get_error(inst->sslClients[i], len);
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
						break; // Exit the loop if no more data to read or write
					} else {
						DBGPRINTF("imdtls: SSL_read error on index %d, removing client.\n", i);
						SSL_free(inst->sslClients[i]);
						inst->sslClients[i] = NULL;
						// Exit the loop if an error other than SSL_ERROR_WANT_READ/WRITE occurs
						break; 
					}
				}
			} while (len > 0);
		}
	}
}

static void*
startDtlsHandler(void *myself) {
	instanceConf_t *inst = (instanceConf_t *) myself;
	DBGPRINTF("imdtls: start DtlsHandler for thread %s\n", inst->pszInputName);

	/* DTLS Receiving Loop */
	while(glbl.GetGlobalInputTermState() == 0) {
		DBGPRINTF("imdtls: begin handle DTSL Sessions\n");
		DTLSHandleSessions(inst);
	}

	DBGPRINTF("imdtls: stop DtlsHandler for thread %s\n", inst->pszInputName);
	return NULL;
}

BEGINnewInpInst
	struct cnfparamvals *pvals;
	instanceConf_t *inst = NULL;
	int i,j;
	FILE *fp;
CODESTARTnewInpInst
	DBGPRINTF("newInpInst (imdtls)\n");

	if((pvals = nvlstGetParams(lst, &inppblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("input param blk in imdtls:\n");
		cnfparamsPrint(&inppblk, pvals);
	}

	CHKiRet(createInstance(&inst));

	for(i = 0 ; i < inppblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(inppblk.descr[i].name, "port")) {
			inst->pszBindPort = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "address")) {
			inst->pszBindAddr = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "ruleset")) {
			inst->pszBindRuleset = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "name")) {
			inst->pszInputName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
//		} else if(!strcmp(inppblk.descr[i].name, "tls.prioritystring")) {
//			inst->pNetOssl->pristring = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "tls.authmode")) {
			char* pszAuthMode = es_str2cstr(pvals[i].val.d.estr, NULL);
			if(!strcasecmp(pszAuthMode, "fingerprint"))
				inst->authMode = OSSL_AUTH_CERTFINGERPRINT;
			else if(!strcasecmp(pszAuthMode, "name"))
				inst->authMode = OSSL_AUTH_CERTNAME;
			else if(!strcasecmp(pszAuthMode, "certvalid"))
				inst->authMode = OSSL_AUTH_CERTVALID;
			else
				inst->authMode = OSSL_AUTH_CERTANON;
			free(pszAuthMode);
		} else if(!strcmp(inppblk.descr[i].name, "tls.cacert")) {
			inst->pNetOssl->pszCAFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			fp = fopen((const char*)inst->pNetOssl->pszCAFile, "r");
			if(fp == NULL) {
				char errStr[1024];
				rs_strerror_r(errno, errStr, sizeof(errStr));
				LogError(0, RS_RET_NO_FILE_ACCESS,
				"error: certificate file %s couldn't be accessed: %s\n",
				inst->pNetOssl->pszCAFile, errStr);
			} else {
				fclose(fp);
			}
		} else if(!strcmp(inppblk.descr[i].name, "tls.mycert")) {
			inst->pNetOssl->pszCertFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			fp = fopen((const char*)inst->pNetOssl->pszCertFile, "r");
			if(fp == NULL) {
				char errStr[1024];
				rs_strerror_r(errno, errStr, sizeof(errStr));
				LogError(0, RS_RET_NO_FILE_ACCESS,
				"error: certificate file %s couldn't be accessed: %s\n",
				inst->pNetOssl->pszCertFile, errStr);
			} else {
				fclose(fp);
			}
		} else if(!strcmp(inppblk.descr[i].name, "tls.myprivkey")) {
			inst->pNetOssl->pszKeyFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			fp = fopen((const char*)inst->pNetOssl->pszKeyFile, "r");
			if(fp == NULL) {
				char errStr[1024];
				rs_strerror_r(errno, errStr, sizeof(errStr));
				LogError(0, RS_RET_NO_FILE_ACCESS,
				"error: certificate file %s couldn't be accessed: %s\n",
				inst->pNetOssl->pszKeyFile, errStr);
			} else {
				fclose(fp);
			}
		} else if(!strcmp(inppblk.descr[i].name, "tls.tlscfgcmd")) {
			inst->tlscfgcmd = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "tls.permittedpeer")) {
			inst->permittedPeers.nmemb = pvals[i].val.d.ar->nmemb;
			CHKmalloc(inst->permittedPeers.name =
				malloc(sizeof(uchar*) * inst->permittedPeers.nmemb));
			for(j = 0 ; j <  pvals[i].val.d.ar->nmemb ; ++j) {
				inst->permittedPeers.name[j] = (uchar*)es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
			}
		} else {
			dbgprintf("imdtls: program error, non-handled "
			  "param '%s'\n", inppblk.descr[i].name);
		}
	}
	
	/*
	if(inst->myCertFile  != NULL && inst->myPrivKeyFile == NULL) {
		LogError(0, RS_RET_ERR, "imdtls: Certificate file given but no corresponding "
			"private key file - this is invalid, listener cannot be started");
		ABORT_FINALIZE(RS_RET_ERR);
	}
	if(inst->myCertFile  == NULL && inst->myPrivKeyFile != NULL) {
		LogError(0, RS_RET_ERR, "imdtls: private key file given but no corresponding "
			"certificate file - this is invalid, listener cannot be started");
		ABORT_FINALIZE(RS_RET_ERR);
	}
	*/

	inst->bEnableLstn = -1; /* all ok, ready to start up */

finalize_it:
CODE_STD_FINALIZERnewInpInst
	cnfparamvalsDestruct(pvals, &inppblk);
	if(iRet != RS_RET_OK) {
		if(inst != NULL) {
			// free(inst->tlscfgcmd);
			// inst->tlscfgcmd = NULL;
		}
	}
ENDnewInpInst


BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
	pModConf->pszBindRuleset = NULL;
	pModConf->drvrAuthMode = OSSL_AUTH_CERTANON;
	pModConf->tlslib = NULL;
	/* init legacy config variables */
	cs.pszBindRuleset = NULL;
ENDbeginCnfLoad


BEGINsetModCnf
	struct cnfparamvals *pvals = NULL;
	int i;
CODESTARTsetModCnf
	pvals = nvlstGetParams(lst, &modpblk, NULL);
	if(pvals == NULL) {
		LogError(0, RS_RET_MISSING_CNFPARAMS, "error processing module "
				"config parameters [module(...)]");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("module (global) param blk for imdtls:\n");
		cnfparamsPrint(&modpblk, pvals);
	}

	for(i = 0 ; i < modpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(modpblk.descr[i].name, "ruleset")) {
			loadModConf->pszBindRuleset = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(modpblk.descr[i].name, "tls.authmode")) {
			char* pszAuthMode = es_str2cstr(pvals[i].val.d.estr, NULL);
			if(!strcasecmp(pszAuthMode, "fingerprint"))
				loadModConf->drvrAuthMode = OSSL_AUTH_CERTFINGERPRINT;
			else if(!strcasecmp(pszAuthMode, "name"))
				loadModConf->drvrAuthMode = OSSL_AUTH_CERTNAME;
			else if(!strcasecmp(pszAuthMode, "certvalid"))
				loadModConf->drvrAuthMode = OSSL_AUTH_CERTVALID;
			else
				loadModConf->drvrAuthMode = OSSL_AUTH_CERTANON;
			free(pszAuthMode);

		} else {
			dbgprintf("imdtls: program error, non-handled "
			  "param '%s' in beginCnfLoad\n", modpblk.descr[i].name);
		}
	}
finalize_it:
	if(pvals != NULL)
		cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf


BEGINendCnfLoad
CODESTARTendCnfLoad
	if(loadModConf->pszBindRuleset == NULL) {
		if((cs.pszBindRuleset == NULL) || (cs.pszBindRuleset[0] == '\0')) {
			loadModConf->pszBindRuleset = NULL;
		} else {
			CHKmalloc(loadModConf->pszBindRuleset = ustrdup(cs.pszBindRuleset));
		}
	} else {
		if((cs.pszBindRuleset != NULL) && (cs.pszBindRuleset[0] != '\0')) {
			LogError(0, RS_RET_DUP_PARAM, "imdtls: ruleset "
					"set via legacy directive ignored");
		}
	}
finalize_it:
	free(cs.pszBindRuleset);
	cs.pszBindRuleset = NULL;
	loadModConf = NULL; /* done loading */
ENDendCnfLoad


BEGINcheckCnf
	instanceConf_t *inst;
CODESTARTcheckCnf
	for(inst = pModConf->root ; inst != NULL ; inst = inst->next) {
		if(inst->pszBindRuleset == NULL && pModConf->pszBindRuleset != NULL) {
			CHKmalloc(inst->pszBindRuleset = ustrdup(pModConf->pszBindRuleset));
		}
		std_checkRuleset(pModConf, inst);
	}
finalize_it:
ENDcheckCnf


BEGINactivateCnfPrePrivDrop
	instanceConf_t *inst;
CODESTARTactivateCnfPrePrivDrop
	runModConf = pModConf;
	DBGPRINTF("imdtls: activate addListners for dtls\n");
	for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
		addListner(pModConf, inst);
	}
//	if(pRelpEngine == NULL) {
//		LogError(0, RS_RET_NO_LSTN_DEFINED, "imdtls: no DTLS listener defined, module can not run.");
//		ABORT_FINALIZE(RS_RET_NO_RUN);
//	}
//finalize_it:
ENDactivateCnfPrePrivDrop

BEGINactivateCnf
CODESTARTactivateCnf
ENDactivateCnf


BEGINfreeCnf
	instanceConf_t *inst, *del;
	int i;
CODESTARTfreeCnf
	for(inst = pModConf->root ; inst != NULL ; ) {
		free(inst->pszBindPort);
		if (inst->pszBindAddr != NULL) {
			free(inst->pszBindAddr);
		}
		free(inst->pszBindRuleset);
		free(inst->pszInputName);
		// free(inst->pristring);
		// free(inst->authmode);
		for(i = 0 ; i <  inst->permittedPeers.nmemb ; ++i) {
			free(inst->permittedPeers.name[i]);
		}
		if(inst->bEnableLstn) {
			prop.Destruct(&inst->pInputName);
			statsobj.Destruct(&(inst->stats));
		}
		del = inst;
		inst = inst->next;
		free(del);
	}
	free(pModConf->pszBindRuleset);
ENDfreeCnf



/* This function is called to gather input.
 * In essence, it just starts the pool of workers. To save resources,
 * we run one of the workers on our own thread -- otherwise that thread would
 * just idle around and wait for the workers to finish.
 */
BEGINrunInput
	instanceConf_t *inst;
	pthread_attr_t wrkrThrdAttr;
CODESTARTrunInput
	pthread_attr_init(&wrkrThrdAttr);
	pthread_attr_setstacksize(&wrkrThrdAttr, 4096*1024);

	DBGPRINTF("imdtls: create dtls handling threads\n");
	for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
		if(inst->bEnableLstn) {
			// inst.pThrd = pThrd;
			pthread_create(&inst->tid, &wrkrThrdAttr, startDtlsHandler, inst);
		}
	}
	pthread_attr_destroy(&wrkrThrdAttr);

	DBGPRINTF("imdtls: starting to wait for close condition\n");
	while(glbl.GetGlobalInputTermState() == 0) {
		srSleep(0, 400000);
	}

	DBGPRINTF("imdtls: received close signal, signaling instance threads...\n");
	for (inst = runModConf->root; inst != NULL; inst = inst->next) {
		pthread_kill(inst->tid, SIGTTIN);
	}

	DBGPRINTF("imdtls: threads signaled, waiting for join...");
	for (inst = runModConf->root ; inst != NULL ; inst = inst->next) {
		pthread_join(inst->tid, NULL);
	}

	DBGPRINTF("imdtls: finished threads, stopping\n");
ENDrunInput


BEGINwillRun
CODESTARTwillRun
	/* we need to create the inputName property (only once during our lifetime) */
	CHKiRet(prop.Construct(&pInputName));
	CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imdtls"), sizeof("imdtls") - 1));
	CHKiRet(prop.ConstructFinalize(pInputName));
finalize_it:
ENDwillRun

/* This function is called by the framework after runInput() has been terminated. It
 * shall free any resources and prepare the module for unload.
 * CODEqueryEtryPt_STD_IMOD_QUERIES
 */
BEGINafterRun
CODESTARTafterRun
	/* TODO: do cleanup here ?! */
	dbgprintf("imdtls: AfterRun\n");
	if(pInputName != NULL)
		prop.Destruct(&pInputName);
ENDafterRun

BEGINmodExit
CODESTARTmodExit
	/* release objects we used */
	objRelease(net_ossl, CORE_COMPONENT);
	objRelease(statsobj, CORE_COMPONENT);
	objRelease(ruleset, CORE_COMPONENT);
	objRelease(prop, CORE_COMPONENT);
	objRelease(datetime, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);

	net_osslClassExit();
ENDmodExit

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURENonCancelInputTermination)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES
CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	/* request objects we use */
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));
	CHKiRet(objUse(prop, CORE_COMPONENT));
	CHKiRet(objUse(ruleset, CORE_COMPONENT));
	CHKiRet(objUse(statsobj, CORE_COMPONENT));
	CHKiRet(objUse(net_ossl, CORE_COMPONENT));

	CHKiRet(net_osslClassInit(pModInfo)); /* must be done after tcps_sess, as we use it */
ENDmodInit
