#include <sys/param.h>
#include <sys/types.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "authlogd.h"

extern char cert_file[MAXPATHLEN];
extern char pubk_file[MAXPATHLEN];
extern char privk_file[MAXPATHLEN];

static SSL_CTX  *ssl_global_conf;

static EVP_MD_CTX *sign_global_conf;
static EVP_MD_CTX *verify_global_conf;
static const EVP_MD     *sign_method;

static EVP_PKEY     *eprivkey;
static EVP_PKEY     *epubkey;
static X509         *xcert;

/*!
 * Initialize signing module.
 */
void
authlogd_sign_init(void)
{
	SSL *ssl;

	sign_global_conf =  EVP_MD_CTX_create();
	EVP_MD_CTX_init(sign_global_conf);

	if (ssl = SSL_new(ssl_global_conf)) {
		DPRINTF(("Try to get keys from TLS X.509 cert...\n"));

		if (!(xcert = SSL_get_certificate(ssl))) {
			DPRINTF(("SSL_get_certificate() failed"));
			SSL_free(ssl);
			return;
		}
		if (!(eprivkey = SSL_get_privatekey(ssl))) {
			DPRINTF(("SSL_get_privatekey() failed"));
			SSL_free(ssl);
			return;
		}
		if (!(epubkey = X509_get_pubkey(xcert))) {
			DPRINTF(("X509_get_pubkey() failed"));
			SSL_free(ssl);
			return;
		}
	}

	SSL_free(ssl);

	if (EVP_PKEY_DSA != EVP_PKEY_type(epubkey->type)) {
		DPRINTF(("X.509 cert has no DSA key\n"));
		EVP_PKEY_free(epubkey);
		eprivkey = NULL;
		epubkey = NULL;
	} else {
		DPRINTF(("Got public and private key "
		    "from X.509 --> use type PKIX\n"));

		sign_method = EVP_dss1();
	}
}

char *
authlogd_sign_buf(const char *buff, size_t len)
{
	char *buf;
	unsigned char sig_b64[65];
	unsigned sig_len = EVP_PKEY_size(eprivkey);
	char *signature;
	
	buf = malloc ((EVP_PKEY_size(eprivkey)) * sizeof(uint8_t));
	
	EVP_SignInit(sign_global_conf, sign_method);
	EVP_SignUpdate(sign_global_conf, buff, len);
	EVP_SignFinal(sign_global_conf, buf, &sig_len, eprivkey);

	b64_ntop(buf, sig_len, (char *)sig_b64, sizeof(sig_b64));
	signature = strdup((char *)sig_b64);

	return signature;
}

int
authlogd_verify_buf(const char *config, size_t config_len, 
	const char *sign, size_t sign_len)
{
	
	EVP_VerifyInit(verify_global_conf, sign_method);
	EVP_VerifyUpdate(verify_global_conf, config, config_len);
	EVP_VerifyFinal(verify_global_conf, sign, sign_len, epubkey);

	return 0;
}

void
authlogd_ssl_init(void)
{

	const char *keyfilename   = privk_file;
	const char *certfilename  = cert_file;

	SSL_CTX *ctx;

	FILE *priv;
	FILE *certf;

	DPRINTF(("Opening files: %s, %s\n", certfilename, keyfilename));

	SSL_library_init();
	
	if (!(ctx = SSL_CTX_new(SSLv23_method())))
		err(EXIT_FAILURE, "Cannot initialize SSL %s\n", 
			ERR_error_string(ERR_get_error(), NULL));

	if (!(priv  = fopen(keyfilename,  "r")) || !(certf = fopen(certfilename, "r"))) {
		DPRINTF(("Unable to open certfilenameificate file %s and private key file %s\n",
		 	certfilename, keyfilename));
		return;
	} 

	/* Close files */
	fclose(priv);
	fclose(certf);

	/* Open cert filename file and private key file */
	if (!SSL_CTX_use_PrivateKey_file(ctx, keyfilename, SSL_FILETYPE_PEM) ||
	    !SSL_CTX_use_certificate_chain_file(ctx, certfilename)) {
		DPRINTF(("Unable to load key/certfilename files: %s\n", 
			ERR_error_string(ERR_get_error(), NULL)));
		return;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		DPRINTF(("Private key \"%s\" does not match "
		    "certificate \"%s\": %s",
		    keyfilename, certfilename,
		    ERR_error_string(ERR_get_error(), NULL)));
		return;
	}

	(void)SSL_CTX_set_options(ctx,
	    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE);
	(void)SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	ssl_global_conf = ctx;

	return;
}
