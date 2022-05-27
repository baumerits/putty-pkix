/*
 * CNG RSA implementation for PuTTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh.h"
#include "mpint.h"
#include "misc.h"

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <cryptuiapi.h>


void cngrsa_sha1_to_binary(PSTR szHex, PBYTE pbBin)
{
	unsigned char i, h, l;
	for (i = 0; i < 20; i++) {
		h = szHex[i << 1];
		l = szHex[(i << 1) + 1];
		pbBin[i] =
			(((h >= '0' && h <= '9') ? h - '0' : ((h >= 'a' && h <= 'f') ? h - 'a' + 10 : ((h >= 'A' && h <= 'F') ? h - 'A' + 10 : 0))) << 4) +
			(((l >= '0' && l <= '9') ? l - '0' : ((l >= 'a' && l <= 'f') ? l - 'a' + 10 : ((l >= 'A' && l <= 'F') ? l - 'A' + 10 : 0))));
	}
}


void cngrsa_sha1_from_binary(PBYTE pbBin, PSTR szHex, int startPos)
{
	unsigned char i, h, l;
	char chrs[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	for (i = 0; i < 20; i++) {
		h = (pbBin[i + startPos] >> 4) & 0x0F;
		l = pbBin[i + startPos] & 0x0F;
		szHex[i * 2] = chrs[h];
		szHex[i * 2 + 1] = chrs[l];
	}
}

void cngrsa_ssh1_public_blob(BinarySink* bs, RSAKey* key,
	RsaSsh1Order order)
{
	put_uint32(bs, mp_get_nbits(key->modulus));
	if (order == RSA_SSH1_EXPONENT_FIRST) {
		put_mp_ssh1(bs, key->exponent);
		put_mp_ssh1(bs, key->modulus);
	}
	else {
		put_mp_ssh1(bs, key->modulus);
		put_mp_ssh1(bs, key->exponent);
	}
}

void cngrsa_ssh1_private_blob_agent(BinarySink* bs, RSAKey* key)
{
	cngrsa_ssh1_public_blob(bs, key, RSA_SSH1_MODULUS_FIRST);
	put_mp_ssh1(bs, key->private_exponent);
	put_mp_ssh1(bs, key->iqmp);
	put_mp_ssh1(bs, key->q);
	put_mp_ssh1(bs, key->p);
}

/* Given an SSH-1 public key blob, determine its length. */
int cngrsa_ssh1_public_blob_len(ptrlen data)
{
	BinarySource src[1];

	BinarySource_BARE_INIT_PL(src, data);

	/* Expect a length word, then exponent and modulus. (It doesn't
	 * even matter which order.) */
	get_uint32(src);
	mp_free(get_mp_ssh1(src));
	mp_free(get_mp_ssh1(src));

	if (get_err(src))
		return -1;

	/* Return the number of bytes consumed. */
	return src->pos;
}

void freecngrsapriv(RSAKey* key)
{
	if (key->private_exponent) {
		mp_free(key->private_exponent);
		key->private_exponent = NULL;
	}
	if (key->p) {
		mp_free(key->p);
		key->p = NULL;
	}
	if (key->q) {
		mp_free(key->q);
		key->q = NULL;
	}
	if (key->iqmp) {
		mp_free(key->iqmp);
		key->iqmp = NULL;
	}
}

void freecngrsakey(RSAKey* key)
{
	freecngrsapriv(key);
	if (key->modulus) {
		mp_free(key->modulus);
		key->modulus = NULL;
	}
	if (key->exponent) {
		mp_free(key->exponent);
		key->exponent = NULL;
	}
	if (key->comment) {
		sfree(key->comment);
		key->comment = NULL;
	}
}

/* ----------------------------------------------------------------------
 * Implementation of the ssh-rsa signing key type family.
 */

struct ssh2_rsa_extra {
	unsigned signflags;
};

static void cngrsa2_freekey(ssh_key* key);   /* forward reference */


static void cngrsa2_freekey(ssh_key* key)
{
	RSAKey* rsa = container_of(key, RSAKey, sshk);
	freecngrsakey(rsa);
	sfree(rsa);
}



static void cngrsa2_public_blob(ssh_key* key, BinarySink* bs)
{
	RSAKey* rsa = container_of(key, RSAKey, sshk);

	put_stringz(bs, "ssh-rsa");
	put_mp_ssh2(bs, rsa->exponent);
	put_mp_ssh2(bs, rsa->modulus);
}


/*
 * Reverse a byte array.
 */
static void cngrsa_reverse_array(PBYTE pb, DWORD cb)
{
	DWORD i;
	BYTE t;
	for (i = 0; i < cb >> 1; i++) {
		t = pb[i];
		pb[i] = pb[cb - i - 1];
		pb[cb - i - 1] = t;
	}
}


/*
 * Select a certificate given the criteria provided.
 * If a criterion is absent it will be disregarded.
 */
static void cngrsa_select_cert_2(PBYTE pbSHA1, LPWSTR wszCN, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	HCERTSTORE hStoreMY = NULL, hStoreTMP = NULL;
	PCCERT_CONTEXT pCertCtx = NULL;
	HMODULE hCryptUIDLL = NULL;
	//DFNCryptUIDlgSelectCertificateFromStore dfnCryptUIDlgSelectCertificateFromStore;
	CRYPT_HASH_BLOB cryptHashBlob;
	DWORD dwCertCount = 0;
	if (!(hStoreMY = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY"))) {
		goto error;
	}
	if (pbSHA1) {
		cryptHashBlob.cbData = 20;
		cryptHashBlob.pbData = pbSHA1;
		if ((*ppCertCtx = CertFindCertificateInStore(hStoreMY, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &cryptHashBlob, pCertCtx))) {
			*phStore = hStoreMY;
			return;
		}
		else {
			goto error;
		}
	}
	if (!(hStoreTMP = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL))) {
		goto error;
	}
	while (TRUE) {
		if (wszCN) {
			pCertCtx = CertFindCertificateInStore(hStoreMY, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, wszCN, pCertCtx);
		}
		else {
			pCertCtx = CertEnumCertificatesInStore(hStoreMY, pCertCtx);
		}
		if (!pCertCtx) {
			break;
		}

		dwCertCount++;
		CertAddCertificateContextToStore(hStoreTMP, pCertCtx, CERT_STORE_ADD_ALWAYS, NULL);
	}
	CertCloseStore(hStoreMY, CERT_CLOSE_STORE_FORCE_FLAG);
	hStoreMY = NULL;
	if (dwCertCount == 1) {
		*ppCertCtx = CertEnumCertificatesInStore(hStoreTMP, NULL);
		*phStore = hStoreTMP;
		return;
	}
	else if (dwCertCount > 1) {
		*ppCertCtx = CryptUIDlgSelectCertificateFromStore(hStoreTMP, NULL, NULL, NULL, CRYPTUI_SELECT_EXPIRATION_COLUMN, 0, NULL);
		*phStore = hStoreTMP;
		return;
	}
error:
	if (hCryptUIDLL) { FreeLibrary(hCryptUIDLL); }
	if (hStoreTMP) { CertCloseStore(hStoreTMP, CERT_CLOSE_STORE_FORCE_FLAG); }
	if (hStoreMY) { CertCloseStore(hStoreMY, CERT_CLOSE_STORE_FORCE_FLAG); }
	*ppCertCtx = NULL;
	*phStore = NULL;
}

/*
 * Return a malloc'ed string containing the requested subitem.
 */
PSTR cngrsa_select_cert_finditem(PSTR szCert, PCSTR szStart)
{
	PSTR ptrStart, ptrEnd, szResult;
	ptrStart = strstr(szCert, szStart);
	ptrEnd = strstr(szCert, ",");
	if (!ptrEnd || ptrEnd < ptrStart) {
		ptrEnd = szCert + strlen(szCert);
	}
	if (!ptrStart || ptrStart > ptrEnd) {
		return NULL;
	}
	ptrStart += strlen(szStart);
	szResult = (PSTR)calloc(ptrEnd - ptrStart + 1, sizeof(char));
	memcpy(szResult, ptrStart, ptrEnd - ptrStart);
	return szResult;
}


/*
 * Select a certificate given the definition string.
 */
static void cngrsa_select_cert(PSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	PSTR szCN = NULL, szThumb, ptrStart, ptrStartAll;
	LPWSTR wszCN = NULL;
	DWORD i, len;
	PBYTE pbThumb = snewn(20, BYTE);
	ptrStart = strstr(szCert, "cert://");
	ptrStartAll = strstr(szCert, "cert://*");
	if (ptrStart != szCert) {
		*ppCertCtx = NULL;
		*phStore = NULL;
		return;
	}
	if (ptrStartAll) {
		cngrsa_select_cert_2(NULL, NULL, ppCertCtx, phStore);
		return;
	}
	szThumb = cngrsa_select_cert_finditem(szCert, "thumbprint=");
	if (szThumb && 40 == strlen(szThumb)) {
		cngrsa_sha1_to_binary(szThumb, pbThumb);
		cngrsa_select_cert_2(pbThumb, NULL, ppCertCtx, phStore);
	}
	else {
		szCN = cngrsa_select_cert_finditem(szCert, "cn=");
		if (szCN) {
			len = strlen(szCN);
			wszCN = (LPWSTR)calloc(len + 1, sizeof(wchar_t));
			for (i = 0; i < len; i++) {
				wszCN[i] = szCN[i];
			}
		}
		cngrsa_select_cert_2(NULL, wszCN, ppCertCtx, phStore);
	}
	if (szCN) { free(szCN); }
	if (wszCN) { free(wszCN); }
	sfree(pbThumb);
}


static ssh_key* cngrsa2_new_pub(const ssh_keyalg* self, ptrlen data)
{
	BinarySource src[1];
	RSAKey* rsa;
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertCtx;
	BOOL fSuccess;
	DWORD cbPublicKeyBlob = 8192;
	PBYTE pbPublicKeyBlob = NULL;
	RSAPUBKEY* pRSAPubKey;


	cngrsa_select_cert(data.ptr, &pCertCtx, &hCertStore);
	 
	if (pCertCtx == NULL)
		return NULL;

	rsa = snew(RSAKey);
	memset(rsa, 0, sizeof(RSAKey));

	fSuccess = CryptDecodeObject(
		X509_ASN_ENCODING,
		RSA_CSP_PUBLICKEYBLOB,
		pCertCtx->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
		pCertCtx->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
		0,
		(void*)(pbPublicKeyBlob = snewn(cbPublicKeyBlob, BYTE)),
		&cbPublicKeyBlob);
	if (!fSuccess)
		return NULL;

	pRSAPubKey = (RSAPUBKEY*)(pbPublicKeyBlob + sizeof(BLOBHEADER));
	cngrsa_reverse_array(pbPublicKeyBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY), pRSAPubKey->bitlen / 8);
	rsa->sshk.vt = self;
	rsa->exponent = mp_from_integer(pRSAPubKey->pubexp);
	rsa->modulus = mp_from_bytes_be(make_ptrlen(pbPublicKeyBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY), pRSAPubKey->bitlen / 8));
	rsa->iqmp = mp_from_bytes_be(make_ptrlen(pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded));
	rsa->private_exponent = mp_from_integer(pCertCtx->cbCertEncoded);

	BYTE* thumbPrint = malloc(20);
	if (thumbPrint) {
		DWORD thumbPrintSize = 20;
		if (!CryptHashCertificate(0, NULL, 0, pCertCtx->pbCertEncoded,
			pCertCtx->cbCertEncoded, thumbPrint, &thumbPrintSize)) {
			return false;
		}
		BYTE* strThumb = malloc(41);
		if (strThumb) {
			memset(strThumb, 0, 41);
			cngrsa_sha1_from_binary(thumbPrint, strThumb, 0);
			rsa->comment = dupprintf("cert://thumbprint=%s", strThumb);
			free(strThumb);
		}
		free(thumbPrint);
	}

	// cleanup
	sfree(pbPublicKeyBlob);
	CertFreeCertificateContext(pCertCtx);

	return &rsa->sshk;
}


static ssh_key* cngrsa2_new_priv(const ssh_keyalg* self,
	ptrlen pub, ptrlen priv)
{
	BinarySource src[1];
	ssh_key* sshk;
	RSAKey* rsa;

	sshk = cngrsa2_new_pub(self, pub);
	if (!sshk)
		return NULL;

	rsa = container_of(sshk, RSAKey, sshk);

	rsa->comment = mkstr(pub);
	return  &rsa->sshk;

}


static ssh_key* cngrsa2_new_priv_openssh(const ssh_keyalg* self,
	BinarySource* src)
{
	ssh_key* sshk;
	RSAKey* rsa;
	ptrlen line;
	line = get_string(src);
	sshk = cngrsa2_new_pub(self, line);
	if (!sshk)
		return NULL;

	rsa = container_of(sshk, RSAKey, sshk);

	rsa->comment = mkstr(line);
	return  &rsa->sshk;

}

static void cngrsa2_sign(ssh_key* key, ptrlen data,
	unsigned flags, BinarySink* bs)
{
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertCtx;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
	HCRYPTHASH hHash = 0;
	PBYTE pbSig = NULL;
	DWORD dwSpec, cbSig = 0;
	BOOL fCallerFreeProvAlwaysFalse = TRUE;
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	BCRYPT_ALG_HANDLE       hHashAlg = NULL;
	BCRYPT_HASH_HANDLE      hHashBcrypt = NULL;
	NTSTATUS                status = 0;
	DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE                   pbHashObject = NULL;
	PBYTE                   pbHash = NULL;

	unsigned short* bcrypt_alg = NULL;
	ALG_ID alg = CALG_SHA1;
	const char* sign_alg_name;
	RSAKey* rsa = container_of(key, RSAKey, sshk);

	int len = strlen(rsa->comment);
	if ((len < 7)
		|| !(0 == strncmp("cert://", rsa->comment, 7))) {
		return;
	}

	if (flags & SSH_AGENT_RSA_SHA2_256) {
		alg = CALG_SHA_256;
		bcrypt_alg = BCRYPT_SHA256_ALGORITHM;
		padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		sign_alg_name = "rsa-sha2-256";
	}
	else if (flags & SSH_AGENT_RSA_SHA2_512) {
		alg = CALG_SHA_512;
		bcrypt_alg = BCRYPT_SHA512_ALGORITHM;
		padInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
		sign_alg_name = "rsa-sha2-512";
	}
	else {
		alg = CALG_SHA1;
		bcrypt_alg = BCRYPT_SHA1_ALGORITHM;
		padInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
		sign_alg_name = "ssh-rsa";
	}

	cngrsa_select_cert(rsa->comment, &pCertCtx, &hCertStore);
	if (pCertCtx)
	{
		if (CryptAcquireCertificatePrivateKey(pCertCtx, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, 0, &hCryptProvOrNCryptKey, &dwSpec, &fCallerFreeProvAlwaysFalse)) {
			if (dwSpec == AT_KEYEXCHANGE || dwSpec == AT_SIGNATURE) {
				/* A lot faster for smartcards because CryptSignHash for asking buffersize is querying sc already */
				cbSig = 2048;
				pbSig = snewn(cbSig, BYTE);

				/* CSP implementation */
				if (!CryptCreateHash((HCRYPTPROV)hCryptProvOrNCryptKey, alg, 0, 0, &hHash)) {
					goto Cleanup;
				}

				if (!CryptHashData(hHash, data.ptr, data.len, 0)) {
					goto Cleanup;
				}

				if (!CryptSignHash(hHash, dwSpec, NULL, 0, pbSig, &cbSig)) {
					goto Cleanup;
				}

				cngrsa_reverse_array(pbSig, cbSig);
				put_stringz(bs, sign_alg_name);
				put_uint32(bs, cbSig);
				put_data(bs, pbSig, cbSig);
			}
			else if (dwSpec == CERT_NCRYPT_KEY_SPEC) {
				/* KSP/CNG implementation */

				if ((status = BCryptOpenAlgorithmProvider(
					&hHashAlg, bcrypt_alg, NULL, 0)) != 0) {
					goto Cleanup;
				}

				if ((status = BCryptGetProperty(
					hHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) != 0) {
					goto Cleanup;
				}

				pbHashObject = snewn(cbHashObject, BYTE);
				if (NULL == pbHashObject) {
					goto Cleanup;
				}

				if ((status = BCryptGetProperty(
					hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)) != 0) {
					goto Cleanup;
				}

				pbHash = snewn(cbHash, BYTE);
				if (NULL == pbHash) {
					goto Cleanup;
				}

				if ((status = BCryptCreateHash(
					hHashAlg, &hHashBcrypt, pbHashObject, cbHashObject, NULL, 0, 0)) != 0) {
					goto Cleanup;
				}

				if ((status = BCryptHashData(
					hHashBcrypt, (PUCHAR)data.ptr, data.len, 0)) != 0) {
					goto Cleanup;
				}

				if ((status = BCryptFinishHash(
					hHashBcrypt, pbHash, cbHash, 0)) != 0) {
					goto Cleanup;
				}

				if ((status = NCryptSignHash(
					hCryptProvOrNCryptKey, &padInfo, pbHash, cbHash, NULL, 0, &cbSig, BCRYPT_PAD_PKCS1)) != 0) {
					goto Cleanup;
				}

				pbSig = snewn(cbSig, BYTE);
				if (NULL == pbSig) {
					goto Cleanup;
				}

				if ((status = NCryptSignHash(
					hCryptProvOrNCryptKey, &padInfo, pbHash, cbHash, pbSig, cbSig, &cbSig, BCRYPT_PAD_PKCS1)) != 0) {
					goto Cleanup;
				}

				put_stringz(bs, sign_alg_name);
				put_uint32(bs, cbSig);
				put_data(bs, pbSig, cbSig);
			}
		}
	}
Cleanup:
	if (hHashAlg)
		BCryptCloseAlgorithmProvider(hHashAlg, 0);
	if (hHashBcrypt)
		BCryptDestroyHash(hHashBcrypt);
	if (pbHashObject)
		sfree(pbHashObject);
	if (pbHash)
		sfree(pbHash);
	if (pbSig)
		sfree(pbSig);
	if (hHash)
		CryptDestroyHash(hHash);
	if (pCertCtx)
		CertFreeCertificateContext(pCertCtx);
	if (hCertStore)
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
}

static char* cngrsa2_invalid(ssh_key* key, unsigned flags)
{
	RSAKey* rsa = container_of(key, RSAKey, sshk);
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertCtx;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
	DWORD dwSpec, cbSig = 0;
	BOOL fCallerFreeProvAlwaysFalse = TRUE;

	cngrsa_select_cert(rsa->comment, &pCertCtx, &hCertStore);
	if (pCertCtx)
	{
		if (CryptAcquireCertificatePrivateKey(pCertCtx, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, 0, &hCryptProvOrNCryptKey, &dwSpec, &fCallerFreeProvAlwaysFalse)) {
			return NULL;
		}
		CertFreeCertificateContext(pCertCtx);
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
	}
	return dupstr("Could not acquire private key..");
}

static const struct ssh2_rsa_extra
cngrsa_extra = { 0 },
cngrsa_sha256_extra = { SSH_AGENT_RSA_SHA2_256 },
cngrsa_sha512_extra = { SSH_AGENT_RSA_SHA2_512 };

#define COMMON_KEYALG_FIELDS                    \
    .new_pub = cngrsa2_new_pub,                    \
    .new_priv = cngrsa2_new_priv,                  \
    .new_priv_openssh = cngrsa2_new_priv_openssh,  \
    .freekey = cngrsa2_freekey,                    \
    .invalid = cngrsa2_invalid,                    \
    .sign = cngrsa2_sign,                          \
    .verify = NULL,                      \
    .public_blob = cngrsa2_public_blob,            \
    .private_blob = NULL,          \
    .openssh_blob = NULL,          \
    .cache_str = NULL,                \
    .components = NULL,              \
    .pubkey_bits = NULL,            \
    .cache_id = "cngrsa2"

const ssh_keyalg ssh_cngrsa = {
	COMMON_KEYALG_FIELDS,
	.ssh_id = "ssh-cngrsa",
	.supported_flags = SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512,
	.extra = &cngrsa_extra,
};


