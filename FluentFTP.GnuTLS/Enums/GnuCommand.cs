﻿using System;
using System.Collections.Generic;
using System.Text;

namespace FluentFTP.GnuTLS.Enums {
	/// <summary>
	/// A configuration option for the GnuTLS security suite.
	/// Source : https://www.gnutls.org/manual/gnutls.html#tab_003aprio_002dkeywords
	/// </summary>
	public enum GnuCommand : int {
		Gost,
		Cipher_All,
		Cipher_Gost_All,
		Cipher_Aes_128_Gcm,
		Cipher_Aes_256_Gcm,
		Cipher_Aes_128_Ccm,
		Cipher_Aes_256_Ccm,
		Cipher_Chacha20_Poly1305,
		Cipher_Aes_128_Ccm_8,
		Cipher_Aes_256_Ccm_8,
		Cipher_Camellia_128_Gcm,
		Cipher_Camellia_256_Gcm,
		Cipher_Aes_128_Cbc,
		Cipher_Aes_256_Cbc,
		Cipher_Camellia_128_Cbc,
		Cipher_Camellia_256_Cbc,
		Cipher_3des_Cbc,
		Cipher_Arcfour_128,
		Cipher_Gost28147_Tc26z_Cnt,
		Cipher_Null,
		Cipher_Mac_Md5,
		Cipher_Mac_Sha1,
		Cipher_Mac_Sha256,
		Cipher_Mac_Sha384,
		Cipher_Gost28147_Tc26z_Imit,
		Cipher_Mac_Aead,
		KeyExchange_All,
		KeyExchange_Gost_All,
		KeyExchange_Rsa,
		KeyExchange_Rsa_Psk,
		KeyExchange_Rsa_Export,
		KeyExchange_Dhe_Rsa,
		KeyExchange_Dhe_Dss,
		KeyExchange_Srp,
		KeyExchange_Srp_Rsa,
		KeyExchange_Srp_Dss,
		KeyExchange_Psk,
		KeyExchange_Dhe_Psk,
		KeyExchange_Ecdhe_Psk,
		KeyExchange_Ecdhe_Rsa,
		KeyExchange_Ecdhe_Ecdsa,
		KeyExchange_Vko_Gost_12,
		KeyExchange_Anon_Ecdh,
		KeyExchange_Anon_Dh,
		KeyExchange_Mac_All,
		KeyExchange_Mac_Gost_All,
		Mac_Md5,
		Mac_Sha1,
		Mac_Sha256,
		Mac_Sha384,
		Mac_Gost28147_Tc26z_Imit,
		Mac_Aead,
		Compress_All,
		Compress_Null,
		Compress_Deflate,
		Protocol_All,
		Protocol_Tls_All,
		Protocol_Dtls_All,
		Protocol_Tls10,
		Protocol_Tls11,
		Protocol_Tls12,
		Protocol_Tls13,
		Protocol_Dtls09,
		Protocol_Dtls10,
		Protocol_Dtls12,
		Sign_All,
		Sign_Gost_All,
		Sign_Rsa_Sha1,
		Sign_Rsa_Sha224,
		Sign_Rsa_Sha256,
		Sign_Rsa_Sha384,
		Sign_Rsa_Sha512,
		Sign_Dsa_Sha1,
		Sign_Dsa_Sha224,
		Sign_Dsa_Sha256,
		Sign_Rsa_Md5,
		Sign_Ecdsa_Sha1,
		Sign_Ecdsa_Sha224,
		Sign_Ecdsa_Sha256,
		Sign_Ecdsa_Sha384,
		Sign_Ecdsa_Sha512,
		Sign_Eddsa_Ed25519,
		Sign_Eddsa_Ed448,
		Sign_Rsa_Pss_Sha256,
		Sign_Rsa_Pss_Sha384,
		Sign_Rsa_Pss_Sha512,
		Sign_Gostr341001,
		Sign_Gostr341012_256,
		Sign_Gostr341012_512,
		Group_All,
		Group_Dh_All,
		Group_Gost_All,
		Group_Ec_All,
		Group_Secp192r1,
		Group_Secp224r1,
		Group_Secp256r1,
		Group_Secp384r1,
		Group_Secp521r1,
		Group_X25519,
		Group_X448,
		Group_Gc256b,
		Group_Gc512a,
		Group_Ffdhe2048,
		Group_Ffdhe3072,
		Group_Ffdhe4096,
		Group_Ffdhe6144,
		Group_Ffdhe8192,
		Curve_Secp192r1,
		Curve_Secp224r1,
		Curve_Secp256r1,
		Curve_Secp384r1,
		Curve_Secp521r1,
		Curve_X25519,
		Curve_X448,
		Curve_All,
		Certificate_All,
		Certificate_Cli_All,
		Certificate_Srv_All,
		Certificate_X509,
		Certificate_Rawpk,
		Certificate_Cli_X509,
		Certificate_Srv_X509,
		Certificate_Cli_Rawpk,
		Certificate_Srv_Rawpk,

	}
}
