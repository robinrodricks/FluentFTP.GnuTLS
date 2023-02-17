﻿using System;
using System.Collections.Generic;
using System.Text;

namespace FluentFTP.GnuTLS.Priority {
	internal static class PriorityConstants {

		public static List<string> Suites = new List<string> {
			"PERFORMANCE", "NORMAL", "LEGACY", "PFS", "SECURE128", "SECURE192", "SECURE256", "SUITEB128", "SUITEB192", "NONE"
		};

		public static List<string> Options = new List<string>{
			"GOST", "CIPHER-ALL", "CIPHER-GOST-ALL", "AES-128-GCM", "AES-256-GCM", "AES-128-CCM", "AES-256-CCM", "CHACHA20-POLY1305", "AES-128-CCM-8", "AES-256-CCM-8", "CAMELLIA-128-GCM", "CAMELLIA-256-GCM", "AES-128-CBC", "AES-256-CBC", "CAMELLIA-128-CBC", "CAMELLIA-256-CBC", "3DES-CBC", "ARCFOUR-128", "GOST28147-TC26Z-CNT", "NULL", "MAC-MD5", "MAC-SHA1", "MAC-SHA256", "MAC-SHA384", "GOST28147-TC26Z-IMIT", "MAC-AEAD", "KX-ALL", "KX-GOST-ALL", "RSA", "RSA-PSK", "RSA-EXPORT", "DHE-RSA", "DHE-DSS", "SRP", "SRP-RSA", "SRP-DSS", "PSK", "DHE-PSK", "ECDHE-PSK", "ECDHE-RSA", "ECDHE-ECDSA", "VKO-GOST-12", "ANON-ECDH", "ANON-DH", "MAC-ALL", "MAC-GOST-ALL", "MD5", "SHA1", "SHA256", "SHA384", "GOST28147-TC26Z-IMIT", "AEAD", "COMP-ALL", "COMP-NULL", "COMP-DEFLATE", "VERS-ALL", "VERS-TLS-ALL", "VERS-DTLS-ALL", "VERS-TLS1.0", "VERS-TLS1.1", "VERS-TLS1.2", "VERS-TLS1.3", "VERS-DTLS0.9", "VERS-DTLS1.0", "VERS-DTLS1.2", "SIGN-ALL", "SIGN-GOST-ALL", "SIGN-RSA-SHA1", "SIGN-RSA-SHA224", "SIGN-RSA-SHA256", "SIGN-RSA-SHA384", "SIGN-RSA-SHA512", "SIGN-DSA-SHA1", "SIGN-DSA-SHA224", "SIGN-DSA-SHA256", "SIGN-RSA-MD5", "SIGN-ECDSA-SHA1", "SIGN-ECDSA-SHA224", "SIGN-ECDSA-SHA256", "SIGN-ECDSA-SHA384", "SIGN-ECDSA-SHA512", "SIGN-EdDSA-Ed25519", "SIGN-EdDSA-Ed448", "SIGN-RSA-PSS-SHA256", "SIGN-RSA-PSS-SHA384", "SIGN-RSA-PSS-SHA512", "SIGN-GOSTR341001", "SIGN-GOSTR341012-256", "SIGN-GOSTR341012-512", "GROUP-ALL", "GROUP-DH-ALL", "GROUP-GOST-ALL", "GROUP-EC-ALL", "GROUP-SECP192R1", "GROUP-SECP224R1", "GROUP-SECP256R1", "GROUP-SECP384R1", "GROUP-SECP521R1", "GROUP-X25519", "GROUP-X448", "GROUP-GC256B", "GROUP-GC512A", "GROUP-FFDHE2048", "GROUP-FFDHE3072", "GROUP-FFDHE4096", "GROUP-FFDHE6144", "GROUP-FFDHE8192", "CURVE-SECP192R1", "CURVE-SECP224R1", "CURVE-SECP256R1", "CURVE-SECP384R1", "CURVE-SECP521R1", "CURVE-X25519", "CURVE-X448", "CURVE-ALL", "CTYPE-ALL", "CTYPE-CLI-ALL", "CTYPE-SRV-ALL", "CTYPE-X509", "CTYPE-RAWPK", "CTYPE-CLI-X509", "CTYPE-SRV-X509", "CTYPE-CLI-RAWPK", "CTYPE-SRV-RAWPK",
		};

		public static List<string> Specials = new List<string>{
			"%COMPAT", "%DUMBFW", "%NO_EXTENSIONS", "%NO_STATUS_REQUEST", "%NO_TICKETS", "%NO_TICKETS_TLS12", "%NO_SESSION_HASH", "%SERVER_PRECEDENCE", "%SSL3_RECORD_VERSION", "%LATEST_RECORD_VERSION", "%DISABLE_WILDCARDS", "%NO_ETM", "%FORCE_ETM", "%DISABLE_SAFE_RENEGOTIATION", "%UNSAFE_RENEGOTIATION", "%PARTIAL_RENEGOTIATION", "%SAFE_RENEGOTIATION", "%FALLBACK_SCSV", "%DISABLE_TLS13_COMPAT_MODE", "%VERIFY_ALLOW_BROKEN", "%VERIFY_ALLOW_SIGN_RSA_MD5", "%VERIFY_ALLOW_SIGN_WITH_SHA1", "%VERIFY_DISABLE_CRL_CHECKS", "%VERIFY_ALLOW_X509_V1_CA_CRT",
		};

		public static List<string> Profiles = new List<string>{
			"%PROFILE_LOW", "%PROFILE_LEGACY", "%PROFILE_MEDIUM", "%PROFILE_HIGH", "%PROFILE_ULTRA", "%PROFILE_FUTURE", "%PROFILE_SUITEB128", "%PROFILE_SUITEB192",
		};


	}
}