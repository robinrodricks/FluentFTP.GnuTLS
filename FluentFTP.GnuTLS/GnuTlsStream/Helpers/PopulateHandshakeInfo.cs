using System;
using System.IO;
using System.Security.Authentication;
using FluentFTP.GnuTLS.Core;
using FluentFTP.GnuTLS.Enums;

namespace FluentFTP.GnuTLS {

	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		public void PopulateHandshakeInfo() {

			// This will be the GnuTLS format of the protocol name
			// TLS1.2, TLS1.3 or other
			ProtocolName = GnuTls.GnuTlsProtocolGetName(GnuTls.GnuTlsProtocolGetVersion(sess));

			// Try to "back-translate" to SslStream / System.Net.Security 
			if (ProtocolName == "TLS1.2") {
				SslProtocol = SslProtocols.Tls12;
			}
			else if (ProtocolName == "TLS1.3") {
				// Cannot set TLS1.3 on all builds, even if GnuTLS can do it, .NET can not
#if NET5_0_OR_GREATER
				SslProtocol = SslProtocols.Tls13;
#else
				SslProtocol = SslProtocols.None;
#endif
			}
			else {
				SslProtocol = SslProtocols.None;
			}

			// (TLS1.2)-(ECDHE-SECP384R1)-(ECDSA-SHA384)-(AES-256-GCM)
			// (TLS1.3)-(ECDHE-SECP256R1)-(ECDSA-SECP256R1-SHA256)-(AES-256-GCM)
			CipherSuite = GnuTls.GnuTlsSessionGetDesc(sess);

			// ftp / ftp-data
			AlpnProtocol = GnuTls.GnuTlsAlpnGetSelectedProtocol(sess);

			// Maximum record size
			MaxRecordSize = GnuTls.GnuTlsRecordGetMaxSize(sess);
			Logging.LogGnuFunc(GnuMessage.Handshake, "Maximum record size: " + MaxRecordSize);

			// Is this session a resume one?
			IsResumed = GnuTls.GnuTlsSessionIsResumed(sess);
			if (IsResumed) {
				Logging.LogGnuFunc(GnuMessage.Handshake, "Session is resumed from control connection");
			}

		}

	}
}
