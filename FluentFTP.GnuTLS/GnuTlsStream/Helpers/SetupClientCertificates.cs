using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentFTP.GnuTLS.Core;
using FluentFTP.GnuTLS.Enums;

namespace FluentFTP.GnuTLS {

	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		private void SetupClientCertificates(X509CertificateCollection certs) {

			//
			// TODO: Setup (if any) client certificates for verification
			//       by the server, at this point.
			// ****
			//

			Logging.LogGnuFunc(GnuMessage.Handshake, "*SetupClientCertificates(...) - currently being implemented");

			foreach (X509Certificate2 cert in certs) {
				string pass = "testtest";

				string certData = ExportCertToPEM(cert);

				string keyData = ExportKeyToPEM(cert);

				int oldMaxLevel = Logging.LogMaxLevel;
				Logging.LogMaxLevel = 99;

				_ = GnuTls.GnutlsCertificateSetX509KeyMem2(cred.ptr, certData, keyData, X509CrtFmtT.GNUTLS_X509_FMT_PEM, pass, 0);

				Logging.LogMaxLevel = oldMaxLevel;
			}
		}

		private static string ExportCertToPEM(X509Certificate2 cert) {
			StringBuilder builder = new StringBuilder();

			builder.AppendLine("-----BEGIN CERTIFICATE-----");
			builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Pkcs12), Base64FormattingOptions.InsertLineBreaks));
			builder.AppendLine("-----END CERTIFICATE-----");

			return builder.ToString();
		}

		private static string ExportKeyToPEM(X509Certificate2 cert) {
			StringBuilder builder = new StringBuilder();

			builder.AppendLine("-----BEGIN PRIVATE KEY-----");
			builder.AppendLine("*****TODO TODO TODO********");
			builder.AppendLine("-----END PRIVATE KEY-----");

			return builder.ToString();
		}
	}
}

