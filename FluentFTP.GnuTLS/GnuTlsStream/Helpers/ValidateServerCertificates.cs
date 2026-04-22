using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using FluentFTP.GnuTLS.Core;
using FluentFTP.GnuTLS.Enums;

namespace FluentFTP.GnuTLS {

	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		private void ValidateServerCertificates(CustomRemoteCertificateValidationCallback customRemoteCertificateValidation) {

			// Set Certificate Verification Profile and Flags
			// If no profile is set (uppermost 8 bits), it is taken from the priority string, please
			// read the GnuTLS docs on "priority strings".
			// If no flags are set, the internal default is used.

			// You could set these flags programmatically here, to overide the priority mechanism,
			// if you uncomment this statement:
			// Native.GnuTlsCertificateSetVerifyFlags(cred, (CertificateVerifyFlagsT)0x00FFFFFF);

			//
			// Perform the GnuTls internal validation, it is part of the handshake process
			//
			GnuTls.GnuTlsCertificateVerifyPeers3(sess, hostname, out CertificateStatusT serverCertificateStatus);

			string serverCertificateStatusText = serverCertificateStatus.ToString("G");
			if (serverCertificateStatusText == "0") {
				serverCertificateStatusText = string.Empty;
			}

			if (serverCertificateStatus != 0) {
				Logging.LogGnuFunc(GnuMessage.Handshake, "Internal server certificate validation function reports:");
				Logging.LogGnuFunc(GnuMessage.Handshake, serverCertificateStatusText);
			}

			//
			// Setup the (possibly) user supplied external validation callback
			//

			//
			// Determine the type of the servers certificate(s)/key and get the certList out
			// from them.
			//
			CertificateTypeT certificateType = GnuTls.GnuTlsCertificateTypeGet2(sess, CtypeTargetT.GNUTLS_CTYPE_PEERS);

			string serverCertificate = string.Empty;

			switch (certificateType) {

				case CertificateTypeT.GNUTLS_CRT_X509:

					// Extract X509 certificate(s)
					GetCertInfoX509(out serverCertificate);

					break;

				case CertificateTypeT.GNUTLS_CRT_RAWPK:

					// Extract Raw Public Key "certificate(s)"
					GetCertInfoRAWPK();

					break;

				default:
					break;

			}

			//
			// TODO: **** DONE
			// Convert the servers certificate, which is available now in a PEM format in
			// a string, to the .NET certificate type. This is then passed to the callback
			// in the same format as it is in the SslStream validation callback, for coding
			// compatibility.
			//

			X509Certificate valCert = null;

			if (!string.IsNullOrEmpty(serverCertificate)) {
#pragma warning disable SYSLIB0057 // Type or member is obsolete
				valCert = new X509Certificate2(Encoding.ASCII.GetBytes(serverCertificate));
#pragma warning restore SYSLIB0057 // Type or member is obsolete
			}

			//
			// TODO:
			// Convert the servers certificate chain to the .NET format.
			//

			X509Chain valChain = null;

			//
			// Invoke any external user supplied validation callback
			//
			if (!customRemoteCertificateValidation(this, valCert, valChain, serverCertificateStatusText)) {
				string text = "The remote certificate was rejected by the provided RemoteCertificateValidationCallback.";
				Logging.LogGnuFunc(GnuMessage.ClientCertificateValidation, text);
				throw new AuthenticationException(text, new GnuTlsException("Certificate validation failure: " + serverCertificateStatusText));
			}

			// End of method here
			// Local context functions:

			//
			// Extract X509 certificate(s)
			//
			#region GetCertInfoX509(out string pCertS)

			void GetCertInfoX509(out string pCertS) {

				pCertS = string.Empty;

				DatumT[] certList;
				uint certListLength = 0;

				// Get the servers list of X.509 certificates, these will be in DER format
				certList = GnuTls.GnuTlsCertificateGetPeers(sess, ref certListLength);
				if (certListLength == 0) {
					Logging.LogGnuFunc(GnuMessage.X509, "No certificates found");
					return;
				}

				string s = "Certificate type: X.509, list contains " + certListLength + " certificate" + (certListLength > 1 ? "s" : "");
				Logging.LogGnuFunc(GnuMessage.X509, s);

				for (uint i = 0; i < certListLength; i++) {

					if (weAreControlConnection) {
						Logging.LogGnuFunc(GnuMessage.X509, "Certificate #" + (i + 1));
					}

					IntPtr cert = IntPtr.Zero;

					int result = GnuTls.GnuTlsX509CrtInit(ref cert);

					if (result < 0) {
						Logging.LogGnuFunc(GnuMessage.X509, "Error allocating Memory");
						continue;
					}

					try {
						result = GnuTls.GnuTlsX509CrtImport(cert, ref certList[i], X509CrtFmtT.GNUTLS_X509_FMT_DER);
						if (result < 0) {
							Logging.LogGnuFunc(GnuMessage.X509, "Error decoding: " + GnuUtils.GnuTlsErrorText(result));
							continue;
						}

						DatumT pinfo = new();
						CertificatePrintFormatsT flag = CertificatePrintFormatsT.GNUTLS_CRT_PRINT_FULL;
						result = GnuTls.GnuTlsX509CrtPrint(cert, flag, ref pinfo);
						if (result == 0) {
							try {
								string pOutput = Marshal.PtrToStringAnsi(pinfo.ptr);
								if (weAreControlConnection) {
									Logging.LogGnuFunc(GnuMessage.ShowClientCertificateInfo, pOutput);
								}
							}
							finally {
								GnuTls.GnuTlsFree(pinfo.ptr);
							}
						}

						DatumT cinfo = new();
						result = GnuTls.GnuTlsX509CrtExport2(cert, X509CrtFmtT.GNUTLS_X509_FMT_PEM, ref cinfo);
						if (result == 0) {
							try {
								string cOutput = Marshal.PtrToStringAnsi(cinfo.ptr);
								if (weAreControlConnection) {
									Logging.LogGnuFunc(GnuMessage.ShowClientCertificatePEM, "X.509 Certificate (PEM)" + Environment.NewLine + cOutput);
								}
								pCertS = cOutput;
							}
							finally {
								GnuTls.GnuTlsFree(cinfo.ptr);
							}
						}
					}
					finally {
						GnuTls.GnuTlsX509CrtDeinit(cert);
					}
				}

				return;
			}
			#endregion

			//
			// Extract Raw Public Key "certificate(s)"
			//
			#region GetCertInfoRAWPK()

			void GetCertInfoRAWPK() {

				DatumT[] certList;
				uint certListLength = 0;

				// Get the servers list of Raw Public Key certificates, these will be in DER format
				certList = GnuTls.GnuTlsCertificateGetPeers(sess, ref certListLength);
				if (certListLength == 0) {
					Logging.LogGnuFunc(GnuMessage.RAWPK, "No certificates found");
					return;
				}

				//Logging.LogGnuFunc("Certificate type: Raw Public Key, list contains " + certListLength);

				IntPtr cert = IntPtr.Zero;
				// PkAlgorithmT algo;
				// DatumT cinfo = new();

				try {
					int result = GnuTls.GnuTlsPcertImportRawpkRaw(cert, ref certList[0], X509CrtFmtT.GNUTLS_X509_FMT_DER, 0, 0);
					if (result < 0) {
						Logging.LogGnuFunc(GnuMessage.RAWPK, "Error decoding: " + GnuUtils.GnuTlsErrorText(result));
						return;
					}

					if (weAreControlConnection) {

						//
						// TODO:
						//
						//pk_algo = gnutls_pubkey_get_pk_algorithm(pk_cert.pubkey, NULL);

						//log_msg(out, "- Raw pk info:\n");
						//log_msg(out, " - PK algo: %s\n", gnutls_pk_algorithm_get_name(pk_algo));

						//if (print_cert) {
						//	gnutls_datum_t pem;

						//	ret = gnutls_pubkey_export2(pk_cert.pubkey, GNUTLS_X509_FMT_PEM, &pem);
						//	if (ret < 0) {
						//		fprintf(stderr, "Encoding error: %s\n",
						//			gnutls_strerror(ret));
						//		return;
						//	}

						//	log_msg(out, "\n%s\n", (char*)pem.certList);

					}

					//	gnutls_free(pem.certList);
					//}
				}
				finally {
				}

				return;
			}
			#endregion

		}

	}
}
