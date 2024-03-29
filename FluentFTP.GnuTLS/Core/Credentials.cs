﻿using System;

namespace FluentFTP.GnuTLS.Core {
	internal abstract class Credentials : IDisposable {

		public IntPtr ptr;

		public CredentialsTypeT credentialsType;

		public Credentials(CredentialsTypeT type) {
			credentialsType = type;
		}

		public virtual void Dispose() {
		}
	}

	internal class CertificateCredentials : Credentials, IDisposable {

		public CertificateCredentials() : base(CredentialsTypeT.GNUTLS_CRD_CERTIFICATE) {
			string gcm = GnuUtils.GetCurrentMethod() + ":CertificateCredentials";
			Logging.LogGnuFunc(gcm);

			_ = GnuUtils.Check("*GnuTlsCertificateAllocateCredentials(...)", GnuTls.GnuTlsCertificateAllocateCredentials(ref ptr));
		}

		public CertificateCredentials(CertificateCredentials cred) : base(CredentialsTypeT.GNUTLS_CRD_CERTIFICATE) {
			string gcm = GnuUtils.GetCurrentMethod() + ":CertificateCredentials";
			Logging.LogGnuFunc(gcm);

			ptr = cred.ptr;
			credentialsType = cred.credentialsType;

			_ = GnuUtils.Check("*GnuTlsCertificateAllocateCredentials(...)", GnuTls.GnuTlsCertificateAllocateCredentials(ref ptr));
		}

		public override void Dispose() {
			if (ptr != IntPtr.Zero) {
				string gcm = GnuUtils.GetCurrentMethod() + ":CertificateCredentials";
				Logging.LogGnuFunc(gcm);

				GnuTls.GnuTlsCertificateFreeCredentials(ptr);
				ptr = IntPtr.Zero;
			}
			base.Dispose();
		}
	}
}
