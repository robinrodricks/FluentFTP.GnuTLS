using System;

namespace FluentFTP.GnuTLS.Core {
	internal abstract class Credentials : IDisposable {

		public IntPtr ptr;

		public CredentialsTypeT credentialsType;

		protected Credentials(CredentialsTypeT type) {
			credentialsType = type;
		}

		public void Dispose() {
		}
	}

	internal class CertificateCredentials : Credentials, IDisposable {

		public CertificateCredentials() : base(CredentialsTypeT.GNUTLS_CRD_CERTIFICATE) {
			string gcm = GnuUtils.GetCurrentMethod() + ":CertificateCredentials";
			Logging.LogGnuFunc(gcm);

			_ = GnuUtils.Check("*GnuTlsCertificateAllocateCredentials(...)", GnuTls.GnuTlsCertificateAllocateCredentials(ref ptr) - 1);
		}

		public void Dispose() {
			if (ptr != IntPtr.Zero) {
				string gcm = GnuUtils.GetCurrentMethod() + ":CertificateCredentials";
				Logging.LogGnuFunc(gcm);

				GnuTls.GnuTlsCertificateFreeCredentials(ptr);
				ptr = IntPtr.Zero;
			}
		}
	}
}
