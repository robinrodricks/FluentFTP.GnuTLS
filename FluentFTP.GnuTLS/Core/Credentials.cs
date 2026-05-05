using System;

namespace FluentFTP.GnuTLS.Core {
	internal abstract class Credentials : IDisposable {
		private bool _disposed = false;

		public IntPtr ptr;

		public CredentialsTypeT credentialsType;

		public Credentials(CredentialsTypeT type) {
			credentialsType = type;
		}

		public void Dispose() {
			Dispose(true);

			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing) {
			if (!_disposed) {
				if (disposing) {
					// managed resources would be disposed here, but there are none in this class
				}
				if (ptr != IntPtr.Zero) {
					// Free the unmanaged resources
					string gcm = GnuUtils.GetCurrentMethod() + ":CertificateCredentials";
					Logging.LogGnuFunc(gcm);

					GnuTls.GnuTlsCertificateFreeCredentials(ptr);
					ptr = IntPtr.Zero;
				}

				// Mark the object as disposed
				_disposed = true;
			}
		}

		~Credentials() {
			Dispose(false);
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
	}
}
