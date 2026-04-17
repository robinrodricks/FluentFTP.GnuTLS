using System;

namespace FluentFTP.GnuTLS.Core {
	internal abstract class Session : IDisposable {
		private bool _disposed = false;

		public IntPtr ptr;

		protected Session(InitFlagsT flags) {
			string gcm = GnuUtils.GetCurrentMethod() + ":Session";
			Logging.LogGnuFunc(gcm);

			_ = GnuUtils.Check(gcm, GnuTls.GnuTlsInit(ref ptr, flags));
		}
		protected virtual void Dispose(bool disposing) {
			if (!_disposed) {
				if (disposing) {
					// Free any other managed objects here.
				}

				// Free any unmanaged objects here.
				if (ptr != IntPtr.Zero) {
					string gcm = GnuUtils.GetCurrentMethod() + ":Session";
					Logging.LogGnuFunc(gcm);

					GnuTls.GnuTlsDeinit(ptr);
					ptr = IntPtr.Zero;
				}

				// Note that the object has been disposed.
				_disposed = true;
			}
		}

		public void Dispose() {
			Dispose(true);

			// Use SupressFinalize in case a subclass
			// of this type implements a finalizer.
			GC.SuppressFinalize(this);
		}

		~Session() {
			Dispose(false);
		}

	}

	internal class ClientSession : Session {

		public ClientSession() : base(InitFlagsT.GNUTLS_CLIENT) {
		}
		public ClientSession(InitFlagsT flags) : base(InitFlagsT.GNUTLS_CLIENT | flags & ~InitFlagsT.GNUTLS_SERVER) {
		}
	}

	internal class ServerSession : Session {

		public ServerSession() : base(InitFlagsT.GNUTLS_SERVER) {
		}
		public ServerSession(InitFlagsT flags) : base(InitFlagsT.GNUTLS_SERVER | flags & ~InitFlagsT.GNUTLS_CLIENT) {
		}
	}
}
