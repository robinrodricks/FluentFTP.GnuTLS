using System;
using System.IO;

namespace FluentFTP.GnuTLS {

	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		public void DisableNagle() {
			socket.NoDelay = true;
		}

		public void ReEnableNagle() {
			socket.NoDelay = false;
		}

	}
}
