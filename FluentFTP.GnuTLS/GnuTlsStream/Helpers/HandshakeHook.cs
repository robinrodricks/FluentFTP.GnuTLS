using System;
using System.IO;
using FluentFTP.GnuTLS.Core;
using FluentFTP.GnuTLS.Enums;

namespace FluentFTP.GnuTLS {

	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		// handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned when, unsigned int incoming, const gnutls_datum_t* msg)
		public static int HandshakeHook(IntPtr session, uint htype, uint post, uint incoming, IntPtr msg) {

			if (session == (IntPtr)0) {
				return 0;
			}

			string action;

			// incoming  post
			// ==============
			//    1       0    received
			//    1       1    processed
			//
			//    0       0    about to send
			//    0       1    sent
			//

			if (incoming == 0) {
				// send
				action = post == 0 ? "about to send" : "sent";
			}
			else {
				// receive
				action = post == 0 ? "received" : "processed";
			}

			Logging.LogGnuFunc(GnuMessage.Handshake, "Handshake " + action + " " + Enum.GetName(typeof(HandshakeDescriptionT), htype));

			// Check for certain action/htype combinations

			if (incoming != 0 && post != 0) { // receive processed") 

				//
				// TLS1.2 : If the session ticket extension is active, a session ticket may appear
				//          ProFTPd server will do this, for example
				//          One can forbid this by setting GNUTLS_NO_TICKETS_TLS12 on the init flags
				//          or by using %NO_TICKETS_TLS12 in the priority string in config
				// TLS1.3 : A session ticket appeared
				//

				if (htype == (uint)HandshakeDescriptionT.GNUTLS_HANDSHAKE_NEW_SESSION_TICKET) {
					SessionFlagsT flags = GnuTls.GnuTlsSessionGetFlags(session);
					if (flags.HasFlag(SessionFlagsT.GNUTLS_SFLAGS_SESSION_TICKET)) {
						//No need to do anything here, as the session ticket is automatically handled by GnuTLS and
						//will be used for session resumption on the next connection. We just log that a session ticket was received.
						//If you wanted to manually handle the session ticket, you could retrieve it using GnuTlsSessionGetData2 and
						//store it for later use, but in most cases this is not necessary.
						//GnuTls.GnuTlsSessionGetData2(session, out DatumT resumeDataTLS);
						//Unneeded here: Store the session ticket data for later use (e.g., for session resumption)
						//GnuTls.GnuTlsSessionSetData(session, resumeDataTLS);
						//GnuTls.GnuTlsFree(resumeDataTLS.ptr);
						Logging.LogGnuFunc(GnuMessage.Handshake, "Session ticket received");

					}
				}

			}

			return 0;
		}
	}
}
