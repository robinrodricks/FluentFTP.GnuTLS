using FluentFTP.GnuTLS.Enums;
using System;
using System.Runtime.InteropServices;

namespace FluentFTP.GnuTLS.Core {
	internal static class GnuTls {

		// running under linux type os?
		private static bool linux = false;

		static GnuTls() {
			PlatformID platformID = Environment.OSVersion.Platform;

			if ((int)platformID == 4 || (int)platformID == 6 || (int)platformID == 128) {
				linux = true;
			}
		}

		// G l o b a l

		public static int GnuTlsInit(ref IntPtr session, InitFlagsT flags) {
			return linux ?
				GnuTlsLin.gnutls_init(ref session, flags) :
				GnuTlsWin.gnutls_init(ref session, flags);
		}
		public static void GnuTlsDeinit(IntPtr session) {
			if (linux) GnuTlsLin.gnutls_deinit(session);
			else GnuTlsWin.gnutls_deinit(session);
		}

		public static int gnutls_certificate_allocate_credentials(ref IntPtr res) {
			return linux ?
				GnuTlsLin.gnutls_certificate_allocate_credentials(ref res) :
				GnuTlsWin.gnutls_certificate_allocate_credentials(ref res);
		}

		public static void gnutls_certificate_free_credentials(IntPtr sc) {
			if (linux) GnuTlsLin.gnutls_certificate_free_credentials(sc);
			else GnuTlsWin.gnutls_certificate_free_credentials(sc);
		}

		public static string GnuTlsCheckVersion(string reqVersion) {
			return Marshal.PtrToStringAnsi(linux ?
				GnuTlsLin.gnutls_check_version(reqVersion) :
				GnuTlsWin.gnutls_check_version(reqVersion));
		}

		public static void GnuTlsGlobalSetLogFunction(Logging.GnuTlsLogCBFunc logCBFunc) {
			if (linux) GnuTlsLin.gnutls_global_set_log_function(logCBFunc);
			else GnuTlsWin.gnutls_global_set_log_function(logCBFunc);
		}

		public static void GnuTlsGlobalSetLogLevel(int level) {
			if (linux) GnuTlsLin.gnutls_global_set_log_level(level);
			else GnuTlsWin.gnutls_global_set_log_level(level);
		}

		public static int GnuTlsGlobalInit() {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_global_init() :
				GnuTlsWin.gnutls_global_init());
		}

		public static void GnuTlsGlobalDeInit() {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_global_deinit();
			else GnuTlsWin.gnutls_global_deinit();
		}

		public static void GnuTlsFree(IntPtr ptr) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.GnuTlsFree(ptr);
			else GnuTlsWin.GnuTlsFree(ptr);
		}

		// S e s s i o n

		// G N U T L S API calls for session init / deinit

		public static IntPtr GnuTlsSessionGetPtr(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_session_get_ptr(sess.ptr) :
				GnuTlsWin.gnutls_session_get_ptr(sess.ptr);
		}

		public static void GnuTlsSessionSetPtr(Session sess, IntPtr ptr) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_session_set_ptr(sess.ptr, ptr);
			else GnuTlsWin.gnutls_session_set_ptr(sess.ptr, ptr);
		}

		public static void GnuTlsDbSetCacheExpiration(Session sess, int seconds) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_db_set_cache_expiration(sess.ptr, seconds);
			else GnuTlsWin.gnutls_db_set_cache_expiration(sess.ptr, seconds);
		}

		// Info

		public static string GnuTlsSessionGetDesc(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr descPtr = linux ?
				GnuTlsLin.gnutls_session_get_desc(sess.ptr) :
				GnuTlsWin.gnutls_session_get_desc(sess.ptr);

			string desc = Marshal.PtrToStringAnsi(descPtr);

			GnuTlsFree(descPtr);

			return desc;
		}

		public static string GnuTlsProtocolGetName(ProtocolT version) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr namePtr = linux ?
				GnuTlsLin.gnutls_protocol_get_name(version) :
				GnuTlsWin.gnutls_protocol_get_name(version);

			string name = Marshal.PtrToStringAnsi(namePtr);

			// GnuTlsFree(namePtr); strangely enough, this free seems unneeded

			return name;
		}

		public static ProtocolT GnuTlsProtocolGetVersion(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return (ProtocolT)GnuUtils.Check(gcm, (int)(linux ?
				GnuTlsLin.gnutls_protocol_get_version(sess.ptr) :
				GnuTlsWin.gnutls_protocol_get_version(sess.ptr)));
		}

		public static int GnuTlsRecordGetMaxSize(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_record_get_max_size(sess.ptr) :
				GnuTlsWin.gnutls_record_get_max_size(sess.ptr);
		}

		public static AlertDescriptionT GnuTlsAlertGet(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_alert_get(sess.ptr) :
				GnuTlsWin.gnutls_alert_get(sess.ptr);
		}

		public static string GnuTlsAlertGetName(AlertDescriptionT alert) {
			return Marshal.PtrToStringAnsi(linux ?
				GnuTlsLin.gnutls_get_alert_name(alert) :
				GnuTlsWin.gnutls_get_alert_name(alert));
		}

		public static bool GnuTlsErrorIsFatal(int error) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_error_is_fatal(error) :
				GnuTlsWin.gnutls_error_is_fatal(error);
		}

		// Traffic

		public static int GnuTlsHandShake(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			int result;
			do {
				result = linux ?
					GnuTlsLin.gnutls_handshake(sess.ptr) :
					GnuTlsWin.gnutls_handshake(sess.ptr);
				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) { break; }
				Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " repeat due to " + Enum.GetName(typeof(EC.en), result));
			} while (result == (int)EC.en.GNUTLS_E_AGAIN ||
					 result == (int)EC.en.GNUTLS_E_INTERRUPTED ||
					 result == (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED ||
					 result == (int)EC.en.GNUTLS_E_GOT_APPLICATION_DATA);

			return GnuUtils.Check(gcm, result);
		}

		public static void GnuTlsHandshakeSetHookFunction(Session sess, uint htype, int when, GnuTlsInternalStream.GnuTlsHandshakeHookFunc handshakeHookFunc) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_handshake_set_hook_function(sess.ptr, htype, when, handshakeHookFunc);
			else GnuTlsWin.gnutls_handshake_set_hook_function(sess.ptr, htype, when, handshakeHookFunc);
		}

		public static int GnuTlsBye(Session sess, CloseRequestT how) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			int result;
			do {
				result = linux ?
					GnuTlsLin.gnutls_bye(sess.ptr, how) :
					GnuTlsWin.gnutls_bye(sess.ptr, how);
				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) { break; }
				Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " repeat due to " + Enum.GetName(typeof(EC.en), result));
			} while (result == (int)EC.en.GNUTLS_E_AGAIN ||
					 result == (int)EC.en.GNUTLS_E_INTERRUPTED);

			return GnuUtils.Check(gcm, result);
		}

		public static void GnuTlsHandshakeSetTimeout(Session sess, uint ms) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_handshake_set_timeout(sess.ptr, ms);
			else GnuTlsWin.gnutls_handshake_set_timeout(sess.ptr, ms);
		}

		public static int GnuTlsRecordCheckPending(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_record_check_pending(sess.ptr) :
				GnuTlsWin.gnutls_record_check_pending(sess.ptr);
		}

		// Priorities

		public static int GnuTlsSetDefaultPriority(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_set_default_priority(sess.ptr) :
				GnuTlsWin.gnutls_set_default_priority(sess.ptr));
		}

		public static int GnuTlsPrioritySetDirect(Session sess, string priorities) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr errPos; // does not seem terribly useful...
			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_priority_set_direct(sess.ptr, priorities, out errPos) :
				GnuTlsWin.gnutls_priority_set_direct(sess.ptr, priorities, out errPos));
		}

		public static int GnuTlsSetDefaultPriorityAppend(Session sess, string priorities) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr errPos; // does not seem terribly useful...
			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_set_default_priority_append(sess.ptr, priorities, out errPos, 0) :
				GnuTlsWin.gnutls_set_default_priority_append(sess.ptr, priorities, out errPos, 0));
		}

		public static int GnuTlsDhSetPrimeBits(Session sess, uint bits) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_dh_set_prime_bits(sess.ptr, bits) :
				GnuTlsWin.gnutls_dh_set_prime_bits(sess.ptr, bits));
		}

		// Transport

		public static void GnuTlsTransportSetPtr(Session sess, IntPtr socketDescriptor) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_transport_set_ptr(sess.ptr, socketDescriptor);
			else GnuTlsWin.gnutls_transport_set_ptr(sess.ptr, socketDescriptor);
		}

		public static void GnuTlsTransportSetInt2(Session sess, int socketDescriptorRecv, int socketDescriptorSend) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_transport_set_int2(sess.ptr, socketDescriptorRecv, socketDescriptorSend);
			else GnuTlsWin.gnutls_transport_set_int2(sess.ptr, socketDescriptorRecv, socketDescriptorSend);
		}

		public static int GnuTlsRecordRecv(IntPtr session, byte[] data, int data_size) {
			return linux ?
				GnuTlsLin.gnutls_record_recv(session, data, data_size) :
				GnuTlsWin.gnutls_record_recv(session, data, data_size);
		}

		public static int GnuTlsRecordSend(IntPtr session, byte[] data, int data_size) {
			return linux ?
				GnuTlsLin.gnutls_record_send(session, data, data_size) :
				GnuTlsWin.gnutls_record_send(session, data, data_size);
		}

		// Session Resume

		public static bool GnuTlsSessionIsResumed(Session sess) {
			return linux ?
				GnuTlsLin.gnutls_session_is_resumed(sess.ptr) :
				GnuTlsWin.gnutls_session_is_resumed(sess.ptr);
		}

		public static int GnuTlsSessionGetData2(Session sess, out DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_session_get_data2(sess.ptr, out data) :
				GnuTlsWin.gnutls_session_get_data2(sess.ptr, out data));
		}
		// Special overload for HandshakeHook callback function
		public static int GnuTlsSessionGetData2(IntPtr sess, out DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_session_get_data2(sess, out data) :
				GnuTlsWin.gnutls_session_get_data2(sess, out data));
		}

		public static int GnuTlsSessionSetData(Session sess, DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_session_set_data(sess.ptr, data.ptr, data.size) :
				GnuTlsWin.gnutls_session_set_data(sess.ptr, data.ptr, data.size));
		}
		// Special overload for HandshakeHook callback function
		public static int GnuTlsSessionSetData(IntPtr sess, DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_session_set_data(sess, data.ptr, data.size) :
				GnuTlsWin.gnutls_session_set_data(sess, data.ptr, data.size));
		}

		public static SessionFlagsT GnuTlsSessionGetFlags(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_session_get_flags(sess.ptr) :
				GnuTlsWin.gnutls_session_get_flags(sess.ptr);
		}
		// Special overload for HandshakeHook callback function
		public static SessionFlagsT GnuTlsSessionGetFlags(IntPtr sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_session_get_flags(sess) :
				GnuTlsWin.gnutls_session_get_flags(sess);
		}

		// ALPN

		public static int GnuTlsAlpnSetProtocols(Session sess, string protocols) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			var datumPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DatumT>());
			var valuePtr = Marshal.StringToHGlobalAnsi(protocols);

			Marshal.StructureToPtr(new DatumT { ptr = valuePtr, size = (uint)protocols.Length + 1 }, datumPtr, true);

			int result = GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_alpn_set_protocols(sess.ptr, datumPtr, 1, AlpnFlagsT.GNUTLS_ALPN_MANDATORY) :
				GnuTlsWin.gnutls_alpn_set_protocols(sess.ptr, datumPtr, 1, AlpnFlagsT.GNUTLS_ALPN_MANDATORY));

			Marshal.FreeHGlobal(valuePtr);
			Marshal.FreeHGlobal(datumPtr);

			return result;
		}

		public static string GnuTlsAlpnGetSelectedProtocol(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			DatumT data = new DatumT();

			_ = GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_alpn_get_selected_protocol(sess.ptr, data) :
				GnuTlsWin.gnutls_alpn_get_selected_protocol(sess.ptr, data),
				(int)EC.en.GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

			return Marshal.PtrToStringAnsi(data.ptr);
		}

		// C r e d e n t i a l s

		// G N U T L S API calls for certificate credentials init / deinit

		// Set

		public static int GnuTlsCredentialsSet(Credentials cred, Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, linux ?
				GnuTlsLin.gnutls_credentials_set(sess.ptr, CredentialsTypeT.GNUTLS_CRD_CERTIFICATE, cred.ptr) :
				GnuTlsWin.gnutls_credentials_set(sess.ptr, CredentialsTypeT.GNUTLS_CRD_CERTIFICATE, cred.ptr));
		}
		// Info

		public static bool GnuTlsCertificateClientGetRequestStatus(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_certificate_client_get_request_status(sess.ptr) :
				GnuTlsWin.gnutls_certificate_client_get_request_status(sess.ptr);
		}

		// C e r t i f i c a t e  V e r i f i c a t i o n

		public static int GnuTlsCertificateAllocateCredentials(ref IntPtr res) {
			return linux ?
				GnuTlsLin.gnutls_certificate_allocate_credentials(ref res) :
				GnuTlsWin.gnutls_certificate_allocate_credentials(ref res);
		}

		public static void GnuTlsCertificateFreeCredentials(IntPtr sc) {
			if (linux) GnuTlsLin.gnutls_certificate_free_credentials(sc);
			else GnuTlsWin.gnutls_certificate_free_credentials(sc);
		}

		public static int GnuTlsCertificateVerifyPeers3(Session sess, string hostname, out CertificateStatusT status) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			CertificateStatusT temp;

			int result = linux ?
				GnuTlsLin.gnutls_certificate_verify_peers3(sess.ptr, hostname, out temp) :
				GnuTlsWin.gnutls_certificate_verify_peers3(sess.ptr, hostname, out temp);

			status = temp;

			return GnuUtils.Check(gcm, result);
		}

		public static void GnuTlsCertificateSetVerifyFlags(CertificateCredentials res, CertificateVerifyFlagsT flags) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			if (linux) GnuTlsLin.gnutls_certificate_set_verify_flags(res.ptr, flags);
			else GnuTlsWin.gnutls_certificate_set_verify_flags(res.ptr, flags);
		}

		public static CertificateTypeT GnuTlsCertificateTypeGet2(Session sess, CtypeTargetT target) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_certificate_type_get2(sess.ptr, target) :
				GnuTlsWin.gnutls_certificate_type_get2(sess.ptr, target);
		}

		// Retrieve certificate(s)

		public static DatumT[] GnuTlsCertificateGetPeers(Session sess, ref uint listSize) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr datumTAPtr = linux ?
				GnuTlsLin.gnutls_certificate_get_peers(sess.ptr, ref listSize) :
				GnuTlsWin.gnutls_certificate_get_peers(sess.ptr, ref listSize);

			if (listSize == 0) { return null; }

			ulong datumTAInt = (ulong)datumTAPtr;

			DatumT[] peers = new DatumT[listSize];

			for (int i = 0; i < listSize; i++) {
				peers[i] = Marshal.PtrToStructure<DatumT>((IntPtr)datumTAInt);
				datumTAInt += 16;
			}

			return peers;
		}

		// X 5 0 9

		public static int GnuTlsX509CrtInit(ref IntPtr cert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_x509_crt_init(ref cert) :
				GnuTlsWin.gnutls_x509_crt_init(ref cert);
		}

		public static int GnuTlsX509CrtDeinit(IntPtr cert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_x509_crt_deinit(cert) :
				GnuTlsWin.gnutls_x509_crt_deinit(cert);
		}

		public static int GnuTlsX509CrtImport(IntPtr cert, ref DatumT data, X509CrtFmtT format) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_x509_crt_import(cert, ref data, format) :
				GnuTlsWin.gnutls_x509_crt_import(cert, ref data, format);
		}

		public static int GnuTlsX509CrtPrint(IntPtr cert, CertificatePrintFormatsT format, ref DatumT output) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_x509_crt_print(cert, format, ref output) :
				GnuTlsWin.gnutls_x509_crt_print(cert, format, ref output);
		}

		public static int GnuTlsX509CrtExport2(IntPtr cert, X509CrtFmtT format, ref DatumT output) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_x509_crt_export2(cert, format, ref output) :
				GnuTlsWin.gnutls_x509_crt_export2(cert, format, ref output);
		}

		public static int GnuTlsPcertImportRawpkRaw(IntPtr pcert, ref DatumT data, X509CrtFmtT format, uint keyUsage, uint flags) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return linux ?
				GnuTlsLin.gnutls_pcert_import_rawpk_raw(pcert, ref data, format, keyUsage, flags) :
				GnuTlsWin.gnutls_pcert_import_rawpk_raw(pcert, ref data, format, keyUsage, flags);
		}

	}
}