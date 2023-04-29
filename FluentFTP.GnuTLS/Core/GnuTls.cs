using FluentFTP.GnuTLS.Enums;
using System;
using System.Runtime.InteropServices;

namespace FluentFTP.GnuTLS.Core {
	internal static class GnuTls {

		internal enum DllImportVariant {
			Windows,
			Linux,
		}

		internal static DllImportVariant useDllImportVariant;

		static GnuTls() {
			PlatformID platformID = Environment.OSVersion.Platform;

			if ((int)platformID == 6 || (int)platformID == 4 || (int)platformID == 128) {
				useDllImportVariant |= DllImportVariant.Linux;
			}
			else {
				useDllImportVariant = DllImportVariant.Windows;
			}
		}

		// G l o b a l

		public static string GnuTlsCheckVersion(string reqVersion) {
			return Marshal.PtrToStringAnsi(gnutls_check_version(reqVersion));
		}
		// const char * gnutls_check_version (const char * req_version)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_check_version")]
		private static extern IntPtr gnutls_check_version([In()][MarshalAs(UnmanagedType.LPStr)] string req_version);

		public static void GnuTlsGlobalSetLogFunction(Logging.GnuTlsLogCBFunc logCBFunc) {
			gnutls_global_set_log_function(logCBFunc);
		}
		// void gnutls_global_set_log_function (gnutls_log_func log_func)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_set_log_function")]
		private static extern void gnutls_global_set_log_function([In()][MarshalAs(UnmanagedType.FunctionPtr)] Logging.GnuTlsLogCBFunc log_func);

		public static void GnuTlsGlobalSetLogLevel(int level) {
			gnutls_global_set_log_level(level);
		}
		// void gnutls_global_set_log_level (int level)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_set_log_level")]
		private static extern void gnutls_global_set_log_level(int level);

		public static int GnuTlsGlobalInit() {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_global_init());
		}
		// int gnutls_global_init ()
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_init")]
		private static extern int gnutls_global_init();

		public static void GnuTlsGlobalDeInit() {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_global_deinit();
		}
		// void gnutls_global_deinit ()
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_deinit")]
		private static extern void gnutls_global_deinit();

		// FREE WORKAROUND

		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
		private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
		private static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);
		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool FreeLibrary(IntPtr hModule);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void freeFuncDelegate(IntPtr ptr);

		public static void GnuTlsFree(IntPtr ptr) {
			IntPtr hDLL = LoadLibrary("libgnutls-30.dll");
			if (hDLL == IntPtr.Zero) {
				throw new GnuTlsException("LoadLibrary for libgnutls-30.dll failed.");
			}

			// gnutls_free is (for reasons beyond my comprehension) exported from libgnutls-30.dll
			// marked as a value, not an entry point. Thus, DllImport would handle it incorrectly.

			// The trick is to, step by step, do the following:

			// Get the address of the exported variable named "gnutls_free".
			IntPtr freeFuncExpPtr = GetProcAddress(hDLL, "gnutls_free");
			if (freeFuncExpPtr == IntPtr.Zero) {
				throw new GnuTlsException("GetProcAddress for libgnutls-30.dll/gnutls_free failed.");
			}

			// At this address, you will find the address of the real gnutls_free function.
			IntPtr freeFuncPtr = (IntPtr)Marshal.PtrToStructure(freeFuncExpPtr, typeof(IntPtr));

			// Using this address, you can setup the delegate
			freeFuncDelegate freeFunc = Marshal.GetDelegateForFunctionPointer<freeFuncDelegate>(freeFuncPtr);

			// And then you can actually invoke the gnutls_free function.
			freeFunc(ptr);

			FreeLibrary(hDLL);
		}

		/*
		// void gnutls_free(* ptr)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_free")]
		public static extern void gnutls_free(IntPtr ptr);
		*/

		//

		// S e s s i o n

		// G N U T L S API calls for session init / deinit

		public static int GnuTlsInit(ref IntPtr session, InitFlagsT flags) {
			return gnutls_init(ref session, flags);
		}
		// int gnutls_init (gnutls_session_t * session, unsigned int flags)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_init")]
		private static extern int gnutls_init(ref IntPtr session, InitFlagsT flags);

		public static void GnuTlsDeinit(IntPtr session) {
			gnutls_deinit(session);
		}
		// void gnutls_deinit (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_deinit")]
		private static extern void gnutls_deinit(IntPtr session);

		public static IntPtr GnuTlsSessionGetPtr(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_session_get_ptr(sess.ptr);
		}
		// IntPtr gnutls_session_get_ptr (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_ptr")]
		private static extern IntPtr gnutls_session_get_ptr(IntPtr session);

		public static void GnuTlsSessionSetPtr(Session sess, IntPtr ptr) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_session_set_ptr(sess.ptr, ptr);
		}
		// void gnutls_session_set_ptr (gnutls_session_t session, void * ptr)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_set_ptr")]
		private static extern void gnutls_session_set_ptr(IntPtr session, IntPtr ptr);


		public static void GnuTlsDbSetCacheExpiration(Session sess, int seconds) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_db_set_cache_expiration(sess.ptr, seconds);
			return;
		}
		// void gnutls_db_set_cache_expiration (gnutls_session_t session, int seconds)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_db_set_cache_expiration")]
		private static extern void gnutls_db_set_cache_expiration(IntPtr session, int seconds);

		// Info

		public static string GnuTlsSessionGetDesc(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr descPtr = gnutls_session_get_desc(sess.ptr);
			string desc = Marshal.PtrToStringAnsi(descPtr);
			GnuTlsFree(descPtr);

			return desc;
		}
		// char* gnutls_session_get_desc(gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_desc")]
		private static extern IntPtr gnutls_session_get_desc(IntPtr session);

		public static string GnuTlsProtocolGetName(ProtocolT version) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr namePtr = gnutls_protocol_get_name(version);
			string name = Marshal.PtrToStringAnsi(namePtr);

			return name;
		}
		// const char * gnutls_protocol_get_name (gnutls_protocol_t version)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_protocol_get_name")]
		private static extern IntPtr gnutls_protocol_get_name(ProtocolT version);

		public static ProtocolT GnuTlsProtocolGetVersion(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return (ProtocolT)GnuUtils.Check(gcm, (int)gnutls_protocol_get_version(sess.ptr));
		}
		// gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_protocol_get_version")]
		private static extern ProtocolT gnutls_protocol_get_version(IntPtr session);

		public static int GnuTlsRecordGetMaxSize(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_record_get_max_size(sess.ptr);
		}
		// size_t gnutls_record_get_max_size (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_get_max_size")]
		private static extern int gnutls_record_get_max_size(IntPtr session);

		public static AlertDescriptionT GnuTlsAlertGet(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_alert_get(sess.ptr);
		}
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_alert_get")]
		private static extern AlertDescriptionT gnutls_alert_get(IntPtr session);

		public static string GnuTlsAlertGetName(AlertDescriptionT alert) {
			return Marshal.PtrToStringAnsi(gnutls_get_alert_name(alert));
		}
		// const char * gnutls_alert_get_name (gnutls_alert_description_t alert)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_get_alert_name")]
		private static extern IntPtr gnutls_get_alert_name(AlertDescriptionT alert);

		public static bool GnuTlsErrorIsFatal(int error) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_error_is_fatal(error);
		}
		// int gnutls_error_is_fatal (int error)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_error_is_fatal")]
		private static extern bool gnutls_error_is_fatal(int error);

		// Traffic

		public static int GnuTlsHandShake(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			int result;
			do {
				result = gnutls_handshake(sess.ptr);
				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) { break; }
				Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " repeat due to " + Enum.GetName(typeof(EC.en), result));
			} while (result == (int)EC.en.GNUTLS_E_AGAIN ||
					 result == (int)EC.en.GNUTLS_E_INTERRUPTED ||
					 result == (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED ||
					 result == (int)EC.en.GNUTLS_E_GOT_APPLICATION_DATA);

			return GnuUtils.Check(gcm, result);
		}
		// int gnutls_handshake (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_handshake")]
		private static extern int gnutls_handshake(IntPtr session);

		public static void GnuTlsHandshakeSetHookFunction(Session sess, uint htype, int when, GnuTlsInternalStream.GnuTlsHandshakeHookFunc handshakeHookFunc) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_handshake_set_hook_function(sess.ptr, htype, when, handshakeHookFunc);
		}
		// void gnutls_handshake_set_hook_function (gnutls_session_t session, unsigned int htype, int when, gnutls_handshake_hook_func func)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_handshake_set_hook_function")]
		private static extern void gnutls_handshake_set_hook_function(IntPtr session, uint htype, int when, [In()][MarshalAs(UnmanagedType.FunctionPtr)] GnuTlsInternalStream.GnuTlsHandshakeHookFunc func);

		public static int GnuTlsBye(Session sess, CloseRequestT how) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			int result;
			do {
				result = gnutls_bye(sess.ptr, how);
				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) { break; }
				Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " repeat due to " + Enum.GetName(typeof(EC.en), result));
			} while (result == (int)EC.en.GNUTLS_E_AGAIN ||
					 result == (int)EC.en.GNUTLS_E_INTERRUPTED);

			return GnuUtils.Check(gcm, result);
		}
		// int gnutls_bye (gnutls_session_t session, gnutls_close_request_t how)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_bye")]
		private static extern int gnutls_bye(IntPtr session, CloseRequestT how);

		public static void GnuTlsHandshakeSetTimeout(Session sess, uint ms) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_handshake_set_timeout(sess.ptr, ms);
		}
		// void gnutls_handshake_set_timeout (gnutls_session_t session, unsigned int ms)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_handshake_set_timeout")]
		private static extern void gnutls_handshake_set_timeout(IntPtr session, uint ms);

		public static int GnuTlsRecordCheckPending(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_record_check_pending(sess.ptr);
		}
		// size_t gnutls_record_check_pending (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_check_pending")]
		private static extern int gnutls_record_check_pending(IntPtr session);


		// Priorities

		public static int GnuTlsSetDefaultPriority(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_set_default_priority(sess.ptr));
		}
		// int gnutls_set_default_priority (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_set_default_priority")]
		private static extern int gnutls_set_default_priority(IntPtr session);

		public static int GnuTlsPrioritySetDirect(Session sess, string priorities) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr errPos; // does not seem terribly useful...
			return GnuUtils.Check(gcm, gnutls_priority_set_direct(sess.ptr, priorities, out errPos));
		}
		// int gnutls_priority_set_direct(gnutls_session_t session, const char* priorities, const char** err_pos)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_priority_set_direct")]
		private static extern int gnutls_priority_set_direct(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string priorities, out IntPtr err_pos);

		public static int GnuTlsSetDefaultPriorityAppend(Session sess, string priorities) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr errPos; // does not seem terribly useful...
			return GnuUtils.Check(gcm, gnutls_set_default_priority_append(sess.ptr, priorities, out errPos, 0));
		}
		// int gnutls_set_default_priority_append (gnutls_session_t session, const char * add_prio, const char ** err_pos, unsigned flags)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_set_default_priority_append")]
		private static extern int gnutls_set_default_priority_append(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string priorities, out IntPtr err_pos, uint flags);

		public static int GnuTlsDhSetPrimeBits(Session sess, uint bits) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_dh_set_prime_bits(sess.ptr, bits));
		}
		// void gnutls_dh_set_prime_bits (gnutls_session_t session, unsigned int bits)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_dh_set_prime_bits")]
		private static extern int gnutls_dh_set_prime_bits(IntPtr session, uint bits);

		// Transport

		public static void GnuTlsTransportSetPtr(Session sess, IntPtr socketDescriptor) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_transport_set_ptr(sess.ptr, socketDescriptor);
		}
		// void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t fd) (= void * fd)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_transport_set_ptr")]
		private static extern void gnutls_transport_set_ptr(IntPtr session, IntPtr fd);

		public static void GnuTlsTransportSetInt2(Session sess, int socketDescriptorRecv, int socketDescriptorSend) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_transport_set_int2(sess.ptr, socketDescriptorRecv, socketDescriptorSend);
		}
		// void gnutls_transport_set_int (gnutls_session_t session, int recv_fd, int send_fd)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_transport_set_int2")]
		private static extern void gnutls_transport_set_int2(IntPtr session, int recv_fd, int send_fd);

		// ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t data_size)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_recv")]
		internal static extern int gnutls_record_recv(IntPtr session, [Out()][MarshalAs(UnmanagedType.LPArray, SizeConst = 2048)] byte[] data, int data_size);

		// ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t data_size)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_send")]
		internal static extern int gnutls_record_send(IntPtr session, [In()][MarshalAs(UnmanagedType.LPArray, SizeConst = 2048)] byte[] data, int data_size);

		// Session Resume

		public static bool GnuTlsSessionIsResumed(Session sess) {
			return gnutls_session_is_resumed(sess.ptr);
		}
		// int gnutls_session_is_resumed (gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_is_resumed")]
		private static extern bool gnutls_session_is_resumed(IntPtr session);

		public static int GnuTlsSessionGetData2(Session sess, out DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_get_data2(sess.ptr, out data));
		}
		// Special overload for HandshakeHook callback function
		public static int GnuTlsSessionGetData2(IntPtr sess, out DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_get_data2(sess, out data));
		}
		// int gnutls_session_get_data2 (gnutls_session_t session, gnutls_datum_t * data)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_data2")]
		private static extern int gnutls_session_get_data2(IntPtr session, out DatumT data);

		public static int GnuTlsSessionSetData(Session sess, DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_set_data(sess.ptr, data.ptr, data.size));
		}
		// Special overload for HandshakeHook callback function
		public static int GnuTlsSessionSetData(IntPtr sess, DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_set_data(sess, data.ptr, data.size));
		}
		// int gnutls_session_set_data (gnutls_session_t session, const void * session_data, size_t session_data_size)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_set_data")]
		private static extern int gnutls_session_set_data(IntPtr session, IntPtr session_data, ulong session_data_size);

		// const gnutls_datum_t* gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_get_peers")]
		private static extern IntPtr gnutls_certificate_get_peers(IntPtr session, IntPtr session_data, uint list_size);

		public static SessionFlagsT GnuTlsSessionGetFlags(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_session_get_flags(sess.ptr);
		}
		// Special overload for HandshakeHook callback function
		public static SessionFlagsT GnuTlsSessionGetFlags(IntPtr sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_session_get_flags(sess);
		}
		// unsigned gnutls_session_get_flags(gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_flags")]
		private static extern SessionFlagsT gnutls_session_get_flags(IntPtr session);


		// ALPN

		public static int GnuTlsAlpnSetProtocols(Session sess, string protocols) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			var datumPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DatumT>());
			var valuePtr = Marshal.StringToHGlobalAnsi(protocols);

			Marshal.StructureToPtr(new DatumT { ptr = valuePtr, size = (uint)protocols.Length }, datumPtr, true);

			int result = GnuUtils.Check(gcm, gnutls_alpn_set_protocols(sess.ptr, datumPtr, 1, AlpnFlagsT.GNUTLS_ALPN_MANDATORY));

			Marshal.FreeHGlobal(valuePtr);
			Marshal.FreeHGlobal(datumPtr);

			return result;
		}
		// int gnutls_alpn_set_protocols (gnutls_session_t session, const gnutls_datum_t * protocols, unsigned protocols_size, unsigned int flags)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_alpn_set_protocols")]
		private static extern int gnutls_alpn_set_protocols(IntPtr session, IntPtr protocols, int protocols_size, AlpnFlagsT flags);

		public static string GnuTlsAlpnGetSelectedProtocol(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			DatumT data = new DatumT();
			_ = GnuUtils.Check(gcm, gnutls_alpn_get_selected_protocol(sess.ptr, data), (int)EC.en.GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
			return Marshal.PtrToStringAnsi(data.ptr);
		}
		// int gnutls_alpn_get_selected_protocol (gnutls_session_t session, gnutls_datum_t * protocol)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_alpn_get_selected_protocol")]
		private static extern int gnutls_alpn_get_selected_protocol(IntPtr session, DatumT data);


		// C r e d e n t i a l s

		// G N U T L S API calls for certificate credentials init / deinit

		public static int GnuTlsCertificateAllocateCredentials(ref IntPtr res) {
			return gnutls_certificate_allocate_credentials(ref res);
		}
		// int gnutls_certificate_allocate_credentials (gnutls_certificate_credentials_t * res)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_allocate_credentials")]
		private static extern int gnutls_certificate_allocate_credentials(ref IntPtr res);

		public static void GnuTlsCertificateFreeCredentials(IntPtr sc) {
			gnutls_certificate_free_credentials(sc);
		}
		// void gnutls_certificate_free_credentials(gnutls_certificate_credentials_t sc)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_free_credentials")]
		private static extern void gnutls_certificate_free_credentials(IntPtr sc);

		// Set

		public static int GnuTlsCredentialsSet(Credentials cred, Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_credentials_set(sess.ptr, CredentialsTypeT.GNUTLS_CRD_CERTIFICATE, cred.ptr));
		}
		// int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_credentials_set")]
		private static extern int gnutls_credentials_set(IntPtr session, CredentialsTypeT type, IntPtr cred);

		// Info

		public static bool GnuTlsCertificateClientGetRequestStatus(Session sess) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_certificate_client_get_request_status(sess.ptr);
		}
		// unsigned gnutls_certificate_client_get_request_status(gnutls_session_t session)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_client_get_request_status")]
		private static extern bool gnutls_certificate_client_get_request_status(IntPtr session);

		// C e r t i f i c a t e  V e r i f i c a t i o n

		public static int GnuTlsCertificateVerifyPeers3(Session sess, string hostname, out CertificateStatusT status) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			CertificateStatusT temp;
			int result = gnutls_certificate_verify_peers3(sess.ptr, hostname, out temp);
			status = temp;
			return GnuUtils.Check(gcm, result);
		}
		// int gnutls_certificate_verify_peers3 (gnutls_session_t session, const char * hostname, unsigned int * status)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_verify_peers3")]
		private static extern int gnutls_certificate_verify_peers3(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string hostname, [Out()][MarshalAs(UnmanagedType.U4)] out CertificateStatusT status);

		public static void GnuTlsCertificateSetVerifyFlags(CertificateCredentials res, CertificateVerifyFlagsT flags) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_certificate_set_verify_flags(res.ptr, flags);
			return;
		}
		// void gnutls_certificate_set_verify_flags(gnutls_certificate_credentials_t res, unsigned int flags)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_set_verify_flags")]
		private static extern void gnutls_certificate_set_verify_flags(IntPtr res, CertificateVerifyFlagsT flags);

		public static CertificateTypeT GnuTlsCertificateTypeGet2(Session sess, CtypeTargetT target) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_certificate_type_get2(sess.ptr, target);
		}
		// gnutls_certificate_type_t gnutls_certificate_type_get2 (gnutls_session_t session, gnutls_ctype_target_t target)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_type_get2")]
		private static extern CertificateTypeT gnutls_certificate_type_get2(IntPtr session, CtypeTargetT target);

		// Retrieve certificate(s)

		public static DatumT[] GnuTlsCertificateGetPeers(Session sess, ref uint listSize) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr datumTAPtr = gnutls_certificate_get_peers(sess.ptr, ref listSize);
			if (listSize == 0) {
				return null;
			}

			ulong datumTAInt = (ulong)datumTAPtr;

			DatumT[] temp = new DatumT[listSize];

			for (int i = 0; i < listSize; i++) {
				temp[i] = Marshal.PtrToStructure<DatumT>((IntPtr)datumTAInt);
				datumTAInt += 16;
			}

			return temp;
		}
		// const gnutls_datum_t * gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_get_peers")]
		private static extern IntPtr gnutls_certificate_get_peers(IntPtr session, ref uint list_size);


		// X 5 0 9

		public static int GnuTlsX509CrtInit(ref IntPtr cert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_init(ref cert);
		}
		//  int gnutls_x509_crt_init (gnutls_x509_crt_t * cert)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_init")]
		private static extern int gnutls_x509_crt_init(ref IntPtr cert);

		public static int GnuTlsX509CrtDeinit(IntPtr cert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_deinit(cert);
		}
		//  int gnutls_x509_crt_deinit (gnutls_x509_crt_t * cert)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_deinit")]
		private static extern int gnutls_x509_crt_deinit(IntPtr cert);

		public static int GnuTlsX509CrtImport(IntPtr cert, ref DatumT data, X509CrtFmtT format) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_import(cert, ref data, format);
		}
		// int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_import")]
		private static extern int gnutls_x509_crt_import(IntPtr cert, ref DatumT data, X509CrtFmtT format);

		public static int GnuTlsX509CrtPrint(IntPtr cert, CertificatePrintFormatsT format, ref DatumT output) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_print(cert, format, ref output);
		}
		//  int gnutls_x509_crt_print (gnutls_x509_crt_t cert, gnutls_certificate_print_formats_t format, gnutls_datum_t * out)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_print")]
		private static extern int gnutls_x509_crt_print(IntPtr cert, CertificatePrintFormatsT format, ref DatumT output);

		public static int GnuTlsX509CrtExport2(IntPtr cert, X509CrtFmtT format, ref DatumT output) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_export2(cert, format, ref output);
		}
		// int gnutls_x509_crt_export2(gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_export2")]
		private static extern int gnutls_x509_crt_export2(IntPtr cert, X509CrtFmtT format, ref DatumT output);

		public static int GnuTlsPcertImportRawpkRaw(IntPtr pcert, ref DatumT data, X509CrtFmtT format, uint keyUsage, uint flags) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_pcert_import_rawpk_raw(pcert, ref data, format, keyUsage, flags);
		}
		//  int gnutls_pcert_import_rawpk_raw (gnutls_pcert_st* pcert, const gnutls_datum_t* rawpubkey, gnutls_x509_crt_fmt_t format, unsigned int key_usage, unsigned int flags)
		[DllImport("libgnutls-30.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_pcert_import_rawpk_raw")]
		private static extern int gnutls_pcert_import_rawpk_raw(IntPtr pcert, ref DatumT data, X509CrtFmtT format, uint key_usage, uint flags);

	}


	//	for .NET / Linux: TODO:

	// DllImport("libgnutls-30.dll".... needs to be libgnutls-30.so

	//	LoadLibrary:

	//[DllImport("libdl", ExactSpelling = true)]
	//	public static extern IntPtr dlopen(string filename, int flags);

	//	GetProcAddress:

	//[DllImport("libdl", ExactSpelling = true)]
	//	public static extern IntPtr dlsym(IntPtr handle, string symbol);

	//	FreeLibrary:

	//[DllImport("libdl", ExactSpelling = true)]
	//	public static extern int dlclose(IntPtr handle);

	//	Sample usage:

	//const int RTLD_NOW = 0x002;
	//	IntPtr pDll = dlopen("ourdevice.so.0", RTLD_NOW);
	//	IntPtr pAddressOfFunction = dlsym(pDll, "AdcOpen");
	//	...
	//	dlclose(pDll);

}