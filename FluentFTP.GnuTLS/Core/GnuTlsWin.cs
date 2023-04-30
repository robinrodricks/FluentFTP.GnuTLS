using FluentFTP.GnuTLS.Enums;
using System;
using System.Runtime.InteropServices;
// ReSharper disable all InconsistentNaming
namespace FluentFTP.GnuTLS.Core {
	internal static class GnuTlsWin {

		private const string dllName = @"libgnutls-30.dll";

		// G l o b a l

		// const char * gnutls_check_version (const char * req_version)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_check_version")]
		internal static extern IntPtr gnutls_check_version([In()][MarshalAs(UnmanagedType.LPStr)] string req_version);

		// void gnutls_global_set_log_function (gnutls_log_func log_func)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_set_log_function")]
		internal static extern void gnutls_global_set_log_function([In()][MarshalAs(UnmanagedType.FunctionPtr)] Logging.GnuTlsLogCBFunc log_func);

		// void gnutls_global_set_log_level (int level)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_set_log_level")]
		internal static extern void gnutls_global_set_log_level(int level);

		// int gnutls_global_init ()
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_init")]
		internal static extern int gnutls_global_init();

		// void gnutls_global_deinit ()
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_global_deinit")]
		internal static extern void gnutls_global_deinit();

		// FREE WORKAROUND

		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
		internal static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
		internal static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);
		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool FreeLibrary(IntPtr hModule);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void freeFuncDelegate(IntPtr ptr);

		public static void GnuTlsFree(IntPtr ptr) {
			IntPtr hDLL = LoadLibrary(dllName);
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
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_free")]
		public static extern void gnutls_free(IntPtr ptr);
		*/

		// S e s s i o n

		// G N U T L S API calls for session init / deinit

		// int gnutls_init (gnutls_session_t * session, unsigned int flags)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_init")]
		public static extern int gnutls_init(ref IntPtr session, InitFlagsT flags);

		// void gnutls_deinit (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_deinit")]
		public static extern void gnutls_deinit(IntPtr session);

		// IntPtr gnutls_session_get_ptr (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_ptr")]
		internal static extern IntPtr gnutls_session_get_ptr(IntPtr session);

		// void gnutls_session_set_ptr (gnutls_session_t session, void * ptr)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_set_ptr")]
		internal static extern void gnutls_session_set_ptr(IntPtr session, IntPtr ptr);

		// void gnutls_db_set_cache_expiration (gnutls_session_t session, int seconds)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_db_set_cache_expiration")]
		internal static extern void gnutls_db_set_cache_expiration(IntPtr session, int seconds);

		// Info

		// char* gnutls_session_get_desc(gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_desc")]
		internal static extern IntPtr gnutls_session_get_desc(IntPtr session);

		// const char * gnutls_protocol_get_name (gnutls_protocol_t version)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_protocol_get_name")]
		internal static extern IntPtr gnutls_protocol_get_name(ProtocolT version);

		// gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_protocol_get_version")]
		internal static extern ProtocolT gnutls_protocol_get_version(IntPtr session);

		// size_t gnutls_record_get_max_size (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_get_max_size")]
		internal static extern int gnutls_record_get_max_size(IntPtr session);

		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_alert_get")]
		internal static extern AlertDescriptionT gnutls_alert_get(IntPtr session);

		// const char * gnutls_alert_get_name (gnutls_alert_description_t alert)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_get_alert_name")]
		internal static extern IntPtr gnutls_get_alert_name(AlertDescriptionT alert);

		// int gnutls_error_is_fatal (int error)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_error_is_fatal")]
		internal static extern bool gnutls_error_is_fatal(int error);

		// Traffic

		// int gnutls_handshake (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_handshake")]
		internal static extern int gnutls_handshake(IntPtr session);

		// void gnutls_handshake_set_hook_function (gnutls_session_t session, unsigned int htype, int when, gnutls_handshake_hook_func func)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_handshake_set_hook_function")]
		internal static extern void gnutls_handshake_set_hook_function(IntPtr session, uint htype, int when, [In()][MarshalAs(UnmanagedType.FunctionPtr)] GnuTlsInternalStream.GnuTlsHandshakeHookFunc func);

		// int gnutls_bye (gnutls_session_t session, gnutls_close_request_t how)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_bye")]
		internal static extern int gnutls_bye(IntPtr session, CloseRequestT how);

		// void gnutls_handshake_set_timeout (gnutls_session_t session, unsigned int ms)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_handshake_set_timeout")]
		internal static extern void gnutls_handshake_set_timeout(IntPtr session, uint ms);

		// size_t gnutls_record_check_pending (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_check_pending")]
		internal static extern int gnutls_record_check_pending(IntPtr session);

		// Priorities

		// int gnutls_set_default_priority (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_set_default_priority")]
		internal static extern int gnutls_set_default_priority(IntPtr session);

		// int gnutls_priority_set_direct(gnutls_session_t session, const char* priorities, const char** err_pos)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_priority_set_direct")]
		internal static extern int gnutls_priority_set_direct(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string priorities, out IntPtr err_pos);

		// int gnutls_set_default_priority_append (gnutls_session_t session, const char * add_prio, const char ** err_pos, unsigned flags)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_set_default_priority_append")]
		internal static extern int gnutls_set_default_priority_append(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string priorities, out IntPtr err_pos, uint flags);

		// void gnutls_dh_set_prime_bits (gnutls_session_t session, unsigned int bits)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_dh_set_prime_bits")]
		internal static extern int gnutls_dh_set_prime_bits(IntPtr session, uint bits);

		// Transport

		// void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t fd) (= void * fd)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_transport_set_ptr")]
		internal static extern void gnutls_transport_set_ptr(IntPtr session, IntPtr fd);

		// void gnutls_transport_set_int (gnutls_session_t session, int recv_fd, int send_fd)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_transport_set_int2")]
		internal static extern void gnutls_transport_set_int2(IntPtr session, int recv_fd, int send_fd);

		// ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t data_size)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_recv")]
		internal static extern int gnutls_record_recv(IntPtr session, [Out()][MarshalAs(UnmanagedType.LPArray, SizeConst = 2048)] byte[] data, int data_size);

		// ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t data_size)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_record_send")]
		internal static extern int gnutls_record_send(IntPtr session, [In()][MarshalAs(UnmanagedType.LPArray, SizeConst = 2048)] byte[] data, int data_size);

		// Session Resume

		// int gnutls_session_is_resumed (gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_is_resumed")]
		internal static extern bool gnutls_session_is_resumed(IntPtr session);

		// Special overload for HandshakeHook callback function
		// int gnutls_session_get_data2 (gnutls_session_t session, gnutls_datum_t * data)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_data2")]
		internal static extern int gnutls_session_get_data2(IntPtr session, out DatumT data);

		// int gnutls_session_set_data (gnutls_session_t session, const void * session_data, size_t session_data_size)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_set_data")]
		internal static extern int gnutls_session_set_data(IntPtr session, IntPtr session_data, ulong session_data_size);

		// const gnutls_datum_t* gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_get_peers")]
		internal static extern IntPtr gnutls_certificate_get_peers(IntPtr session, IntPtr session_data, uint list_size);

		// unsigned gnutls_session_get_flags(gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_session_get_flags")]
		internal static extern SessionFlagsT gnutls_session_get_flags(IntPtr session);

		// ALPN

		// int gnutls_alpn_set_protocols (gnutls_session_t session, const gnutls_datum_t * protocols, unsigned protocols_size, unsigned int flags)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_alpn_set_protocols")]
		internal static extern int gnutls_alpn_set_protocols(IntPtr session, IntPtr protocols, int protocols_size, AlpnFlagsT flags);

		// int gnutls_alpn_get_selected_protocol (gnutls_session_t session, gnutls_datum_t * protocol)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_alpn_get_selected_protocol")]
		internal static extern int gnutls_alpn_get_selected_protocol(IntPtr session, DatumT data);

		// C r e d e n t i a l s

		// G N U T L S API calls for certificate credentials init / deinit

		// int gnutls_certificate_allocate_credentials (gnutls_certificate_credentials_t * res)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_allocate_credentials")]
		public static extern int gnutls_certificate_allocate_credentials(ref IntPtr res);

		// void gnutls_certificate_free_credentials(gnutls_certificate_credentials_t sc)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_free_credentials")]
		public static extern void gnutls_certificate_free_credentials(IntPtr sc);

		// Set

		// int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_credentials_set")]
		internal static extern int gnutls_credentials_set(IntPtr session, CredentialsTypeT type, IntPtr cred);

		// Info

		// unsigned gnutls_certificate_client_get_request_status(gnutls_session_t session)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_client_get_request_status")]
		internal static extern bool gnutls_certificate_client_get_request_status(IntPtr session);

		// C e r t i f i c a t e  V e r i f i c a t i o n

		// int gnutls_certificate_verify_peers3 (gnutls_session_t session, const char * hostname, unsigned int * status)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_verify_peers3")]
		internal static extern int gnutls_certificate_verify_peers3(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string hostname, [Out()][MarshalAs(UnmanagedType.U4)] out CertificateStatusT status);

		// void gnutls_certificate_set_verify_flags(gnutls_certificate_credentials_t res, unsigned int flags)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_set_verify_flags")]
		internal static extern void gnutls_certificate_set_verify_flags(IntPtr res, CertificateVerifyFlagsT flags);

		// gnutls_certificate_type_t gnutls_certificate_type_get2 (gnutls_session_t session, gnutls_ctype_target_t target)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_type_get2")]
		internal static extern CertificateTypeT gnutls_certificate_type_get2(IntPtr session, CtypeTargetT target);

		// Retrieve certificate(s)

		// const gnutls_datum_t * gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_certificate_get_peers")]
		internal static extern IntPtr gnutls_certificate_get_peers(IntPtr session, ref uint list_size);

		// X 5 0 9

		//  int gnutls_x509_crt_init (gnutls_x509_crt_t * cert)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_init")]
		internal static extern int gnutls_x509_crt_init(ref IntPtr cert);

		//  int gnutls_x509_crt_deinit (gnutls_x509_crt_t * cert)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_deinit")]
		internal static extern int gnutls_x509_crt_deinit(IntPtr cert);

		// int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_import")]
		internal static extern int gnutls_x509_crt_import(IntPtr cert, ref DatumT data, X509CrtFmtT format);

		//  int gnutls_x509_crt_print (gnutls_x509_crt_t cert, gnutls_certificate_print_formats_t format, gnutls_datum_t * out)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_print")]
		internal static extern int gnutls_x509_crt_print(IntPtr cert, CertificatePrintFormatsT format, ref DatumT output);

		// int gnutls_x509_crt_export2(gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_x509_crt_export2")]
		internal static extern int gnutls_x509_crt_export2(IntPtr cert, X509CrtFmtT format, ref DatumT output);

		//  int gnutls_pcert_import_rawpk_raw (gnutls_pcert_st* pcert, const gnutls_datum_t* rawpubkey, gnutls_x509_crt_fmt_t format, unsigned int key_usage, unsigned int flags)
		[DllImport(dllName, CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gnutls_pcert_import_rawpk_raw")]
		internal static extern int gnutls_pcert_import_rawpk_raw(IntPtr pcert, ref DatumT data, X509CrtFmtT format, uint key_usage, uint flags);

	}
}