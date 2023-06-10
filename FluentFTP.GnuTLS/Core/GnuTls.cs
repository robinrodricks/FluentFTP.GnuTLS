using FluentFTP.GnuTLS.Enums;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FluentFTP.GnuTLS.Core {
	internal static class GnuTls {

		public static bool platformIsLinux;

		public static string loadLibraryDllNamePrefix = string.Empty;

		#region FunctionLoader
		private static IntPtr hModule = IntPtr.Zero;
		private static bool functionsAreLoaded = false;

		private static class FunctionLoader {

			// Linux
			private const string dllNameLinUtil = @"libdl.so.2";
			[DllImport(dllNameLinUtil, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
			private static extern IntPtr dlerror();
			[DllImport(dllNameLinUtil, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
			private static extern IntPtr dlopen([MarshalAs(UnmanagedType.LPStr)] string filename, int flags);
			[DllImport(dllNameLinUtil, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
			private static extern IntPtr dlsym(IntPtr handle, [MarshalAs(UnmanagedType.LPStr)] string symbol);
			[DllImport(dllNameLinUtil, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)]
			private static extern int dlclose(IntPtr handle);

			// Windows
			[System.Flags]
			private enum ErrorModes : uint {
				SYSTEM_DEFAULT = 0x0,
				SEM_FAILCRITICALERRORS = 0x0001,
				SEM_NOALIGNMENTFAULTEXCEPT = 0x0004,
				SEM_NOGPFAULTERRORBOX = 0x0002,
				SEM_NOOPENFILEERRORBOX = 0x8000
			}
			private const string dllNameWinUtil = @"Kernel32.dll";
			[DllImport(dllNameWinUtil, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			private static extern ErrorModes SetErrorMode(ErrorModes uMode);
			[DllImport(dllNameWinUtil, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			private static extern uint GetLastError();
			[DllImport(dllNameWinUtil, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			private static extern int FormatMessage(uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId, ref IntPtr lpBuffer, uint dwSize, IntPtr parms);
			[DllImport(dllNameWinUtil, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
			[DllImport(dllNameWinUtil, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			private static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);
			[DllImport(dllNameWinUtil, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			[return: MarshalAs(UnmanagedType.Bool)]
			private static extern bool FreeLibrary(IntPtr hModule);

			public static void Load(string dllPath) {
				IntPtr errMsgPtr = IntPtr.Zero;
				string errMsg = string.Empty;
				if (platformIsLinux) {
					_ = dlerror();
					hModule = dlopen(dllPath, 2);

					if (hModule == IntPtr.Zero) {
						errMsgPtr = dlerror();
						Logging.Log(errMsgPtr.ToString());
						if (errMsgPtr != IntPtr.Zero) {
							errMsg = Marshal.PtrToStringAnsi(errMsgPtr);
						}
						throw new GnuTlsException("Could not load " + dllPath + ", " + errMsg);
					}
				}
				else {
					_ = SetErrorMode(ErrorModes.SEM_FAILCRITICALERRORS | ErrorModes.SEM_NOGPFAULTERRORBOX | ErrorModes.SEM_NOOPENFILEERRORBOX);
					_ = GetLastError();
					hModule = LoadLibrary(dllPath);

					if (hModule == IntPtr.Zero) {
						uint err = GetLastError();
						if (err != 0) {
							_ = FormatMessage(0x00001300, IntPtr.Zero, err, 0, ref errMsgPtr, 256, IntPtr.Zero);
						}
						if (errMsgPtr != IntPtr.Zero) {
							errMsg = Marshal.PtrToStringAnsi(errMsgPtr).TrimEnd(Environment.NewLine.ToCharArray());
						}
						throw new GnuTlsException("Could not load " + dllPath + ", (" + err + ") " + errMsg);
					}
				}
			}

			public static Delegate LoadFunction<T>(string entryName, bool exportIsValueType = false) {
				var pFunc = platformIsLinux ? dlsym(hModule, entryName) : GetProcAddress(hModule, entryName);
				if (pFunc == IntPtr.Zero) { throw new GnuTlsException("Could not find entry " + entryName); }

				if (exportIsValueType) {
					// If the entry point is exported as a value, DllImport would handle it incorrectly.
					// It then needs an additional dereference to work correctly.
					pFunc = (IntPtr)Marshal.PtrToStructure(pFunc, typeof(IntPtr));
				}

				return Marshal.GetDelegateForFunctionPointer(pFunc, typeof(T));
			}

			public static void Free() {
				_ = platformIsLinux ? dlclose(hModule) == 1 : FreeLibrary(hModule);
				functionsAreLoaded = false;
			}
		}
		#endregion

		static GnuTls() {

			// Static class construction, used to initialize the entry point addresses of the HANDLERs
			// that are defined as properties in this class.

			// LoadAllFunctions(); Most of the (Global)Init functions will do this now.
		}

		internal static void SetLoadLibraryDllNamePrefix(string pfx) {
			loadLibraryDllNamePrefix = pfx;
		}

		private static void LoadAllFunctions() {
			if (functionsAreLoaded) return;

			string useDllName;

			// Determine the platform we are running under

			#region Platform
			PlatformID platformID = Environment.OSVersion.Platform;

			if ((int)platformID == 4 || (int)platformID == 6 || (int)platformID == 128) {
				platformIsLinux = true;
				useDllName = @"libgnutls.so.30";
			}
			else {
				platformIsLinux = false;
				useDllName = @"libgnutls-30.dll";
			}
			#endregion

			// Initialize the function loader

			if (platformIsLinux || loadLibraryDllNamePrefix == string.Empty) {
				FunctionLoader.Load(useDllName);
			}
			else {
				FunctionLoader.Load(loadLibraryDllNamePrefix + @"libgcc_s_seh-1.dll");
				FunctionLoader.Load(loadLibraryDllNamePrefix + @"libgmp-10.dll");
				FunctionLoader.Load(loadLibraryDllNamePrefix + @"libnettle-8.dll");
				FunctionLoader.Load(loadLibraryDllNamePrefix + @"libwinpthread-1.dll");
				FunctionLoader.Load(loadLibraryDllNamePrefix + @"libhogweed-6.dll");
				FunctionLoader.Load(loadLibraryDllNamePrefix + useDllName);
			}

			// Get all the needed functions from the library into handlers via delegates.
			// In this section of the code:
			// gnutls_func_name_ is the delegate, gnutls_func_name_h is the handler.

			#region Global
			gnutls_check_version_h = (gnutls_check_version_)FunctionLoader.LoadFunction<gnutls_check_version_>(@"gnutls_check_version");
			gnutls_global_set_log_function_h = (gnutls_global_set_log_function_)FunctionLoader.LoadFunction<gnutls_global_set_log_function_>(@"gnutls_global_set_log_function");
			gnutls_global_set_log_level_h = (gnutls_global_set_log_level_)FunctionLoader.LoadFunction<gnutls_global_set_log_level_>(@"gnutls_global_set_log_level");
			gnutls_global_init_h = (gnutls_global_init_)FunctionLoader.LoadFunction<gnutls_global_init_>(@"gnutls_global_init");
			gnutls_global_deinit_h = (gnutls_global_deinit_)FunctionLoader.LoadFunction<gnutls_global_deinit_>(@"gnutls_global_deinit");
			// gnutls_free is (for reasons beyond my comprehension) exported from libgnutls marked as a value, not an entry point.
			gnutls_free_h = (gnutls_free_)FunctionLoader.LoadFunction<gnutls_free_>(@"gnutls_free", true);
			#endregion

			#region Session
			gnutls_init_h = (gnutls_init_)FunctionLoader.LoadFunction<gnutls_init_>(@"gnutls_init");
			gnutls_deinit_h = (gnutls_deinit_)FunctionLoader.LoadFunction<gnutls_deinit_>(@"gnutls_deinit");
			gnutls_db_set_cache_expiration_h = (gnutls_db_set_cache_expiration_)FunctionLoader.LoadFunction<gnutls_db_set_cache_expiration_>(@"gnutls_db_set_cache_expiration");
			gnutls_session_get_desc_h = (gnutls_session_get_desc_)FunctionLoader.LoadFunction<gnutls_session_get_desc_>(@"gnutls_session_get_desc");
			gnutls_protocol_get_name_h = (gnutls_protocol_get_name_)FunctionLoader.LoadFunction<gnutls_protocol_get_name_>(@"gnutls_protocol_get_name");
			gnutls_protocol_get_version_h = (gnutls_protocol_get_version_)FunctionLoader.LoadFunction<gnutls_protocol_get_version_>(@"gnutls_protocol_get_version");
			gnutls_record_get_max_size_h = (gnutls_record_get_max_size_)FunctionLoader.LoadFunction<gnutls_record_get_max_size_>(@"gnutls_record_get_max_size");
			gnutls_alert_get_h = (gnutls_alert_get_)FunctionLoader.LoadFunction<gnutls_alert_get_>(@"gnutls_alert_get");
			gnutls_alert_get_name_h = (gnutls_alert_get_name_)FunctionLoader.LoadFunction<gnutls_alert_get_name_>(@"gnutls_alert_get_name");
			gnutls_error_is_fatal_h = (gnutls_error_is_fatal_)FunctionLoader.LoadFunction<gnutls_error_is_fatal_>(@"gnutls_error_is_fatal");
			gnutls_handshake_h = (gnutls_handshake_)FunctionLoader.LoadFunction<gnutls_handshake_>(@"gnutls_handshake");
			gnutls_handshake_set_hook_function_h = (gnutls_handshake_set_hook_function_)FunctionLoader.LoadFunction<gnutls_handshake_set_hook_function_>(@"gnutls_handshake_set_hook_function");
			gnutls_bye_h = (gnutls_bye_)FunctionLoader.LoadFunction<gnutls_bye_>(@"gnutls_bye");
			gnutls_handshake_set_timeout_h = (gnutls_handshake_set_timeout_)FunctionLoader.LoadFunction<gnutls_handshake_set_timeout_>(@"gnutls_handshake_set_timeout");
			gnutls_record_check_pending_h = (gnutls_record_check_pending_)FunctionLoader.LoadFunction<gnutls_record_check_pending_>(@"gnutls_record_check_pending");
			gnutls_set_default_priority_h = (gnutls_set_default_priority_)FunctionLoader.LoadFunction<gnutls_set_default_priority_>(@"gnutls_set_default_priority");
			gnutls_priority_set_direct_h = (gnutls_priority_set_direct_)FunctionLoader.LoadFunction<gnutls_priority_set_direct_>(@"gnutls_priority_set_direct");
			gnutls_set_default_priority_append_h = (gnutls_set_default_priority_append_)FunctionLoader.LoadFunction<gnutls_set_default_priority_append_>(@"gnutls_set_default_priority_append");
			gnutls_dh_set_prime_bits_h = (gnutls_dh_set_prime_bits_)FunctionLoader.LoadFunction<gnutls_dh_set_prime_bits_>(@"gnutls_dh_set_prime_bits");
			gnutls_transport_set_ptr_h = (gnutls_transport_set_ptr_)FunctionLoader.LoadFunction<gnutls_transport_set_ptr_>(@"gnutls_transport_set_ptr");
			gnutls_record_recv_h = (gnutls_record_recv_)FunctionLoader.LoadFunction<gnutls_record_recv_>(@"gnutls_record_recv");
			gnutls_record_send_h = (gnutls_record_send_)FunctionLoader.LoadFunction<gnutls_record_send_>(@"gnutls_record_send");
			gnutls_session_is_resumed_h = (gnutls_session_is_resumed_)FunctionLoader.LoadFunction<gnutls_session_is_resumed_>(@"gnutls_session_is_resumed");
			gnutls_session_get_data2_h = (gnutls_session_get_data2_)FunctionLoader.LoadFunction<gnutls_session_get_data2_>(@"gnutls_session_get_data2");
			gnutls_session_set_data_h = (gnutls_session_set_data_)FunctionLoader.LoadFunction<gnutls_session_set_data_>(@"gnutls_session_set_data");
			gnutls_session_get_flags_h = (gnutls_session_get_flags_)FunctionLoader.LoadFunction<gnutls_session_get_flags_>(@"gnutls_session_get_flags");
			gnutls_alpn_set_protocols_h = (gnutls_alpn_set_protocols_)FunctionLoader.LoadFunction<gnutls_alpn_set_protocols_>(@"gnutls_alpn_set_protocols");
			gnutls_alpn_get_selected_protocol_h = (gnutls_alpn_get_selected_protocol_)FunctionLoader.LoadFunction<gnutls_alpn_get_selected_protocol_>(@"gnutls_alpn_get_selected_protocol");
			#endregion

			#region Credentials
			gnutls_certificate_allocate_credentials_h = (gnutls_certificate_allocate_credentials_)FunctionLoader.LoadFunction<gnutls_certificate_allocate_credentials_>(@"gnutls_certificate_allocate_credentials");
			gnutls_certificate_free_credentials_h = (gnutls_certificate_free_credentials_)FunctionLoader.LoadFunction<gnutls_certificate_free_credentials_>(@"gnutls_certificate_free_credentials");
			gnutls_credentials_set_h = (gnutls_credentials_set_)FunctionLoader.LoadFunction<gnutls_credentials_set_>(@"gnutls_credentials_set");
			gnutls_certificate_client_get_request_status_h = (gnutls_certificate_client_get_request_status_)FunctionLoader.LoadFunction<gnutls_certificate_client_get_request_status_>(@"gnutls_certificate_client_get_request_status");
			gnutls_certificate_verify_peers3_h = (gnutls_certificate_verify_peers3_)FunctionLoader.LoadFunction<gnutls_certificate_verify_peers3_>(@"gnutls_certificate_verify_peers3");
			gnutls_certificate_type_get2_h = (gnutls_certificate_type_get2_)FunctionLoader.LoadFunction<gnutls_certificate_type_get2_>(@"gnutls_certificate_type_get2");
			gnutls_certificate_get_peers_h = (gnutls_certificate_get_peers_)FunctionLoader.LoadFunction<gnutls_certificate_get_peers_>(@"gnutls_certificate_get_peers");
			gnutls_certificate_set_x509_system_trust_h = (gnutls_certificate_set_x509_system_trust_)FunctionLoader.LoadFunction<gnutls_certificate_set_x509_system_trust_>(@"gnutls_certificate_set_x509_system_trust");
			gnutls_certificate_set_x509_key_mem2_h = (gnutls_certificate_set_x509_key_mem2_)FunctionLoader.LoadFunction<gnutls_certificate_set_x509_key_mem2_>(@"gnutls_certificate_set_x509_key_mem2");
			gnutls_x509_crt_init_h = (gnutls_x509_crt_init_)FunctionLoader.LoadFunction<gnutls_x509_crt_init_>(@"gnutls_x509_crt_init");
			gnutls_x509_crt_deinit_h = (gnutls_x509_crt_deinit_)FunctionLoader.LoadFunction<gnutls_x509_crt_deinit_>(@"gnutls_x509_crt_deinit");
			gnutls_x509_crt_import_h = (gnutls_x509_crt_import_)FunctionLoader.LoadFunction<gnutls_x509_crt_import_>(@"gnutls_x509_crt_import");
			gnutls_x509_crt_print_h = (gnutls_x509_crt_print_)FunctionLoader.LoadFunction<gnutls_x509_crt_print_>(@"gnutls_x509_crt_print");
			gnutls_x509_crt_export2_h = (gnutls_x509_crt_export2_)FunctionLoader.LoadFunction<gnutls_x509_crt_export2_>(@"gnutls_x509_crt_export2");
			gnutls_pcert_import_rawpk_raw_h = (gnutls_pcert_import_rawpk_raw_)FunctionLoader.LoadFunction<gnutls_pcert_import_rawpk_raw_>(@"gnutls_pcert_import_rawpk_raw");
			#endregion

			functionsAreLoaded = true;

			//FunctionLoader.Free(); will be done when GnuTlsStream is disposed.
		}

		// The following code is platform independant, the magic is in the FunctionLoader above
		//
		// Define the delegates, assign the handlers, code the methods for the outside world
		//
		// For each entry point:
		//
		// [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		// DELEGATE_TYPE definition                 <- Each such type is specific to the entry point
		//
		// STATIC DELEGATE_TYPE HANDLER declaration <- this value is initialized in "static GnuTls()" by
		//                                             the FunctionLoader invocations for this entry point
		//
		// PUBLIC C# Method that will then use the HANDLER in some intelligent fashion
		//

		#region Global

		// const char * gnutls_check_version (const char * req_version)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate IntPtr gnutls_check_version_([In()][MarshalAs(UnmanagedType.LPStr)] string req_version);
		static gnutls_check_version_ gnutls_check_version_h;
		public static string GnuTlsCheckVersion(string reqVersion) {
			if (!functionsAreLoaded) LoadAllFunctions();

			IntPtr versionPtr = gnutls_check_version_h(reqVersion);
			string version = Marshal.PtrToStringAnsi(versionPtr);
			// gnutls_free_h(versionPtr);

			return version;
		}

		// void gnutls_global_set_log_function (gnutls_log_func log_func)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_global_set_log_function_([In()][MarshalAs(UnmanagedType.FunctionPtr)] Logging.GnuTlsLogCBFunc log_func);
		static gnutls_global_set_log_function_ gnutls_global_set_log_function_h;
		public static void GnuTlsGlobalSetLogFunction(Logging.GnuTlsLogCBFunc logCBFunc) {
			if (!functionsAreLoaded) LoadAllFunctions();

			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_global_set_log_function_h(logCBFunc);
		}

		// void gnutls_global_set_log_level (int level)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_global_set_log_level_(int level);
		static gnutls_global_set_log_level_ gnutls_global_set_log_level_h;
		public static void GnuTlsGlobalSetLogLevel(int level) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_global_set_log_level_h(level);
		}

		// int gnutls_global_init ()
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_global_init_();
		static gnutls_global_init_ gnutls_global_init_h;
		public static int GnuTlsGlobalInit() {
			if (!functionsAreLoaded) LoadAllFunctions();

			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_global_init_h());
		}

		// void gnutls_global_deinit ()
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_global_deinit_();
		static gnutls_global_deinit_ gnutls_global_deinit_h;
		public static void GnuTlsGlobalDeInit() {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_global_deinit_h();

			FunctionLoader.Free();
		}

		// void gnutls_free(* ptr)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_free_(IntPtr ptr);
		static gnutls_free_ gnutls_free_h;
		public static void GnuTlsFree(IntPtr ptr) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_free_h(ptr);
		}

		#endregion

		#region Session

		// API calls for session init / deinit

		// int gnutls_init (gnutls_session_t * session, unsigned int flags)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_init_(ref IntPtr session, InitFlagsT flags);
		static gnutls_init_ gnutls_init_h;
		public static int GnuTlsInit(ref IntPtr sessionPtr, InitFlagsT flags) {
			return gnutls_init_h(ref sessionPtr, flags);
		}

		// void gnutls_deinit (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_deinit_(IntPtr session);
		static gnutls_deinit_ gnutls_deinit_h;
		public static void GnuTlsDeinit(IntPtr sessionPtr) {
			gnutls_deinit_h(sessionPtr);
		}

		// void gnutls_db_set_cache_expiration (gnutls_session_t session, int seconds)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_db_set_cache_expiration_(IntPtr session, int seconds);
		static gnutls_db_set_cache_expiration_ gnutls_db_set_cache_expiration_h;
		public static void GnuTlsDbSetCacheExpiration(Session session, int seconds) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_db_set_cache_expiration_h(session.ptr, seconds);
		}

		// Info

		// char* gnutls_session_get_desc(gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate IntPtr gnutls_session_get_desc_(IntPtr session);
		static gnutls_session_get_desc_ gnutls_session_get_desc_h;
		public static string GnuTlsSessionGetDesc(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr descPtr = gnutls_session_get_desc_h(session.ptr);
			string desc = Marshal.PtrToStringAnsi(descPtr);
			gnutls_free_h(descPtr);

			return desc;
		}

		// const char * gnutls_protocol_get_name (gnutls_protocol_t version)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate IntPtr gnutls_protocol_get_name_(ProtocolT version);
		static gnutls_protocol_get_name_ gnutls_protocol_get_name_h;
		public static string GnuTlsProtocolGetName(ProtocolT version) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr namePtr = gnutls_protocol_get_name_h(version);
			string name = Marshal.PtrToStringAnsi(namePtr);
			// gnutls_free_h(namePtr); strangely enough, this free seems unneeded

			return name;
		}

		// gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate ProtocolT gnutls_protocol_get_version_(IntPtr session);
		static gnutls_protocol_get_version_ gnutls_protocol_get_version_h;
		public static ProtocolT GnuTlsProtocolGetVersion(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return (ProtocolT)GnuUtils.Check(gcm, (int)gnutls_protocol_get_version_h(session.ptr));
		}

		// size_t gnutls_record_get_max_size (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_record_get_max_size_(IntPtr session);
		static gnutls_record_get_max_size_ gnutls_record_get_max_size_h;
		public static int GnuTlsRecordGetMaxSize(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_record_get_max_size_h(session.ptr);
		}

		// gnutls_alert_description_t gnutls_alert_get (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate AlertDescriptionT gnutls_alert_get_(IntPtr session);
		static gnutls_alert_get_ gnutls_alert_get_h;
		public static AlertDescriptionT GnuTlsAlertGet(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_alert_get_h(session.ptr);
		}

		// const char * gnutls_alert_get_name (gnutls_alert_description_t alert)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate IntPtr gnutls_alert_get_name_(AlertDescriptionT alert);
		static gnutls_alert_get_name_ gnutls_alert_get_name_h;
		public static string GnuTlsAlertGetName(AlertDescriptionT alert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr namePtr = gnutls_alert_get_name_h(alert);
			string name = Marshal.PtrToStringAnsi(namePtr);
			// gnutls_free_h(namePtr); strangely enough, this free seems unneeded

			return name;
		}

		// int gnutls_error_is_fatal (int error)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate bool gnutls_error_is_fatal_(int error);
		static gnutls_error_is_fatal_ gnutls_error_is_fatal_h;
		public static bool GnuTlsErrorIsFatal(int error) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_error_is_fatal_h(error);
		}

		// Traffic

		// int gnutls_handshake (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_handshake_(IntPtr session);
		static gnutls_handshake_ gnutls_handshake_h;
		public static int GnuTlsHandShake(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			int result;
			bool needRepeat;
			int msMax;
			int repeatCount = 0;

			var stopWatch = new Stopwatch();
			stopWatch.Start();

			do {
				result = gnutls_handshake_h(session.ptr);

				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) {
					break;
				}

				needRepeat = GnuUtils.NeedRepeat(GnuUtils.RepeatType.Handshake, result, out msMax);

				if ((stopWatch.ElapsedMilliseconds < msMax) && needRepeat) {
					repeatCount++;

					// if (repeatCount <= 2) Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " repeat due to " + Enum.GetName(typeof(EC.en), result));

					switch (result) {
						case (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED:
							Logging.LogGnuFunc(GnuMessage.Alert, "Warning alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(session)));
							break;
						case (int)EC.en.GNUTLS_E_FATAL_ALERT_RECEIVED:
							Logging.LogGnuFunc(GnuMessage.Alert, "Fatal alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(session)));
							break;
						default:
							break;
					}
				}
			} while (needRepeat);

			// if (repeatCount > 2) Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " " + repeatCount + " repeats overall");

			stopWatch.Stop();

			return GnuUtils.Check(gcm, result);
		}

		// void gnutls_handshake_set_hook_function (gnutls_session_t session, unsigned int htype, int when, gnutls_handshake_hook_func func)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		internal delegate void gnutls_handshake_set_hook_function_(IntPtr session, uint htype, int when, [In()][MarshalAs(UnmanagedType.FunctionPtr)] GnuTlsInternalStream.GnuTlsHandshakeHookFunc func);
		internal static gnutls_handshake_set_hook_function_ gnutls_handshake_set_hook_function_h;
		public static void GnuTlsHandshakeSetHookFunction(Session session, uint htype, int when, GnuTlsInternalStream.GnuTlsHandshakeHookFunc handshakeHookFunc) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_handshake_set_hook_function_h(session.ptr, htype, when, handshakeHookFunc);
		}

		// int gnutls_bye (gnutls_session_t session, gnutls_close_request_t how)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_bye_(IntPtr session, CloseRequestT how);
		static gnutls_bye_ gnutls_bye_h;
		public static int GnuTlsBye(Session session, CloseRequestT how) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			int result;
			bool needRepeat;
			int msMax;
			int repeatCount = 0;

			var stopWatch = new Stopwatch();
			stopWatch.Start();

			do {
				result = gnutls_bye_h(session.ptr, how);

				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) {
					break;
				}

				needRepeat = GnuUtils.NeedRepeat(GnuUtils.RepeatType.Bye, result, out msMax);

				if ((stopWatch.ElapsedMilliseconds < msMax) && needRepeat) {
					repeatCount++;

					// if (repeatCount <= 2) Logging.LogGnuFunc(GnuMessage.InteropFunction, gcm + " repeat due to " + Enum.GetName(typeof(EC.en), result));

					//switch (result) {
					//	case (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED:
					//		Logging.LogGnuFunc(GnuMessage.Alert, "Warning alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(sess)));
					//		break;
					//	case (int)EC.en.GNUTLS_E_FATAL_ALERT_RECEIVED:
					//		Logging.LogGnuFunc(GnuMessage.Alert, "Fatal alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(sess)));
					//		break;
					//	default:
					//		break;
					//}
				}
			} while (needRepeat);

			// if (repeatCount > 2) Logging.LogGnuFunc(GnuMessage.Handshake, gcm + " " + repeatCount + " repeats overall");

			stopWatch.Stop();

			return GnuUtils.Check(gcm, result);
		}

		// void gnutls_handshake_set_timeout (gnutls_session_t session, unsigned int ms)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_record_check_pending_(IntPtr session);
		static gnutls_record_check_pending_ gnutls_record_check_pending_h;
		public static void GnuTlsHandshakeSetTimeout(Session session, uint ms) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_handshake_set_timeout_h(session.ptr, ms);
		}

		// size_t gnutls_record_check_pending (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_handshake_set_timeout_(IntPtr session, uint ms);
		static gnutls_handshake_set_timeout_ gnutls_handshake_set_timeout_h;
		public static int GnuTlsRecordCheckPending(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_record_check_pending_h(session.ptr);
		}

		// Priorities

		// int gnutls_set_default_priority (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_set_default_priority_(IntPtr session);
		static gnutls_set_default_priority_ gnutls_set_default_priority_h;
		public static int GnuTlsSetDefaultPriority(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_set_default_priority_h(session.ptr));
		}

		// int gnutls_priority_set_direct(gnutls_session_t session, const char* priorities, const char** err_pos)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_priority_set_direct_(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string priorities, out IntPtr err_pos);
		static gnutls_priority_set_direct_ gnutls_priority_set_direct_h;
		public static int GnuTlsPrioritySetDirect(Session session, string priorities) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm + "(" + priorities + ")");

			IntPtr errPos; // does not seem terribly useful...
			return GnuUtils.Check(gcm, gnutls_priority_set_direct_h(session.ptr, priorities, out errPos));
		}

		// int gnutls_set_default_priority_append (gnutls_session_t session, const char * add_prio, const char ** err_pos, unsigned flags)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_set_default_priority_append_(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string priorities, out IntPtr err_pos, uint flags);
		static gnutls_set_default_priority_append_ gnutls_set_default_priority_append_h;
		public static int GnuTlsSetDefaultPriorityAppend(Session session, string priorities) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm + "(" + priorities + ")");

			IntPtr errPos; // does not seem terribly useful...
			return GnuUtils.Check(gcm, gnutls_set_default_priority_append_h(session.ptr, priorities, out errPos, 0));
		}

		// void gnutls_dh_set_prime_bits (gnutls_session_t session, unsigned int bits)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_dh_set_prime_bits_(IntPtr session, uint bits);
		static gnutls_dh_set_prime_bits_ gnutls_dh_set_prime_bits_h;
		public static int GnuTlsDhSetPrimeBits(Session session, uint bits) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_dh_set_prime_bits_h(session.ptr, bits));
		}

		// Transport

		// void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t fd) (= void * fd)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_transport_set_ptr_(IntPtr session, IntPtr fd);
		static gnutls_transport_set_ptr_ gnutls_transport_set_ptr_h;
		public static void GnuTlsTransportSetPtr(Session session, IntPtr socketDescriptor) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			gnutls_transport_set_ptr_h(session.ptr, socketDescriptor);
		}

		// ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t data_size)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_record_recv_(IntPtr session, [Out()][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] data, int data_size);
		static gnutls_record_recv_ gnutls_record_recv_h;
		public static int GnuTlsRecordRecv(Session session, byte[] data, int data_size) {
			return gnutls_record_recv_h(session.ptr, data, data_size);
		}

		// ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t data_size)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_record_send_(IntPtr session, [In()][MarshalAs(UnmanagedType.LPArray)] byte[] data, int data_size);
		static gnutls_record_send_ gnutls_record_send_h;
		public static int GnuTlsRecordSend(Session session, byte[] data, int data_size) {
			return gnutls_record_send_h(session.ptr, data, data_size);
		}

		// Session Resume

		// int gnutls_session_is_resumed (gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate bool gnutls_session_is_resumed_(IntPtr session);
		static gnutls_session_is_resumed_ gnutls_session_is_resumed_h;
		public static bool GnuTlsSessionIsResumed(Session session) {
			return gnutls_session_is_resumed_h(session.ptr);
		}

		// int gnutls_session_get_data2 (gnutls_session_t session, gnutls_datum_t * data)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_session_get_data2_(IntPtr session, out DatumT data);
		static gnutls_session_get_data2_ gnutls_session_get_data2_h;
		public static int GnuTlsSessionGetData2(Session session, out DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_get_data2_h(session.ptr, out data));
		}
		// Special overload for HandshakeHook callback function
		public static int GnuTlsSessionGetData2(IntPtr sessionPtr, out DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_get_data2_h(sessionPtr, out data));
		}

		// int gnutls_session_set_data (gnutls_session_t session, const void * session_data, size_t session_data_size)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_session_set_data_(IntPtr session, IntPtr session_data, ulong session_data_size);
		static gnutls_session_set_data_ gnutls_session_set_data_h;
		public static int GnuTlsSessionSetData(Session session, DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_set_data_h(session.ptr, data.ptr, data.size));
		}
		// Special overload for HandshakeHook callback function
		public static int GnuTlsSessionSetData(IntPtr sessionPtr, DatumT data) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_session_set_data_h(sessionPtr, data.ptr, data.size));
		}

		// unsigned gnutls_session_get_flags(gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate SessionFlagsT gnutls_session_get_flags_(IntPtr session);
		static gnutls_session_get_flags_ gnutls_session_get_flags_h;
		public static SessionFlagsT GnuTlsSessionGetFlags(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_session_get_flags_h(session.ptr);
		}
		// Special overload for HandshakeHook callback function
		public static SessionFlagsT GnuTlsSessionGetFlags(IntPtr sessionPtr) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_session_get_flags_h(sessionPtr);
		}

		// ALPN

		// int gnutls_alpn_set_protocols (gnutls_session_t session, const gnutls_datum_t * protocols, unsigned protocols_size, unsigned int flags)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_alpn_set_protocols_(IntPtr session, IntPtr protocols, int protocols_size, AlpnFlagsT flags);
		static gnutls_alpn_set_protocols_ gnutls_alpn_set_protocols_h;
		public static int GnuTlsAlpnSetProtocols(Session session, string protocols) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm + "(" + protocols + ")");

			var datumPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DatumT>());
			var valuePtr = Marshal.StringToHGlobalAnsi(protocols);

			Marshal.StructureToPtr(new DatumT { ptr = valuePtr, size = (uint)protocols.Length + 1 }, datumPtr, true);

			int result = GnuUtils.Check(gcm, gnutls_alpn_set_protocols_h(session.ptr, datumPtr, 1, AlpnFlagsT.GNUTLS_ALPN_MANDATORY));

			Marshal.FreeHGlobal(valuePtr);
			Marshal.FreeHGlobal(datumPtr);

			return result;
		}

		// int gnutls_alpn_get_selected_protocol (gnutls_session_t session, gnutls_datum_t * protocol)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_alpn_get_selected_protocol_(IntPtr session, DatumT data);
		static gnutls_alpn_get_selected_protocol_ gnutls_alpn_get_selected_protocol_h;
		public static string GnuTlsAlpnGetSelectedProtocol(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			DatumT data = new DatumT();

			_ = GnuUtils.Check(gcm, gnutls_alpn_get_selected_protocol_h(session.ptr, data), (int)EC.en.GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

			return Marshal.PtrToStringAnsi(data.ptr);
		}

		#endregion

		#region Credentials

		// API calls for certificate credentials init / deinit

		// int gnutls_certificate_allocate_credentials (gnutls_certificate_credentials_t * res)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_certificate_allocate_credentials_(ref IntPtr res);
		static gnutls_certificate_allocate_credentials_ gnutls_certificate_allocate_credentials_h;
		public static int GnuTlsCertificateAllocateCredentials(ref IntPtr res) {
			return gnutls_certificate_allocate_credentials_h(ref res);
		}

		// void gnutls_certificate_free_credentials(gnutls_certificate_credentials_t sc)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate void gnutls_certificate_free_credentials_(IntPtr sc);
		static gnutls_certificate_free_credentials_ gnutls_certificate_free_credentials_h;
		public static void GnuTlsCertificateFreeCredentials(IntPtr sc) {
			gnutls_certificate_free_credentials_h(sc);
		}

		// Set

		// int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_credentials_set_(IntPtr session, CredentialsTypeT type, IntPtr cred);
		static gnutls_credentials_set_ gnutls_credentials_set_h;
		public static int GnuTlsCredentialsSet(Credentials credentials, Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return GnuUtils.Check(gcm, gnutls_credentials_set_h(session.ptr, CredentialsTypeT.GNUTLS_CRD_CERTIFICATE, credentials.ptr));
		}

		// Info

		// unsigned gnutls_certificate_client_get_request_status(gnutls_session_t session)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate bool gnutls_certificate_client_get_request_status_(IntPtr session);
		static gnutls_certificate_client_get_request_status_ gnutls_certificate_client_get_request_status_h;
		public static bool GnuTlsCertificateClientGetRequestStatus(Session session) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_certificate_client_get_request_status_h(session.ptr);
		}

		// Verification

		// int gnutls_certificate_verify_peers3 (gnutls_session_t session, const char * hostname, unsigned int * status)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_certificate_verify_peers3_(IntPtr session, [In()][MarshalAs(UnmanagedType.LPStr)] string hostname, [Out()][MarshalAs(UnmanagedType.U4)] out CertificateStatusT status);
		static gnutls_certificate_verify_peers3_ gnutls_certificate_verify_peers3_h;
		public static int GnuTlsCertificateVerifyPeers3(Session session, string hostname, out CertificateStatusT status) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			CertificateStatusT temp;

			int result = gnutls_certificate_verify_peers3_h(session.ptr, hostname, out temp);

			status = temp;

			return GnuUtils.Check(gcm, result);
		}

		// gnutls_certificate_type_t gnutls_certificate_type_get2 (gnutls_session_t session, gnutls_ctype_target_t target)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate CertificateTypeT gnutls_certificate_type_get2_(IntPtr session, CtypeTargetT target);
		static gnutls_certificate_type_get2_ gnutls_certificate_type_get2_h;
		public static CertificateTypeT GnuTlsCertificateTypeGet2(Session session, CtypeTargetT target) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_certificate_type_get2_h(session.ptr, target);
		}

		// Retrieve certificates(s)

		// const gnutls_datum_t * gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate IntPtr gnutls_certificate_get_peers_(IntPtr session, ref uint list_size);
		static gnutls_certificate_get_peers_ gnutls_certificate_get_peers_h;
		public static DatumT[] GnuTlsCertificateGetPeers(Session session, ref uint listSize) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			IntPtr datumTAPtr = gnutls_certificate_get_peers_h(session.ptr, ref listSize);

			if (listSize == 0) { return null; }

			ulong datumTAInt = (ulong)datumTAPtr;

			DatumT[] peers = new DatumT[listSize];

			for (int i = 0; i < listSize; i++) {
				peers[i] = Marshal.PtrToStructure<DatumT>((IntPtr)datumTAInt);
				datumTAInt += 16;
			}

			return peers;
		}

		// int gnutls_certificate_set_x509_system_trust (gnutls_certificate_credentials_t cred)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_certificate_set_x509_system_trust_(IntPtr cred);
		static gnutls_certificate_set_x509_system_trust_ gnutls_certificate_set_x509_system_trust_h;
		public static int GnuTlsCertificateSetX509SystemTrust(IntPtr cred) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_certificate_set_x509_system_trust_h(cred);
		}

		// int gnutls_certificate_set_x509_key_mem2 (gnutls_certificate_credentials_t res, const gnutls_datum_t * cert, const gnutls_datum_t * key, gnutls_x509_crt_fmt_t type, const char * pass, unsigned int flags)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_certificate_set_x509_key_mem2_(IntPtr res, IntPtr cert, IntPtr key, X509CrtFmtT type, [In()][MarshalAs(UnmanagedType.LPStr)] string pass, uint flags);
		static gnutls_certificate_set_x509_key_mem2_ gnutls_certificate_set_x509_key_mem2_h;
		public static int GnutlsCertificateSetX509KeyMem2(IntPtr res, string cert, string key, X509CrtFmtT pem, string pass, uint flags) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			var certDatumPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DatumT>());
			var certValuePtr = Marshal.StringToHGlobalAnsi(cert);

			Marshal.StructureToPtr(new DatumT { ptr = certValuePtr, size = (uint)cert.Length + 1 }, certDatumPtr, true);

			var keyDatumPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DatumT>());
			var keyValuePtr = Marshal.StringToHGlobalAnsi(key);

			Marshal.StructureToPtr(new DatumT { ptr = keyValuePtr, size = (uint)key.Length + 1 }, keyDatumPtr, true);

			int result = gnutls_certificate_set_x509_key_mem2_h(res, certDatumPtr, keyDatumPtr, pem, pass, flags);

			Marshal.FreeHGlobal(certValuePtr);
			Marshal.FreeHGlobal(certDatumPtr);

			Marshal.FreeHGlobal(keyValuePtr);
			Marshal.FreeHGlobal(keyDatumPtr);

			return result;
		}

		// X509

		//  int gnutls_x509_crt_init (gnutls_x509_crt_t * cert)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_x509_crt_init_(ref IntPtr cert);
		static gnutls_x509_crt_init_ gnutls_x509_crt_init_h;
		public static int GnuTlsX509CrtInit(ref IntPtr cert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_init_h(ref cert);
		}

		//  int gnutls_x509_crt_deinit (gnutls_x509_crt_t * cert)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_x509_crt_deinit_(IntPtr cert);
		static gnutls_x509_crt_deinit_ gnutls_x509_crt_deinit_h;
		public static int GnuTlsX509CrtDeinit(IntPtr cert) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_deinit_h(cert);
		}

		// int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_x509_crt_import_(IntPtr cert, ref DatumT data, X509CrtFmtT format);
		static gnutls_x509_crt_import_ gnutls_x509_crt_import_h;
		public static int GnuTlsX509CrtImport(IntPtr cert, ref DatumT data, X509CrtFmtT format) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_import_h(cert, ref data, format);
		}

		//  int gnutls_x509_crt_print (gnutls_x509_crt_t cert, gnutls_certificate_print_formats_t format, gnutls_datum_t * out)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_x509_crt_print_(IntPtr cert, CertificatePrintFormatsT format, ref DatumT output);
		static gnutls_x509_crt_print_ gnutls_x509_crt_print_h;
		public static int GnuTlsX509CrtPrint(IntPtr cert, CertificatePrintFormatsT format, ref DatumT output) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_print_h(cert, format, ref output);
		}

		// int gnutls_x509_crt_export2(gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_x509_crt_export2_(IntPtr cert, X509CrtFmtT format, ref DatumT output);
		static gnutls_x509_crt_export2_ gnutls_x509_crt_export2_h;
		public static int GnuTlsX509CrtExport2(IntPtr cert, X509CrtFmtT format, ref DatumT output) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_x509_crt_export2_h(cert, format, ref output);
		}

		//  int gnutls_pcert_import_rawpk_raw (gnutls_pcert_st* pcert, const gnutls_datum_t* rawpubkey, gnutls_x509_crt_fmt_t format, unsigned int key_usage, unsigned int flags)
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		delegate int gnutls_pcert_import_rawpk_raw_(IntPtr pcert, ref DatumT data, X509CrtFmtT format, uint key_usage, uint flags);
		static gnutls_pcert_import_rawpk_raw_ gnutls_pcert_import_rawpk_raw_h;
		public static int GnuTlsPcertImportRawpkRaw(IntPtr pcert, ref DatumT data, X509CrtFmtT format, uint keyUsage, uint flags) {
			string gcm = GnuUtils.GetCurrentMethod();
			Logging.LogGnuFunc(gcm);

			return gnutls_pcert_import_rawpk_raw_h(pcert, ref data, format, keyUsage, flags);
		}

		#endregion
	}
}