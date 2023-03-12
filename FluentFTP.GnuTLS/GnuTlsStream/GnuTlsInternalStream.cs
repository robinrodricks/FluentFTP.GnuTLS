using System;
using System.IO;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using FluentFTP.GnuTLS.Core;
using FluentFTP.GnuTLS.Enums;

namespace FluentFTP.GnuTLS {

	/// <summary>
	/// Adds support for GnuTLS TLS1.2 and TLS1.3 (with session resume capability)
	/// for FluentFTP by using a .NET c# wrapper for GnuTLS.
	/// </summary>
	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		// After a successful handshake, the following will be available:
		public static string ProtocolName { get; private set; } = "Unknown";
		public static string CipherSuite { get; private set; } = "None";
		public static string? AlpnProtocol { get; private set; } = null;
		public static SslProtocols SslProtocol { get; private set; } = SslProtocols.None;
		public static int MaxRecordSize { get; private set; } = 8192;

		public bool IsResumed { get; private set; } = false;
		public bool IsSessionOk { get; private set; } = false;

		// Logging call back to our user.
		public delegate void GnuStreamLogCBFunc(string message);

		//
		// These are brought in by the .ctor
		//

		// The underlying socket of the connection
		private Socket socket;

		// The desired ALPN string to be used in the handshake
		private string alpn;

		// The desired Priority string to be used in the handshake
		private string priority;

		// The expected Host name for certificate verification
		private string hostname;

		// The Handshake Timeout to be honored on handshake
		private int htimeout;

		// The Poll Timeout to use for connectivity test
		private int ptimeout;

		//
		// For our own inside use
		//

		internal Logging logging;

		// GnuTLS Handshake Hook function
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		internal delegate void GnuTlsHandshakeHookFunc(IntPtr session, uint htype, uint post, uint incoming);
		internal GnuTlsHandshakeHookFunc handshakeHookFunc = HandshakeHook;

		// Keep track: Is this the first instance or a subsequent one?
		// We need to do a "GLobal Init" and a "Global DeInit" when the first
		// instance is born or dies.
		private static int ctorCount = 0;

		//

		// The TLS session associated with this GnuTlsStream
		private ClientSession sess;

		// The Certificate Credentials associated with this
		// GnuTlsStream and ALL streams resumed from it
		// One for all of these, therefore static
		private static CertificateCredentials cred;

		// Storage for resume data:
		// * retrieved from the "session-to-be-resumed"
		// * used for a session that is "to-be-resumed"
		// * re-used, therefore static
		private static DatumT resumeDataTLS = new();

		// Handle for Libs/gnutls-30.dll
		internal static IntPtr hDLL = IntPtr.Zero;

		//
		// Constructor
		//

		public GnuTlsInternalStream(
			string targetHostString,
			Socket socketDescriptor,
			CustomRemoteCertificateValidationCallback customRemoteCertificateValidation,
			string? alpnString,
			GnuTlsInternalStream streamToResume,
			string priorityString,
			int handshakeTimeout,
			int pollTimeout,
			GnuStreamLogCBFunc elog,
			int logMaxLevel,
			GnuMessage logDebugInformationMessages,
			int logQueueMaxSize) {

			socket = socketDescriptor;
			alpn = alpnString;
			priority = priorityString;
			hostname = targetHostString;
			htimeout = handshakeTimeout;
			ptimeout = pollTimeout;

			if (ctorCount < 1) {

				// On the first instance of GnuTlsStream, setup:
				// 1. Logging
				// 2. Make sure GnuTls version corresponds to our Native. and Enums.
				// 3. GnuTls Gobal Init
				// 4. One single credentials set

				Logging.InitLogging(elog, logMaxLevel, logDebugInformationMessages, logQueueMaxSize);

				ValidateLibrary(true);

				// GnuTlsStreams are organized as
				// TLS 1.2:
				// First one: Creates/Initializes the GnuTls infrastructure, cannot resume
				// Subsequent ones: Re-use part of the GnuTls infrastructure, can resume from first
				// one or previous ones
				// TLS 1.3:
				// Additionally, Session Tickets to store session data may appear at any time
				if (streamToResume != null) {
					throw new GnuTlsException("Cannot resume from anything if fresh stream");
				}

				// Setup the GnuTLS infrastructure
				GnuTls.GnuTlsGlobalInit();

				// Setup/Allocate certificate credentials for this first session
				cred = new();

			}

			// Further code runs on first and all subsequent instantiations of
			// GnuTlsStream - for FTP, typically there is one control connection
			// as the first instance, and one further instance that is born and then dies
			// multiple times as a data connection.

			ctorCount++;

			sess = new(/*InitFlagsT.GNUTLS_NO_TICKETS_TLS12*/);

			SetupHandshake();

			// Setup handshake hook
			GnuTls.GnuTlsHandshakeSetHookFunction(sess, (uint)HandshakeDescriptionT.GNUTLS_HANDSHAKE_ANY, (int)HandshakeHookT.GNUTLS_HOOK_BOTH, handshakeHookFunc);

			IsSessionOk = true;

			// Setup Session Resume
			if (streamToResume != null) {
				GnuTls.GnuTlsSessionGetData2(streamToResume.sess, out resumeDataTLS);

				Logging.LogGnuFunc(GnuMessage.Handshake, "Setting up session resume from control connection");
				GnuTls.GnuTlsSessionSetData(sess, resumeDataTLS);
				GnuTls.GnuTlsFree(resumeDataTLS.ptr);
			}

			DisableNagle();

			GnuTls.GnuTlsHandShake(sess);

			ReEnableNagle();

			PopulateHandshakeInfo();

			ReportClientCertificateUsed();

			ValidateServerCertificates(customRemoteCertificateValidation);

		}

		public static bool ValidateLibrary(bool log) {

			int bitsNeeded = 64;
			int bits = IntPtr.Size * 8;

			if (bits != bitsNeeded) {
				throw new GnuTlsException("GnuTlsStream needs to run as 64bit process");
			}

			string versionNeeded = "3.7.8";
			string version = GnuTls.GnuTlsCheckVersion(null);

			if (log) {
				string applicationVersion = Assembly.GetAssembly(MethodBase.GetCurrentMethod().DeclaringType).GetName().Version.ToString();
				Logging.Log("FluentFTP.GnuTLS " + applicationVersion + " / GnuTLS " + version + " (x" + bits + ")");
			}

			if (version != versionNeeded) {
				throw new GnuTlsException("GnuTLS library version must be " + versionNeeded);
			}

			return true;
		}

		// Destructor

		~GnuTlsInternalStream() {
		}

		// Dispose

		public void Dispose() {
			if (sess != null) {
				if (IsSessionOk) {
					int count = GnuTls.GnuTlsRecordCheckPending(sess);
					if (count > 0) {
						byte[] buf = new byte[count];
						this.Read(buf, 0, count);
					}
					GnuTls.GnuTlsBye(sess, CloseRequestT.GNUTLS_SHUT_RDWR);
				}
				sess.Dispose();
			}

			if (ctorCount <= 1) {
				cred.Dispose();
				GnuTls.GnuTlsGlobalDeInit();
				GnuTls.FreeLibrary(GnuTlsInternalStream.hDLL);
			}

			ctorCount--;
		}

		// Methods overriding base ( = Stream )

		public override int Read(byte[] buffer, int offset, int maxCount) {
			if (maxCount <= 0) {
				throw new ArgumentException("FtpGnuStream.Read: maxCount must be greater than zero");
			}
			if (offset + maxCount > buffer.Length) {
				throw new ArgumentException("FtpGnuStream.Read: offset + maxCount go beyond buffer length");
			}

			maxCount = Math.Min(maxCount, MaxRecordSize);

			int result;
			bool needRepeat;
			int repeatCount = 0;

			do {
				result = GnuTls.gnutls_record_recv(sess.ptr, buffer, maxCount);

				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) {
					break;
				}

				needRepeat = GnuUtils.NeedRdWrRepeat(result);

				if ((repeatCount < 5) && needRepeat) {
					repeatCount++;

					Logging.LogGnuFunc(GnuMessage.Read, "FtpGnuStream.Read repeat #" + repeatCount + " due to " + Enum.GetName(typeof(EC.en), result));

					switch (result) {
						case (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED:
							Logging.LogGnuFunc(GnuMessage.Alert, "Warning alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(sess)));
							break;
						case (int)EC.en.GNUTLS_E_FATAL_ALERT_RECEIVED:
							Logging.LogGnuFunc(GnuMessage.Alert, "Fatal alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(sess)));
							break;
						default:
							break;
					}
				}
			} while (needRepeat);

			GnuUtils.Check("FtpGnuStream.Read", result);

			return result;
		}

		public override void Write(byte[] buffer, int offset, int count) {
			if (count <= 0) {
				throw new ArgumentException("FtpGnuStream.Write: count must be greater than zero");
			}
			if (offset + count > buffer.Length) {
				throw new ArgumentException("FtpGnuStream.Write: offset + count go beyond buffer length");
			}

			byte[] buf = new byte[count];

			Array.Copy(buffer, offset, buf, 0, count);

			int result = int.MaxValue;
			bool needRepeat;
			int repeatCount = 0;

			while (result > 0) {
				do {
					result = GnuTls.gnutls_record_send(sess.ptr, buf, Math.Min(buf.Length, MaxRecordSize));
					if (result >= (int)EC.en.GNUTLS_E_SUCCESS) {
						break;
					}

					needRepeat = GnuUtils.NeedRdWrRepeat(result);

					if ((repeatCount < 5) && needRepeat) {
						repeatCount++;

						Logging.LogGnuFunc(GnuMessage.Read, "FtpGnuStream.Write repeat #" + repeatCount + " due to " + Enum.GetName(typeof(EC.en), result));

						switch (result) {
							case (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED:
								Logging.LogGnuFunc(GnuMessage.Alert, "Warning alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(sess)));
								break;
							case (int)EC.en.GNUTLS_E_FATAL_ALERT_RECEIVED:
								Logging.LogGnuFunc(GnuMessage.Alert, "Fatal alert received: " + GnuTls.GnuTlsAlertGetName(GnuTls.GnuTlsAlertGet(sess)));
								break;
							default:
								break;
						}
					}
				} while (needRepeat);

				int newLength = buf.Length - result;
				if (newLength <= 0) {
					break;
				}
				Array.Copy(buf, result, buf, 0, newLength);
				Array.Resize(ref buf, buf.Length - result);
			}

			if (result < 0) {
				GnuUtils.Check("FtpGnuStream.Write", result);
			}
		}

		public override bool CanRead {
			get {
				return IsSessionOk;
			}
		}

		public override bool CanWrite {
			get {
				return IsSessionOk;
			}
		}

		public override bool CanSeek { get { return false; } }

		public override long Length => throw new NotImplementedException();
		public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

		public override void Flush() {
			// Do we need to do anything here? This is actually invoked.
		}

		public override long Seek(long offset, SeekOrigin origin) {
			throw new NotImplementedException();
		}

		public override void SetLength(long value) {
			throw new NotImplementedException();
		}

	}
}
