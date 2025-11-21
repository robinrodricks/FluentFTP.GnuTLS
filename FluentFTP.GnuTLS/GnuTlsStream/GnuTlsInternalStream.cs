using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using FluentFTP.GnuTLS.Core;
using FluentFTP.GnuTLS.Enums;

namespace FluentFTP.GnuTLS {

	/// <summary>
	/// Adds support for GnuTLS TLS1.2 and TLS1.3 (with session resume capability)
	/// for FluentFTP by using a .NET c# wrapper for GnuTLS.
	/// </summary>
	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		// After a successful handshake, the following will be available:
		public string ProtocolName { get; private set; } = "Unknown";
		public string CipherSuite { get; private set; } = "None";
		public string? AlpnProtocol { get; private set; } = null;
		public SslProtocols SslProtocol { get; private set; } = SslProtocols.None;
		public int MaxRecordSize { get; private set; } = DefaultMaxRecordSize;

		public bool IsResumed { get; private set; } = false;
		public bool IsSessionUsable { get; private set; } = false;

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

		// The Communications Timeout to be honored for RECV, SEND, HANDSHAKE and BYE API comms
		private int ctimeout;

		// The Poll Timeout to use for connectivity test
		private int ptimeout;

		//
		// For our own inside use
		//

		// GnuTLS Handshake Hook function
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		internal delegate int GnuTlsHandshakeHookFunc(IntPtr session, uint htype, uint post, uint incoming, IntPtr msg);
		internal GnuTlsHandshakeHookFunc handshakeHookFunc = HandshakeHook;

		private bool weAreControlConnection = true;

		// Keep track: Is this the first instance or a subsequent one?
		// We need to do a "Global Init" and a "Global DeInit" when the first
		// instance is born or dies.
		private static readonly object initLock = new object();

		private static int streamUseCount = 0;

		//

		// The TLS session associated with this GnuTlsStream
		private ClientSession sess;

		// The Certificate Credentials associated with this
		// GnuTlsStream and ALL streams resumed from it
		// One for all of these, therefore static
		private CertificateCredentials cred;

		//
		// Constants
		//

		private const int DefaultMaxRecordSize = 8192;
		private const int LogRepeatInterval = 100;
		private const int MaxInitialRepeats = 2;

		//
		// Constructor
		//
		public GnuTlsInternalStream(
			string targetHostString,
			Socket socketDescriptor,
			CustomRemoteCertificateValidationCallback customRemoteCertificateValidation,
			X509CertificateCollection clientCertificates,
			string? alpnString,
			GnuTlsInternalStream streamToResumeFrom,
			string priorityString,
			string loadLibraryDllNamePrefix,
			int handshakeTimeout,
			int commTimeout,
			int pollTimeout,
			GnuStreamLogCBFunc elog,
			int logMaxLevel,
			GnuMessage logDebugInformationMessages,
			int logQueueMaxSize) {

			socket = socketDescriptor;
			alpn = alpnString;
			priority = priorityString;
			GnuTls.SetLoadLibraryDllNamePrefix(loadLibraryDllNamePrefix);
			hostname = targetHostString;
			htimeout = handshakeTimeout;
			ctimeout = commTimeout;
			ptimeout = pollTimeout;

			weAreControlConnection = streamToResumeFrom == null;

			lock (initLock) {
				if (streamUseCount == 0) {

					// On constructing the first instance of GnuTlsStream, setup:
					// 1. Logging init
					// 2. Make sure GnuTls version corresponds to our Native. and Enums.
					// 3. Loggin attach

					Logging.InitLogging(elog, logMaxLevel, logDebugInformationMessages, logQueueMaxSize);

					Validate(true);

					Logging.AttachGnuTlsLogging();

					GnuTls.GnuTlsGlobalInit();
				}

				++streamUseCount;
			}

			// Setup/Allocate certificate credentials
			cred = weAreControlConnection ? new() : new(streamToResumeFrom.cred);

			// sets the system trusted CAs for Internet PKI
			int n = GnuTls.GnuTlsCertificateSetX509SystemTrust(cred.ptr);
			if (n > 0) {
				Logging.LogGnuFunc(GnuMessage.Handshake, "Processed " + n + " certificates in system X509 trust list");
			}
			else {
				Logging.LogGnuFunc(GnuMessage.Handshake, "Loading system X509 trust list failed: " + GnuUtils.GnuTlsErrorText(n));
			}

			// Any client certificates for presentation to server?
			SetupClientCertificates(clientCertificates);

			sess = new(/*InitFlagsT.GNUTLS_NO_TICKETS_TLS12*/);

			SetupHandshake();

			// Setup handshake hook
			GnuTls.GnuTlsHandshakeSetHookFunction(sess, (uint)HandshakeDescriptionT.GNUTLS_HANDSHAKE_ANY, (int)HandshakeHookT.GNUTLS_HOOK_BOTH, handshakeHookFunc);

			IsSessionUsable = true;

			// Setup Session Resume
			if (streamToResumeFrom != null) {
				Logging.LogGnuFunc(GnuMessage.Handshake, "Session resume - Using session data from control connection");
				DatumT resumeDataTLS;
				GnuTls.GnuTlsSessionGetData2(streamToResumeFrom.sess, out resumeDataTLS);
				GnuTls.GnuTlsSessionSetData(sess, resumeDataTLS);
				GnuTls.GnuTlsFree(resumeDataTLS.ptr);
			}

			DisableNagle();

			GnuTls.GnuTlsHandShake(sess, ctimeout);

			ReEnableNagle();

			PopulateHandshakeInfo();

			ReportClientCertificateUsed();

			ValidateServerCertificates(customRemoteCertificateValidation);

		}

		// Dispose

		protected override void Dispose(bool disposing) {
			if (disposing) {
				if (sess != null) {
					if (IsSessionUsable) {
						int count = GnuTls.GnuTlsRecordCheckPending(sess);
						if (count > 0) {
							byte[] buf = new byte[count];
							Read(buf, 0, count);
						}
						GnuTls.GnuTlsBye(sess, CloseRequestT.GNUTLS_SHUT_RDWR, ctimeout);
					}
					sess.Dispose();
					sess = null;
				}

				if (cred != null) {
					cred.Dispose();
					cred = null;
				}

				lock (initLock) {
					if (streamUseCount > 0) {
						--streamUseCount;
						if (streamUseCount == 0) {
							GnuTls.GnuTlsGlobalDeInit();
						}
					}
				}
			}

			base.Dispose(disposing);
		}

		// Methods overriding base ( = System.IO.Stream )

		public override int Read(byte[] buffer, int offset, int maxCount) {
			if (maxCount <= 0) {
				throw new ArgumentException("GnuTlsInternalStream.Read: maxCount must be greater than zero");
			}
			if (offset + maxCount > buffer.Length) {
				throw new ArgumentException("GnuTlsInternalStream.Read: offset + maxCount go beyond buffer length");
			}

			GnuMessage gnm = weAreControlConnection ? GnuMessage.ReadControl : GnuMessage.ReadData;

			maxCount = Math.Min(maxCount, MaxRecordSize);

			int result;
			bool needRepeat;
			int repeatCount = 0;

			var stopWatch = new Stopwatch();
			stopWatch.Start();

			Logging.LogGnuFunc(gnm, "*GnuTlsRecordRecv(..., " + offset + ", " + maxCount + ")");

			do {
				long msElapsed = stopWatch.ElapsedMilliseconds;
				if (msElapsed > ctimeout) {
					GnuUtils.Check("*GnuTlsRecordRecv(...)", (int)EC.en.GNUTLS_E_SOCKET, false);
					return 0;
				}

				result = GnuTls.GnuTlsRecordRecv(sess, buffer, maxCount);

				if (result >= (int)EC.en.GNUTLS_E_SUCCESS) {
					break;
				}

				needRepeat = GnuUtils.NeedRepeat(GnuUtils.RepeatType.Read, result);

				if (needRepeat) {
					repeatCount++;

					if (repeatCount <= MaxInitialRepeats || repeatCount % LogRepeatInterval == 0) {
						Logging.LogGnuFunc(gnm, "*GnuTlsRecordRecv(...) repeat due to " + Enum.GetName(typeof(EC.en), result));
					}

					/* Small delay before repeat */
					Thread.Sleep(0);

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

			if (repeatCount > 0) Logging.LogGnuFunc(gnm, "*GnuTlsRecordRecv(...) " + repeatCount + " repeats overall");

			stopWatch.Stop();

			if (GnuTls.GnuTlsErrorIsFatal(result)) {
				IsSessionUsable = false;
			}

			return GnuUtils.Check("*GnuTlsRecordRecv(...)", result, false);
		}

		public override void Write(byte[] buffer, int offset, int count) {
			if (count <= 0) {
				throw new ArgumentException("GnuTlsInternalStream.Write: count must be greater than zero");
			}
			if (offset + count > buffer.Length) {
				throw new ArgumentException("GnuTlsInternalStream.Write: offset + count go beyond buffer length");
			}

			GnuMessage gnm = weAreControlConnection ? GnuMessage.WriteControl : GnuMessage.WriteData;

			byte[] buf = new byte[count];

			Array.Copy(buffer, offset, buf, 0, count);

			int result = int.MaxValue;
			bool needRepeat;
			int repeatCount;
			var stopWatch = new Stopwatch();

			Logging.LogGnuFunc(gnm, "*GnuTlsRecordSend(..., " + offset + ", " + count + ")");

			repeatCount = 0;
			stopWatch.Start();

			while (result > 0) {

				do {
					long msElapsed = stopWatch.ElapsedMilliseconds;
					if (msElapsed > ctimeout) {
						GnuUtils.Check("*GnuTlsRecordSend(...)", (int)EC.en.GNUTLS_E_SOCKET, false);
						return;
					}

					result = GnuTls.GnuTlsRecordSend(sess, buf, Math.Min(buf.Length, MaxRecordSize));
					if (result >= (int)EC.en.GNUTLS_E_SUCCESS) {
						break;
					}

					needRepeat = GnuUtils.NeedRepeat(GnuUtils.RepeatType.Write, result);

					if (needRepeat) {
						repeatCount++;

						if (repeatCount <= MaxInitialRepeats || repeatCount % LogRepeatInterval == 0) {
							Logging.LogGnuFunc(gnm, "*GnuTlsRecordSend(...) repeat due to " + Enum.GetName(typeof(EC.en), result));
						}

						/* Small delay before repeat */
						Thread.Sleep(0);

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

			if (repeatCount > 0) Logging.LogGnuFunc(gnm, "*GnuTlsRecordSend(...) " + repeatCount + " repeats overall");

			stopWatch.Stop();

			if (GnuTls.GnuTlsErrorIsFatal(result)) {
				IsSessionUsable = false;
			}

			GnuUtils.Check("*GnuTlsRecordSend(...)", result, false);
		}

		public override bool CanRead {
			get {
				return IsSessionUsable;
			}
		}

		public override bool CanWrite {
			get {
				return IsSessionUsable;
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

		// Methods extending base ( = System.IO.Stream )

		// Make our version accessible
		public static string GetLibVersion() {
			return GnuUtils.GetLibVersion();
		}

		// Internal methods

		internal static bool Validate(bool log) {

			string gnuTlsVersionNeeded = "3.8.0";

			PlatformID platformID = Environment.OSVersion.Platform;

			string applicationVersion = GnuUtils.GetLibVersion() + "(" + platformID.ToString() + "/" + GnuUtils.GetLibTarget() + ")";

			if ((int)platformID != 2 && (int)platformID != 4 && (int)platformID != 6 && (int)platformID != 128) {
				Exception nex = new GnuTlsException("Unsupported platform: " + platformID.ToString());
				Logging.Log(nex.Message);
				Logging.Log("FluentFTP.GnuTLS " + applicationVersion);
				throw new GnuTlsException("Environment validation error", nex);
			}

			if (!Environment.Is64BitProcess) {
				Exception nex = new GnuTlsException("GnuTlsStream needs to be run as a 64bit process");
				Logging.Log(nex.Message);
				Logging.Log("FluentFTP.GnuTLS " + applicationVersion);
				throw new GnuTlsException("Process validation error", nex);
			}

			string gnuTlsVersion;

			try {
				gnuTlsVersion = GnuTls.GnuTlsCheckVersion(null);
			}
			catch (Exception ex) {
				Logging.Log(ex.Message);
				if (ex.InnerException != null) {
					Logging.Log(ex.InnerException.Message);
					Logging.Log("FluentFTP.GnuTLS " + applicationVersion);
					Exception nex = new GnuTlsException(ex.InnerException.Message);
					throw new GnuTlsException("GnuTLS .dll load/call validation error", nex);
				}
				else {
					Logging.Log("FluentFTP.GnuTLS " + applicationVersion);
					throw new GnuTlsException("GnuTLS .dll load/call validation error", ex);
				}
			}

			// Under windows, we need the explicitly built libgnutls.dll, whose version we know from our build chain
			// Under linux, we ignore the version and take whatever the distro provides (and hope for the best)
			if ((int)platformID == 2 && gnuTlsVersion != gnuTlsVersionNeeded) {
				Exception nex = new GnuTlsException("GnuTLS library version must be " + gnuTlsVersionNeeded);
				Logging.Log(nex.Message);
				Logging.Log("FluentFTP.GnuTLS " + applicationVersion + " / GnuTLS " + gnuTlsVersion);
				throw new GnuTlsException("GnuTLS .dll version validation error", nex);
			}

			if (log) {
				Logging.Log("FluentFTP.GnuTLS " + applicationVersion + " / GnuTLS " + gnuTlsVersion);
			}

			return true;
		}

	}
}
