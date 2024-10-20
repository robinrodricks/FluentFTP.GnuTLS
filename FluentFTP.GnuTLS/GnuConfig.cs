using FluentFTP.GnuTLS.Enums;
using FluentFTP.Streams;
using System;
using System.Collections.Generic;

namespace FluentFTP.GnuTLS {

	public class GnuConfig : IFtpStreamConfig {

		/// <summary>
		/// Which security suite to use as a starting point.
		/// The suite enables a fully pre-configured configuration, which is then manually modified using `SecurityOptions`.
		/// </summary>
		public GnuSuite SecuritySuite { get; set; } = GnuSuite.Normal;

		/// <summary>
		/// Additional options to add to the basic security suite specified by `SecuritySuite`.
		/// </summary>
		public IList<GnuOption> SecurityOptions { get; set; } = null;

		/// <summary>
		/// Which security profile to use (advanced option that is not normally needed).
		/// If you set this, you don't need to set individual `SecurityOptions`.
		/// </summary>
		public GnuProfile SecurityProfile { get; set; } = GnuProfile.None;

		/// <summary>
		/// Additional options to configure GnuTLS protocol handling.
		/// (advanced flags that are not normally needed).
		/// </summary>
		public IList<GnuAdvanced> AdvancedOptions { get; set; } = null;

		/// <summary>
		/// Options to configure GnuTLS ALPN protocol(s) setting.
		/// To disable the setting of the ALPN protocol(s) string, use string.Empty.
		/// </summary>
		public string SetALPNControlConnection { get; set; } = "ftp";
		public string SetALPNDataConnection { get; set; } = "ftp-data";

		/// <summary>
		/// Add an optional string prefix to the LoadLibrary dllname. For ClickOnce
		/// Single File deployment, specify "ClickOnceSingleFile" instead of a path and
		/// use "IncludeAllContentForSelfExtract" set to True in your apps .csproj 
		/// </summary>
		public string LoadLibraryDllNamePrefix = string.Empty;

		/// <summary>
		/// How long to wait for a handshake before giving up, in milliseconds.
		/// Set to zero to disable.
		/// </summary>
		public int HandshakeTimeout { get; set; } = 5000;

		private int commTimeout = 15000;

		/// <summary>
		/// How long to wait for a RECV, SEND, HANDSHAKE or BYE API call before giving up,
		/// in milliseconds.
		/// Minimum allowed value is 15000.
		/// </summary>
		public int CommTimeout {
			get { return commTimeout; }
			set { commTimeout = Math.Max(15000, value); }
		}

		/// <summary>
		/// How long to wait for a connectivity socket poll, in milliseconds.
		/// Set to zero to disable.
		/// </summary>
		public int PollTimeout { get; set; } = 500;

		/// <summary>
		/// Select the maximum verbosity of the GnuTLS messages which are logged with serverity "verbose".
		/// The allowed values are 0-99, where 0 suppresses GnuTls related messages entirely, and 99 includes every possible message.
		/// Consult the online docs for more help.
		/// </summary>
		public int LogLevel { get; set; } = 0;

		/// <summary>
		/// What additional debug information to log? You can combine multiple of these.
		/// These messages all carry a log level of "1", so to see them you must set
		/// LogLevel (see above) to at least "1" or more.
		/// </summary>
		public GnuMessage LogMessages { get; set; } = GnuMessage.None;

		/// <summary>
		/// In case of a catastrophic failure, how many messages at maximum
		/// verbosity should be output prior to termination.
		/// </summary>
		public int LogLength { get; set; } = 150;

	}
}