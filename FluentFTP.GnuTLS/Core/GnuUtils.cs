using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace FluentFTP.GnuTLS.Core {
	internal class GnuUtils {

		[MethodImpl(MethodImplOptions.NoInlining)]
		public static string GetCurrentMethod([CallerMemberName] string memberName = "") {
			return "*" + memberName + "(...)";
		}

		public static int Check(string methodName, int result, params int[] resultsAllowed) {

			if (result >= 0) {
				return result;
			}

			if (resultsAllowed.Contains(result)) {
				return result;
			}

			// Consider also checking GnuTls.GnuTlsErrorIsFatal(result)

			GnuTlsException ex;

			string errTxt = GnuTlsErrorText(result);

			ex = new GnuTlsException("Error   : " + methodName + " failed: (" + result + ") " + errTxt);
			ex.ExMethod = methodName;
			ex.ExResult = result;
			ex.ExMeaning = errTxt;

			Logging.LogNoQueue(ex.Message);

			Logging.LogNoQueue("Debug   : Last " + Logging.logQueueMaxSize + " GnuTLS buffered debug messages follow:");

			foreach (string s in Logging.logQueue) {
				Logging.LogNoQueue("Debug   : " + s);
			}

			throw ex;
		}

		public static string GnuTlsErrorText(int errorCode) {
			if (!EC.ec.TryGetValue(errorCode, out string errText)) errText = "Unknown error";
			return errText;
		}

		public enum RepeatType {
			Read,
			Write,
			Handshake,
			Bye,
		}

		public static bool NeedRepeat(RepeatType type, int result, out int msMax) {
			switch (type) {

				case RepeatType.Read:
					msMax = 30000;
					return result == (int)EC.en.GNUTLS_E_AGAIN ||
						   result == (int)EC.en.GNUTLS_E_INTERRUPTED ||
						   result == (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED ||
						   result == (int)EC.en.GNUTLS_E_FATAL_ALERT_RECEIVED;

				case RepeatType.Write:
					msMax = 30000;
					return result == (int)EC.en.GNUTLS_E_AGAIN ||
						   result == (int)EC.en.GNUTLS_E_INTERRUPTED ||
						   result == (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED ||
						   result == (int)EC.en.GNUTLS_E_FATAL_ALERT_RECEIVED;

				case RepeatType.Handshake:
					msMax = 30000;
					return result == (int)EC.en.GNUTLS_E_AGAIN ||
						   result == (int)EC.en.GNUTLS_E_INTERRUPTED ||
					       result == (int)EC.en.GNUTLS_E_WARNING_ALERT_RECEIVED ||
					       result == (int)EC.en.GNUTLS_E_GOT_APPLICATION_DATA;

				case RepeatType.Bye:
					msMax = 30000;
					return result == (int)EC.en.GNUTLS_E_AGAIN ||
						   result == (int)EC.en.GNUTLS_E_INTERRUPTED;
			}

			msMax = 30000;
			return false;
		}

		public static string GetLibVersion() {
			return Assembly.GetAssembly(MethodBase.GetCurrentMethod().DeclaringType).GetName().Version.ToString();
		}

		public static string GetLibTarget() {
			// Return the library target version chosen by the build process of
			// the user of this library, useful when multitargeted Nuget package
			// is accessed.
			string target = "Unknown";
#if NET20
			target = ".NET Framework 2.0";
#elif NET35
			target = ".NET Framework 3.5";
#elif NET40
			target = ".NET Framework 4.0";
#elif NET45
			target = ".NET Framework 4.5";
#elif NET451
			target = ".NET Framework 4.5.1";
#elif NET452
			target = ".NET Framework 4.5.2";
#elif NET46
			target = ".NET Framework 4.6";
#elif NET461
			target = ".NET Framework 4.6.1";
#elif NET462
			target = ".NET Framework 4.6.2";
#elif NET47
			target = ".NET Framework 4.7";
#elif NET471
			target = ".NET Framework 4.7.1";
#elif NET472
			target = ".NET Framework 4.7.2";
#elif NET48
			target = ".NET Framework 4.8";
#elif NET48_OR_GREATER
			target = ".NET Framework 4.8+";
#elif NETSTANDARD1_0
			target = ".NET Standard 1.0";
#elif NETSTANDARD1_1
			target = ".NET Standard 1.1";
#elif NETSTANDARD1_2
			target = ".NET Standard 1.2";
#elif NETSTANDARD1_3
			target = ".NET Standard 1.3";
#elif NETSTANDARD1_4
			target = ".NET Standard 1.4";
#elif NETSTANDARD1_5
			target = ".NET Standard 1.5";
#elif NETSTANDARD1_6
			target = ".NET Standard 1.6";
#elif NETSTANDARD2_0
			target = ".NET Standard 2.0";
#elif NETSTANDARD2_1
			target = ".NET Standard 2.1";
#elif NETSTANDARD2_1_OR_GREATER
			target = ".NET Standard 2.1+";
#elif NETCOREAPP1_0
			target = ".NET Core 1.0";
#elif NETCOREAPP1_1
			target = ".NET Core 1.1";
#elif NETCOREAPP2_0
			target = ".NET Core 2.0";
#elif NETCOREAPP2_1
			target = ".NET Core 2.1";
#elif NETCOREAPP2_2
			target = ".NET Core 2.2";
#elif NETCOREAPP3_0
			target = ".NET Core 3.0";
#elif NETCOREAPP3_1
			target = ".NET Core 3.1";
#elif NET5_0
			target = ".NET 5.0";
#elif NET6_0
			target = ".NET 6.0";
#elif NET7_0
			target = ".NET 7.0";
#elif NET8_0
			target = ".NET 8.0";
#elif NET8_0_OR_GREATER
			target = ".NET 8.0+";
#endif
			return target;
		}

	}
}
