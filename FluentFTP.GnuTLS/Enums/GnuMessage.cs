using System;
using System.Collections.Generic;
using System.Text;

namespace FluentFTP.GnuTLS.Enums {

	[Flags]
	public enum GnuMessage : ushort {
		None = 0,

		InteropFunction = 1,
		InteropMsg = 1 << 1,
		FunctionLoader = 1 << 2,
		Handshake = 1 << 3,
		Alert = 1 << 4,
		Read = 1 << 5,
		Write = 1 << 6,
		ClientCertificateValidation = 1 << 7,
		ShowClientCertificateInfo = 1 << 8,
		ShowClientCertificatePEM = 1 << 9,
		X509 = 1 << 10,
		RAWPK = 1 << 11,

		All = unchecked((ushort)-1 - Read - Write),
	}

}
