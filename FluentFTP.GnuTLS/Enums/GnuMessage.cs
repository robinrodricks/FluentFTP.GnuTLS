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
		ReadControl = 1 << 5,
		ReadData = 1 << 6,
		WriteControl = 1 << 7,
		WriteData = 1 << 8,
		ClientCertificateValidation = 1 << 9,
		ShowClientCertificateInfo = 1 << 10,
		ShowClientCertificatePEM = 1 << 11,
		X509 = 1 << 12,
		RAWPK = 1 << 13,

		All = unchecked((ushort)-1 - ReadControl - ReadData - WriteControl - WriteData),
	}

}
