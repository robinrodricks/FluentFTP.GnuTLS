using FluentFTP.Exceptions;
using FluentFTP.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Xunit;
using FluentFTP;
using FluentFTP.Client.BaseClient;
using FluentFTP.GnuTLS;
using FluentFTP.GnuTLS.Enums;
using System.Threading.Tasks;
using System.Threading;
using System.Net.Sockets;

namespace FluentFTP.Tests {
	public class GnuTests {

		[Fact]
		public void ConstructTest() {

			var stream = new GnuTlsStream();

			Assert.True(stream.Validate());

		}


	}
}