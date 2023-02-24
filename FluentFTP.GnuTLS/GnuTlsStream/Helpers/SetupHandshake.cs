using System;
using System.IO;
using System.Net.Sockets;
using FluentFTP.GnuTLS.Core;

namespace FluentFTP.GnuTLS {

	internal partial class GnuTlsInternalStream : Stream, IDisposable {

		private void SetupHandshake() {

			// Stangely, one reads that this also somehow influences maximum TLS session time
			Core.GnuTls.DbSetCacheExpiration(sess, 100000000);

			// Handle the different ways Config could pass a priority string to here
			if (priority == string.Empty) {
				// None given, so use GnuTLS default
				Core.GnuTls.SetDefaultPriority(sess);
			}
			else if (priority.StartsWith("+") || priority.StartsWith("-")) {
				// Add or subtract from default
				Core.GnuTls.SetDefaultPriorityAppend(sess, priority);
			}
			else {
				// Use verbatim
				Core.GnuTls.PrioritySetDirect(sess, priority);
			}

			// Bits for Diffie-Hellman prime
			Core.GnuTls.DhSetPrimeBits(sess, 1024);

			// Allocate and link credential object
			Core.GnuTls.CredentialsSet(cred, sess);

			// Application Layer Protocol Negotiation (ALPN)
			// (alway AFTER credential allocation and setup
			if (!string.IsNullOrEmpty(alpn)) {
				Core.GnuTls.AlpnSetProtocols(sess, alpn);
			}

			// Tell GnuTLS how to send and receive: Use already open socket
			// Need to check for connectivity on this socket, cannot just blithely use it
			if (!SocketUsable(socket, out string reason)) {
				throw new GnuTlsException("Socket is unusable" + reason);
			}

			Core.GnuTls.TransportSetInt(sess, (int)socket.Handle);

			// Set the timeout for the handshake process
			Core.GnuTls.HandshakeSetTimeout(sess, (uint)timeout);

			// Any client certificate for presentation to server?
			SetupClientCertificates();

		}

		private static bool SocketUsable(Socket sock, out string rsn) {
			try {
				if (sock == null) {
					rsn = "sock == null";
					return false;
				}

				if (sock.Handle == IntPtr.Zero) {
					rsn = "sock handle == zero";
					return false;
				}

				if (!sock.Connected) {
					rsn = "sock !connected";
					return false;
				}

				// Poll (SelectRead) returns true if:
				// Listen has been called and connection is pending (cannot be the case)
				// Data is available for reading
				// Connection has been closed, reset or terminated <--- this is the one we want
				// The ordering in the if-statement is important: Available is updated by the Poll
				if (sock.Poll(500000, SelectMode.SelectRead) && sock.Available == 0) {
					rsn = "sock closed/reset/terminated";
					return false;
				}
			}
			catch (SocketException sockex) {
				rsn = "sock sockex: " + sockex.Message;
				return false;
			}
			catch (IOException ioex) {
				rsn = "sock ioex: " + ioex.Message;
				return false;
			}

			rsn = string.Empty;
			return true;
		}

	}
}
