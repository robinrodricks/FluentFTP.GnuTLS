# Release Notes

#### 1.0.14
  - Eliminate static constructs, make de-init optional, make log queue thread-safe
    and improve function pointer loading for multi-threaded usage

#### 1.0.13
  - Reload all function pointers for repeated client create - dispose sequences

#### 1.0.12
  - Enable ALPN protocols to be set (or disabled) via config options
  - Logging improvements

#### 1.0.11
  - Set up X509 System Trust List: adds the system’s default trusted CAs
    for certificate validation.

#### 1.0.10
  - Support running on linux (.Net and Mono), Mac OSX
    using new delegate/FunctionLoader technology

#### 1.0.9
  - Support running on linux (.Net and Mono), Mac OSX
    using classic DllImport switching logic (thanks for contributing: [acorchia](/acorchia))

#### 1.0.8
 - Improved: Certificate validation failure exception text

#### 1.0.7
 - Fix: Further safety on cached `DLL` load address handle to avoid `AccessViolation` exceptions
 - Fix: Certificate details not available to validation on subsequent TLS handshakes
 - Fix: Allow multiple TLS handshakes without disposing

#### 1.0.6
 - HotFix: `AccessViolation` exception due to cached `gnutls_free` handle

#### 1.0.5
 - Package: Multitarget: `net50`, `net60`, `net462`, `net472`, `netstandard2.0`, `netstandard2.1`
 - Package: Prepare for Win/Linux/64bit/32bit: change paths and copy-to-output handling again
 - Package: Smaller DLL files: stripped symbols and debug information

#### 1.0.4
 - Package: Multitarget: `net50`, `net462`, `netstandard2.0`
 - Package: Prepare for Win/Linux/64bit/32bit: change paths and copy-to-output handling
 - Improved: logging and diagnosis on validation errors
 - Fix: Overly long poll timeout delay: added config parameter for this
 - Fix: `GetCurrentMethod`: incorrect output value

#### 1.0.3
 - Attempt to fix DLL packaging issues (DLLs correctly marked Copy-To-Output)

#### 1.0.2
 - Attempt to fix DLL packaging issues (DLLs correctly added to host project)

#### 1.0.1
 - Fix: Check Socket for validity before using
 - Rename GnuTls methods for more consistency
 - Add `gnutls_transport_set_int2` as a possible alternative
 - Fix: Transport Set functions are C type void, not int
 - New: `Validate` method to check if the GnuTLS libraries have loaded

#### 1.0.0
 - First release with basic GnuTLS functionality integrated into FluentFTP