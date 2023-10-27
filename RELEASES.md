# Release Notes

#### 1.0.24
  - Stream disposal can result in GnuTls_Bye to fail with PUSH error. Fixed.

#### 1.0.23
  - Some more logging tweaks and small code cleanup changes.

#### 1.0.22
  - Add some logging to the loading of the GnuTLS API function delegates
  - Add some error messages to the function loader for function delegate loading and library
    freeing processes (Linux/Windows)
  - Move the use-count based Init- and De-Init- logic of the GnuTls library into the stream itself
  - Important: Disable and library freeing under Windows and Linux. libgnutls-30.dll remains 
    permanently loaded (once) until the parent process (i.e. your app) terminates.
    See issue #100.
  - Remove config parm DllUnloadByUseCount to disable use-count based unloading, this logic is now
    unchangeable. GlobalDeInit ist done on use count 0 and has no detrimental effects, library unloading
    is now irrevocably disabled - library remains permanently loaded.

#### 1.0.21
  - Implement a use-count based load/unload logic for the .dll libraries (thanks @Jojo-1000)
  - Add logging for load and unload library actions
  - Add a config parm DllUnloadByUseCount to disable use-count based unloading
  - Remove the interim experimental parm DeInitGnuTLS that had a similar function
  - Improve cred and sess dispose handling (thanks @Jojo-1000)

#### 1.0.20
  - Add copy for non-managed dlls to publish dir to support dotnet publish command

#### 1.0.19
  - Improve validation error message logging
  - gnutls lib update to 3.8.0
  - nettle lib update to 3.9.1
  - Survive all failing x509 system trust calls

#### 1.0.18
  - set_x509_system_trust failure (-64) E_FILE_ERROR: Do not terminate on this error.

#### 1.0.17
  - Improve FunctionLoader for Azure environments

#### 1.0.16
  - 1.0.15 Re-release

#### 1.0.15
  - Provide a "LoadLibraryDllPrefix" config parameter to aid in difficult dll packaging 
    scenarios

#### 1.0.14
  - Eliminate static constructs, make de-init optional, make log queue thread-safe
    and improve function pointer loading for multi-threaded usage

#### 1.0.13
  - Reload all function pointers for repeated client create - dispose sequences

#### 1.0.12
  - Enable ALPN protocols to be set (or disabled) via config options
  - Logging improvements

#### 1.0.11
  - Set up X509 System Trust List: adds the system�s default trusted CAs
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