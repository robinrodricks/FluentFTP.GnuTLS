# Release Notes

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