This is a form of SudsSigner. Work in progress (aka Axis 1 compat).

SOAP signature plugin for SUDS
==============================

[![Flattr Button](http://api.flattr.com/button/button-static-50x60.png "Flattr This!")](https://flattr.com/thing/438516/SOAP-signature-plugin-for-SUDS "Flattr")

Usage
-----

Just include an instance of `SudsSigner.plugin.SignerPlugin` in the `plugins`
list passed to the `suds.client.Client` constructor. In most cases (RSA or DSA
key in PEM format without password), only one parameter needs to be given;
the name of the file containing the private key and the certificate. In case
of password protected keys, the password can be supplied either as a string
using the `pwd` parameter, or a callback and an optional context using the
`pwdCallback` and `pwdCallbackCtx` parameters, respectively.

License
-------

The plugin is licensed under MIT license.

Dependencies
------------

 - Python 2.x (tested on 2.7)
 - libxml2 and Python bindings (Debian/Ubuntu package: `python-libxml2`, Pypi: `libxml2-python`)
 - SUDS >= 0.4.1 (Debian/Ubuntu package: `python-suds`, Pypi: `suds-jurko`, `suds-philpem`)
 - xmlsec library and development files  (Debian/Ubuntu package: `libxmlsec1-dev`)
 - PyXMLSec >= 0.3.1
 - pyOpenSSL (Debian/Ubuntu package: `python-openssl`, Pypi: `pyopenssl`)
 - LXML (Debian/Ubuntu package: `python-lxml`, Pypi: `lxml`)
