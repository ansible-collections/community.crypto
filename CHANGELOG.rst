==============================
Community Crypto Release Notes
==============================

.. contents:: Topics


v2.12.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- get_certificate - add ``asn1_base64`` option to control whether the ASN.1 included in the ``extensions`` return value is binary data or Base64 encoded (https://github.com/ansible-collections/community.crypto/pull/592).

v2.11.1
=======

Release Summary
---------------

Maintenance release with improved documentation.

v2.11.0
=======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- get_certificate - adds ``ciphers`` option for custom cipher selection (https://github.com/ansible-collections/community.crypto/pull/571).

Bugfixes
--------

- action plugin helper - fix handling of deprecations for ansible-core 2.14.2 (https://github.com/ansible-collections/community.crypto/pull/572).
- execution environment binary dependencies (bindep.txt) - fix ``python3-pyOpenSSL`` dependency resolution on RHEL 9+ / CentOS Stream 9+ platforms (https://github.com/ansible-collections/community.crypto/pull/575).
- various plugins - remove unnecessary imports (https://github.com/ansible-collections/community.crypto/pull/569).

v2.10.0
=======

Release Summary
---------------

Bugfix and feature release.

Bugfixes
--------

- openssl_csr, openssl_csr_pipe - prevent invalid values for ``crl_distribution_points`` that do not have one of ``full_name``, ``relative_name``, and ``crl_issuer`` (https://github.com/ansible-collections/community.crypto/pull/560).
- openssl_publickey_info - do not crash with internal error when public key cannot be parsed (https://github.com/ansible-collections/community.crypto/pull/551).

New Plugins
-----------

Filter
~~~~~~

- openssl_csr_info - Retrieve information from OpenSSL Certificate Signing Requests (CSR)
- openssl_privatekey_info - Retrieve information from OpenSSL private keys
- openssl_publickey_info - Retrieve information from OpenSSL public keys in PEM format
- split_pem - Split PEM file contents into multiple objects
- x509_certificate_info - Retrieve information from X.509 certificates in PEM format
- x509_crl_info - Retrieve information from X.509 CRLs in PEM format

v2.9.0
======

Release Summary
---------------

Regular feature release.

Minor Changes
-------------

- x509_certificate_info - adds ``issuer_uri`` field in return value based on Authority Information Access data (https://github.com/ansible-collections/community.crypto/pull/530).

v2.8.1
======

Release Summary
---------------

Maintenance release with improved documentation.

v2.8.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme_* modules - handle more gracefully if CA's new nonce call does not return a nonce (https://github.com/ansible-collections/community.crypto/pull/525).
- acme_* modules - include symbolic HTTP status codes in error and log messages when available (https://github.com/ansible-collections/community.crypto/pull/524).
- openssl_pkcs12 - add option ``encryption_level`` which allows to chose ``compatibility2022`` when cryptography >= 38.0.0 is used to enable a more backwards compatible encryption algorithm. If cryptography uses OpenSSL 3.0.0 or newer, the default algorithm is not compatible with older software (https://github.com/ansible-collections/community.crypto/pull/523).

v2.7.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- acme_* modules - improve feedback when importing ``cryptography`` does not work (https://github.com/ansible-collections/community.crypto/issues/518, https://github.com/ansible-collections/community.crypto/pull/519).

v2.7.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme* modules - also support the HTTP 503 Service Unavailable and 408 Request Timeout response status for automatic retries (https://github.com/ansible-collections/community.crypto/pull/513).

Bugfixes
--------

- openssl_privatekey_pipe - ensure compatibility with newer versions of ansible-core (https://github.com/ansible-collections/community.crypto/pull/515).

v2.6.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- acme* modules - support the HTTP 429 Too Many Requests response status (https://github.com/ansible-collections/community.crypto/pull/508).
- openssh_keypair - added ``pkcs1``, ``pkcs8``, and ``ssh`` to the available choices for the ``private_key_format`` option (https://github.com/ansible-collections/community.crypto/pull/511).

v2.5.0
======

Release Summary
---------------

Maintenance release with improved licensing declaration and documentation fixes.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root. Moreover, ``SPDX-License-Identifier:`` is used to declare the applicable license for every file that is not automatically generated (https://github.com/ansible-collections/community.crypto/pull/491).

v2.4.0
======

Release Summary
---------------

Deprecation and bugfix release. No new features this time.

Deprecated Features
-------------------

- Support for Ansible 2.9 and ansible-base 2.10 is deprecated, and will be removed in the next major release (community.crypto 3.0.0). Some modules might still work with these versions afterwards, but we will no longer keep compatibility code that was needed to support them (https://github.com/ansible-collections/community.crypto/pull/460).

Bugfixes
--------

- openssl_pkcs12 - when using the pyOpenSSL backend, do not crash when trying to read non-existing other certificates (https://github.com/ansible-collections/community.crypto/issues/486, https://github.com/ansible-collections/community.crypto/pull/487).

v2.3.4
======

Release Summary
---------------

Re-release of what was intended to be 2.3.3.

A mistake during the release process caused the 2.3.3 tag to end up on the
commit for 1.9.17, which caused the release pipeline to re-publish 1.9.17
as 2.3.3.

This release is identical to what should have been 2.3.3, except that the
version number has been bumped to 2.3.4 and this changelog entry for 2.3.4
has been added.


v2.3.3
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Include ``Apache-2.0.txt`` file for ``plugins/module_utils/crypto/_obj2txt.py`` and ``plugins/module_utils/crypto/_objects_data.py``.
- openssl_csr - the module no longer crashes with 'permitted_subtrees/excluded_subtrees must be a non-empty list or None' if only one of ``name_constraints_permitted`` and ``name_constraints_excluded`` is provided (https://github.com/ansible-collections/community.crypto/issues/481).
- x509_crl - do not crash when signing CRL with Ed25519 or Ed448 keys (https://github.com/ansible-collections/community.crypto/issues/473, https://github.com/ansible-collections/community.crypto/pull/474).

v2.3.2
======

Release Summary
---------------

Maintenance and bugfix release.

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for the ECS module utils.
- certificate_complete_chain - do not stop execution if an unsupported signature algorithm is encountered; warn instead (https://github.com/ansible-collections/community.crypto/pull/457).

v2.3.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.

v2.3.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- Prepare collection for inclusion in an Execution Environment by declaring its dependencies. Please note that system packages are used for cryptography and PyOpenSSL, which can be rather limited. If you need features from newer cryptography versions, you will have to manually force a newer version to be installed by pip by specifying something like ``cryptography >= 37.0.0`` in your Execution Environment's Python dependencies file (https://github.com/ansible-collections/community.crypto/pull/440).
- Support automatic conversion for Internalionalized Domain Names (IDNs). When passing general names, for example Subject Altenative Names to ``community.crypto.openssl_csr``, these will automatically be converted to IDNA. Conversion will be done per label to IDNA2008 if possible, and IDNA2003 if IDNA2008 conversion fails for that label. Note that IDNA conversion requires `the Python idna library <https://pypi.org/project/idna/>`_ to be installed. Please note that depending on which versions of the cryptography library are used, it could try to process the converted IDNA another time with the Python ``idna`` library and reject IDNA2003 encoded values. Using a new enough ``cryptography`` version avoids this (https://github.com/ansible-collections/community.crypto/issues/426, https://github.com/ansible-collections/community.crypto/pull/436).
- acme_* modules - add parameter ``request_timeout`` to manage HTTP(S) request timeout (https://github.com/ansible-collections/community.crypto/issues/447, https://github.com/ansible-collections/community.crypto/pull/448).
- luks_devices - added ``perf_same_cpu_crypt``, ``perf_submit_from_crypt_cpus``, ``perf_no_read_workqueue``, ``perf_no_write_workqueue`` for performance tuning when opening LUKS2 containers (https://github.com/ansible-collections/community.crypto/issues/427).
- luks_devices - added ``persistent`` option when opening LUKS2 containers (https://github.com/ansible-collections/community.crypto/pull/434).
- openssl_csr_info - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).
- openssl_pkcs12 - allow to provide the private key as text instead of having to read it from a file. This allows to store the private key in an encrypted form, for example in Ansible Vault (https://github.com/ansible-collections/community.crypto/pull/452).
- x509_certificate_info - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).
- x509_crl - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).
- x509_crl_info - add ``name_encoding`` option to control the encoding (IDNA, Unicode) used to return domain names in general names (https://github.com/ansible-collections/community.crypto/pull/436).

Bugfixes
--------

- Make collection more robust when PyOpenSSL is used with an incompatible cryptography version (https://github.com/ansible-collections/community.crypto/pull/445).
- x509_crl - fix crash when ``issuer`` for a revoked certificate is specified (https://github.com/ansible-collections/community.crypto/pull/441).

v2.2.4
======

Release Summary
---------------

Regular maintenance release.

Bugfixes
--------

- openssh_* modules - fix exception handling to report traceback to users for enhanced traceability (https://github.com/ansible-collections/community.crypto/pull/417).

v2.2.3
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- luks_device - fix parsing of ``lsblk`` output when device name ends with ``crypt`` (https://github.com/ansible-collections/community.crypto/issues/409, https://github.com/ansible-collections/community.crypto/pull/410).

v2.2.2
======

Release Summary
---------------

Regular bugfix release.

In this release, we extended the test matrix to include Alpine 3, ArchLinux, Debian Bullseye, and CentOS Stream 8. CentOS 8 was removed from the test matrix.


Bugfixes
--------

- certificate_complete_chain - allow multiple potential intermediate certificates to have the same subject (https://github.com/ansible-collections/community.crypto/issues/399, https://github.com/ansible-collections/community.crypto/pull/403).
- x509_certificate - for the ``ownca`` provider, check whether the CA private key actually belongs to the CA certificate (https://github.com/ansible-collections/community.crypto/pull/407).
- x509_certificate - regenerate certificate when the CA's public key changes for ``provider=ownca`` (https://github.com/ansible-collections/community.crypto/pull/407).
- x509_certificate - regenerate certificate when the CA's subject changes for ``provider=ownca`` (https://github.com/ansible-collections/community.crypto/issues/400, https://github.com/ansible-collections/community.crypto/pull/402).
- x509_certificate - regenerate certificate when the private key changes for ``provider=selfsigned`` (https://github.com/ansible-collections/community.crypto/pull/407).

v2.2.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- openssh_cert - fixed false ``changed`` status for ``host`` certificates when using ``full_idempotence`` (https://github.com/ansible-collections/community.crypto/issues/395, https://github.com/ansible-collections/community.crypto/pull/396).

v2.2.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- openssh_cert - added ``ignore_timestamps`` parameter so it can be used semi-idempotent with relative timestamps in ``valid_to``/``valid_from`` (https://github.com/ansible-collections/community.crypto/issues/379).

Bugfixes
--------

- luks_devices - set ``LANG`` and similar environment variables to avoid translated output, which can break some of the module's functionality like key management (https://github.com/ansible-collections/community.crypto/pull/388, https://github.com/ansible-collections/community.crypto/issues/385).

v2.1.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- Adjust error messages that indicate ``cryptography`` is not installed from ``Can't`` to ``Cannot`` (https://github.com/ansible-collections/community.crypto/pull/374).

Bugfixes
--------

- Various modules and plugins - use vendored version of ``distutils.version`` instead of the deprecated Python standard library ``distutils`` (https://github.com/ansible-collections/community.crypto/pull/353).
- certificate_complete_chain - do not append root twice if the chain already ends with a root certificate (https://github.com/ansible-collections/community.crypto/pull/360).
- certificate_complete_chain - do not hang when infinite loop is found (https://github.com/ansible-collections/community.crypto/issues/355, https://github.com/ansible-collections/community.crypto/pull/360).

New Modules
-----------

- crypto_info - Retrieve cryptographic capabilities
- openssl_privatekey_convert - Convert OpenSSL private keys

v2.0.2
======

Release Summary
---------------

Documentation fix release. No actual code changes.

v2.0.1
======

Release Summary
---------------

Bugfix release with extra forward compatibility for newer versions of cryptography.

Minor Changes
-------------

- acme_* modules - fix usage of ``fetch_url`` with changes in latest ansible-core ``devel`` branch (https://github.com/ansible-collections/community.crypto/pull/339).

Bugfixes
--------

- acme_certificate - avoid passing multiple certificates to ``cryptography``'s X.509 certificate loader when ``fullchain_dest`` is used (https://github.com/ansible-collections/community.crypto/pull/324).
- get_certificate, openssl_csr_info, x509_certificate_info - add fallback code for extension parsing that works with cryptography 36.0.0 and newer. This code re-serializes de-serialized extensions and thus can return slightly different values if the extension in the original CSR resp. certificate was not canonicalized correctly. This code is currently used as a fallback if the existing code stops working, but we will switch it to be the main code in a future release (https://github.com/ansible-collections/community.crypto/pull/331).
- luks_device - now also runs a built-in LUKS signature cleaner on ``state=absent`` to make sure that also the secondary LUKS2 header is wiped when older versions of wipefs are used (https://github.com/ansible-collections/community.crypto/issues/326, https://github.com/ansible-collections/community.crypto/pull/327).
- openssl_pkcs12 - use new PKCS#12 deserialization infrastructure from cryptography 36.0.0 if available (https://github.com/ansible-collections/community.crypto/pull/302).

v2.0.0
======

Release Summary
---------------

A new major release of the ``community.crypto`` collection. The main changes are removal of the PyOpenSSL backends for almost all modules (``openssl_pkcs12`` being the only exception), and removal of the ``assertonly`` provider in the ``x509_certificate`` provider. There are also some other breaking changes which should improve the user interface/experience of this collection long-term.


Minor Changes
-------------

- acme_certificate - the ``subject`` and ``issuer`` fields in in the ``select_chain`` entries are now more strictly validated (https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_csr, openssl_csr_pipe - provide a new ``subject_ordered`` option if the order of the components in the subject is of importance (https://github.com/ansible-collections/community.crypto/issues/291, https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_csr, openssl_csr_pipe - there is now stricter validation of the values of the ``subject`` option (https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_privatekey_info - add ``check_consistency`` option to request private key consistency checks to be done (https://github.com/ansible-collections/community.crypto/pull/309).
- x509_certificate, x509_certificate_pipe - add ``ignore_timestamps`` option which allows to enable idempotency for 'not before' and 'not after' options (https://github.com/ansible-collections/community.crypto/issues/295, https://github.com/ansible-collections/community.crypto/pull/317).
- x509_crl - provide a new ``issuer_ordered`` option if the order of the components in the issuer is of importance (https://github.com/ansible-collections/community.crypto/issues/291, https://github.com/ansible-collections/community.crypto/pull/316).
- x509_crl - there is now stricter validation of the values of the ``issuer`` option (https://github.com/ansible-collections/community.crypto/pull/316).

Breaking Changes / Porting Guide
--------------------------------

- Adjust ``dirName`` text parsing and to text converting code to conform to `Sections 2 and 3 of RFC 4514 <https://datatracker.ietf.org/doc/html/rfc4514.html>`_. This is similar to how `cryptography handles this <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name.rfc4514_string>`_ (https://github.com/ansible-collections/community.crypto/pull/274).
- acme module utils - removing compatibility code (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_* modules - removed vendored copy of the Python library ``ipaddress``. If you are using Python 2.x, please make sure to install the library (https://github.com/ansible-collections/community.crypto/pull/287).
- compatibility module_utils - removed vendored copy of the Python library ``ipaddress`` (https://github.com/ansible-collections/community.crypto/pull/287).
- crypto module utils - removing compatibility code (https://github.com/ansible-collections/community.crypto/pull/290).
- get_certificate, openssl_csr_info, x509_certificate_info - depending on the ``cryptography`` version used, the modules might not return the ASN.1 value for an extension as contained in the certificate respectively CSR, but a re-encoded version of it. This should usually be identical to the value contained in the source file, unless the value was malformed. For extensions not handled by C(cryptography) the value contained in the source file is always returned unaltered (https://github.com/ansible-collections/community.crypto/pull/318).
- module_utils - removed various PyOpenSSL support functions and default backend values that are not needed for the openssl_pkcs12 module (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_csr, openssl_csr_pipe, x509_crl - the ``subject`` respectively ``issuer`` fields no longer ignore empty values, but instead fail when encountering them (https://github.com/ansible-collections/community.crypto/pull/316).
- openssl_privatekey_info - by default consistency checks are not run; they need to be explicitly requested by passing ``check_consistency=true`` (https://github.com/ansible-collections/community.crypto/pull/309).
- x509_crl - for idempotency checks, the ``issuer`` order is ignored. If order is important, use the new ``issuer_ordered`` option (https://github.com/ansible-collections/community.crypto/pull/316).

Deprecated Features
-------------------

- acme_* modules - ACME version 1 is now deprecated and support for it will be removed in community.crypto 2.0.0 (https://github.com/ansible-collections/community.crypto/pull/288).

Removed Features (previously deprecated)
----------------------------------------

- acme_* modules - the ``acme_directory`` option is now required (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_* modules - the ``acme_version`` option is now required (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_account_facts - the deprecated redirect has been removed. Use community.crypto.acme_account_info instead (https://github.com/ansible-collections/community.crypto/pull/290).
- acme_account_info - ``retrieve_orders=url_list`` no longer returns the return value ``orders``. Use the ``order_uris`` return value instead (https://github.com/ansible-collections/community.crypto/pull/290).
- crypto.info module utils - the deprecated redirect has been removed. Use ``crypto.pem`` instead (https://github.com/ansible-collections/community.crypto/pull/290).
- get_certificate - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_certificate - the deprecated redirect has been removed. Use community.crypto.x509_certificate instead (https://github.com/ansible-collections/community.crypto/pull/290).
- openssl_certificate_info - the deprecated redirect has been removed. Use community.crypto.x509_certificate_info instead (https://github.com/ansible-collections/community.crypto/pull/290).
- openssl_csr - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_csr and openssl_csr_pipe - ``version`` now only accepts the (default) value 1 (https://github.com/ansible-collections/community.crypto/pull/290).
- openssl_csr_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_csr_pipe - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_privatekey - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_privatekey_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_privatekey_pipe - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_publickey - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_publickey_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_signature - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- openssl_signature_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- x509_certificate - remove ``assertonly`` provider (https://github.com/ansible-collections/community.crypto/pull/289).
- x509_certificate - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- x509_certificate_info - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).
- x509_certificate_pipe - removed the ``pyopenssl`` backend (https://github.com/ansible-collections/community.crypto/pull/273).

Bugfixes
--------

- cryptography backend - improve Unicode handling for Python 2 (https://github.com/ansible-collections/community.crypto/pull/313).
- get_certificate - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- openssl_csr_info - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- openssl_pkcs12 - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/296).
- x509_certificate_info - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).

v1.9.4
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- acme_* modules - fix commands composed for OpenSSL backend to retrieve information on CSRs and certificates from stdin to use ``/dev/stdin`` instead of ``-``. This is needed for OpenSSL 1.0.1 and 1.0.2, apparently (https://github.com/ansible-collections/community.crypto/pull/279).
- acme_challenge_cert_helper - only return exception when cryptography is not installed, not when a too old version of it is installed. This prevents Ansible's callback to crash (https://github.com/ansible-collections/community.crypto/pull/281).

v1.9.3
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- openssl_csr and openssl_csr_pipe - make sure that Unicode strings are used to compare strings with the cryptography backend. This fixes idempotency problems with non-ASCII letters on Python 2 (https://github.com/ansible-collections/community.crypto/issues/270, https://github.com/ansible-collections/community.crypto/pull/271).

v1.9.2
======

Release Summary
---------------

Bugfix release to fix the changelog. No other change compared to 1.9.0.

v1.9.1
======

Release Summary
---------------

Accidental 1.9.1 release. Identical to 1.9.0.

v1.9.0
======

Release Summary
---------------

Regular feature release.

Minor Changes
-------------

- get_certificate - added ``starttls`` option to retrieve certificates from servers which require clients to request an encrypted connection (https://github.com/ansible-collections/community.crypto/pull/264).
- openssh_keypair - added ``diff`` support (https://github.com/ansible-collections/community.crypto/pull/260).

Bugfixes
--------

- keypair_backend module utils - simplify code to pass sanity tests (https://github.com/ansible-collections/community.crypto/pull/263).
- openssh_keypair - fixed ``cryptography`` backend to preserve original file permissions when regenerating a keypair requires existing files to be overwritten (https://github.com/ansible-collections/community.crypto/pull/260).
- openssh_keypair - fixed error handling to restore original keypair if regeneration fails (https://github.com/ansible-collections/community.crypto/pull/260).
- x509_crl - restore inherited function signature to pass sanity tests (https://github.com/ansible-collections/community.crypto/pull/263).

v1.8.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.crypto/pull/253).
- openssh certificate module utils - new module_utils for parsing OpenSSH certificates (https://github.com/ansible-collections/community.crypto/pull/246).
- openssh_cert - added ``regenerate`` option to validate additional certificate parameters which trigger regeneration of an existing certificate (https://github.com/ansible-collections/community.crypto/pull/256).
- openssh_cert - adding ``diff`` support (https://github.com/ansible-collections/community.crypto/pull/255).

Bugfixes
--------

- openssh_cert - fixed certificate generation to restore original certificate if an error is encountered (https://github.com/ansible-collections/community.crypto/pull/255).
- openssh_keypair - fixed a bug that prevented custom file attributes being applied to public keys (https://github.com/ansible-collections/community.crypto/pull/257).

v1.7.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- openssl_pkcs12 - fix crash when loading passphrase-protected PKCS#12 files with ``cryptography`` backend (https://github.com/ansible-collections/community.crypto/issues/247, https://github.com/ansible-collections/community.crypto/pull/248).

v1.7.0
======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- cryptography_openssh module utils - new module_utils for managing asymmetric keypairs and OpenSSH formatted/encoded asymmetric keypairs (https://github.com/ansible-collections/community.crypto/pull/213).
- openssh_keypair - added ``backend`` parameter for selecting between the cryptography library or the OpenSSH binary for the execution of actions performed by ``openssh_keypair`` (https://github.com/ansible-collections/community.crypto/pull/236).
- openssh_keypair - added ``passphrase`` parameter for encrypting/decrypting OpenSSH private keys (https://github.com/ansible-collections/community.crypto/pull/225).
- openssl_csr - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_csr_info - now returns ``public_key_type`` and ``public_key_data`` (https://github.com/ansible-collections/community.crypto/pull/233).
- openssl_csr_info - refactor module to allow code re-use for diff mode (https://github.com/ansible-collections/community.crypto/pull/204).
- openssl_csr_pipe - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_pkcs12 - added option ``select_crypto_backend`` and a ``cryptography`` backend. This requires cryptography 3.0 or newer, and does not support the ``iter_size`` and ``maciter_size`` options (https://github.com/ansible-collections/community.crypto/pull/234).
- openssl_privatekey - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_privatekey_info - refactor module to allow code re-use for diff mode (https://github.com/ansible-collections/community.crypto/pull/205).
- openssl_privatekey_pipe - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- openssl_publickey - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_certificate - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_certificate_info - now returns ``public_key_type`` and ``public_key_data`` (https://github.com/ansible-collections/community.crypto/pull/233).
- x509_certificate_info - refactor module to allow code re-use for diff mode (https://github.com/ansible-collections/community.crypto/pull/206).
- x509_certificate_pipe - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_crl - add diff mode (https://github.com/ansible-collections/community.crypto/issues/38, https://github.com/ansible-collections/community.crypto/pull/150).
- x509_crl_info - add ``list_revoked_certificates`` option to avoid enumerating all revoked certificates (https://github.com/ansible-collections/community.crypto/pull/232).
- x509_crl_info - refactor module to allow code re-use for diff mode (https://github.com/ansible-collections/community.crypto/pull/203).

Bugfixes
--------

- openssh_keypair - fix ``check_mode`` to populate return values for existing keypairs (https://github.com/ansible-collections/community.crypto/issues/113, https://github.com/ansible-collections/community.crypto/pull/230).
- various modules - prevent crashes when modules try to set attributes on not yet existing files in check mode. This will be fixed in ansible-core 2.12, but it is not backported to every Ansible version we support (https://github.com/ansible-collections/community.crypto/issue/242, https://github.com/ansible-collections/community.crypto/pull/243).
- x509_certificate - fix crash when ``assertonly`` provider is used and some error conditions should be reported (https://github.com/ansible-collections/community.crypto/issues/240, https://github.com/ansible-collections/community.crypto/pull/241).

New Modules
-----------

- openssl_publickey_info - Provide information for OpenSSL public keys

v1.6.2
======

Release Summary
---------------

Bugfix release. Fixes compatibility issue of ACME modules with step-ca.

Bugfixes
--------

- acme_* modules - avoid crashing for ACME servers where the ``meta`` directory key is not present (https://github.com/ansible-collections/community.crypto/issues/220, https://github.com/ansible-collections/community.crypto/pull/221).

v1.6.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- acme_* modules - fix wrong usages of ``ACMEProtocolException`` (https://github.com/ansible-collections/community.crypto/pull/216, https://github.com/ansible-collections/community.crypto/pull/217).

v1.6.0
======

Release Summary
---------------

Fixes compatibility issues with the latest ansible-core 2.11 beta, and contains a lot of internal refactoring for the ACME modules and support for private key passphrases for them.

Minor Changes
-------------

- acme module_utils - the ``acme`` module_utils has been split up into several Python modules (https://github.com/ansible-collections/community.crypto/pull/184).
- acme_* modules - codebase refactor which should not be visible to end-users (https://github.com/ansible-collections/community.crypto/pull/184).
- acme_* modules - support account key passphrases for ``cryptography`` backend (https://github.com/ansible-collections/community.crypto/issues/197, https://github.com/ansible-collections/community.crypto/pull/207).
- acme_certificate_revoke - support revoking by private keys that are passphrase protected for ``cryptography`` backend (https://github.com/ansible-collections/community.crypto/pull/207).
- acme_challenge_cert_helper - add ``private_key_passphrase`` parameter (https://github.com/ansible-collections/community.crypto/pull/207).

Deprecated Features
-------------------

- acme module_utils - the ``acme`` module_utils (``ansible_collections.community.crypto.plugins.module_utils.acme``) is deprecated and will be removed in community.crypto 2.0.0. Use the new Python modules in the ``acme`` package instead (``ansible_collections.community.crypto.plugins.module_utils.acme.xxx``) (https://github.com/ansible-collections/community.crypto/pull/184).

Bugfixes
--------

- action_module plugin helper - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.crypto/pull/202).
- openssl_privatekey_pipe - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.crypto/pull/202).

v1.5.0
======

Release Summary
---------------

Regular feature and bugfix release. Deprecates a return value.

Minor Changes
-------------

- acme_account_info - when ``retrieve_orders`` is not ``ignore`` and the ACME server allows to query orders, the new return value ``order_uris`` is always populated with a list of URIs (https://github.com/ansible-collections/community.crypto/pull/178).
- luks_device - allow to specify sector size for LUKS2 containers with new ``sector_size`` parameter (https://github.com/ansible-collections/community.crypto/pull/193).

Deprecated Features
-------------------

- acme_account_info - when ``retrieve_orders=url_list``, ``orders`` will no longer be returned in community.crypto 2.0.0. Use ``order_uris`` instead (https://github.com/ansible-collections/community.crypto/pull/178).

Bugfixes
--------

- openssl_csr - no longer fails when comparing CSR without basic constraint when ``basic_constraints`` is specified (https://github.com/ansible-collections/community.crypto/issues/179, https://github.com/ansible-collections/community.crypto/pull/180).

v1.4.0
======

Release Summary
---------------

Release with several new features and bugfixes.

Minor Changes
-------------

- The ACME module_utils has been relicensed back from the Simplified BSD License (https://opensource.org/licenses/BSD-2-Clause) to the GPLv3+ (same license used by most other code in this collection). This undoes a licensing change when the original GPLv3+ licensed code was moved to module_utils in https://github.com/ansible/ansible/pull/40697 (https://github.com/ansible-collections/community.crypto/pull/165).
- The ``crypto/identify.py`` module_utils has been renamed to ``crypto/pem.py`` (https://github.com/ansible-collections/community.crypto/pull/166).
- luks_device - ``new_keyfile``, ``new_passphrase``, ``remove_keyfile`` and ``remove_passphrase`` are now idempotent (https://github.com/ansible-collections/community.crypto/issues/19, https://github.com/ansible-collections/community.crypto/pull/168).
- luks_device - allow to configure PBKDF (https://github.com/ansible-collections/community.crypto/pull/163).
- openssl_csr, openssl_csr_pipe - allow to specify CRL distribution endpoints with ``crl_distribution_points`` (https://github.com/ansible-collections/community.crypto/issues/147, https://github.com/ansible-collections/community.crypto/pull/167).
- openssl_pkcs12 - allow to specify certificate bundles in ``other_certificates`` by using new option ``other_certificates_parse_all`` (https://github.com/ansible-collections/community.crypto/issues/149, https://github.com/ansible-collections/community.crypto/pull/166).

Bugfixes
--------

- acme_certificate - error when requested challenge type is not found for non-valid challenges, instead of hanging on step 2 (https://github.com/ansible-collections/community.crypto/issues/171, https://github.com/ansible-collections/community.crypto/pull/173).

v1.3.0
======

Release Summary
---------------

Contains new modules ``openssl_privatekey_pipe``, ``openssl_csr_pipe`` and ``x509_certificate_pipe`` which allow to create or update private keys, CSRs and X.509 certificates without having to write them to disk.


Minor Changes
-------------

- openssh_cert - add module parameter ``use_agent`` to enable using signing keys stored in ssh-agent (https://github.com/ansible-collections/community.crypto/issues/116).
- openssl_csr - refactor module to allow code re-use by openssl_csr_pipe (https://github.com/ansible-collections/community.crypto/pull/123).
- openssl_privatekey - refactor module to allow code re-use by openssl_privatekey_pipe (https://github.com/ansible-collections/community.crypto/pull/119).
- openssl_privatekey - the elliptic curve ``secp192r1`` now triggers a security warning. Elliptic curves of at least 224 bits should be used for new keys; see `here <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec.html#elliptic-curves>`_ (https://github.com/ansible-collections/community.crypto/pull/132).
- x509_certificate - for the ``selfsigned`` provider, a CSR is not required anymore. If no CSR is provided, the module behaves as if a minimal CSR which only contains the public key has been provided (https://github.com/ansible-collections/community.crypto/issues/32, https://github.com/ansible-collections/community.crypto/pull/129).
- x509_certificate - refactor module to allow code re-use by x509_certificate_pipe (https://github.com/ansible-collections/community.crypto/pull/135).

Bugfixes
--------

- openssl_pkcs12 - report the correct state when ``action`` is ``parse`` (https://github.com/ansible-collections/community.crypto/issues/143).
- support code - improve handling of certificate and certificate signing request (CSR) loading with the ``cryptography`` backend when errors occur (https://github.com/ansible-collections/community.crypto/issues/138, https://github.com/ansible-collections/community.crypto/pull/139).
- x509_certificate - fix ``entrust`` provider, which was broken since community.crypto 0.1.0 due to a feature added before the collection move (https://github.com/ansible-collections/community.crypto/pull/135).

New Modules
-----------

- openssl_csr_pipe - Generate OpenSSL Certificate Signing Request (CSR)
- openssl_privatekey_pipe - Generate OpenSSL private keys without disk access
- x509_certificate_pipe - Generate and/or check OpenSSL certificates

v1.2.0
======

Release Summary
---------------

Please note that this release fixes a security issue (CVE-2020-25646).

Minor Changes
-------------

- acme_certificate - allow to pass CSR file as content with new option ``csr_content`` (https://github.com/ansible-collections/community.crypto/pull/115).
- x509_certificate_info - add ``fingerprints`` return value which returns certificate fingerprints (https://github.com/ansible-collections/community.crypto/pull/121).

Security Fixes
--------------

- openssl_csr - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- openssl_privatekey_info - the option ``content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- openssl_publickey - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- openssl_signature - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- x509_certificate - the options ``privatekey_content`` and ``ownca_privatekey_content`` were not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).
- x509_crl - the option ``privatekey_content`` was not marked as ``no_log``, resulting in it being dumped into the system log by default, and returned in the registered results in the ``invocation`` field (CVE-2020-25646, https://github.com/ansible-collections/community.crypto/pull/125).

Bugfixes
--------

- openssl_pkcs12 - do not crash when reading PKCS#12 file which has no private key and/or no main certificate (https://github.com/ansible-collections/community.crypto/issues/103).

v1.1.1
======

Release Summary
---------------

Bugfixes for Ansible 2.10.0.

Bugfixes
--------

- meta/runtime.yml - convert Ansible version numbers for old names of modules to collection version numbers (https://github.com/ansible-collections/community.crypto/pull/108).
- openssl_csr - improve handling of IDNA errors (https://github.com/ansible-collections/community.crypto/issues/105).

v1.1.0
======

Release Summary
---------------

Release for Ansible 2.10.0.


Minor Changes
-------------

- acme_account - add ``external_account_binding`` option to allow creation of ACME accounts with External Account Binding (https://github.com/ansible-collections/community.crypto/issues/89).
- acme_certificate - allow new selector ``test_certificates: first`` for ``select_chain`` parameter (https://github.com/ansible-collections/community.crypto/pull/102).
- cryptography backends - support arbitrary dotted OIDs (https://github.com/ansible-collections/community.crypto/issues/39).
- get_certificate - add support for SNI (https://github.com/ansible-collections/community.crypto/issues/69).
- luks_device - add support for encryption options on container creation (https://github.com/ansible-collections/community.crypto/pull/97).
- openssh_cert - add support for PKCS#11 tokens (https://github.com/ansible-collections/community.crypto/pull/95).
- openssl_certificate - the PyOpenSSL backend now uses 160 bits of randomness for serial numbers, instead of a random number between 1000 and 99999. Please note that this is not a high quality random number (https://github.com/ansible-collections/community.crypto/issues/76).
- openssl_csr - add support for name constraints extension (https://github.com/ansible-collections/community.crypto/issues/46).
- openssl_csr_info - add support for name constraints extension (https://github.com/ansible-collections/community.crypto/issues/46).

Bugfixes
--------

- acme_inspect - fix problem with Python 3.5 that JSON was not decoded (https://github.com/ansible-collections/community.crypto/issues/86).
- get_certificate - fix ``ca_cert`` option handling when ``proxy_host`` is used (https://github.com/ansible-collections/community.crypto/pull/84).
- openssl_*, x509_* modules - fix handling of general names which refer to IP networks and not IP addresses (https://github.com/ansible-collections/community.crypto/pull/92).

New Modules
-----------

- openssl_signature - Sign data with openssl
- openssl_signature_info - Verify signatures with openssl

v1.0.0
======

Release Summary
---------------

This is the first proper release of the ``community.crypto`` collection. This changelog contains all changes to the modules in this collection that were added after the release of Ansible 2.9.0.


Minor Changes
-------------

- luks_device - accept ``passphrase``, ``new_passphrase`` and ``remove_passphrase``.
- luks_device - add ``keysize`` parameter to set key size at LUKS container creation
- luks_device - added support to use UUIDs, and labels with LUKS2 containers
- luks_device - added the ``type`` option that allows user explicit define the LUKS container format version
- openssh_keypair - instead of regenerating some broken or password protected keys, fail the module. Keys can still be regenerated by calling the module with ``force=yes``.
- openssh_keypair - the ``regenerate`` option allows to configure the module's behavior when it should or needs to regenerate private keys.
- openssl_* modules - the cryptography backend now properly supports ``dirName``, ``otherName`` and ``RID`` (Registered ID) names.
- openssl_certificate - Add option for changing which ACME directory to use with acme-tiny. Set the default ACME directory to Let's Encrypt instead of using acme-tiny's default. (acme-tiny also uses Let's Encrypt at the time being, so no action should be neccessary.)
- openssl_certificate - Change the required version of acme-tiny to >= 4.0.0
- openssl_certificate - allow to provide content of some input files via the ``csr_content``, ``privatekey_content``, ``ownca_privatekey_content`` and ``ownca_content`` options.
- openssl_certificate - allow to return the existing/generated certificate directly as ``certificate`` by setting ``return_content`` to ``yes``.
- openssl_certificate_info - allow to provide certificate content via ``content`` option (https://github.com/ansible/ansible/issues/64776).
- openssl_csr - Add support for specifying the SAN ``otherName`` value in the OpenSSL ASN.1 UTF8 string format, ``otherName:<OID>;UTF8:string value``.
- openssl_csr - allow to provide private key content via ``private_key_content`` option.
- openssl_csr - allow to return the existing/generated CSR directly as ``csr`` by setting ``return_content`` to ``yes``.
- openssl_csr_info - allow to provide CSR content via ``content`` option.
- openssl_dhparam - allow to return the existing/generated DH params directly as ``dhparams`` by setting ``return_content`` to ``yes``.
- openssl_dhparam - now supports a ``cryptography``-based backend. Auto-detection can be overwritten with the ``select_crypto_backend`` option.
- openssl_pkcs12 - allow to return the existing/generated PKCS#12 directly as ``pkcs12`` by setting ``return_content`` to ``yes``.
- openssl_privatekey - add ``format`` and ``format_mismatch`` options.
- openssl_privatekey - allow to return the existing/generated private key directly as ``privatekey`` by setting ``return_content`` to ``yes``.
- openssl_privatekey - the ``regenerate`` option allows to configure the module's behavior when it should or needs to regenerate private keys.
- openssl_privatekey_info - allow to provide private key content via ``content`` option.
- openssl_publickey - allow to provide private key content via ``private_key_content`` option.
- openssl_publickey - allow to return the existing/generated public key directly as ``publickey`` by setting ``return_content`` to ``yes``.

Deprecated Features
-------------------

- openssl_csr - all values for the ``version`` option except ``1`` are deprecated. The value 1 denotes the current only standardized CSR version.

Removed Features (previously deprecated)
----------------------------------------

- The ``letsencrypt`` module has been removed. Use ``acme_certificate`` instead.

Bugfixes
--------

- ACME modules: fix bug in ACME v1 account update code
- ACME modules: make sure some connection errors are handled properly
- ACME modules: support Buypass' ACME v1 endpoint
- acme_certificate - fix crash when module is used with Python 2.x.
- acme_certificate - fix misbehavior when ACME v1 is used with ``modify_account`` set to ``false``.
- ecs_certificate - Always specify header ``connection: keep-alive`` for ECS API connections.
- ecs_certificate - Fix formatting of contents of ``full_chain_path``.
- get_certificate - Fix cryptography backend when pyopenssl is unavailable (https://github.com/ansible/ansible/issues/67900)
- openssh_keypair - add logic to avoid breaking password protected keys.
- openssh_keypair - fixes idempotence issue with public key (https://github.com/ansible/ansible/issues/64969).
- openssh_keypair - public key's file attributes (permissions, owner, group, etc.) are now set to the same values as the private key.
- openssl_* modules - prevent crash on fingerprint determination in FIPS mode (https://github.com/ansible/ansible/issues/67213).
- openssl_certificate - When provider is ``entrust``, use a ``connection: keep-alive`` header for ECS API connections.
- openssl_certificate - ``provider`` option was documented as required, but it was not checked whether it was provided. It is now only required when ``state`` is ``present``.
- openssl_certificate - fix ``assertonly`` provider certificate verification, causing 'private key mismatch' and 'subject mismatch' errors.
- openssl_certificate and openssl_csr - fix Ed25519 and Ed448 private key support for ``cryptography`` backend. This probably needs at least cryptography 2.8, since older versions have problems with signing certificates or CSRs with such keys. (https://github.com/ansible/ansible/issues/59039, PR https://github.com/ansible/ansible/pull/63984)
- openssl_csr - a warning is issued if an unsupported value for ``version`` is used for the ``cryptography`` backend.
- openssl_csr - the module will now enforce that ``privatekey_path`` is specified when ``state=present``.
- openssl_publickey - fix a module crash caused when pyOpenSSL is not installed (https://github.com/ansible/ansible/issues/67035).

New Modules
-----------

- ecs_domain - Request validation of a domain with the Entrust Certificate Services (ECS) API
- x509_crl - Generate Certificate Revocation Lists (CRLs)
- x509_crl_info - Retrieve information on Certificate Revocation Lists (CRLs)
