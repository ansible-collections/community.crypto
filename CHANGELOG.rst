==============================
Community Crypto Release Notes
==============================

.. contents:: Topics


v1.9.8
======

Release Summary
---------------

Documentation fix release. No actual code changes.

v1.9.7
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

v1.9.6
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- cryptography backend - improve Unicode handling for Python 2 (https://github.com/ansible-collections/community.crypto/pull/313).

v1.9.5
======

Release Summary
---------------

Bugfix release to fully support cryptography 35.0.0.

Bugfixes
--------

- get_certificate - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- openssl_csr_info - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- openssl_csr_info - fix compatibility with the cryptography 35.0.0 release in PyOpenSSL backend (https://github.com/ansible-collections/community.crypto/pull/300).
- openssl_pkcs12 - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/296).
- x509_certificate_info - fix compatibility with the cryptography 35.0.0 release (https://github.com/ansible-collections/community.crypto/pull/294).
- x509_certificate_info - fix compatibility with the cryptography 35.0.0 release in PyOpenSSL backend (https://github.com/ansible-collections/community.crypto/pull/300).

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
