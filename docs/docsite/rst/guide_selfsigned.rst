..
  Copyright (c) Ansible Project
  GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
  SPDX-License-Identifier: GPL-3.0-or-later

.. _ansible_collections.community.crypto.docsite.guide_selfsigned:

How to create self-signed certificates
======================================

The `community.crypto collection <https://galaxy.ansible.com/ui/repo/published/community/crypto/>`_ offers multiple modules that create private keys, certificate signing requests, and certificates. This guide shows how to create self-signed certificates.

For creating any kind of certificate, you always have to start with a private key. You can use the :ref:`community.crypto.openssl_privatekey module <ansible_collections.community.crypto.openssl_privatekey_module>` to create a private key. If you only specify :ansopt:`community.crypto.openssl_privatekey#module:path`, the default parameters will be used. This will result in a 4096 bit RSA private key:

.. code-block:: yaml+jinja

    - name: Create private key (RSA, 4096 bits)
      community.crypto.openssl_privatekey:
        path: /path/to/certificate.key

You can specify :ansopt:`community.crypto.openssl_privatekey#module:type` to select another key type, :ansopt:`community.crypto.openssl_privatekey#module:size` to select a different key size (only available for RSA and DSA keys), or :ansopt:`community.crypto.openssl_privatekey#module:passphrase` if you want to store the key password-protected:

.. code-block:: yaml+jinja

    - name: Create private key (X25519) with password protection
      community.crypto.openssl_privatekey:
        path: /path/to/certificate.key
        type: X25519
        passphrase: changeme

To create a very simple self-signed certificate with no specific information, you can proceed directly with the :ref:`community.crypto.x509_certificate module <ansible_collections.community.crypto.x509_certificate_module>`:

.. code-block:: yaml+jinja

    - name: Create simple self-signed certificate
      community.crypto.x509_certificate:
        path: /path/to/certificate.pem
        privatekey_path: /path/to/certificate.key
        provider: selfsigned

(If you used :ansopt:`community.crypto.openssl_privatekey#module:passphrase` for the private key, you have to provide :ansopt:`community.crypto.x509_certificate#module:privatekey_passphrase`.)

You can use :ansopt:`community.crypto.x509_certificate#module:selfsigned_not_after` to define when the certificate expires (default: in roughly 10 years), and :ansopt:`community.crypto.x509_certificate#module:selfsigned_not_before` to define from when the certificate is valid (default: now).

To define further properties of the certificate, like the subject, Subject Alternative Names (SANs), key usages, name constraints, etc., you need to first create a Certificate Signing Request (CSR) and provide it to the :ref:`community.crypto.x509_certificate module <ansible_collections.community.crypto.x509_certificate_module>`. If you do not need the CSR file, you can use the :ref:`community.crypto.openssl_csr_pipe module <ansible_collections.community.crypto.openssl_csr_pipe_module>` as in the example below. (To store it to disk, use the :ref:`community.crypto.openssl_csr module <ansible_collections.community.crypto.openssl_csr_module>` instead.)

.. code-block:: yaml+jinja

    - name: Create certificate signing request (CSR) for self-signed certificate
      community.crypto.openssl_csr_pipe:
        privatekey_path: /path/to/certificate.key
        common_name: ansible.com
        organization_name: Ansible, Inc.
        subject_alt_name:
          - "DNS:ansible.com"
          - "DNS:www.ansible.com"
          - "DNS:docs.ansible.com"
      register: csr

    - name: Create self-signed certificate from CSR
      community.crypto.x509_certificate:
        path: /path/to/certificate.pem
        csr_content: "{{ csr.csr }}"
        privatekey_path: /path/to/certificate.key
        provider: selfsigned
