..
  Copyright (c) Ansible Project
  GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
  SPDX-License-Identifier: GPL-3.0-or-later

.. _ansible_collections.community.crypto.docsite.guide_ownca:

How to create a small CA
========================

The `community.crypto collection <https://galaxy.ansible.com/community/crypto>`_ offers multiple modules that create private keys, certificate signing requests, and certificates. This guide shows how to create your own small CA and how to use it to sign certificates.

In all examples, we assume that the CA's private key is password protected, where the password is provided in the ``secret_ca_passphrase`` variable.

Set up the CA
-------------

Any certificate can be used as a CA certificate. You can create a self-signed certificate (see :ref:`ansible_collections.community.crypto.docsite.guide_selfsigned`), use another CA certificate to sign a new certificate (using the instructions below for signing a certificate), ask (and pay) a commercial CA to sign your CA certificate, etc.

The following instructions show how to set up a simple self-signed CA certificate.

.. code-block:: yaml+jinja

    - name: Create private key with password protection
      community.crypto.openssl_privatekey:
        path: /path/to/ca-certificate.key
        passphrase: "{{ secret_ca_passphrase }}"

    - name: Create certificate signing request (CSR) for CA certificate
      community.crypto.openssl_csr_pipe:
        privatekey_path: /path/to/ca-certificate.key
        privatekey_passphrase: "{{ secret_ca_passphrase }}"
        common_name: Ansible CA
        use_common_name_for_san: false  # since we do not specify SANs, don't use CN as a SAN
        basic_constraints:
          - 'CA:TRUE'
        basic_constraints_critical: true
        key_usage:
          - keyCertSign
        key_usage_critical: true
      register: ca_csr

    - name: Create self-signed CA certificate from CSR
      community.crypto.x509_certificate:
        path: /path/to/ca-certificate.pem
        csr_content: "{{ ca_csr.csr }}"
        privatekey_path: /path/to/ca-certificate.key
        privatekey_passphrase: "{{ secret_ca_passphrase }}"
        provider: selfsigned

Use the CA to sign a certificate
--------------------------------

To sign a certificate, you must pass a CSR to the :ref:`community.crypto.x509_certificate module <ansible_collections.community.crypto.x509_certificate_module>` or :ref:`community.crypto.x509_certificate_pipe module <ansible_collections.community.crypto.x509_certificate_pipe_module>`.

In the following example, we assume that the certificate to sign (including its private key) are on ``server_1``, while our CA certificate is on ``server_2``. We do not want any key material to leave each respective server.

.. code-block:: yaml+jinja

    - name: Create private key for new certificate on server_1
      community.crypto.openssl_privatekey:
        path: /path/to/certificate.key
      delegate_to: server_1
      run_once: true

    - name: Create certificate signing request (CSR) for new certificate
      community.crypto.openssl_csr_pipe:
        privatekey_path: /path/to/certificate.key
        subject_alt_name:
          - "DNS:ansible.com"
          - "DNS:www.ansible.com"
          - "DNS:docs.ansible.com"
      delegate_to: server_1
      run_once: true
      register: csr

    - name: Sign certificate with our CA
      community.crypto.x509_certificate_pipe:
        csr_content: "{{ csr.csr }}"
        provider: ownca
        ownca_path: /path/to/ca-certificate.pem
        ownca_privatekey_path: /path/to/ca-certificate.key
        ownca_privatekey_passphrase: "{{ secret_ca_passphrase }}"
        ownca_not_after: +365d  # valid for one year
        ownca_not_before: "-1d"  # valid since yesterday
      delegate_to: server_2
      run_once: true
      register: certificate

    - name: Write certificate file on server_1
      copy:
        dest: /path/to/certificate.pem
        content: "{{ certificate.certificate }}"
      delegate_to: server_1
      run_once: true

Please note that the above procedure is **not idempotent**. The following extended example reads the existing certificate from ``server_1`` (if exists) and provides it to the :ref:`community.crypto.x509_certificate_pipe module <ansible_collections.community.crypto.x509_certificate_pipe_module>`, and only writes the result back if it was changed:

.. code-block:: yaml+jinja

    - name: Create private key for new certificate on server_1
      community.crypto.openssl_privatekey:
        path: /path/to/certificate.key
      delegate_to: server_1
      run_once: true

    - name: Create certificate signing request (CSR) for new certificate
      community.crypto.openssl_csr_pipe:
        privatekey_path: /path/to/certificate.key
        subject_alt_name:
          - "DNS:ansible.com"
          - "DNS:www.ansible.com"
          - "DNS:docs.ansible.com"
      delegate_to: server_1
      run_once: true
      register: csr

    - name: Check whether certificate exists
      stat:
        path: /path/to/certificate.pem
      delegate_to: server_1
      run_once: true
      register: certificate_exists

    - name: Read existing certificate if exists
      slurp:
        src: /path/to/certificate.pem
      when: certificate_exists.stat.exists
      delegate_to: server_1
      run_once: true
      register: certificate

    - name: Sign certificate with our CA
      community.crypto.x509_certificate_pipe:
        content: "{{ (certificate.content | b64decode) if certificate_exists.stat.exists else omit }}"
        csr_content: "{{ csr.csr }}"
        provider: ownca
        ownca_path: /path/to/ca-certificate.pem
        ownca_privatekey_path: /path/to/ca-certificate.key
        ownca_privatekey_passphrase: "{{ secret_ca_passphrase }}"
        ownca_not_after: +365d  # valid for one year
        ownca_not_before: "-1d"  # valid since yesterday
      delegate_to: server_2
      run_once: true
      register: certificate

    - name: Write certificate file on server_1
      copy:
        dest: /path/to/certificate.pem
        content: "{{ certificate.certificate }}"
      delegate_to: server_1
      run_once: true
      when: certificate is changed
