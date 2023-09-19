<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Ansible Community Crypto Collection

[![Build Status](https://dev.azure.com/ansible/community.crypto/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.crypto/_build?definitionId=21)
[![EOL CI](https://github.com/ansible-collections/community.crypto/workflows/EOL%20CI/badge.svg?event=push)](https://github.com/ansible-collections/community.crypto/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.crypto)](https://codecov.io/gh/ansible-collections/community.crypto)

Provides modules for [Ansible](https://www.ansible.com/community) for various cryptographic operations.

You can find [documentation for this collection on the Ansible docs site](https://docs.ansible.com/ansible/latest/collections/community/crypto/).

Please note that this collection does **not** support Windows targets.

## Tested with Ansible

Tested with the current Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, ansible-core 2.14, ansible-core 2.15, and ansible-core-2.16 releases and the current development version of ansible-core. Ansible versions before 2.9.10 are not supported.

## External requirements

The exact requirements for every module are listed in the module documentation. 

Most modules require a recent enough version of [the Python cryptography library](https://pypi.org/project/cryptography/). See the module documentations for the minimal version supported for each module.

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/ansible/latest/collections/community/crypto) will show docs for the _latest version released in the Ansible package_, not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/crypto) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.crypto/branch/main/) which shows docs for the _latest commit in the `main` branch_.

If you use the Ansible package and do not update collections independently, use **latest**. If you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Included content

- OpenSSL / PKI modules and plugins:
  - certificate_complete_chain module
  - openssl_csr_info module and filter
  - openssl_csr_pipe module
  - openssl_csr module
  - openssl_dhparam module
  - openssl_pkcs12 module
  - openssl_privatekey_convert module
  - openssl_privatekey_info module and filter
  - openssl_privatekey_pipe module
  - openssl_privatekey module
  - openssl_publickey_info module and filter
  - openssl_publickey module
  - openssl_signature_info module
  - openssl_signature module
  - split_pem filter
  - x509_certificate_info module and filter
  - x509_certificate_pipe module
  - x509_certificate module
  - x509_crl_info module and filter
  - x509_crl module
- OpenSSH modules and plugins:
  - openssh_cert module
  - openssh_keypair module
- ACME modules and plugins:
  - acme_account_info module
  - acme_account module
  - acme_certificate module
  - acme_certificate_revoke module
  - acme_challenge_cert_helper module
  - acme_inspect module
- ECS modules and plugins:
  - ecs_certificate module
  - ecs_domain module
- GnuPG modules and plugins:
  - gpg_fingerprint lookup and filter
- Miscellaneous modules and plugins:
  - crypto_info module
  - get_certificate module
  - luks_device module

You can also find a list of all modules and plugins with documentation on the [Ansible docs site](https://docs.ansible.com/ansible/latest/collections/community/crypto/), or the [latest commit collection documentation](https://ansible-collections.github.io/community.crypto/branch/main/).

## Using this collection

Before using the crypto community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.crypto

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.crypto
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html). -->

We're following the general Ansible contributor guidelines; see [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

If you want to clone this repositority (or a fork of it) to improve it, you can proceed as follows:
1. Create a directory `ansible_collections/community`;
2. In there, checkout this repository (or a fork) as `crypto`;
3. Add the directory containing `ansible_collections` to your [ANSIBLE_COLLECTIONS_PATH](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths).

See [Ansible's dev guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections) for more information.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.crypto/blob/main/CHANGELOG.rst).

## Roadmap

We plan to regularly release minor and patch versions, whenever new features are added or bugs fixed. Our collection follows [semantic versioning](https://semver.org/), so breaking changes will only happen in major releases.

Most modules will drop PyOpenSSL support in version 2.0.0 of the collection, i.e. in the next major version. We currently plan to release 2.0.0 somewhen during 2021. Around then, the supported versions of the most common distributions will contain a new enough version of ``cryptography``.

Once 2.0.0 has been released, bugfixes will still be backported to 1.0.0 for some time, and some features might also be backported. If we do not want to backport something ourselves because we think it is not worth the effort, backport PRs by non-maintainers are usually accepted.

In 2.0.0, the following notable features will be removed:
* PyOpenSSL backends of all modules, except ``openssl_pkcs12`` which does not have a ``cryptography`` backend due to lack of support of PKCS#12 functionality in ``cryptography``.
* The ``assertonly`` provider of ``x509_certificate`` will be removed.

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

This collection is primarily licensed and distributed as a whole under the GNU General Public License v3.0 or later.

See [LICENSES/GPL-3.0-or-later.txt](https://github.com/ansible-collections/community.crypto/blob/main/COPYING) for the full text.

Parts of the collection are licensed under the [Apache 2.0 license](https://github.com/ansible-collections/community.crypto/blob/main/LICENSES/Apache-2.0.txt) (`plugins/module_utils/crypto/_obj2txt.py` and `plugins/module_utils/crypto/_objects_data.py`), the [BSD 2-Clause license](https://github.com/ansible-collections/community.crypto/blob/main/LICENSES/BSD-2-Clause.txt) (`plugins/module_utils/ecs/api.py`), the [BSD 3-Clause license](https://github.com/ansible-collections/community.crypto/blob/main/LICENSES/BSD-3-Clause.txt) (`plugins/module_utils/crypto/_obj2txt.py`, `tests/integration/targets/prepare_jinja2_compat/filter_plugins/jinja_compatibility.py`), and the [PSF 2.0 license](https://github.com/ansible-collections/community.crypto/blob/main/LICENSES/PSF-2.0.txt) (`plugins/module_utils/_version.py`). This only applies to vendored files in ``plugins/module_utils/`` and to the ECS module utils.

Almost all files have a machine readable `SDPX-License-Identifier:` comment denoting its respective license(s) or an equivalent entry in an accompanying `.license` file. Only changelog fragments (which will not be part of a release) are covered by a blanket statement in `.reuse/dep5`. Right now a few vendored PEM files do not have licensing information as well. This conforms to the [REUSE specification](https://reuse.software/spec/) up to the aforementioned PEM files.
