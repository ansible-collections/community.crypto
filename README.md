# Ansible Community Crypto Collection

[![Build Status](https://dev.azure.com/ansible/community.crypto/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.crypto/_build?definitionId=21)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.crypto)](https://codecov.io/gh/ansible-collections/community.crypto)

Provides modules for [Ansible](https://www.ansible.com/community) for various cryptographic operations.

You can find [documentation for this collection on the Ansible docs site](https://docs.ansible.com/ansible/latest/collections/community/crypto/).

## Tested with Ansible

Tested with both the current Ansible 2.9 and 2.10 releases and the current development version of Ansible. Ansible versions before 2.9.10 are not supported.

## External requirements

The exact requirements for every module are listed in the module documentation. 

Most modules require a recent enough version of [the Python cryptography library](https://pypi.org/project/cryptography/). See the module documentations for the minimal version supported for each module.

## Included content

- OpenSSL / PKI modules:
  - openssl_csr_info
  - openssl_csr
  - openssl_dhparam
  - openssl_pkcs12
  - openssl_privatekey_info
  - openssl_privatekey
  - openssl_publickey
  - openssl_signature_info
  - openssl_signature
  - x509_certificate_info
  - x509_certificate
  - x509_crl_info
  - x509_crl
  - certificate_complete_chain
- OpenSSH modules:
  - openssh_cert
  - openssh_keypair
- ACME modules:
  - acme_account_info
  - acme_account
  - acme_certificate
  - acme_certificate_revoke
  - acme_challenge_cert_helper
  - acme_inspect
- ECS modules:
  - ecs_certificate
  - ecs_domain
- Miscellaneous modules:
  - get_certificate
  - luks_device

You can also find a list of all modules with documentation on the [Ansible docs site](https://docs.ansible.com/ansible/latest/collections/community/crypto/).

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

GNU General Public License v3.0 or later.

See [COPYING](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
