# Foo Collection
[![Shippable build status](https://api.shippable.com/projects/5e66776ca27f990007073a42/badge?branch=master)](https://app.shippable.com/projects/5e66776ca27f990007073a42)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.crypto)](https://codecov.io/gh/ansible-collections/community.crypto)

Provides modules for [Ansible](https://www.ansible.com/community) for various cryptographic operations.

<!-- Describe the collection and why a user would want to use it. What does the collection do? -->

## Tested with Ansible

Tested with the currently development version of Ansible.

<!-- List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->

## External requirements

The exact requirements for every module is listed in the module documentation. Many modules require a recent enough version of [the Python cryptography library](https://pypi.org/project/cryptography/). See the module documentations for the minimal version supported for each module.

## Included content

- OpenSSL / PKI modules:
  - openssl_certificate_info
  - openssl_certificate
  - openssl_csr_info
  - openssl_csr
  - openssl_dhparam
  - openssl_pkcs12
  - openssl_privatekey_info
  - openssl_privatekey
  - openssl_publickey
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

## Using this collection

<!--Include some quick examples that cover the most common use cases for your collection content. -->

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html). -->

We're following the general Ansible contributor guidelines; see [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

If you want to clone this repositority (or a fork of it) to improve it, you can proceed as follows:
1. Create a directory `ansible_collections/community`;
2. In there, checkout this repository (or a fork) as `crypto`;
3. Add the directory containing `ansible_collections` to your [ANSIBLE_COLLECTIONS_PATHS](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths).

## Release notes

<!--Add a link to a changelog.md file or an external docsite to cover this information. -->

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

<!-- List out where the user can find additional information, such as working group meeting times, slack/IRC channels, or documentation for the product this collection automates. At a minimum, link to: -->

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [COPYING](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
