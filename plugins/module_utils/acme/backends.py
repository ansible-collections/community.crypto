# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc

from ansible.module_utils import six


@six.add_metaclass(abc.ABCMeta)
class CryptoBackend(object):
    def __init__(self, module):
        self.module = module

    @abc.abstractmethod
    def parse_key(self, key_file=None, key_content=None, passphrase=None):
        '''
        Parses an RSA or Elliptic Curve key file in PEM format and returns key_data.
        Raises KeyParsingError in case of errors.
        '''

    @abc.abstractmethod
    def sign(self, payload64, protected64, key_data):
        pass

    @abc.abstractmethod
    def create_mac_key(self, alg, key):
        '''Create a MAC key.'''

    def get_ordered_csr_identifiers(self, csr_filename=None, csr_content=None):
        '''
        Return a list of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.

        The list is deduplicated, and if a CNAME is present, it will be returned
        as the first element in the result.
        '''
        self.module.deprecate(
            "Every backend must override the get_ordered_csr_identifiers() method."
            " The default implementation will be removed in 3.0.0 and this method will be marked as `abstractmethod` by then.",
            version='3.0.0',
            collection_name='community.crypto',
        )
        return sorted(self.get_csr_identifiers(csr_filename=csr_filename, csr_content=csr_content))

    @abc.abstractmethod
    def get_csr_identifiers(self, csr_filename=None, csr_content=None):
        '''
        Return a set of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.
        '''

    @abc.abstractmethod
    def get_cert_days(self, cert_filename=None, cert_content=None, now=None):
        '''
        Return the days the certificate in cert_filename remains valid and -1
        if the file was not found. If cert_filename contains more than one
        certificate, only the first one will be considered.

        If now is not specified, datetime.datetime.now() is used.
        '''

    @abc.abstractmethod
    def create_chain_matcher(self, criterium):
        '''
        Given a Criterium object, creates a ChainMatcher object.
        '''
