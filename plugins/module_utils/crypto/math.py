# -*- coding: utf-8 -*-
#
# (c) 2019, Felix Fontein <felix@fontein.de>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import sys


def binary_exp_mod(f, e, m):
    '''Computes f^e mod m in O(log e) multiplications modulo m.'''
    # Compute len_e = floor(log_2(e))
    len_e = -1
    x = e
    while x > 0:
        x >>= 1
        len_e += 1
    # Compute f**e mod m
    result = 1
    for k in range(len_e, -1, -1):
        result = (result * result) % m
        if ((e >> k) & 1) != 0:
            result = (result * f) % m
    return result


def simple_gcd(a, b):
    '''Compute GCD of its two inputs.'''
    while b != 0:
        a, b = b, a % b
    return a


def quick_is_not_prime(n):
    '''Does some quick checks to see if we can poke a hole into the primality of n.

    A result of `False` does **not** mean that the number is prime; it just means
    that we couldn't detect quickly whether it is not prime.
    '''
    if n <= 2:
        return True
    # The constant in the next line is the product of all primes < 200
    if simple_gcd(n, 7799922041683461553249199106329813876687996789903550945093032474868511536164700810) > 1:
        return True
    # TODO: maybe do some iterations of Miller-Rabin to increase confidence
    # (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
    return False


python_version = (sys.version_info[0], sys.version_info[1])
if python_version >= (2, 7) or python_version >= (3, 1):
    # Ansible still supports Python 2.6 on remote nodes
    def count_bits(no):
        no = abs(no)
        if no == 0:
            return 0
        return no.bit_length()
else:
    # Slow, but works
    def count_bits(no):
        no = abs(no)
        count = 0
        while no > 0:
            no >>= 1
            count += 1
        return count
