from __future__ import absolute_import, division, print_function
__metaclass__ = type


from mock import MagicMock


from ansible_collections.community.crypto.plugins.module_utils.acme.io import (
    read_file,
    write_file,
)


TEST_TEXT = r"""1234
5678"""


def test_read_file(tmpdir):
    fn = tmpdir / 'test.txt'
    fn.write(TEST_TEXT)
    assert read_file(str(fn), 't') == TEST_TEXT
    assert read_file(str(fn), 'b') == TEST_TEXT.encode('utf-8')


def test_write_file(tmpdir):
    fn = tmpdir / 'test.txt'
    module = MagicMock()
    write_file(module, str(fn), TEST_TEXT.encode('utf-8'))
    assert fn.read() == TEST_TEXT
