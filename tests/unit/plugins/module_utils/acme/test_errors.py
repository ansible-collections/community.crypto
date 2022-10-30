# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import pytest

from ansible_collections.community.crypto.tests.unit.compat.mock import MagicMock


from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    format_error_problem,
    ACMEProtocolException,
)


TEST_FORMAT_ERROR_PROBLEM = [
    (
        {
            'type': 'foo',
        },
        '',
        'Error foo'
    ),
    (
        {
            'type': 'foo',
            'title': 'bar'
        },
        '',
        'Error "bar" (foo)'
    ),
    (
        {
            'type': 'foo',
            'detail': 'bar baz'
        },
        '',
        'Error foo: "bar baz"'
    ),
    (
        {
            'type': 'foo',
            'subproblems': []
        },
        '',
        'Error foo Subproblems:'
    ),
    (
        {
            'type': 'foo',
            'subproblems': [
                {
                    'type': 'bar',
                },
            ]
        },
        '',
        'Error foo Subproblems:\n(0) Error bar'
    ),
    (
        {
            'type': 'foo',
            'subproblems': [
                {
                    'type': 'bar',
                    'subproblems': [
                        {
                            'type': 'baz',
                        },
                    ]
                },
            ]
        },
        '',
        'Error foo Subproblems:\n(0) Error bar Subproblems:\n(0.0) Error baz'
    ),
    (
        {
            'type': 'foo',
            'title': 'Foo Error',
            'detail': 'Foo went wrong',
            'subproblems': [
                {
                    'type': 'bar',
                    'detail': 'Bar went wrong',
                    'subproblems': [
                        {
                            'type': 'baz',
                            'title': 'Baz Error',
                        },
                    ]
                },
                {
                    'type': 'bar2',
                    'title': 'Bar 2 Error',
                    'detail': 'Bar really went wrong'
                },
            ]
        },
        'X.',
        'Error "Foo Error" (foo): "Foo went wrong" Subproblems:\n'
        '(X.0) Error bar: "Bar went wrong" Subproblems:\n'
        '(X.0.0) Error "Baz Error" (baz)\n'
        '(X.1) Error "Bar 2 Error" (bar2): "Bar really went wrong"'
    ),
]


@pytest.mark.parametrize("problem, subproblem_prefix, result", TEST_FORMAT_ERROR_PROBLEM)
def test_format_error_problem(problem, subproblem_prefix, result):
    res = format_error_problem(problem, subproblem_prefix)
    assert res == result


def create_regular_response(response_text):
    response = MagicMock()
    response.read = MagicMock(return_value=response_text.encode('utf-8'))
    response.closed = False
    return response


def create_error_response():
    response = MagicMock()
    response.read = MagicMock(side_effect=AttributeError('read'))
    response.closed = True
    return response


def create_decode_error(msg):
    def f(content):
        raise Exception(msg)

    return f


TEST_ACME_PROTOCOL_EXCEPTION = [
    (
        {},
        None,
        'ACME request failed.',
        {
        },
    ),
    (
        {
            'msg': 'Foo',
            'extras': {
                'foo': 'bar',
            },
        },
        None,
        'Foo.',
        {
            'foo': 'bar',
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
        },
        None,
        'ACME request failed for https://ca.example.com/foo with HTTP status 201 Created.',
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
            'response': create_regular_response('xxx'),
        },
        None,
        'ACME request failed for https://ca.example.com/foo with HTTP status 201 Created. The raw error result: xxx',
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
            'response': create_regular_response('xxx'),
        },
        create_decode_error('yyy'),
        'ACME request failed for https://ca.example.com/foo with HTTP status 201 Created. The raw error result: xxx',
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
            'response': create_regular_response('xxx'),
        },
        lambda content: dict(foo='bar'),
        "ACME request failed for https://ca.example.com/foo with HTTP status 201 Created. The JSON error result: {'foo': 'bar'}",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
            'response': create_error_response(),
        },
        None,
        'ACME request failed for https://ca.example.com/foo with HTTP status 201 Created.',
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
                'body': 'xxx',
            },
            'response': create_error_response(),
        },
        lambda content: dict(foo='bar'),
        "ACME request failed for https://ca.example.com/foo with HTTP status 201 Created. The JSON error result: {'foo': 'bar'}",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
            'content': 'xxx',
        },
        None,
        "ACME request failed for https://ca.example.com/foo with HTTP status 201 Created. The raw error result: xxx",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 400,
            },
            'content_json': {
                'foo': 'bar',
            },
            'extras': {
                'bar': 'baz',
            }
        },
        None,
        "ACME request failed for https://ca.example.com/foo with HTTP status 400 Bad Request. The JSON error result: {'foo': 'bar'}",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 400,
            'bar': 'baz',
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 201,
            },
            'content_json': {
                'type': 'foo',
            },
        },
        None,
        "ACME request failed for https://ca.example.com/foo with HTTP status 201 Created. The JSON error result: {'type': 'foo'}",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 201,
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 400,
            },
            'content_json': {
                'type': 'foo',
            },
        },
        None,
        "ACME request failed for https://ca.example.com/foo with status 400 Bad Request. Error foo.",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 400,
            'problem': {
                'type': 'foo',
            },
            'subproblems': [],
        },
    ),
    (
        {
            'info': {
                'url': 'https://ca.example.com/foo',
                'status': 400,
            },
            'content_json': {
                'type': 'foo',
                'title': 'Foo Error',
                'subproblems': [
                    {
                        'type': 'bar',
                        'detail': 'This is a bar error',
                        'details': 'Details.',
                    },
                ],
            },
        },
        None,
        "ACME request failed for https://ca.example.com/foo with status 400 Bad Request. Error \"Foo Error\" (foo). Subproblems:\n"
        "(0) Error bar: \"This is a bar error\".",
        {
            'http_url': 'https://ca.example.com/foo',
            'http_status': 400,
            'problem': {
                'type': 'foo',
                'title': 'Foo Error',
            },
            'subproblems': [
                {
                    'type': 'bar',
                    'detail': 'This is a bar error',
                    'details': 'Details.',
                },
            ],
        },
    ),
]


@pytest.mark.parametrize("input, from_json, msg, args", TEST_ACME_PROTOCOL_EXCEPTION)
def test_acme_protocol_exception(input, from_json, msg, args):
    if from_json is None:
        module = None
    else:
        module = MagicMock()
        module.from_json = from_json
    with pytest.raises(ACMEProtocolException) as exc:
        raise ACMEProtocolException(module, **input)

    print(exc.value.msg)
    print(exc.value.module_fail_args)
    print(msg)
    print(args)
    assert exc.value.msg == msg
    assert exc.value.module_fail_args == args
