# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six import binary_type, PY3
from ansible.module_utils.six.moves.http_client import responses as http_responses


def format_http_status(status_code):
    expl = http_responses.get(status_code)
    if not expl:
        return str(status_code)
    return '%d %s' % (status_code, expl)


def format_error_problem(problem, subproblem_prefix=''):
    if 'title' in problem:
        msg = 'Error "{title}" ({type})'.format(
            type=problem['type'],
            title=problem['title'],
        )
    else:
        msg = 'Error {type}'.format(type=problem['type'])
    if 'detail' in problem:
        msg += ': "{detail}"'.format(detail=problem['detail'])
    subproblems = problem.get('subproblems')
    if subproblems is not None:
        msg = '{msg} Subproblems:'.format(msg=msg)
        for index, problem in enumerate(subproblems):
            index_str = '{prefix}{index}'.format(prefix=subproblem_prefix, index=index)
            msg = '{msg}\n({index}) {problem}'.format(
                msg=msg,
                index=index_str,
                problem=format_error_problem(problem, subproblem_prefix='{0}.'.format(index_str)),
            )
    return msg


class ModuleFailException(Exception):
    '''
    If raised, module.fail_json() will be called with the given parameters after cleanup.
    '''
    def __init__(self, msg, **args):
        super(ModuleFailException, self).__init__(self, msg)
        self.msg = msg
        self.module_fail_args = args

    def do_fail(self, module, **arguments):
        module.fail_json(msg=self.msg, other=self.module_fail_args, **arguments)


class ACMEProtocolException(ModuleFailException):
    def __init__(self, module, msg=None, info=None, response=None, content=None, content_json=None, extras=None):
        # Try to get hold of content, if response is given and content is not provided
        if content is None and content_json is None and response is not None:
            try:
                # In Python 2, reading from a closed response yields a TypeError.
                # In Python 3, read() simply returns ''
                if PY3 and response.closed:
                    raise TypeError
                content = response.read()
            except (AttributeError, TypeError):
                content = info.pop('body', None)

        # Make sure that content_json is None or a dictionary
        if content_json is not None and not isinstance(content_json, dict):
            if content is None and isinstance(content_json, binary_type):
                content = content_json
            content_json = None

        # Try to get hold of JSON decoded content, when content is given and JSON not provided
        if content_json is None and content is not None and module is not None:
            try:
                content_json = module.from_json(to_text(content))
            except Exception as e:
                pass

        extras = extras or dict()

        if msg is None:
            msg = 'ACME request failed'
        add_msg = ''

        if info is not None:
            url = info['url']
            code = info['status']
            extras['http_url'] = url
            extras['http_status'] = code
            if code is not None and code >= 400 and content_json is not None and 'type' in content_json:
                if 'status' in content_json and content_json['status'] != code:
                    code = 'status {problem_code} (HTTP status: {http_code})'.format(
                        http_code=format_http_status(code), problem_code=content_json['status'])
                else:
                    code = 'status {problem_code}'.format(problem_code=format_http_status(code))
                subproblems = content_json.pop('subproblems', None)
                add_msg = ' {problem}.'.format(problem=format_error_problem(content_json))
                extras['problem'] = content_json
                extras['subproblems'] = subproblems or []
                if subproblems is not None:
                    add_msg = '{add_msg} Subproblems:'.format(add_msg=add_msg)
                    for index, problem in enumerate(subproblems):
                        add_msg = '{add_msg}\n({index}) {problem}.'.format(
                            add_msg=add_msg,
                            index=index,
                            problem=format_error_problem(problem, subproblem_prefix='{0}.'.format(index)),
                        )
            else:
                code = 'HTTP status {code}'.format(code=format_http_status(code))
                if content_json is not None:
                    add_msg = ' The JSON error result: {content}'.format(content=content_json)
                elif content is not None:
                    add_msg = ' The raw error result: {content}'.format(content=to_text(content))
            msg = '{msg} for {url} with {code}'.format(msg=msg, url=url, code=format_http_status(code))
        elif content_json is not None:
            add_msg = ' The JSON result: {content}'.format(content=content_json)
        elif content is not None:
            add_msg = ' The raw result: {content}'.format(content=to_text(content))

        super(ACMEProtocolException, self).__init__(
            '{msg}.{add_msg}'.format(msg=msg, add_msg=add_msg),
            **extras
        )
        self.problem = {}
        self.subproblems = []
        for k, v in extras.items():
            setattr(self, k, v)


class BackendException(ModuleFailException):
    pass


class NetworkException(ModuleFailException):
    pass


class KeyParsingError(ModuleFailException):
    pass
