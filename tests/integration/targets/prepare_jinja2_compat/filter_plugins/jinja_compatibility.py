# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is licensed under the
# BSD-3-Clause  License. Modules you write using this snippet, which is embedded
# dynamically by Ansible, still belong to the author of the module, and may assign
# their own license to the complete work.

# The BSD License license has been included as LICENSES/BSD-3-Clause.txt in this collection.
# SPDX-License-Identifier: BSD-3-Clause

# Copyright 2007 Pallets
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# 3.  Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from jinja2.filters import contextfilter
from jinja2.runtime import Undefined
from jinja2.exceptions import TemplateRuntimeError, FilterArgumentError

try:
    from jinja2.nodes import EvalContext
    HAS_EVALCONTEXT = True
except ImportError:
    HAS_EVALCONTEXT = False


def call_test(environment, test_name, value, args, kwargs):
    try:
        return environment.call_test(test_name, value, args, kwargs)
    except AttributeError:
        # call_test was added together with selectattr...
        func = environment.tests.get(test_name)
        if func is None:
            raise TemplateRuntimeError('no test named %r' % test_name)
        return func(value, *args, **kwargs)


def call_filter(environment, name, value, args=None, kwargs=None,
                context=None, eval_ctx=None):
    func = environment.filters.get(name)
    if func is None:
        raise TemplateRuntimeError('no filter named %r' % name)
    args = list(args or ())
    if getattr(func, 'contextfilter', False):
        if context is None:
            raise TemplateRuntimeError('Attempted to invoke context filter without context')
        args.insert(0, context)
    elif getattr(func, 'evalcontextfilter', False):
        if eval_ctx is None:
            if context is not None:
                eval_ctx = context.eval_ctx
            elif HAS_EVALCONTEXT:
                eval_ctx = EvalContext(environment)
            else:
                raise TemplateRuntimeError('Too old Jinja2 does not have EvalContext')
        args.insert(0, eval_ctx)
    elif getattr(func, 'environmentfilter', False):
        args.insert(0, environment)
    return func(value, *args, **(kwargs or {}))


@contextfilter
def compatibility_select_filter(context, sequence, test_name, *args, **kwargs):
    for item in sequence:
        if call_test(context.environment, test_name, item, args, kwargs):
            yield item


@contextfilter
def compatibility_reject_filter(context, sequence, test_name, *args, **kwargs):
    for item in sequence:
        if not call_test(context.environment, test_name, item, args, kwargs):
            yield item


def make_attrgetter(environment, attribute_str, default=None):
    attributes = [int(attribute) if attribute.isdigit() else attribute for attribute in attribute_str.split(".")]

    def f(item):
        for attribute in attributes:
            item = environment.getitem(item, attribute)
            if default and isinstance(item, Undefined):
                item = default
        return item

    return f


@contextfilter
def compatibility_selectattr_filter(context, sequence, attribute_str, test_name, *args, **kwargs):
    f = make_attrgetter(context.environment, attribute_str)
    for item in sequence:
        if call_test(context.environment, test_name, f(item), args, kwargs):
            yield item


@contextfilter
def compatibility_rejectattr_filter(context, sequence, attribute_str, test_name, *args, **kwargs):
    f = make_attrgetter(context.environment, attribute_str)
    for item in sequence:
        if not call_test(context.environment, test_name, f(item), args, kwargs):
            yield item


def prepare_map(context, args, kwargs):
    if len(args) == 0 and "attribute" in kwargs:
        attribute = kwargs.pop("attribute")
        default = kwargs.pop("default", None)
        if kwargs:
            raise FilterArgumentError("Unexpected keyword argument {0!r}".format(next(iter(kwargs))))
        func = make_attrgetter(context.environment, attribute, default=default)
    else:
        try:
            name = args[0]
            args = args[1:]
        except LookupError:
            raise FilterArgumentError("map requires a filter argument")

        def func(item):
            return call_filter(context.environment, name, item, args, kwargs, context=context)

    return func


@contextfilter
def compatibility_map_filter(context, seq, *args, **kwargs):
    func = prepare_map(context, args, kwargs)
    if seq:
        for item in seq:
            yield func(item)


class FilterModule:
    ''' Jinja2 compat filters '''

    def filters(self):
        return {
            'select': compatibility_select_filter,
            'selectattr': compatibility_selectattr_filter,
            'reject': compatibility_reject_filter,
            'rejectattr': compatibility_rejectattr_filter,
            'map': compatibility_map_filter,
        }
