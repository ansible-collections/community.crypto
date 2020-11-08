# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2013 Michael DeHaan <michael.dehaan@gmail.com>
# Copyright (c) 2016 Toshio Kuratomi <tkuratomi@ansible.com>
# Copyright (c) 2019 Ansible Project
# Copyright (c) 2020 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Parts taken from ansible.module_utils.basic and ansible.module_utils.common.warnings.

# NOTE: THIS MUST NOT BE USED BY A MODULE! THIS IS ONLY FOR ACTION PLUGINS!

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import copy
import traceback

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.module_utils import six
from ansible.module_utils.basic import AnsibleFallbackNotFound, SEQUENCETYPE, remove_values
from ansible.module_utils.common._collections_compat import (
    Mapping
)
from ansible.module_utils.common.parameters import (
    handle_aliases,
    list_deprecations,
    list_no_log_values,
    PASS_VARS,
    PASS_BOOLS,
)
from ansible.module_utils.common.validation import (
    check_mutually_exclusive,
    check_required_arguments,
    check_required_by,
    check_required_if,
    check_required_one_of,
    check_required_together,
    count_terms,
    check_type_bool,
    check_type_bits,
    check_type_bytes,
    check_type_float,
    check_type_int,
    check_type_jsonarg,
    check_type_list,
    check_type_dict,
    check_type_path,
    check_type_raw,
    check_type_str,
    safe_eval,
)
from ansible.module_utils.common.text.formatters import (
    lenient_lowercase,
)
from ansible.module_utils.parsing.convert_bool import BOOLEANS_FALSE, BOOLEANS_TRUE
from ansible.module_utils.six import (
    binary_type,
    string_types,
    text_type,
)
from ansible.module_utils._text import to_native, to_text
from ansible.plugins.action import ActionBase


class _ModuleExitException(Exception):
    def __init__(self, result):
        super(_ModuleExitException, self).__init__()
        self.result = result


class AnsibleActionModule(object):
    def __init__(self, action_plugin, argument_spec, bypass_checks=False,
                 mutually_exclusive=None, required_together=None,
                 required_one_of=None, supports_check_mode=False,
                 required_if=None, required_by=None):
        # Internal data
        self.__action_plugin = action_plugin
        self.__warnings = []
        self.__deprecations = []

        # AnsibleModule data
        self._name = self.__action_plugin._task.action
        self.argument_spec = argument_spec
        self.supports_check_mode = supports_check_mode
        self.check_mode = self.__action_plugin._play_context.check_mode
        self.bypass_checks = bypass_checks
        self.no_log = self.__action_plugin._play_context.no_log

        self.mutually_exclusive = mutually_exclusive
        self.required_together = required_together
        self.required_one_of = required_one_of
        self.required_if = required_if
        self.required_by = required_by
        self._diff = self.__action_plugin._play_context.diff
        self._verbosity = self.__action_plugin._display.verbosity
        self._string_conversion_action = C.STRING_CONVERSION_ACTION

        self.aliases = {}
        self._legal_inputs = []
        self._options_context = list()

        self.params = copy.deepcopy(action_plugin._task.args)
        self._set_fallbacks()

        # append to legal_inputs and then possibly check against them
        try:
            self.aliases = self._handle_aliases()
        except (ValueError, TypeError) as e:
            # Use exceptions here because it isn't safe to call fail_json until no_log is processed
            raise _ModuleExitException(dict(failed=True, msg="Module alias error: %s" % to_native(e)))

        # Save parameter values that should never be logged
        self.no_log_values = set()
        self._handle_no_log_values()

        self._check_arguments()

        # check exclusive early
        if not bypass_checks:
            self._check_mutually_exclusive(mutually_exclusive)

        self._set_defaults(pre=True)

        self._CHECK_ARGUMENT_TYPES_DISPATCHER = {
            'str': self._check_type_str,
            'list': self._check_type_list,
            'dict': self._check_type_dict,
            'bool': self._check_type_bool,
            'int': self._check_type_int,
            'float': self._check_type_float,
            'path': self._check_type_path,
            'raw': self._check_type_raw,
            'jsonarg': self._check_type_jsonarg,
            'json': self._check_type_jsonarg,
            'bytes': self._check_type_bytes,
            'bits': self._check_type_bits,
        }
        if not bypass_checks:
            self._check_required_arguments()
            self._check_argument_types()
            self._check_argument_values()
            self._check_required_together(required_together)
            self._check_required_one_of(required_one_of)
            self._check_required_if(required_if)
            self._check_required_by(required_by)

        self._set_defaults(pre=False)

        # deal with options sub-spec
        self._handle_options()

    def _handle_aliases(self, spec=None, param=None, option_prefix=''):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        # this uses exceptions as it happens before we can safely call fail_json
        alias_warnings = []
        alias_results, self._legal_inputs = handle_aliases(spec, param, alias_warnings=alias_warnings)
        for option, alias in alias_warnings:
            self.warn('Both option %s and its alias %s are set.' % (option_prefix + option, option_prefix + alias))

        deprecated_aliases = []
        for i in spec.keys():
            if 'deprecated_aliases' in spec[i].keys():
                for alias in spec[i]['deprecated_aliases']:
                    deprecated_aliases.append(alias)

        for deprecation in deprecated_aliases:
            if deprecation['name'] in param.keys():
                self.deprecate("Alias '%s' is deprecated. See the module docs for more information" % deprecation['name'],
                               version=deprecation.get('version'), date=deprecation.get('date'),
                               collection_name=deprecation.get('collection_name'))
        return alias_results

    def _handle_no_log_values(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        try:
            self.no_log_values.update(list_no_log_values(spec, param))
        except TypeError as te:
            self.fail_json(msg="Failure when processing no_log parameters. Module invocation will be hidden. "
                               "%s" % to_native(te), invocation={'module_args': 'HIDDEN DUE TO FAILURE'})

        for message in list_deprecations(spec, param):
            self.deprecate(message['msg'], version=message.get('version'), date=message.get('date'),
                           collection_name=message.get('collection_name'))

    def _check_arguments(self, spec=None, param=None, legal_inputs=None):
        self._syslog_facility = 'LOG_USER'
        unsupported_parameters = set()
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        if legal_inputs is None:
            legal_inputs = self._legal_inputs

        for k in list(param.keys()):

            if k not in legal_inputs:
                unsupported_parameters.add(k)

        for k in PASS_VARS:
            # handle setting internal properties from internal ansible vars
            param_key = '_ansible_%s' % k
            if param_key in param:
                if k in PASS_BOOLS:
                    setattr(self, PASS_VARS[k][0], self.boolean(param[param_key]))
                else:
                    setattr(self, PASS_VARS[k][0], param[param_key])

                # clean up internal top level params:
                if param_key in self.params:
                    del self.params[param_key]
            else:
                # use defaults if not already set
                if not hasattr(self, PASS_VARS[k][0]):
                    setattr(self, PASS_VARS[k][0], PASS_VARS[k][1])

        if unsupported_parameters:
            msg = "Unsupported parameters for (%s) module: %s" % (self._name, ', '.join(sorted(list(unsupported_parameters))))
            if self._options_context:
                msg += " found in %s." % " -> ".join(self._options_context)
            supported_parameters = list()
            for key in sorted(spec.keys()):
                if 'aliases' in spec[key] and spec[key]['aliases']:
                    supported_parameters.append("%s (%s)" % (key, ', '.join(sorted(spec[key]['aliases']))))
                else:
                    supported_parameters.append(key)
            msg += " Supported parameters include: %s" % (', '.join(supported_parameters))
            self.fail_json(msg=msg)
        if self.check_mode and not self.supports_check_mode:
            self.exit_json(skipped=True, msg="action module (%s) does not support check mode" % self._name)

    def _count_terms(self, check, param=None):
        if param is None:
            param = self.params
        return count_terms(check, param)

    def _check_mutually_exclusive(self, spec, param=None):
        if param is None:
            param = self.params

        try:
            check_mutually_exclusive(spec, param)
        except TypeError as e:
            msg = to_native(e)
            if self._options_context:
                msg += " found in %s" % " -> ".join(self._options_context)
            self.fail_json(msg=msg)

    def _check_required_one_of(self, spec, param=None):
        if spec is None:
            return

        if param is None:
            param = self.params

        try:
            check_required_one_of(spec, param)
        except TypeError as e:
            msg = to_native(e)
            if self._options_context:
                msg += " found in %s" % " -> ".join(self._options_context)
            self.fail_json(msg=msg)

    def _check_required_together(self, spec, param=None):
        if spec is None:
            return
        if param is None:
            param = self.params

        try:
            check_required_together(spec, param)
        except TypeError as e:
            msg = to_native(e)
            if self._options_context:
                msg += " found in %s" % " -> ".join(self._options_context)
            self.fail_json(msg=msg)

    def _check_required_by(self, spec, param=None):
        if spec is None:
            return
        if param is None:
            param = self.params

        try:
            check_required_by(spec, param)
        except TypeError as e:
            self.fail_json(msg=to_native(e))

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        try:
            check_required_arguments(spec, param)
        except TypeError as e:
            msg = to_native(e)
            if self._options_context:
                msg += " found in %s" % " -> ".join(self._options_context)
            self.fail_json(msg=msg)

    def _check_required_if(self, spec, param=None):
        ''' ensure that parameters which conditionally required are present '''
        if spec is None:
            return
        if param is None:
            param = self.params

        try:
            check_required_if(spec, param)
        except TypeError as e:
            msg = to_native(e)
            if self._options_context:
                msg += " found in %s" % " -> ".join(self._options_context)
            self.fail_json(msg=msg)

    def _check_argument_values(self, spec=None, param=None):
        ''' ensure all arguments have the requested values, and there are no stray arguments '''
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        for (k, v) in spec.items():
            choices = v.get('choices', None)
            if choices is None:
                continue
            if isinstance(choices, SEQUENCETYPE) and not isinstance(choices, (binary_type, text_type)):
                if k in param:
                    # Allow one or more when type='list' param with choices
                    if isinstance(param[k], list):
                        diff_list = ", ".join([item for item in param[k] if item not in choices])
                        if diff_list:
                            choices_str = ", ".join([to_native(c) for c in choices])
                            msg = "value of %s must be one or more of: %s. Got no match for: %s" % (k, choices_str, diff_list)
                            if self._options_context:
                                msg += " found in %s" % " -> ".join(self._options_context)
                            self.fail_json(msg=msg)
                    elif param[k] not in choices:
                        # PyYaml converts certain strings to bools.  If we can unambiguously convert back, do so before checking
                        # the value.  If we can't figure this out, module author is responsible.
                        lowered_choices = None
                        if param[k] == 'False':
                            lowered_choices = lenient_lowercase(choices)
                            overlap = BOOLEANS_FALSE.intersection(choices)
                            if len(overlap) == 1:
                                # Extract from a set
                                (param[k],) = overlap

                        if param[k] == 'True':
                            if lowered_choices is None:
                                lowered_choices = lenient_lowercase(choices)
                            overlap = BOOLEANS_TRUE.intersection(choices)
                            if len(overlap) == 1:
                                (param[k],) = overlap

                        if param[k] not in choices:
                            choices_str = ", ".join([to_native(c) for c in choices])
                            msg = "value of %s must be one of: %s, got: %s" % (k, choices_str, param[k])
                            if self._options_context:
                                msg += " found in %s" % " -> ".join(self._options_context)
                            self.fail_json(msg=msg)
            else:
                msg = "internal error: choices for argument %s are not iterable: %s" % (k, choices)
                if self._options_context:
                    msg += " found in %s" % " -> ".join(self._options_context)
                self.fail_json(msg=msg)

    def safe_eval(self, value, locals=None, include_exceptions=False):
        return safe_eval(value, locals, include_exceptions)

    def _check_type_str(self, value, param=None, prefix=''):
        opts = {
            'error': False,
            'warn': False,
            'ignore': True
        }

        # Ignore, warn, or error when converting to a string.
        allow_conversion = opts.get(self._string_conversion_action, True)
        try:
            return check_type_str(value, allow_conversion)
        except TypeError:
            common_msg = 'quote the entire value to ensure it does not change.'
            from_msg = '{0!r}'.format(value)
            to_msg = '{0!r}'.format(to_text(value))

            if param is not None:
                if prefix:
                    param = '{0}{1}'.format(prefix, param)

                from_msg = '{0}: {1!r}'.format(param, value)
                to_msg = '{0}: {1!r}'.format(param, to_text(value))

            if self._string_conversion_action == 'error':
                msg = common_msg.capitalize()
                raise TypeError(to_native(msg))
            elif self._string_conversion_action == 'warn':
                msg = ('The value "{0}" (type {1.__class__.__name__}) was converted to "{2}" (type string). '
                       'If this does not look like what you expect, {3}').format(from_msg, value, to_msg, common_msg)
                self.warn(to_native(msg))
                return to_native(value, errors='surrogate_or_strict')

    def _check_type_list(self, value):
        return check_type_list(value)

    def _check_type_dict(self, value):
        return check_type_dict(value)

    def _check_type_bool(self, value):
        return check_type_bool(value)

    def _check_type_int(self, value):
        return check_type_int(value)

    def _check_type_float(self, value):
        return check_type_float(value)

    def _check_type_path(self, value):
        return check_type_path(value)

    def _check_type_jsonarg(self, value):
        return check_type_jsonarg(value)

    def _check_type_raw(self, value):
        return check_type_raw(value)

    def _check_type_bytes(self, value):
        return check_type_bytes(value)

    def _check_type_bits(self, value):
        return check_type_bits(value)

    def _handle_options(self, argument_spec=None, params=None, prefix=''):
        ''' deal with options to create sub spec '''
        if argument_spec is None:
            argument_spec = self.argument_spec
        if params is None:
            params = self.params

        for (k, v) in argument_spec.items():
            wanted = v.get('type', None)
            if wanted == 'dict' or (wanted == 'list' and v.get('elements', '') == 'dict'):
                spec = v.get('options', None)
                if v.get('apply_defaults', False):
                    if spec is not None:
                        if params.get(k) is None:
                            params[k] = {}
                    else:
                        continue
                elif spec is None or k not in params or params[k] is None:
                    continue

                self._options_context.append(k)

                if isinstance(params[k], dict):
                    elements = [params[k]]
                else:
                    elements = params[k]

                for idx, param in enumerate(elements):
                    if not isinstance(param, dict):
                        self.fail_json(msg="value of %s must be of type dict or list of dict" % k)

                    new_prefix = prefix + k
                    if wanted == 'list':
                        new_prefix += '[%d]' % idx
                    new_prefix += '.'

                    self._set_fallbacks(spec, param)
                    options_aliases = self._handle_aliases(spec, param, option_prefix=new_prefix)

                    options_legal_inputs = list(spec.keys()) + list(options_aliases.keys())

                    self._check_arguments(spec, param, options_legal_inputs)

                    # check exclusive early
                    if not self.bypass_checks:
                        self._check_mutually_exclusive(v.get('mutually_exclusive', None), param)

                    self._set_defaults(pre=True, spec=spec, param=param)

                    if not self.bypass_checks:
                        self._check_required_arguments(spec, param)
                        self._check_argument_types(spec, param, new_prefix)
                        self._check_argument_values(spec, param)

                        self._check_required_together(v.get('required_together', None), param)
                        self._check_required_one_of(v.get('required_one_of', None), param)
                        self._check_required_if(v.get('required_if', None), param)
                        self._check_required_by(v.get('required_by', None), param)

                    self._set_defaults(pre=False, spec=spec, param=param)

                    # handle multi level options (sub argspec)
                    self._handle_options(spec, param, new_prefix)
                self._options_context.pop()

    def _get_wanted_type(self, wanted, k):
        if not callable(wanted):
            if wanted is None:
                # Mostly we want to default to str.
                # For values set to None explicitly, return None instead as
                # that allows a user to unset a parameter
                wanted = 'str'
            try:
                type_checker = self._CHECK_ARGUMENT_TYPES_DISPATCHER[wanted]
            except KeyError:
                self.fail_json(msg="implementation error: unknown type %s requested for %s" % (wanted, k))
        else:
            # set the type_checker to the callable, and reset wanted to the callable's name (or type if it doesn't have one, ala MagicMock)
            type_checker = wanted
            wanted = getattr(wanted, '__name__', to_native(type(wanted)))

        return type_checker, wanted

    def _handle_elements(self, wanted, param, values):
        type_checker, wanted_name = self._get_wanted_type(wanted, param)
        validated_params = []
        # Get param name for strings so we can later display this value in a useful error message if needed
        # Only pass 'kwargs' to our checkers and ignore custom callable checkers
        kwargs = {}
        if wanted_name == 'str' and isinstance(wanted, string_types):
            if isinstance(param, string_types):
                kwargs['param'] = param
            elif isinstance(param, dict):
                kwargs['param'] = list(param.keys())[0]
        for value in values:
            try:
                validated_params.append(type_checker(value, **kwargs))
            except (TypeError, ValueError) as e:
                msg = "Elements value for option %s" % param
                if self._options_context:
                    msg += " found in '%s'" % " -> ".join(self._options_context)
                msg += " is of type %s and we were unable to convert to %s: %s" % (type(value), wanted_name, to_native(e))
                self.fail_json(msg=msg)
        return validated_params

    def _check_argument_types(self, spec=None, param=None, prefix=''):
        ''' ensure all arguments have the requested type '''

        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        for (k, v) in spec.items():
            wanted = v.get('type', None)
            if k not in param:
                continue

            value = param[k]
            if value is None:
                continue

            type_checker, wanted_name = self._get_wanted_type(wanted, k)
            # Get param name for strings so we can later display this value in a useful error message if needed
            # Only pass 'kwargs' to our checkers and ignore custom callable checkers
            kwargs = {}
            if wanted_name == 'str' and isinstance(type_checker, string_types):
                kwargs['param'] = list(param.keys())[0]

                # Get the name of the parent key if this is a nested option
                if prefix:
                    kwargs['prefix'] = prefix

            try:
                param[k] = type_checker(value, **kwargs)
                wanted_elements = v.get('elements', None)
                if wanted_elements:
                    if wanted != 'list' or not isinstance(param[k], list):
                        msg = "Invalid type %s for option '%s'" % (wanted_name, param)
                        if self._options_context:
                            msg += " found in '%s'." % " -> ".join(self._options_context)
                        msg += ", elements value check is supported only with 'list' type"
                        self.fail_json(msg=msg)
                    param[k] = self._handle_elements(wanted_elements, k, param[k])

            except (TypeError, ValueError) as e:
                msg = "argument %s is of type %s" % (k, type(value))
                if self._options_context:
                    msg += " found in '%s'." % " -> ".join(self._options_context)
                msg += " and we were unable to convert to %s: %s" % (wanted_name, to_native(e))
                self.fail_json(msg=msg)

    def _set_defaults(self, pre=True, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        for (k, v) in spec.items():
            default = v.get('default', None)
            if pre is True:
                # this prevents setting defaults on required items
                if default is not None and k not in param:
                    param[k] = default
            else:
                # make sure things without a default still get set None
                if k not in param:
                    param[k] = default

    def _set_fallbacks(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        for (k, v) in spec.items():
            fallback = v.get('fallback', (None,))
            fallback_strategy = fallback[0]
            fallback_args = []
            fallback_kwargs = {}
            if k not in param and fallback_strategy is not None:
                for item in fallback[1:]:
                    if isinstance(item, dict):
                        fallback_kwargs = item
                    else:
                        fallback_args = item
                try:
                    param[k] = fallback_strategy(*fallback_args, **fallback_kwargs)
                except AnsibleFallbackNotFound:
                    continue

    def warn(self, warning):
        # Copied from ansible.module_utils.common.warnings:
        if isinstance(warning, string_types):
            self.__warnings.append(warning)
        else:
            raise TypeError("warn requires a string not a %s" % type(warning))

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        if version is not None and date is not None:
            raise AssertionError("implementation error -- version and date must not both be set")

        # Copied from ansible.module_utils.common.warnings:
        if isinstance(msg, string_types):
            # For compatibility, we accept that neither version nor date is set,
            # and treat that the same as if version would haven been set
            if date is not None:
                self.__deprecations.append({'msg': msg, 'date': date, 'collection_name': collection_name})
            else:
                self.__deprecations.append({'msg': msg, 'version': version, 'collection_name': collection_name})
        else:
            raise TypeError("deprecate requires a string not a %s" % type(msg))

    def _return_formatted(self, kwargs):
        if 'invocation' not in kwargs:
            kwargs['invocation'] = {'module_args': self.params}

        if 'warnings' in kwargs:
            if isinstance(kwargs['warnings'], list):
                for w in kwargs['warnings']:
                    self.warn(w)
            else:
                self.warn(kwargs['warnings'])

        if self.__warnings:
            kwargs['warnings'] = self.__warnings

        if 'deprecations' in kwargs:
            if isinstance(kwargs['deprecations'], list):
                for d in kwargs['deprecations']:
                    if isinstance(d, SEQUENCETYPE) and len(d) == 2:
                        self.deprecate(d[0], version=d[1])
                    elif isinstance(d, Mapping):
                        self.deprecate(d['msg'], version=d.get('version'), date=d.get('date'),
                                       collection_name=d.get('collection_name'))
                    else:
                        self.deprecate(d)  # pylint: disable=ansible-deprecated-no-version
            else:
                self.deprecate(kwargs['deprecations'])  # pylint: disable=ansible-deprecated-no-version

        if self.__deprecations:
            kwargs['deprecations'] = self.__deprecations

        kwargs = remove_values(kwargs, self.no_log_values)
        raise _ModuleExitException(kwargs)

    def exit_json(self, **kwargs):
        result = dict(kwargs)
        if 'failed' not in result:
            result['failed'] = False
        self._return_formatted(result)

    def fail_json(self, msg, **kwargs):
        result = dict(kwargs)
        result['failed'] = True
        result['msg'] = msg
        self._return_formatted(result)


@six.add_metaclass(abc.ABCMeta)
class ActionModuleBase(ActionBase):
    @abc.abstractmethod
    def setup_module(self):
        """Return pair (ArgumentSpec, kwargs)."""
        pass

    @abc.abstractmethod
    def run_module(self, module):
        """Run module code"""
        module.fail_json(msg='Not implemented.')

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModuleBase, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        try:
            argument_spec, kwargs = self.setup_module()
            module = argument_spec.create_ansible_module_helper(AnsibleActionModule, (self, ), **kwargs)
            self.run_module(module)
            raise AnsibleError('Internal error: action module did not call module.exit_json()')
        except _ModuleExitException as mee:
            result.update(mee.result)
            return result
        except Exception as dummy:
            result['failed'] = True
            result['msg'] = 'MODULE FAILURE'
            result['exception'] = traceback.format_exc()
            return result
