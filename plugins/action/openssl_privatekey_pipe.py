# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64

from ansible.module_utils.common.text.converters import to_native, to_bytes

from ansible_collections.community.crypto.plugins.plugin_utils.action_module import ActionModuleBase

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.privatekey import (
    select_backend,
    get_privatekey_argument_spec,
)


class PrivateKeyModule(object):
    def __init__(self, module, module_backend):
        self.module = module
        self.module_backend = module_backend
        self.check_mode = module.check_mode
        self.changed = False
        self.return_current_key = module.params['return_current_key']

        if module.params['content'] is not None:
            if module.params['content_base64']:
                try:
                    data = base64.b64decode(module.params['content'])
                except Exception as e:
                    module.fail_json(msg='Cannot decode Base64 encoded data: {0}'.format(e))
            else:
                data = to_bytes(module.params['content'])
            module_backend.set_existing(data)

    def generate(self, module):
        """Generate a keypair."""

        if self.module_backend.needs_regeneration():
            # Regenerate
            if not self.check_mode:
                self.module_backend.generate_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                self.privatekey_bytes = privatekey_data
            self.changed = True
        elif self.module_backend.needs_conversion():
            # Convert
            if not self.check_mode:
                self.module_backend.convert_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                self.privatekey_bytes = privatekey_data
            self.changed = True

    def dump(self):
        """Serialize the object into a dictionary."""
        result = self.module_backend.dump(include_key=self.changed or self.return_current_key)
        result['changed'] = self.changed
        return result


class ActionModule(ActionModuleBase):
    @staticmethod
    def setup_module():
        argument_spec = get_privatekey_argument_spec()
        argument_spec.argument_spec.update(dict(
            content=dict(type='str', no_log=True),
            content_base64=dict(type='bool', default=False),
            return_current_key=dict(type='bool', default=False),
        ))
        return argument_spec, dict(
            supports_check_mode=True,
        )

    @staticmethod
    def run_module(module):
        backend, module_backend = select_backend(
            module=module,
            backend=module.params['select_crypto_backend'],
        )

        try:
            private_key = PrivateKeyModule(module, module_backend)
            private_key.generate(module)
            result = private_key.dump()
            if private_key.return_current_key:
                # In case the module's input (`content`) is returned as `privatekey`:
                # Since `content` is no_log=True, `privatekey`'s value will get replaced by
                # VALUE_SPECIFIED_IN_NO_LOG_PARAMETER. To avoid this, we remove the value of
                # `content` from module.no_log_values. Since we explicitly set
                # `module.no_log = True`, this should be safe.
                module.no_log = True
                try:
                    module.no_log_values.remove(module.params['content'])
                except KeyError:
                    pass
                module.params['content'] = 'ANSIBLE_NO_LOG_VALUE'
            module.exit_json(**result)
        except OpenSSLObjectError as exc:
            module.fail_json(msg=to_native(exc))
