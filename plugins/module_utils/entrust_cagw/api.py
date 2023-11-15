# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is licensed under the
# GNU General Public License v3.0+. Modules you write using this snippet, which is embedded
# dynamically by Ansible, still belong to the author of the module, and may assign
# their own license to the complete work.
#
# Copyright (c), Entrust Datacard Corporation, 2020
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re
import time
import traceback

from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import Request

YAML_IMP_ERR = None
try:
    import yaml
except ImportError:
    YAML_FOUND = False
    YAML_IMP_ERR = traceback.format_exc()
else:
    YAML_FOUND = True

valid_file_format = re.compile(r".*(\.)(yml|yaml|json)$")


def cagw_client_argument_spec():
    return dict(
            cagw_api_client_cert_path=dict(type='path', required=True),
            cagw_api_client_cert_key_path=dict(type='path', required=True),
            cagw_api_specification_path=dict(type='path'),
            )


class SessionConfigurationException(Exception):
    """ Raised if we cannot configure a session with the API """

    pass


class RestOperationException(Exception):
    """ Encapsulate a REST API error """

    def __init__(self, error):
        self.status = to_native(error.get("status", None))
        self.errors = [to_native(err.get("message")) for err in error.get("errors", {})]
        self.message = to_native(" ".join(self.errors))

def generate_docstring(operation_spec):
    """Generate a docstring for an operation defined in operation_spec (swagger)"""
    # Description of the operation
    docs = operation_spec.get("description", "No Description")
    docs += "\n\n"

    # Parameters of the operation
    parameters = operation_spec.get("parameters", [])
    if len(parameters) != 0:
        docs += "\tArguments:\n\n"
    for parameter in parameters:
        docs += "{0} ({1}:{2}): {3}\n".format(
                parameter.get("name"),
                parameter.get("type", "No Type"),
                "Required" if parameter.get("required", False) else "Not Required",
                parameter.get("description"),
                )

    return docs


def bind(instance, method, operation_spec):
    def binding_scope_fn(*args, **kwargs):
        return method(instance, *args, **kwargs)

    # Make sure we don't confuse users; add the proper name and documentation to the function.
    # Users can use !help(<function>) to get help on the function from interactive python or pdb
    operation_name = operation_spec.get("operationId").split("Using")[0]
    binding_scope_fn.__name__ = str(operation_name)
    binding_scope_fn.__doc__ = generate_docstring(operation_spec)

    return binding_scope_fn


class RestOperation(object):
    def __init__(self, session, uri, method, parameters=None):
        self.session = session
        self.method = method
        self.uri = uri
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters
        self.url = "{scheme}://{host}:{port}{base_path}{uri}".format(scheme="https", host=("example.com"), port=("443"), base_path=session._spec.get("basePath"), uri=uri)

    def restmethod(self, *args, **kwargs):
        """Do the hard work of making the request here"""
        validate_certs_val = kwargs.get("validate_certs", True)
        host = kwargs.get("host", None)
        port = kwargs.get("port", None)
        url = "{scheme}://{host}:{port}{base_path}{uri}".format(scheme="https", host=host, port=port, base_path=self.session._spec.get("basePath"), uri=self.uri)
        # gather named path parameters and do substitution on the URL
        if self.parameters:
            path_parameters = {}
            body_parameters = {}
            query_parameters = {}
            for x in self.parameters:
                expected_location = x.get("in")
                key_name = x.get("name", None)
                key_value = kwargs.get(key_name, None)
                if expected_location == "path" and key_name and key_value:
                    path_parameters.update({key_name: key_value})
                elif expected_location == "body" and key_name and key_value:
                    body_parameters.update({key_name: key_value})
                elif expected_location == "query" and key_name and key_value:
                    query_parameters.update({key_name: key_value})

            if len(body_parameters.keys()) >= 1:
                body_parameters = body_parameters.get(list(body_parameters.keys())[0])
            else:
                body_parameters = None
        else:
            path_parameters = {}
            query_parameters = {}
            body_parameters = None

        # This will fail if we have not set path parameters with a KeyError
        url = url.format(**path_parameters)
        if query_parameters:
            # modify the URL to add query parameters
            url = url + "?" + urlencode(query_parameters)

        try:
            if body_parameters:
                body_parameters_json = json.dumps(body_parameters)
                response = self.session.request.open(method=self.method, url=url, data=body_parameters_json, validate_certs=validate_certs_val)
            else:
                response = self.session.request.open(method=self.method, url=url, validate_certs=validate_certs_val)
                request_error = False
        except HTTPError as e:
            # An HTTPError has the same methods available as a valid response from request.open
            response = e
            request_error = True

        # Return the result if JSON and success ({} for empty responses)
        # Raise an exception if there was a failure.
        try:
            result_code = response.getcode()
            result = json.loads(response.read())
        except ValueError:
            result = {}

        if result or result == {}:
            if result_code and result_code < 400:
                return result
            else:
                raise RestOperationException(result)

        # Raise a generic RestOperationException if this fails
        raise RestOperationException({"status": result_code, "errors": [{"message": "REST Operation Failed"}]})


class Resource(object):
    """ Implement basic CRUD operations against a path. """

    def __init__(self, session):
        self.session = session
        self.parameters = {}

        for url in session._spec.get("paths").keys():
            methods = session._spec.get("paths").get(url)
            for method in methods.keys():
                operation_spec = methods.get(method)
                operation_name = operation_spec.get("operationId", None)
                parameters = operation_spec.get("parameters")

                if not operation_name:
                    if method.lower() == "post":
                        operation_name = "Create"
                    elif method.lower() == "get":
                        operation_name = "Get"
                    elif method.lower() == "put":
                        operation_name = "Update"
                    elif method.lower() == "delete":
                        operation_name = "Delete"
                    elif method.lower() == "patch":
                        operation_name = "Patch"
                    else:
                        raise SessionConfigurationException(to_native("Invalid REST method type {0}".format(method)))

                    # Get the non-parameter parts of the URL and append to the operation name
                    # e.g  /application/version -> GetApplicationVersion
                    # e.g. /application/{id}    -> GetApplication
                    # This may lead to duplicates, which we must prevent.
                    operation_name += re.sub(r"{(.*)}", "", url).replace("/", " ").title().replace(" ", "")
                    operation_spec["operationId"] = operation_name

                op = RestOperation(session, url, method, parameters)
                setattr(self, operation_name, bind(self, op.restmethod, operation_spec))


# Session to encapsulate the connection parameters of the module_utils Request object, the api spec, etc
class CAGWSession(object):
    def __init__(self, name, **kwargs):
        """
        Initialize our session
        """

        self._set_config(name, **kwargs)

    def client(self):
        resource = Resource(self)
        return resource

    def _set_config(self, name, **kwargs):
        headers = {
                "Content-Type": "application/json",
                "Connection": "keep-alive",
                }
        self.request = Request(headers=headers, timeout=120)

        configurators = [self._read_config_vars]
        for configurator in configurators:
            self._config = configurator(name, **kwargs)
            if self._config:
                break
        if self._config is None:
            raise SessionConfigurationException(to_native("No Configuration Found."))


        # set up client certificate if passed (support all-in one or cert + key)
        cagw_api_cert = self.get_config("cagw_api_cert")
        cagw_api_cert_key = self.get_config("cagw_api_cert_key")
        if cagw_api_cert:
            self.request.client_cert = cagw_api_cert
            if cagw_api_cert_key:
                self.request.client_key = cagw_api_cert_key
        else:
            raise SessionConfigurationException(to_native("Client certificate for authentication to the API must be provided."))

        # set up the spec
        cagw_api_specification_path = self.get_config("cagw_api_specification_path")

        if not cagw_api_specification_path.startswith("http") and not os.path.isfile(cagw_api_specification_path):
            raise SessionConfigurationException(to_native("OpenAPI specification was not found at location {0}.".format(cagw_api_specification_path)))
        if not valid_file_format.match(cagw_api_specification_path):
            raise SessionConfigurationException(to_native("OpenAPI specification filename must end in .json, .yml or .yaml"))

        self.verify = True

        if cagw_api_specification_path.startswith("http"):
            try:
                http_response = Request().open(method="GET", url=cagw_api_specification_path)
                http_response_contents = http_response.read()
                if cagw_api_specification_path.endswith(".json"):
                    self._spec = json.load(http_response_contents)
                elif cagw_api_specification_path.endswith(".yml") or cagw_api_specification_path.endswith(".yaml"):
                    self._spec = yaml.safe_load(http_response_contents)
            except HTTPError as e:
                raise SessionConfigurationException(to_native("Error downloading specification from address '{0}', received error code '{1}'".format(
                    cagw_api_specification_path, e.getcode())))
        else:
            with open(cagw_api_specification_path) as f:
                if cagw_api_specification_path.endswith(".json"):
                    self._spec = json.load(f)
                elif ".yml" in cagw_api_specification_path or ".yaml" in cagw_api_specification_path:
                    self._spec = yaml.safe_load(f)
                else:
                    raise SessionConfigurationException(to_native("OpenAPI specification filename must end in .json, .yml or .yaml"))

    def get_config(self, item):
        return self._config.get(item, None)

    def _read_config_vars(self, name, **kwargs):
        """ Read configuration from variables passed to the module. """
        config = {}

        cagw_api_specification_path = kwargs.get("cagw_api_specification_path")
        if not cagw_api_specification_path or (not cagw_api_specification_path.startswith("http") and not os.path.isfile(cagw_api_specification_path)):
            raise SessionConfigurationException(
                    to_native(
                        "Parameter provided for cagw_api_specification_path of value '{0}' was not a valid file path or HTTPS address.".format(
                            cagw_api_specification_path
                            )
                        )
                    )

        for required_file in ["cagw_api_cert", "cagw_api_cert_key"]:
            file_path = kwargs.get(required_file)
            if not file_path or not os.path.isfile(file_path):
                raise SessionConfigurationException(
                        to_native("Parameter provided for {0} of value '{1}' was not a valid file path.".format(required_file, file_path))
                        )

        config["cagw_api_cert"] = kwargs.get("cagw_api_cert")
        config["cagw_api_cert_key"] = kwargs.get("cagw_api_cert_key")
        config["cagw_api_specification_path"] = kwargs.get("cagw_api_specification_path")

        return config


def CAGWClient(cagw_api_cert=None, cagw_api_cert_key=None, cagw_api_specification_path=None):
    """Create a CAGW client"""

    if not YAML_FOUND:
        raise SessionConfigurationException(missing_required_lib("PyYAML"), exception=YAML_IMP_ERR)

    #if cagw_api_specification_path is None:
    #    cagw_api_specification_path = "https://cloud.entrust.net/EntrustCloud/documentation/cms-api-2.1.0.yaml"

    # Not functionally necessary with current uses of this module_util, but better to be explicit for future use cases
    cagw_api_cert_key = to_text(cagw_api_cert_key)
    cagw_api_specification_path = to_text(cagw_api_specification_path)

    return CAGWSession(
            "entrust_cagw",
            cagw_api_cert=cagw_api_cert,
            cagw_api_cert_key=cagw_api_cert_key,
            cagw_api_specification_path=cagw_api_specification_path,
            ).client()
