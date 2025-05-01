# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six import PY3, binary_type
from ansible.module_utils.six.moves.http_client import responses as http_responses


def format_http_status(status_code):
    expl = http_responses.get(status_code)
    if not expl:
        return str(status_code)
    return f"{status_code} {expl}"


def format_error_problem(problem, subproblem_prefix=""):
    error_type = problem.get(
        "type", "about:blank"
    )  # https://www.rfc-editor.org/rfc/rfc7807#section-3.1
    if "title" in problem:
        msg = f'Error "{problem["title"]}" ({error_type})'
    else:
        msg = f"Error {error_type}"
    if "detail" in problem:
        msg += f': "{problem["detail"]}"'
    subproblems = problem.get("subproblems")
    if subproblems is not None:
        msg = f"{msg} Subproblems:"
        for index, problem in enumerate(subproblems):
            index_str = f"{subproblem_prefix}{index}"
            problem = format_error_problem(problem, subproblem_prefix=f"{index_str}.")
            msg = f"{msg}\n({index_str}) {problem}"
    return msg


class ModuleFailException(Exception):
    """
    If raised, module.fail_json() will be called with the given parameters after cleanup.
    """

    def __init__(self, msg, **args):
        super(ModuleFailException, self).__init__(self, msg)
        self.msg = msg
        self.module_fail_args = args

    def do_fail(self, module, **arguments):
        module.fail_json(msg=self.msg, other=self.module_fail_args, **arguments)


class ACMEProtocolException(ModuleFailException):
    def __init__(
        self,
        module,
        msg=None,
        info=None,
        response=None,
        content=None,
        content_json=None,
        extras=None,
    ):
        # Try to get hold of content, if response is given and content is not provided
        if content is None and content_json is None and response is not None:
            try:
                # In Python 2, reading from a closed response yields a TypeError.
                # In Python 3, read() simply returns ''
                if PY3 and response.closed:
                    raise TypeError
                content = response.read()
            except (AttributeError, TypeError):
                content = info.pop("body", None)

        # Make sure that content_json is None or a dictionary
        if content_json is not None and not isinstance(content_json, dict):
            if content is None and isinstance(content_json, binary_type):
                content = content_json
            content_json = None

        # Try to get hold of JSON decoded content, when content is given and JSON not provided
        if content_json is None and content is not None and module is not None:
            try:
                content_json = module.from_json(to_text(content))
            except Exception:
                pass

        extras = extras or dict()
        error_code = None
        error_type = None

        if msg is None:
            msg = "ACME request failed"
        add_msg = ""

        if info is not None:
            url = info["url"]
            code = info["status"]
            extras["http_url"] = url
            extras["http_status"] = code
            error_code = code
            if (
                code is not None
                and code >= 400
                and content_json is not None
                and "type" in content_json
            ):
                error_type = content_json["type"]
                if "status" in content_json and content_json["status"] != code:
                    code_msg = f"status {content_json['status']} (HTTP status: {format_http_status(code)})"
                else:
                    code_msg = f"status {format_http_status(code)}"
                    if code == -1 and info.get("msg"):
                        code_msg = f"error: {info['msg']}"
                subproblems = content_json.pop("subproblems", None)
                add_msg = f" {format_error_problem(content_json)}."
                extras["problem"] = content_json
                extras["subproblems"] = subproblems or []
                if subproblems is not None:
                    add_msg = f"{add_msg} Subproblems:"
                    for index, problem in enumerate(subproblems):
                        problem = format_error_problem(
                            problem, subproblem_prefix=f"{index}."
                        )
                        add_msg = f"{add_msg}\n({index}) {problem}."
            else:
                code_msg = f"HTTP status {format_http_status(code)}"
                if code == -1 and info.get("msg"):
                    code_msg = f"error: {info['msg']}"
                if content_json is not None:
                    add_msg = f" The JSON error result: {content_json}"
                elif content is not None:
                    add_msg = f" The raw error result: {to_text(content)}"
            msg = f"{msg} for {url} with {code_msg}"
        elif content_json is not None:
            add_msg = f" The JSON result: {content_json}"
        elif content is not None:
            add_msg = f" The raw result: {to_text(content)}"

        super(ACMEProtocolException, self).__init__(f"{msg}.{add_msg}", **extras)
        self.problem = {}
        self.subproblems = []
        self.error_code = error_code
        self.error_type = error_type
        for k, v in extras.items():
            setattr(self, k, v)


class BackendException(ModuleFailException):
    pass


class NetworkException(ModuleFailException):
    pass


class KeyParsingError(ModuleFailException):
    pass
