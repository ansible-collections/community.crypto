# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t

from ansible.module_utils.basic import AnsibleModule

if t.TYPE_CHECKING:  # pragma: no cover
    import datetime
    from collections.abc import Callable, Mapping, Sequence

    _T = t.TypeVar("_T")

    ArgSpecType = t.Literal[
        "bits",
        "bool",
        "bytes",
        "dict",
        "float",
        "int",
        "json",
        "jsonarg",
        "list",
        "path",
        "raw",
        "sid",
        "str",
    ]
    MutuallyExclusiveT = t.Union[Sequence[str], Sequence[Sequence[str]]]  # noqa: UP007
    MutuallyExclusiveMutT = list[Sequence[str]]
    RequiredTogetherT = Sequence[Sequence[str]]
    RequiredTogetherMutT = list[Sequence[str]]
    RequiredOneOfT = Sequence[Sequence[str]]
    RequiredOneOfMutT = list[Sequence[str]]
    RequiredIfT = Sequence[
        t.Union[  # noqa: UP007
            list[object],
            tuple[str, object, Sequence[str]],
            tuple[str, object, Sequence[str], bool],
        ]
    ]
    RequiredIfMutT = list[
        t.Union[  # noqa: UP007
            list[object],
            tuple[str, object, Sequence[str]],
            tuple[str, object, Sequence[str], bool],
        ]
    ]
    RequiredByT = Mapping[str, Sequence[str]]
    RequiredByMutT = dict[str, Sequence[str]]

    class DeprecatedAlias(t.TypedDict):
        name: str
        date: t.NotRequired[datetime.date | str]
        version: t.NotRequired[str]
        collection_name: str

    class OneArgumentSpecT(t.TypedDict):
        type: t.NotRequired[ArgSpecType | Callable[[object], object]]
        elements: t.NotRequired[ArgSpecType]
        default: t.NotRequired[object]
        # For fallback elements, the first element of the sequence has to be a callable, the others sequences or dicts.
        # Unfortunately there is no way to specify this in a generic way...
        fallback: t.NotRequired[
            Sequence[
                Callable[[object], object] | Sequence[object] | Mapping[str, object]
            ]
        ]
        choices: t.NotRequired[Sequence[object]]
        context: t.NotRequired[Mapping[object, object]]
        required: t.NotRequired[bool]
        no_log: t.NotRequired[bool]
        aliases: t.NotRequired[Sequence[str]]
        apply_defaults: t.NotRequired[bool]
        removed_in_version: t.NotRequired[str]
        removed_at_date: t.NotRequired[datetime.date | str]
        removed_from_collection: t.NotRequired[str]
        options: t.NotRequired[Mapping[str, OneArgumentSpecT]]  # recursive!
        deprecated_aliases: t.NotRequired[Sequence[DeprecatedAlias]]

        mutually_exclusive: t.NotRequired[MutuallyExclusiveT]
        required_together: t.NotRequired[RequiredTogetherT]
        required_one_of: t.NotRequired[RequiredOneOfT]
        required_if: t.NotRequired[RequiredIfT]
        required_by: t.NotRequired[RequiredByT]

    ArgumentSpecT = Mapping[str, OneArgumentSpecT]
    ArgumentSpecMutT = dict[str, OneArgumentSpecT]


class ArgumentSpec:
    def __init__(
        self,
        argument_spec: ArgumentSpecT | None = None,
        *,
        required_together: RequiredTogetherT | None = None,
        required_if: RequiredIfT | None = None,
        required_one_of: RequiredOneOfT | None = None,
        mutually_exclusive: MutuallyExclusiveT | None = None,
        required_by: RequiredByT | None = None,
    ) -> None:
        self.argument_spec: ArgumentSpecMutT = {}
        self.required_together: RequiredTogetherMutT = []
        self.required_if: RequiredIfMutT = []
        self.required_one_of: RequiredOneOfMutT = []
        self.mutually_exclusive: MutuallyExclusiveMutT = []
        self.required_by: RequiredByMutT = {}
        if argument_spec:
            self.argument_spec.update(argument_spec)
        if required_together:
            self.required_together.extend(required_together)
        if required_if:
            self.required_if.extend(required_if)
        if required_one_of:
            self.required_one_of.extend(required_one_of)
        if mutually_exclusive:
            if all(isinstance(me, str) for me in mutually_exclusive):
                # mutually_exclusive is a Sequence[str]
                self.mutually_exclusive.append(mutually_exclusive)  # type: ignore
            else:
                self.mutually_exclusive.extend(mutually_exclusive)
        if required_by:
            self.required_by.update(required_by)

    def update_argspec(self, **kwargs: t.Any) -> t.Self:
        self.argument_spec.update(kwargs)
        return self

    def update(
        self,
        *,
        required_together: RequiredTogetherT | None = None,
        required_if: RequiredIfT | None = None,
        required_one_of: RequiredOneOfT | None = None,
        mutually_exclusive: MutuallyExclusiveT | None = None,
        required_by: RequiredByT | None = None,
    ) -> t.Self:
        if mutually_exclusive:
            self.mutually_exclusive.extend(mutually_exclusive)
        if required_together:
            self.required_together.extend(required_together)
        if required_one_of:
            self.required_one_of.extend(required_one_of)
        if required_if:
            self.required_if.extend(required_if)
        if required_by:
            for k, v in required_by.items():
                if k in self.required_by:
                    v = list(self.required_by[k]) + list(v)
                self.required_by[k] = v
        return self

    def merge(self, other: t.Self) -> t.Self:
        self.update_argspec(**other.argument_spec)
        self.update(
            mutually_exclusive=other.mutually_exclusive,
            required_together=other.required_together,
            required_one_of=other.required_one_of,
            required_if=other.required_if,
            required_by=other.required_by,
        )
        return self

    def create_ansible_module_helper(
        self, clazz: type[_T], args: tuple, **kwargs: t.Any
    ) -> _T:
        for forbidden_name in (
            "argument_spec",
            "mutually_exclusive",
            "required_together",
            "required_one_of",
            "required_if",
            "required_by",
        ):
            if forbidden_name in kwargs:
                raise ValueError(
                    f"You must not provide a {forbidden_name} keyword parameter to create_ansible_module_helper()"
                )
        instance = clazz(  # type: ignore
            *args,
            argument_spec=self.argument_spec,
            mutually_exclusive=self.mutually_exclusive,
            required_together=self.required_together,
            required_one_of=self.required_one_of,
            required_if=self.required_if,
            required_by=self.required_by,
            **kwargs,
        )
        return instance

    def create_ansible_module(self, **kwargs: t.Any) -> AnsibleModule:
        return self.create_ansible_module_helper(AnsibleModule, (), **kwargs)


__all__ = ("ArgumentSpec",)
