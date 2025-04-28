#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: luks_device

short_description: Manage encrypted (LUKS) devices

description:
  - Module manages L(LUKS,https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) on given device. Supports creating, destroying,
    opening and closing of LUKS container and adding or removing new keys and passphrases.
extends_documentation_fragment:
  - community.crypto.attributes

attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  device:
    description:
      - Device to work with (for example V(/dev/sda1)). Needed in most cases. Can be omitted only when O(state=closed) together
        with O(name) is provided.
    type: str
  state:
    description:
      - Desired state of the LUKS container. Based on its value creates, destroys, opens or closes the LUKS container on a
        given device.
      - V(present) will create LUKS container unless already present. Requires O(device) and either O(keyfile) or O(passphrase)
        options to be provided.
      - V(absent) will remove existing LUKS container if it exists. Requires O(device) or O(name) to be specified.
      - V(opened) will unlock the LUKS container. If it does not exist it will be created first. Requires O(device) and either
        O(keyfile) or O(passphrase) to be specified. Use the O(name) option to set the name of the opened container. Otherwise
        the name will be generated automatically and returned as a part of the result.
      - V(closed) will lock the LUKS container. However if the container does not exist it will be created. Requires O(device)
        and either O(keyfile) or O(passphrase) options to be provided. If container does already exist O(device) or O(name)
        will suffice.
    type: str
    default: present
    choices: [present, absent, opened, closed]
  name:
    description:
      - Sets container name when O(state=opened). Can be used instead of O(device) when closing the existing container (that
        is, when O(state=closed)).
    type: str
  keyfile:
    description:
      - Used to unlock the container. Either a O(keyfile) or a O(passphrase) is needed for most of the operations. Parameter
        value is the path to the keyfile with the passphrase.
      - BEWARE that working with keyfiles in plaintext is dangerous. Make sure that they are protected.
    type: path
  passphrase:
    description:
      - Used to unlock the container. Either a O(passphrase) or a O(keyfile) is needed for most of the operations. Parameter
        value is a string with the passphrase.
      - B(Note) that the passphrase must be UTF-8 encoded text. If you want to use arbitrary binary data, or text using
        another encoding, use the O(passphrase_encoding) option and provide the passphrase Base64 encoded.
    type: str
    version_added: '1.0.0'
  passphrase_encoding:
    description:
      - Determine how passphrases are provided to parameters such as O(passphrase), O(new_passphrase), and O(remove_passphrase).
    type: str
    default: text
    choices:
      text:
        - The passphrase is provided as UTF-8 encoded text.
      base64:
        - The passphrase is provided as Base64 encoded bytes.
        - Use the P(ansible.builtin.b64encode#filter) filter to Base64-encode binary data.
    version_added: 2.23.0
  keyslot:
    description:
      - Adds the O(keyfile) or O(passphrase) to a specific keyslot when creating a new container on O(device). Parameter value
        is the number of the keyslot.
      - B(Note) that a device of O(type=luks1) supports the keyslot numbers V(0)-V(7) and a device of O(type=luks2) supports
        the keyslot numbers V(0)-V(31). In order to use the keyslots V(8)-V(31) when creating a new container, setting O(type)
        to V(luks2) is required.
    type: int
    version_added: '2.16.0'
  keysize:
    description:
      - Sets the key size only if LUKS container does not exist.
    type: int
    version_added: '1.0.0'
  new_keyfile:
    description:
      - Adds additional key to given container on O(device). Needs O(keyfile) or O(passphrase) option for authorization. LUKS
        container supports up to 8 keyslots. Parameter value is the path to the keyfile with the passphrase.
      - NOTE that adding additional keys is idempotent only since community.crypto 1.4.0. For older versions, a new keyslot
        will be used even if another keyslot already exists for this keyfile.
      - BEWARE that working with keyfiles in plaintext is dangerous. Make sure that they are protected.
    type: path
  new_passphrase:
    description:
      - Adds additional passphrase to given container on O(device). Needs O(keyfile) or O(passphrase) option for authorization.
        LUKS container supports up to 8 keyslots. Parameter value is a string with the new passphrase.
      - NOTE that adding additional passphrase is idempotent only since community.crypto 1.4.0. For older versions, a new
        keyslot will be used even if another keyslot already exists for this passphrase.
      - B(Note) that the passphrase must be UTF-8 encoded text. If you want to use arbitrary binary data, or text using
        another encoding, use the O(passphrase_encoding) option and provide the passphrase Base64 encoded.
    type: str
    version_added: '1.0.0'
  new_keyslot:
    description:
      - Adds the additional O(new_keyfile) or O(new_passphrase) to a specific keyslot on the given O(device). Parameter value
        is the number of the keyslot.
      - B(Note) that a device of O(type=luks1) supports the keyslot numbers V(0)-V(7) and a device of O(type=luks2) supports
        the keyslot numbers V(0)-V(31).
    type: int
    version_added: '2.16.0'
  remove_keyfile:
    description:
      - Removes given key from the container on O(device). Does not remove the keyfile from filesystem. Parameter value is
        the path to the keyfile with the passphrase.
      - NOTE that removing keys is idempotent only since community.crypto 1.4.0. For older versions, trying to remove a key
        which no longer exists results in an error.
      - NOTE that to remove the last key from a LUKS container, the O(force_remove_last_key) option must be set to V(true).
      - BEWARE that working with keyfiles in plaintext is dangerous. Make sure that they are protected.
    type: path
  remove_passphrase:
    description:
      - Removes given passphrase from the container on O(device). Parameter value is a string with the passphrase to remove.
      - NOTE that removing passphrases is idempotent only since community.crypto 1.4.0. For older versions, trying to remove
        a passphrase which no longer exists results in an error.
      - NOTE that to remove the last keyslot from a LUKS container, the O(force_remove_last_key) option must be set to V(true).
      - B(Note) that the passphrase must be UTF-8 encoded text. If you want to use arbitrary binary data, or text using
        another encoding, use the O(passphrase_encoding) option and provide the passphrase Base64 encoded.
    type: str
    version_added: '1.0.0'
  remove_keyslot:
    description:
      - Removes the key in the given slot on O(device). Needs O(keyfile) or O(passphrase) for authorization.
      - B(Note) that a device of O(type=luks1) supports the keyslot numbers V(0)-V(7) and a device of O(type=luks2) supports
        the keyslot numbers V(0)-V(31).
      - B(Note) that the given O(keyfile) or O(passphrase) must not be in the slot to be removed.
    type: int
    version_added: '2.16.0'
  force_remove_last_key:
    description:
      - If set to V(true), allows removing the last key from a container.
      - BEWARE that when the last key has been removed from a container, the container can no longer be opened!
    type: bool
    default: false
  label:
    description:
      - This option allow the user to create a LUKS2 format container with label support, respectively to identify the container
        by label on later usages.
      - Will only be used on container creation, or when O(device) is not specified.
      - This cannot be specified if O(type) is set to V(luks1).
    type: str
    version_added: '1.0.0'
  uuid:
    description:
      - With this option user can identify the LUKS container by UUID.
      - Will only be used when O(device) and O(label) are not specified.
    type: str
    version_added: '1.0.0'
  type:
    description:
      - This option allow the user explicit define the format of LUKS container that wants to work with. Options are V(luks1)
        or V(luks2).
    type: str
    choices: [luks1, luks2]
    version_added: '1.0.0'
  cipher:
    description:
      - This option allows the user to define the cipher specification string for the LUKS container.
      - Will only be used on container creation.
      - For pre-2.6.10 kernels, use V(aes-plain) as they do not understand the new cipher spec strings. To use ESSIV, use
        V(aes-cbc-essiv:sha256).
    type: str
    version_added: '1.1.0'
  hash:
    description:
      - This option allows the user to specify the hash function used in LUKS key setup scheme and volume key digest.
      - Will only be used on container creation.
    type: str
    version_added: '1.1.0'
  pbkdf:
    description:
      - This option allows the user to configure the Password-Based Key Derivation Function (PBKDF) used.
      - Will only be used on container creation, and when adding keys to an existing container.
    type: dict
    version_added: '1.4.0'
    suboptions:
      iteration_time:
        description:
          - Specify the iteration time used for the PBKDF.
          - Note that this is in B(seconds), not in milliseconds as on the command line.
          - Mutually exclusive with O(pbkdf.iteration_count).
        type: float
      iteration_count:
        description:
          - Specify the iteration count used for the PBKDF.
          - Mutually exclusive with O(pbkdf.iteration_time).
        type: int
      algorithm:
        description:
          - The algorithm to use.
          - Only available for the LUKS 2 format.
        choices:
          - argon2i
          - argon2id
          - pbkdf2
        type: str
      memory:
        description:
          - The memory cost limit in kilobytes for the PBKDF.
          - This is not used for PBKDF2, but only for the Argon PBKDFs.
        type: int
      parallel:
        description:
          - The parallel cost for the PBKDF. This is the number of threads that run in parallel.
          - This is not used for PBKDF2, but only for the Argon PBKDFs.
        type: int
  sector_size:
    description:
      - This option allows the user to specify the sector size (in bytes) used for LUKS2 containers.
      - Will only be used on container creation.
    type: int
    version_added: '1.5.0'
  perf_same_cpu_crypt:
    description:
      - Allows the user to perform encryption using the same CPU that IO was submitted on.
      - The default is to use an unbound workqueue so that encryption work is automatically balanced between available CPUs.
      - Will only be used when opening containers.
    type: bool
    default: false
    version_added: '2.3.0'
  perf_submit_from_crypt_cpus:
    description:
      - Allows the user to disable offloading writes to a separate thread after encryption.
      - There are some situations where offloading block write IO operations from the encryption threads to a single thread
        degrades performance significantly.
      - The default is to offload block write IO operations to the same thread.
      - Will only be used when opening containers.
    type: bool
    default: false
    version_added: '2.3.0'
  perf_no_read_workqueue:
    description:
      - Allows the user to bypass dm-crypt internal workqueue and process read requests synchronously.
      - Will only be used when opening containers.
    type: bool
    default: false
    version_added: '2.3.0'
  perf_no_write_workqueue:
    description:
      - Allows the user to bypass dm-crypt internal workqueue and process write requests synchronously.
      - Will only be used when opening containers.
    type: bool
    default: false
    version_added: '2.3.0'
  persistent:
    description:
      - Allows the user to store options into container's metadata persistently and automatically use them next time. Only
        O(perf_same_cpu_crypt), O(perf_submit_from_crypt_cpus), O(perf_no_read_workqueue), O(perf_no_write_workqueue), and
        O(allow_discards) can be stored persistently.
      - Will only work with LUKS2 containers.
      - Will only be used when opening containers.
    type: bool
    default: false
    version_added: '2.3.0'
  allow_discards:
    description:
      - Allow discards (also known as TRIM) requests for device.
      - Will only be used when opening containers.
    type: bool
    default: false
    version_added: '2.17.0'

requirements:
  - "cryptsetup"
  - "wipefs (when O(state) is V(absent))"
  - "lsblk"
  - "blkid (when O(label) or O(uuid) options are used)"

author: Jan Pokorny (@japokorn)
"""

EXAMPLES = r"""
---
- name: Create LUKS container (remains unchanged if it already exists)
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    keyfile: "/vault/keyfile"

- name: Create LUKS container with a passphrase
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    passphrase: "foo"

- name: Create LUKS container with specific encryption
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    cipher: "aes"
    hash: "sha256"

- name: (Create and) open the LUKS container; name it "mycrypt"
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "opened"
    name: "mycrypt"
    keyfile: "/vault/keyfile"

- name: Close the existing LUKS container "mycrypt"
  community.crypto.luks_device:
    state: "closed"
    name: "mycrypt"

- name: Make sure LUKS container exists and is closed
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "closed"
    keyfile: "/vault/keyfile"

- name: Create container if it does not exist and add new key to it
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    keyfile: "/vault/keyfile"
    new_keyfile: "/vault/keyfile2"

- name: Add new key to the LUKS container (container has to exist)
  community.crypto.luks_device:
    device: "/dev/loop0"
    keyfile: "/vault/keyfile"
    new_keyfile: "/vault/keyfile2"

- name: Add new passphrase to the LUKS container
  community.crypto.luks_device:
    device: "/dev/loop0"
    keyfile: "/vault/keyfile"
    new_passphrase: "foo"

- name: Remove existing keyfile from the LUKS container
  community.crypto.luks_device:
    device: "/dev/loop0"
    remove_keyfile: "/vault/keyfile2"

- name: Remove existing passphrase from the LUKS container
  community.crypto.luks_device:
    device: "/dev/loop0"
    remove_passphrase: "foo"

- name: Completely remove the LUKS container and its contents
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "absent"

- name: Create a container with label
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    keyfile: "/vault/keyfile"
    label: personalLabelName

- name: Open the LUKS container based on label without device; name it "mycrypt"
  community.crypto.luks_device:
    label: "personalLabelName"
    state: "opened"
    name: "mycrypt"
    keyfile: "/vault/keyfile"

- name: Close container based on UUID
  community.crypto.luks_device:
    uuid: 03ecd578-fad4-4e6c-9348-842e3e8fa340
    state: "closed"
    name: "mycrypt"

- name: Create a container using luks2 format
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    keyfile: "/vault/keyfile"
    type: luks2

- name: Create a container with key in slot 4
  community.crypto.luks_device:
    device: "/dev/loop0"
    state: "present"
    keyfile: "/vault/keyfile"
    keyslot: 4

- name: Add a new key in slot 5
  community.crypto.luks_device:
    device: "/dev/loop0"
    keyfile: "/vault/keyfile"
    new_keyfile: "/vault/keyfile"
    new_keyslot: 5

- name: Remove the key from slot 4 (given keyfile must not be slot 4)
  community.crypto.luks_device:
    device: "/dev/loop0"
    keyfile: "/vault/keyfile"
    remove_keyslot: 4
"""

RETURN = r"""
name:
  description: When O(state=opened) returns (generated or given) name of LUKS container. Returns None if no name is supplied.
  returned: success
  type: str
  sample: "luks-c1da9a58-2fde-4256-9d9f-6ab008b4dd1b"
"""

import os
import re
import stat
from base64 import b64decode

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_native


RETURN_CODE = 0
STDOUT = 1
STDERR = 2

# used to get <luks-name> out of lsblk output in format 'crypt <luks-name>'
# regex takes care of any possible blank characters
LUKS_NAME_REGEX = re.compile(r"^crypt\s+([^\s]*)\s*$")
# used to get </luks/device> out of lsblk output
# in format 'device: </luks/device>'
LUKS_DEVICE_REGEX = re.compile(r"\s*device:\s+([^\s]*)\s*")


# See https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
LUKS_HEADER = b"LUKS\xba\xbe"
LUKS_HEADER_L = 6
# See https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/master/luks2_doc_wip.pdf
LUKS2_HEADER_OFFSETS = [
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x40000,
    0x80000,
    0x100000,
    0x200000,
    0x400000,
]
LUKS2_HEADER2 = b"SKUL\xba\xbe"


def wipe_luks_headers(device):
    wipe_offsets = []
    with open(device, "rb") as f:
        # f.seek(0)
        data = f.read(LUKS_HEADER_L)
        if data == LUKS_HEADER:
            wipe_offsets.append(0)
        for offset in LUKS2_HEADER_OFFSETS:
            f.seek(offset)
            data = f.read(LUKS_HEADER_L)
            if data == LUKS2_HEADER2:
                wipe_offsets.append(offset)

    if wipe_offsets:
        with open(device, "wb") as f:
            for offset in wipe_offsets:
                f.seek(offset)
                f.write(b"\x00\x00\x00\x00\x00\x00")


class Handler(object):

    def __init__(self, module):
        self._module = module
        self._lsblk_bin = self._module.get_bin_path("lsblk", True)
        self._passphrase_encoding = module.params["passphrase_encoding"]

    def get_passphrase_from_module_params(self, parameter_name):
        passphrase = self._module.params[parameter_name]
        if passphrase is None:
            return None
        if self._passphrase_encoding == "text":
            return to_bytes(passphrase)
        try:
            return b64decode(to_native(passphrase))
        except Exception as exc:
            self._module.fail_json(
                "Error while base64-decoding '{parameter_name}': {exc}".format(
                    parameter_name=parameter_name, exc=exc
                )
            )

    def _run_command(self, command, data=None):
        return self._module.run_command(command, data=data, binary_data=True)

    def get_device_by_uuid(self, uuid):
        """Returns the device that holds UUID passed by user"""
        self._blkid_bin = self._module.get_bin_path("blkid", True)
        uuid = self._module.params["uuid"]
        if uuid is None:
            return None
        result = self._run_command([self._blkid_bin, "--uuid", uuid])
        if result[RETURN_CODE] != 0:
            return None
        return result[STDOUT].strip()

    def get_device_by_label(self, label):
        """Returns the device that holds label passed by user"""
        self._blkid_bin = self._module.get_bin_path("blkid", True)
        label = self._module.params["label"]
        if label is None:
            return None
        result = self._run_command([self._blkid_bin, "--label", label])
        if result[RETURN_CODE] != 0:
            return None
        return result[STDOUT].strip()

    def generate_luks_name(self, device):
        """Generate name for luks based on device UUID ('luks-<UUID>').
        Raises ValueError when obtaining of UUID fails.
        """
        result = self._run_command([self._lsblk_bin, "-n", device, "-o", "UUID"])

        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while generating LUKS name for %s: %s" % (device, result[STDERR])
            )
        dev_uuid = result[STDOUT].strip()
        return "luks-%s" % dev_uuid


class CryptHandler(Handler):

    def __init__(self, module):
        super(CryptHandler, self).__init__(module)
        self._cryptsetup_bin = self._module.get_bin_path("cryptsetup", True)

    def get_container_name_by_device(self, device):
        """obtain LUKS container name based on the device where it is located
        return None if not found
        raise ValueError if lsblk command fails
        """
        result = self._run_command([self._lsblk_bin, device, "-nlo", "type,name"])
        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while obtaining LUKS name for %s: %s" % (device, result[STDERR])
            )

        for line in result[STDOUT].splitlines(False):
            m = LUKS_NAME_REGEX.match(line)
            if m:
                return m.group(1)
        return None

    def get_container_device_by_name(self, name):
        """obtain device name based on the LUKS container name
        return None if not found
        raise ValueError if lsblk command fails
        """
        # apparently each device can have only one LUKS container on it
        result = self._run_command([self._cryptsetup_bin, "status", name])
        if result[RETURN_CODE] != 0:
            return None

        m = LUKS_DEVICE_REGEX.search(result[STDOUT])
        device = m.group(1)
        return device

    def is_luks(self, device):
        """check if the LUKS container does exist"""
        result = self._run_command([self._cryptsetup_bin, "isLuks", device])
        return result[RETURN_CODE] == 0

    def get_luks_type(self, device):
        """get the luks type of a device"""
        if self.is_luks(device):
            with open(device, "rb") as f:
                for offset in LUKS2_HEADER_OFFSETS:
                    f.seek(offset)
                    data = f.read(LUKS_HEADER_L)
                    if data == LUKS2_HEADER2:
                        return "luks2"
                return "luks1"
        return None

    def is_luks_slot_set(self, device, keyslot):
        """check if a keyslot is set"""
        result = self._run_command([self._cryptsetup_bin, "luksDump", device])
        if result[RETURN_CODE] != 0:
            raise ValueError("Error while dumping LUKS header from %s" % (device,))
        result_luks1 = "Key Slot %d: ENABLED" % (keyslot) in result[STDOUT]
        result_luks2 = " %d: luks2" % (keyslot) in result[STDOUT]
        return result_luks1 or result_luks2

    def _add_pbkdf_options(self, options, pbkdf):
        if pbkdf["iteration_time"] is not None:
            options.extend(["--iter-time", str(int(pbkdf["iteration_time"] * 1000))])
        if pbkdf["iteration_count"] is not None:
            options.extend(["--pbkdf-force-iterations", str(pbkdf["iteration_count"])])
        if pbkdf["algorithm"] is not None:
            options.extend(["--pbkdf", pbkdf["algorithm"]])
        if pbkdf["memory"] is not None:
            options.extend(["--pbkdf-memory", str(pbkdf["memory"])])
        if pbkdf["parallel"] is not None:
            options.extend(["--pbkdf-parallel", str(pbkdf["parallel"])])

    def run_luks_create(
        self,
        device,
        keyfile,
        passphrase,
        keyslot,
        keysize,
        cipher,
        hash_,
        sector_size,
        pbkdf,
    ):
        # create a new luks container; use batch mode to auto confirm
        luks_type = self._module.params["type"]
        label = self._module.params["label"]

        options = []
        if keysize is not None:
            options.append("--key-size=" + str(keysize))
        if label is not None:
            options.extend(["--label", label])
            luks_type = "luks2"
        if luks_type is not None:
            options.extend(["--type", luks_type])
        if cipher is not None:
            options.extend(["--cipher", cipher])
        if hash_ is not None:
            options.extend(["--hash", hash_])
        if pbkdf is not None:
            self._add_pbkdf_options(options, pbkdf)
        if sector_size is not None:
            options.extend(["--sector-size", str(sector_size)])
        if keyslot is not None:
            options.extend(["--key-slot", str(keyslot)])

        args = [self._cryptsetup_bin, "luksFormat"]
        args.extend(options)
        args.extend(["-q", device])
        if keyfile:
            args.append(keyfile)
        else:
            args.append("-")

        result = self._run_command(args, data=passphrase)
        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while creating LUKS on %s: %s" % (device, result[STDERR])
            )

    def run_luks_open(
        self,
        device,
        keyfile,
        passphrase,
        perf_same_cpu_crypt,
        perf_submit_from_crypt_cpus,
        perf_no_read_workqueue,
        perf_no_write_workqueue,
        persistent,
        allow_discards,
        name,
    ):
        args = [self._cryptsetup_bin]
        if keyfile:
            args.extend(["--key-file", keyfile])
        else:
            args.extend(["--key-file", "-"])
        if perf_same_cpu_crypt:
            args.extend(["--perf-same_cpu_crypt"])
        if perf_submit_from_crypt_cpus:
            args.extend(["--perf-submit_from_crypt_cpus"])
        if perf_no_read_workqueue:
            args.extend(["--perf-no_read_workqueue"])
        if perf_no_write_workqueue:
            args.extend(["--perf-no_write_workqueue"])
        if persistent:
            args.extend(["--persistent"])
        if allow_discards:
            args.extend(["--allow-discards"])
        args.extend(["open", "--type", "luks", device, name])

        result = self._run_command(args, data=passphrase)
        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while opening LUKS container on %s: %s"
                % (device, result[STDERR])
            )

    def run_luks_close(self, name):
        result = self._run_command([self._cryptsetup_bin, "close", name])
        if result[RETURN_CODE] != 0:
            raise ValueError("Error while closing LUKS container %s" % (name))

    def run_luks_remove(self, device):
        wipefs_bin = self._module.get_bin_path("wipefs", True)

        name = self.get_container_name_by_device(device)
        if name is not None:
            self.run_luks_close(name)
        result = self._run_command([wipefs_bin, "--all", device])
        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while wiping LUKS container signatures for %s: %s"
                % (device, result[STDERR])
            )

        # For LUKS2, sometimes both `cryptsetup erase` and `wipefs` do **not**
        # erase all LUKS signatures (they seem to miss the second header). That's
        # why we do it ourselves here.
        try:
            wipe_luks_headers(device)
        except Exception as exc:
            raise ValueError(
                "Error while wiping LUKS container signatures for %s: %s"
                % (device, exc)
            )

    def run_luks_add_key(
        self,
        device,
        keyfile,
        passphrase,
        new_keyfile,
        new_passphrase,
        new_keyslot,
        pbkdf,
    ):
        """Add new key from a keyfile or passphrase to given 'device';
        authentication done using 'keyfile' or 'passphrase'.
        Raises ValueError when command fails.
        """
        data = []
        args = [self._cryptsetup_bin, "luksAddKey", device]
        if pbkdf is not None:
            self._add_pbkdf_options(args, pbkdf)

        if new_keyslot is not None:
            args.extend(["--key-slot", str(new_keyslot)])

        if keyfile:
            args.extend(["--key-file", keyfile])
        else:
            args.extend(["--key-file", "-", "--keyfile-size", str(len(passphrase))])
            data.append(passphrase)

        if new_keyfile:
            args.append(new_keyfile)
        else:
            args.append("-")
            data.append(new_passphrase)

        result = self._run_command(args, data=b"".join(data) or None)
        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while adding new LUKS keyslot to %s: %s"
                % (device, result[STDERR])
            )

    def run_luks_remove_key(
        self, device, keyfile, passphrase, keyslot, force_remove_last_key=False
    ):
        """Remove key from given device
        Raises ValueError when command fails
        """
        if not force_remove_last_key:
            result = self._run_command([self._cryptsetup_bin, "luksDump", device])
            if result[RETURN_CODE] != 0:
                raise ValueError("Error while dumping LUKS header from %s" % (device,))
            keyslot_count = 0
            keyslot_area = False
            keyslot_re = re.compile(r"^Key Slot [0-9]+: ENABLED")
            for line in result[STDOUT].splitlines():
                if line.startswith("Keyslots:"):
                    keyslot_area = True
                elif line.startswith("  "):
                    # LUKS2 header dumps use human-readable indented output.
                    # Thus we have to look out for 'Keyslots:' and count the
                    # number of indented keyslot numbers.
                    if keyslot_area and line[2] in "0123456789":
                        keyslot_count += 1
                elif line.startswith("\t"):
                    pass
                elif keyslot_re.match(line):
                    # LUKS1 header dumps have one line per keyslot with ENABLED
                    # or DISABLED in them. We count such lines with ENABLED.
                    keyslot_count += 1
                else:
                    keyslot_area = False
            if keyslot_count < 2:
                self._module.fail_json(
                    msg="LUKS device %s has less than two active keyslots. "
                    "To be able to remove a key, please set "
                    "`force_remove_last_key` to `true`." % device
                )

        if keyslot is None:
            args = [self._cryptsetup_bin, "luksRemoveKey", device, "-q"]
            if keyfile:
                args.extend(["--key-file", keyfile])
            elif passphrase is not None:
                args.extend(["--key-file", "-"])
        else:
            # Since we supply -q no passphrase is needed
            args = [self._cryptsetup_bin, "luksKillSlot", device, "-q", str(keyslot)]
            passphrase = None
        result = self._run_command(args, data=passphrase)
        if result[RETURN_CODE] != 0:
            raise ValueError(
                "Error while removing LUKS key from %s: %s" % (device, result[STDERR])
            )

    def luks_test_key(self, device, keyfile, passphrase, keyslot=None):
        """Check whether the keyfile or passphrase works.
        Raises ValueError when command fails.
        """
        data = None
        args = [self._cryptsetup_bin, "luksOpen", "--test-passphrase", device]

        if keyfile:
            args.extend(["--key-file", keyfile])
        else:
            args.extend(["--key-file", "-"])
            data = passphrase

        if keyslot is not None:
            args.extend(["--key-slot", str(keyslot)])

        result = self._run_command(args, data=data)
        if result[RETURN_CODE] == 0:
            return True
        for output in (STDOUT, STDERR):
            if "No key available with this passphrase" in result[output]:
                return False
            if "No usable keyslot is available." in result[output]:
                return False

        # This check is necessary due to cryptsetup in version 2.0.3 not printing 'No usable keyslot is available'
        # when using the --key-slot parameter in combination with --test-passphrase
        if (
            result[RETURN_CODE] == 1
            and keyslot is not None
            and result[STDOUT] == ""
            and result[STDERR] == ""
        ):
            return False

        raise ValueError(
            "Error while testing whether keyslot exists on %s: %s"
            % (device, result[STDERR])
        )


class ConditionsHandler(Handler):

    def __init__(self, module, crypthandler):
        super(ConditionsHandler, self).__init__(module)
        self._crypthandler = crypthandler
        self.device = self.get_device_name()

    def get_device_name(self):
        device = self._module.params.get("device")
        label = self._module.params.get("label")
        uuid = self._module.params.get("uuid")
        name = self._module.params.get("name")

        if device is None and label is not None:
            device = self.get_device_by_label(label)
        elif device is None and uuid is not None:
            device = self.get_device_by_uuid(uuid)
        elif device is None and name is not None:
            device = self._crypthandler.get_container_device_by_name(name)

        return device

    def luks_create(self):
        return (
            self.device is not None
            and (
                self._module.params["keyfile"] is not None
                or self._module.params["passphrase"] is not None
            )
            and self._module.params["state"] in ("present", "opened", "closed")
            and not self._crypthandler.is_luks(self.device)
        )

    def opened_luks_name(self):
        """If luks is already opened, return its name.
        If 'name' parameter is specified and differs
        from obtained value, fail.
        Return None otherwise
        """
        if self._module.params["state"] != "opened":
            return None

        # try to obtain luks name - it may be already opened
        name = self._crypthandler.get_container_name_by_device(self.device)

        if name is None:
            # container is not open
            return None

        if self._module.params["name"] is None:
            # container is already opened
            return name

        if name != self._module.params["name"]:
            # the container is already open but with different name:
            # suspicious. back off
            self._module.fail_json(
                msg="LUKS container is already opened "
                "under different name '%s'." % name
            )

        # container is opened and the names match
        return name

    def luks_open(self):
        if (
            (
                self._module.params["keyfile"] is None
                and self._module.params["passphrase"] is None
            )
            or self.device is None
            or self._module.params["state"] != "opened"
        ):
            # conditions for open not fulfilled
            return False

        name = self.opened_luks_name()

        if name is None:
            return True
        return False

    def luks_close(self):
        if (
            self._module.params["name"] is None and self.device is None
        ) or self._module.params["state"] != "closed":
            # conditions for close not fulfilled
            return False

        if self.device is not None:
            name = self._crypthandler.get_container_name_by_device(self.device)
            # successfully getting name based on device means that luks is open
            luks_is_open = name is not None

        if self._module.params["name"] is not None:
            self.device = self._crypthandler.get_container_device_by_name(
                self._module.params["name"]
            )
            # successfully getting device based on name means that luks is open
            luks_is_open = self.device is not None

        return luks_is_open

    def luks_add_key(self):
        if (
            self.device is None
            or (
                self._module.params["keyfile"] is None
                and self._module.params["passphrase"] is None
            )
            or (
                self._module.params["new_keyfile"] is None
                and self._module.params["new_passphrase"] is None
            )
        ):
            # conditions for adding a key not fulfilled
            return False

        if self._module.params["state"] == "absent":
            self._module.fail_json(
                msg="Contradiction in setup: Asking to " "add a key to absent LUKS."
            )

        key_present = self._crypthandler.luks_test_key(
            self.device,
            self._module.params["new_keyfile"],
            self.get_passphrase_from_module_params("new_passphrase"),
        )
        if self._module.params["new_keyslot"] is not None:
            key_present_slot = self._crypthandler.luks_test_key(
                self.device,
                self._module.params["new_keyfile"],
                self.get_passphrase_from_module_params("new_passphrase"),
                self._module.params["new_keyslot"],
            )
            if key_present and not key_present_slot:
                self._module.fail_json(
                    msg="Trying to add key that is already present in another slot"
                )

        return not key_present

    def luks_remove_key(self):
        if self.device is None or (
            self._module.params["remove_keyfile"] is None
            and self._module.params["remove_passphrase"] is None
            and self._module.params["remove_keyslot"] is None
        ):
            # conditions for removing a key not fulfilled
            return False

        if self._module.params["state"] == "absent":
            self._module.fail_json(
                msg="Contradiction in setup: Asking to "
                "remove a key from absent LUKS."
            )

        if self._module.params["remove_keyslot"] is not None:
            if not self._crypthandler.is_luks_slot_set(
                self.device, self._module.params["remove_keyslot"]
            ):
                return False
            result = self._crypthandler.luks_test_key(
                self.device,
                self._module.params["keyfile"],
                self.get_passphrase_from_module_params("passphrase"),
            )
            if self._crypthandler.luks_test_key(
                self.device,
                self._module.params["keyfile"],
                self.get_passphrase_from_module_params("passphrase"),
                self._module.params["remove_keyslot"],
            ):
                self._module.fail_json(
                    msg="Cannot remove keyslot with keyfile or passphrase in same slot."
                )
            return result

        return self._crypthandler.luks_test_key(
            self.device,
            self._module.params["remove_keyfile"],
            self.get_passphrase_from_module_params("remove_passphrase"),
        )

    def luks_remove(self):
        return (
            self.device is not None
            and self._module.params["state"] == "absent"
            and self._crypthandler.is_luks(self.device)
        )

    def validate_keyslot(self, param, luks_type):
        if self._module.params[param] is not None:
            if luks_type is None and param == "keyslot":
                if 8 <= self._module.params[param] <= 31:
                    self._module.fail_json(
                        msg="You must specify type=luks2 when creating a new LUKS device to use keyslots 8-31."
                    )
                elif not (0 <= self._module.params[param] <= 7):
                    self._module.fail_json(
                        msg="When not specifying a type, only the keyslots 0-7 are allowed."
                    )

            if luks_type == "luks1" and not 0 <= self._module.params[param] <= 7:
                self._module.fail_json(
                    msg="%s must be between 0 and 7 when using LUKS1."
                    % self._module.params[param]
                )
            elif luks_type == "luks2" and not 0 <= self._module.params[param] <= 31:
                self._module.fail_json(
                    msg="%s must be between 0 and 31 when using LUKS2."
                    % self._module.params[param]
                )


def run_module():
    # available arguments/parameters that a user can pass
    module_args = dict(
        state=dict(
            type="str",
            default="present",
            choices=["present", "absent", "opened", "closed"],
        ),
        device=dict(type="str"),
        name=dict(type="str"),
        keyfile=dict(type="path"),
        new_keyfile=dict(type="path"),
        remove_keyfile=dict(type="path"),
        passphrase=dict(type="str", no_log=True),
        new_passphrase=dict(type="str", no_log=True),
        remove_passphrase=dict(type="str", no_log=True),
        passphrase_encoding=dict(
            type="str", default="text", choices=["text", "base64"], no_log=False
        ),
        keyslot=dict(type="int", no_log=False),
        new_keyslot=dict(type="int", no_log=False),
        remove_keyslot=dict(type="int", no_log=False),
        force_remove_last_key=dict(type="bool", default=False),
        keysize=dict(type="int"),
        label=dict(type="str"),
        uuid=dict(type="str"),
        type=dict(type="str", choices=["luks1", "luks2"]),
        cipher=dict(type="str"),
        hash=dict(type="str"),
        pbkdf=dict(
            type="dict",
            options=dict(
                iteration_time=dict(type="float"),
                iteration_count=dict(type="int"),
                algorithm=dict(type="str", choices=["argon2i", "argon2id", "pbkdf2"]),
                memory=dict(type="int"),
                parallel=dict(type="int"),
            ),
            mutually_exclusive=[("iteration_time", "iteration_count")],
        ),
        sector_size=dict(type="int"),
        perf_same_cpu_crypt=dict(type="bool", default=False),
        perf_submit_from_crypt_cpus=dict(type="bool", default=False),
        perf_no_read_workqueue=dict(type="bool", default=False),
        perf_no_write_workqueue=dict(type="bool", default=False),
        persistent=dict(type="bool", default=False),
        allow_discards=dict(type="bool", default=False),
    )

    mutually_exclusive = [
        ("keyfile", "passphrase"),
        ("new_keyfile", "new_passphrase"),
        ("remove_keyfile", "remove_passphrase", "remove_keyslot"),
    ]

    # seed the result dict in the object
    result = dict(changed=False, name=None)

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        mutually_exclusive=mutually_exclusive,
    )
    module.run_command_environ_update = dict(
        LANG="C", LC_ALL="C", LC_MESSAGES="C", LC_CTYPE="C"
    )

    if module.params["device"] is not None:
        try:
            statinfo = os.stat(module.params["device"])
            mode = statinfo.st_mode
            if not stat.S_ISBLK(mode) and not stat.S_ISCHR(mode):
                raise Exception("{0} is not a device".format(module.params["device"]))
        except Exception as e:
            module.fail_json(msg=str(e))

    crypt = CryptHandler(module)
    conditions = ConditionsHandler(module, crypt)

    # conditions not allowed to run
    if module.params["label"] is not None and module.params["type"] == "luks1":
        module.fail_json(msg="You cannot combine type luks1 with the label option.")

    if (
        module.params["keyslot"] is not None
        or module.params["new_keyslot"] is not None
        or module.params["remove_keyslot"] is not None
    ):
        luks_type = crypt.get_luks_type(conditions.get_device_name())
        if luks_type is None and module.params["type"] is not None:
            luks_type = module.params["type"]
        for param in ["keyslot", "new_keyslot", "remove_keyslot"]:
            conditions.validate_keyslot(param, luks_type)

    for param in ["new_keyslot", "remove_keyslot"]:
        if (
            module.params[param] is not None
            and module.params["keyfile"] is None
            and module.params["passphrase"] is None
        ):
            module.fail_json(
                msg="Removing a keyslot requires the passphrase or keyfile of another slot."
            )

    # The conditions are in order to allow more operations in one run.
    # (e.g. create luks and add a key to it)

    # luks create
    if conditions.luks_create():
        if not module.check_mode:
            try:
                crypt.run_luks_create(
                    conditions.device,
                    module.params["keyfile"],
                    conditions.get_passphrase_from_module_params("passphrase"),
                    module.params["keyslot"],
                    module.params["keysize"],
                    module.params["cipher"],
                    module.params["hash"],
                    module.params["sector_size"],
                    module.params["pbkdf"],
                )
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)

    # luks open

    name = conditions.opened_luks_name()
    if name is not None:
        result["name"] = name

    if conditions.luks_open():
        name = module.params["name"]
        if name is None:
            try:
                name = crypt.generate_luks_name(conditions.device)
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        if not module.check_mode:
            try:
                crypt.run_luks_open(
                    conditions.device,
                    module.params["keyfile"],
                    conditions.get_passphrase_from_module_params("passphrase"),
                    module.params["perf_same_cpu_crypt"],
                    module.params["perf_submit_from_crypt_cpus"],
                    module.params["perf_no_read_workqueue"],
                    module.params["perf_no_write_workqueue"],
                    module.params["persistent"],
                    module.params["allow_discards"],
                    name,
                )
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        result["name"] = name
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)

    # luks close
    if conditions.luks_close():
        if conditions.device is not None:
            try:
                name = crypt.get_container_name_by_device(conditions.device)
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        else:
            name = module.params["name"]
        if not module.check_mode:
            try:
                crypt.run_luks_close(name)
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        result["name"] = name
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)

    # luks add key
    if conditions.luks_add_key():
        if not module.check_mode:
            try:
                crypt.run_luks_add_key(
                    conditions.device,
                    module.params["keyfile"],
                    conditions.get_passphrase_from_module_params("passphrase"),
                    module.params["new_keyfile"],
                    conditions.get_passphrase_from_module_params("new_passphrase"),
                    module.params["new_keyslot"],
                    module.params["pbkdf"],
                )
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)

    # luks remove key
    if conditions.luks_remove_key():
        if not module.check_mode:
            try:
                last_key = module.params["force_remove_last_key"]
                crypt.run_luks_remove_key(
                    conditions.device,
                    module.params["remove_keyfile"],
                    conditions.get_passphrase_from_module_params("remove_passphrase"),
                    module.params["remove_keyslot"],
                    force_remove_last_key=last_key,
                )
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)

    # luks remove
    if conditions.luks_remove():
        if not module.check_mode:
            try:
                crypt.run_luks_remove(conditions.device)
            except ValueError as e:
                module.fail_json(msg="luks_device error: %s" % e)
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)

    # Success - return result
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
