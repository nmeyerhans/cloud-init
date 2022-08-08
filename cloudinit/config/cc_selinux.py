#!/usr/bin/env python3

"""Enable SELinux enforcing mode"""

import re
from logging import Logger
from subprocess import Popen, PIPE

from cloudinit.cloud import Cloud
from cloudinit.config.schema import MetaSchema, get_meta_doc
from cloudinit.distros import ALL_DISTROS
from cloudinit.settings import PER_INSTANCE
from cloudinit import util

MODULE_DESCRIPTION = """\
Toggle SELinux enforcing mode.
"""

meta: MetaSchema = {
    "id": "cc_selinux",
    "name": "SELinux",
    "title": "Controls a system's SELinux configuration",
    "description": MODULE_DESCRIPTION,
    "distros": [ALL_DISTROS],
    "frequency": PER_INSTANCE,
    "examples": [
        "mode: enforcing",
        "selinux_no_reboot: 1",
    ],
}

__doc__ = get_meta_doc(meta)


def get_selinux_state():
    state = {}
    match_spec = [
        ('status', r'SELinux status'),
        ('root_directory', r'SELinux root directory'),
        ('mount_point', r'SELinuxfs mount'),
        ('loaded_policy_name', r'Loaded policy name'),
        ('current_mode', r'Current mode'),
        ('config_mode', r'Mode from config file'),
        ('policy_mls_status', r'Policy MLS status'),
        ('policy_deny_unknown_status', r'Policy deny_unknown status'),
        ('memory_protection_checking', r'Memory protection checking'),
        ('max_kernel_policy_version', r'Max kernel policy version'),
    ]
    with Popen("sestatus", stdout=PIPE, text=True) as p:
        for l in p.stdout.readlines():
            for r in match_spec:
                m = re.match(r"^(?P<%s>%s):\s+(.*)" % r, l)
                if m:
                    state[r[0]] = m.group(2)
    return state


def handle(name: str, cfg: dict, cloud: Cloud, log: Logger, args: list):
    log.debug(f"Hi from module {name}")
    state = get_selinux_state()
    if 'status' in state:
        log.info("Current SELinux state is %s" % state['status'])
        log.info("Current SELinux mode is %s" % state['current_mode'])
        log.info("Configured SELinux mode is %s" % state['config_mode'])
        log.info("Current SELinux policy is %s" % state['loaded_policy_name'])
    else:
        log.info("Unable to determine current SELinux status")
        return
    selinux_cfg = util.get_cfg_by_path(cfg, ("selinux"))
    if selinux_cfg is None:
        log.debug("No SELinux configuration, skipping")
        return
    mode = util.get_cfg_option_str(selinux_cfg, "mode", None)
    if mode is None:
        log.warn("No mode setting in selinux configuration")
        return

# Local variables:
# mode: python
# indent-tabs-mode: nil
# tab-width: 4
# end:
