#!/usr/bin/env python3

"""Enable SELinux enforcing mode"""

import io
import re
import subprocess

from logging import Logger

from cloudinit.cloud import Cloud
from cloudinit.config.schema import MetaSchema, get_meta_doc
from cloudinit.distros import ALL_DISTROS
from cloudinit.settings import PER_INSTANCE
from cloudinit import util

MODULE_DESCRIPTION = """\
Toggle SELinux enforcing mode.
"""

CONFIG_FILE = '/etc/selinux/config'

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
    with subprocess.Popen("sestatus", stdout=subprocess.PIPE, text=True) as p:
        for l in p.stdout.readlines():
            for r in match_spec:
                m = re.match(r"^(?P<%s>%s):\s+(.*)" % r, l)
                if m:
                    state[r[0]] = m.group(2)
    return state


def _update_config_mode(mode: str):
    if mode not in ("enforcing", "permissive"):
        raise ValueError("Invalid mode")
    content = io.StringIO()
    with open(CONFIG_FILE) as infd:
        for line in infd.readlines():
            if re.match(r'^SELINUX=', line):
                content.write("# Added by cloud-init\n")
                content.write("SELINUX=%s\n" % mode)
            elif line.startswith("# Added by cloud-init"):
                # skip our own comments
                True
            else:
                content.write(line)
    util.write_file(CONFIG_FILE, content.getvalue())


def secure_mode_policyload(setmode=None):
    if setmode:
        if setmode not in ("on", "off"):
            raise ValueError("Invalid value for setmode")
        rv = subprocess.run(
            ["setsebool", "-P", "secure_mode_policyload", setmode],
            check=True)
    rv = subprocess.run(["getsebool", "secure_mode_policyload"],
                        stdout=subprocess.PIPE, text=True, check=True)
    print("NOAH: %s" % str(rv.stdout))
    out = re.match(r'secure_mode_policyload --> (\w+)', str(rv.stdout))
    if out.group(1) == "on":
        return True
    return False


def lock_config(state: dict, log):
    _update_config_mode("enforcing")
    rv = subprocess.run(
        ["grubby", "--update-kernel", "ALL", "--args", "enforcing=1"],
        check=True)
    log.debug("grubby exited with status %d", rv.returncode)
    rv = subprocess.run(["chattr", "+i", CONFIG_FILE], check=True)
    log.debug("chattr +i %s exited with status %d", CONFIG_FILE, rv.returncode)
    secure_mode_policyload('on')


def unlock_config(state: dict, log):
    rv = subprocess.run(
        ["grubby", "--update-kernel", "ALL", "--args", "enforcing=0"],
        check=True)
    log.debug("grubby exited with status %d", rv.returncode)
    if state['current_mode'] == 'enforcing' and secure_mode_policyload():
        # We need to reboot here
        log.info("Rebooting to clear enforcing mode")
        _ = subprocess.run(['reboot'], check=True)
    rv = subprocess.run(["chattr", "-i", CONFIG_FILE], check=True)
    log.debug("chattr -i %s exited with status %d", CONFIG_FILE, rv.returncode)
    _update_config_mode("permissive")
    secure_mode_policyload('off')


def set_selinux_mode(mode: str, state: dict, log: Logger, lock=True):
    if mode == "enforcing":
        param = 1
        if state['current_mode'] == 'enforcing':
            # we're already in enforcing mode, so we're unlikely to be
            # able to do anything even if we try
            log.info("SELinux enforcing mode is already active, skipping.")
            return
    elif mode == "permissive":
        param = 0
    else:
        raise ValueError("Invalid SELinux mode provided")

    if mode == "enforcing" and lock:
        lock_config(state, log)
    elif mode == "permissive":
        # We need to reboot to get back to permissive mode...
        unlock_config(state, log)

    _ = subprocess.run(["setenforce", str(param)], check=True)
    # return the updated state
    return get_selinux_state()


def handle(name: str, cfg: dict, cloud: Cloud, log: Logger, args: list):
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
    lock = util.get_cfg_option_bool(selinux_cfg, "mode_lock", True)
    state = set_selinux_mode(mode, state, log, lock)
    log.info("Setting SELinux to %s mode" % state['current_mode'])

# Local variables:
# mode: python
# indent-tabs-mode: nil
# tab-width: 4
# end:
