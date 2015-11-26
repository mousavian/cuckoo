
import logging
import subprocess
import os.path
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

class LXC(Machinery):
    """Virtualization layer for Linux Containers"""
    locked = False

    def initialize(self):
    	self.locked = False
    	
    def _initialize_check(self):
        return ''
    def _check_vmx(self, host):
        return ''
    def _check_snapshot(self, host, snapshot):
        return ''
    def start(self, label):
        return ''
    def stop(self, label):
        return ''
    def _revert(self, host, snapshot):
        return ''
    def _is_running(self, host):
        return ''
    def _parse_label(self, label):
        return ''
    def _get_host_and_snapshot(self, label):
        return ''
    def availables(self):
    	return not self.locked
    	#return super(LXC, self).availables('lxc')