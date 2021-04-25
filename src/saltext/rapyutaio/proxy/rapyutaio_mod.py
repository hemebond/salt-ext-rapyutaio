# -*- coding: utf-8 -*-
"""
This is a simple proxy-minion designed to connect to and
communicate with the Rapyuta.IO web service

Run a standalone proxy-minion as a non-root user:

	$ salt-proxy --proxyid=myproxy \
	             --config-dir=/srv/proxy \
	             --pid-file=/srv/proxy/myproxy.pid \
	             --log-level=debug
"""

import logging
from salt.exceptions import CommandExecutionError



# This must be present or the Salt loader won't load this module
__proxyenabled__ = ["rapyutaio"]



# Variables are scoped to this module so we can have persistent data
# across calls to fns in here.
GRAINS_CACHE = {}
DETAILS = {}

# Want logging!
log = logging.getLogger(__file__)



# This does nothing, it's here just as an example and to provide a log
# entry when the module is loaded.
def __virtual__():
	"""
	Only return if all the modules are available
	"""
	log.debug("rapyutaio Salt extension proxy __virtual__() called...")
	return "rapyutaio"



def init(opts):
	"""
	Every proxy module needs an 'init', though you can
	just put DETAILS['initialized'] = True here if nothing
	else needs to be done.
	"""
	log.debug("rapyutaio proxy init() called...")
	DETAILS["initialized"] = True
	return True



def ping():
	return True



def shutdown(opts):
	"""
	For this proxy shutdown is a no-op
	"""
	log.debug("rapyutaio proxy shutdown() called...")
