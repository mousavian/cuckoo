import xmlrpclib
from lib.common.constants import PATHS
from lib.core.startup import create_folders
from lib.core.config import Config
from droidbox.droidbox import *
import time
import os



class Analyzer:
	"""Cuckoo Windows Analyzer."""

	def __init__(self):
		"""Init."""
		self.config = None
		self.target = None

	def prepare(self):
		# Create the folders used for storing the results.
		create_folders()
		self.config = Config(cfg="analysis.conf")

		self.target = os.path.join('/tmp' + os.sep, str(self.config.file_name))

	def complete(self):
		# Dump all the notified files.
		#dump_files()
		# Hell yeah.
		log.info("Analysis completed")

		while True:
			print "done, waiting ..."
			time.sleep(1)

	def run(self):
		"""Run analysis.
		@return: operation status.
		"""
		self.prepare()
		print "==>prepared"
		droidboxMain(self.target, PATHS['logs'])

		self.complete()
		return True








if __name__ == "__main__":
	success = False
	error = ""

	try:
		# Initialize the main analyzer class.
		analyzer = Analyzer()
		# Run it and wait for the response.
		success = analyzer.run()
	except KeyboardInterrupt:
		error = "Keyboard Interrupt"
	except Exception as e:
		# Store the error.
		#error_exc = traceback.format_exc()
		error = str(e)

		#if len(log.handlers) > 0:
		#	log.exception(error_exc)
		#else:
		#	sys.stderr.write("{0}\n".format(error_exc))
	finally:
		server = xmlrpclib.Server("http://127.0.0.1:8000")
		server.complete(success, error, PATHS["root"])

