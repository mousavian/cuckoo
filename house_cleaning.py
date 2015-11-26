#!/usr/bin/env python
import os
import time
import sys
import paramiko
import mysql.connector
import logging

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
try:
	from sqlalchemy import create_engine, Column
	from sqlalchemy import Integer, String, Boolean, DateTime, Enum
	from sqlalchemy import ForeignKey, Text, Index, Table
	from sqlalchemy.ext.declarative import declarative_base
	from sqlalchemy.exc import SQLAlchemyError, IntegrityError
	from sqlalchemy.orm import sessionmaker, relationship, joinedload, backref
	from sqlalchemy.pool import NullPool
	Base = declarative_base()
except ImportError:
	raise Exception("Unable to import sqlalchemy install with `pip install sqlalchemy`)")

log = logging.getLogger(__name__)







class HouseCleaner:
	def __init__(self):
		self.running = True
		self.db = Database()
		self.config = Config(os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"))
		self.nova_machines = dict()
		self.nova_db = create_engine("mysql://{0}:{1}@{2}/nova".format(
										self.config.openstack.db_username,
										self.config.openstack.db_password,
										self.config.openstack.db_host),
			 poolclass=NullPool).connect()
		cursor = self.nova_db.execute("SELECT ins.id, fip.address, ins.launched_on, ins.vm_state, ins.display_name, ins.hostname, ins.host, ins.uuid "
								   " FROM `instances` ins LEFT JOIN `fixed_ips` fip ON ( fip.`instance_uuid` = ins.`uuid` ) "
								   " WHERE ins.`cleaned`=0 AND fip.`deleted`=0 AND ins.`display_name` like '{0}%%'".format(self.config.openstack.vm_prefix))
		for row in cursor.fetchall():
			_machine_id = "instance-%08x"%int(row[0])
			self.nova_machines[_machine_id] = dict()
			self.nova_machines[_machine_id]["id"] = row[0]
			self.nova_machines[_machine_id]["ip"] = row[1] 
			self.nova_machines[_machine_id]["hypervisor"] = row[2] 
			self.nova_machines[_machine_id]["label"] = _machine_id
			self.nova_machines[_machine_id]["platform"] = self.config.openstack.platform
			self.nova_machines[_machine_id]["tags"] = self.config.openstack.tags
			self.nova_machines[_machine_id]["dsn"] = "qemu+ssh://root@{0}/system".format(row[2])
			self.nova_machines[_machine_id]["connection"] = None



	def stop(self):
		self.nova_db.close()
		self.running = False
		print ""

	def start(self):
		print "Cleaner Started!"
		while self.running:
			time.sleep(2)
			dirty_machines = self.db.get_dirty_machines()
			if ( dirty_machines and len( dirty_machines ) ):
				dirty_machine = dirty_machines[0]
				self.restore_qcow2( dirty_machine.label )
				self.db.set_machine_cleaned( dirty_machine.label )

	def restore_qcow2(self, label):
		log("Restoring `{0}` qcow2.".format(label))
		try:
			ssh_client = paramiko.SSHClient()
			ssh_client.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
			ssh_client.connect(self.nova_machines[label]['hypervisor'], username='root', password='k4hvd')
			qcow2_file_path = "/qcow2/" + label + ".qcow2"
			(stdin, stdout, sterr) = ssh_client.exec_command('yes | cp -rf {0} {1}'.format(qcow2_file_path+".org",qcow2_file_path))
			#now we will wait to finish copying file... 
			stdout.channel.settimeout(10800)
			stdout.channel.recv_exit_status()
			ssh_client.close()
			log("`{0}` is ready!".format(label))
			print 
		except NotImplementedError:
			raise Exception("ssh error")
















def log(str):
	print "{1}\t{0}".format(str, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))



def main():
	try:
		cleaner = HouseCleaner()
		cleaner.start()
	except KeyboardInterrupt:
		cleaner.stop()


if __name__ == "__main__":
	try:
		main()
	except Exception as e:
		message = "{0}: {1}".format(e.__class__.__name__, e)
		sys.stderr.write("{0}\n".format(message))
		sys.exit(1)