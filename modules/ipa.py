# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import hashlib
import magic
import plistlib
import pprint
import uuid
import zipfile

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
	from pyipa import *
	HAVE_PYIPA = True
except:
	HAVE_PYIPA = False

try:
	import macholib.mach_o
	import macholib.MachO
	HAVE_MACHOLIB = True
except:
	HAVE_MACHOLIB = False

class Ipa(Module):
	cmd = 'ipa'
	description = 'Parse IPA iOS Application Files'
	authors = ['Seth Hardy']

	def __init__(self):
		super(Ipa, self).__init__()
		self.parser.add_argument('-d', '--dump', metavar='dump_path', help='Extract all items from IPA')
		self.parser.add_argument('-f', '--file', action='store_true', help='Show IPA file contents')
		self.parser.add_argument('-p', '--plist', action='store_true', help='Show contents of all plists')
		self.parser.add_argument('-u', '--uuid', action='store_true', help='Show Mach-O UUIDs')

	def run(self):

		def read_plist():
		   	with zipfile.ZipFile(__sessions__.current.file.path, 'r') as archive:
		   		plist_contents = []

				for name in archive.namelist():
					if name.endswith(".plist"):
						plistraw = archive.read(name)
						try:
							plist = plistlib.readPlistFromString(plistraw)
						except:
							plist = BPlistReader.plistWithString(plistraw)
						for plistEntry in plist.items():
							entry = pprint.pformat(plistEntry[1])
							plist_contents.append([plistEntry[0], entry])
						self.log('info', name+" Entries:")
						self.log('table', dict(header=['Key', 'Value'], rows=plist_contents))


		def show_files(dump):
			with zipfile.ZipFile(__sessions__.current.file.path, 'r') as archive:
				ipa_files = []

				for name in archive.namelist():
					item_data = archive.read(name)
					item_md5 = hashlib.md5(item_data).hexdigest()
					item_type = magic.from_buffer(item_data, mime=True)
					ipa_files.append([name, item_md5, item_type])

				self.log('info', "IPA Contents:")
				self.log('table', dict(header=['File', 'MD5', 'Type'], rows=ipa_files))
				if dump:
					archive.extractall(self.args.dump)
					self.log('info', "IPA content extracted to {0}".format(self.args.dump))

		def show_uuid():
			with zipfile.ZipFile(__sessions__.current.file.path, 'r') as archive:
				macho_files = []

				for name in archive.namelist():
					item_data = archive.read(name)
					item_type = magic.from_buffer(item_data)
					if "Mach-O" in item_type:
						# TODO: make this not just unix-y
						f = open('/tmp/macho', 'w')
						f.write(item_data)
						f.close()
						binary = macholib.MachO.MachO("/tmp/macho")
						uuid_command, = [c[1] for c in binary.headers[0].commands if type(c[1]) == macholib.mach_o.uuid_command]
						# delete temp file
						macho_files.append([name,uuid.UUID(bytes=uuid_command.uuid).hex])
				
				# TODO: why doesn't this give all of them? limitation in macholib, looks like...
				self.log('info', "Mach-O UUIDs:")
				self.log('warning', "Not all fat binary UUIDs are currently shown!")
				self.log('table', dict(header=['File', 'UUID'], rows=macho_files))


		super(Ipa, self).run()
		if self.args is None:
			returnip

		if not __sessions__.is_set():
			self.log('error', "No session opened")
			return

		if not zipfile.is_zipfile(__sessions__.current.file.path):
			self.log('error', "Doesn't appear to be a valid IPA")
			return

		if not HAVE_PYIPA:
			self.log('error', "Unable to import pyipa")
			self.log('error', "pip install pyipa || get from https://github.com/mogui/pyipa")
			return
		if not HAVE_MACHOLIB:
			self.log('error', "Unable to import macholib")
			self.log('error', "pip install macholib")
			return

		if self.args.file:
			show_files(dump=False)
		elif self.args.dump:
			show_files(dump=True)
		elif self.args.plist:
			read_plist()
		elif self.args.uuid:
			show_uuid()
			