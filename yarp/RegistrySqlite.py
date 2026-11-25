# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements an sqlite3 interface with advanced features.
# Unlike the Registry module, this interface provides a single class to work with a registry hive, a truncated registry hive, and a registry fragment.
# Python 3 only.

from . import Registry, RegistryFile, RegistryRecover, RegistryHelpers
import sqlite3
import os
from hashlib import sha256
from collections import namedtuple

Key = namedtuple('Key', [ 'rowid', 'is_deleted', 'name', 'classname', 'last_written_timestamp', 'access_bits', 'parent_key_id', 'hive_path', 'hive_generation' ])
Value = namedtuple('Value', [ 'rowid', 'is_deleted', 'name', 'type', 'data', 'parent_key_id', 'hive_path', 'hive_generation' ])
Security = namedtuple('Security', [ 'rowid', 'owner_sid' ])
HiveInfo = namedtuple('HiveInfo', [ 'last_written_timestamp', 'last_reorganized_timestamp', 'offreg_serialization_timestamp', 'recovered', 'truncated', 'rebuilt' ])

# Columns selected when reading keys and values (the source columns are the last two in each table).
_KEY_COLUMNS = '`rowid`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id`, `hive_path`, `hive_generation`'
_VALUE_COLUMNS = '`rowid`, `is_deleted`, `name`, `type`, `data`, `parent_key_id`, `hive_path`, `hive_generation`'

# Columns selected when reading keys and values from a composite (multi-hive) database.
_COMPOSITE_KEY_COLUMNS = '`rowid`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_rowid`, `hive_path`, `hive_generation`'
_COMPOSITE_VALUE_COLUMNS = '`rowid`, `is_deleted`, `name`, `type`, `data`, `parent_key_rowid`, `hive_path`, `hive_generation`'

def sqlite3_upper_unicode(string):
	"""The UPPER()-like function with Unicode support."""

	return string.upper()

class YarpDB(object):
	"""This is an implementation of a registry hive to an sqlite3 database converter (and a simple interface to the database)."""

	db_cursor = None
	"""A database cursor."""

	schema_hive = ('CREATE TABLE `hive` ('
					'`id` INTEGER PRIMARY KEY,'
					'`last_written_timestamp` TEXT,'
					'`last_reorganized_timestamp` TEXT,'
					'`offreg_serialization_timestamp` TEXT,'
					'`root_key_id` TEXT,'
					'`recovered` NUMERIC,'
					'`truncated` NUMERIC,'
					'`rebuilt` NUMERIC'
					')')
	"""Schema for the 'hive' table. Timestamps (here and in other places) are integers stored as text (FILETIME). Only one row is allowed in this table."""

	schema_keys = ('CREATE TABLE `keys` ('
					'`id` TEXT PRIMARY KEY,'
					'`is_deleted` NUMERIC,'
					'`name` TEXT,'
					'`classname` TEXT,'
					'`last_written_timestamp` TEXT,'
					'`access_bits` INTEGER,'
					'`parent_key_id` TEXT,'
					'`security_rowid` INTEGER,'
					'`hive_path` TEXT,'
					'`hive_generation` INTEGER'
					')')
	"""Schema for the 'keys' table."""

	schema_values = ('CREATE TABLE `values` ('
					'`id` INTEGER PRIMARY KEY,'
					'`is_deleted` NUMERIC,'
					'`name` TEXT,'
					'`type` INTEGER,'
					'`data` BLOB,'
					'`parent_key_id` TEXT,'
					'`hive_path` TEXT,'
					'`hive_generation` INTEGER'
					')')
	"""Schema for the 'values' table."""

	schema_security = ('CREATE TABLE `security` ('
					'`owner_sid` TEXT'
					')')
	"""Schema for the 'security' table."""

	def __init__(self, primary_or_fragment_path, sqlite_path, no_recovery = False, hive_path = None, hive_generation = None):
		"""Create an sqlite3 database using 'sqlite_path', the database is filled with data from a registry file (primary) or a registry fragment specified by 'primary_or_fragment_path'.
		An existing database is cleared first. When 'no_recovery' is True, transaction log files are not used to recover a primary file.
		If 'primary_or_fragment_path' is None, open an existing database and use it.
		'hive_path' and 'hive_generation' identify the origin of the records; they are stored with
		every key and value (including rejected/deleted ones) so results stay attributable when
		databases of multiple hives are combined. When 'hive_path' is None, the primary path is used.
		"""

		self._hive_path = hive_path if hive_path is not None else primary_or_fragment_path
		self._hive_generation = hive_generation

		if primary_or_fragment_path is None and os.path.isfile(sqlite_path):
			# Use the existing database.
			self._primary = None
			self._hive = None
			self._log = None
			self._log1 = None
			self._log2 = None
			self._hive_path = hive_path
			self._hive_generation = hive_generation

			self._db_connection = sqlite3.connect(sqlite_path, check_same_thread = False)
			self._db_connection.create_function('UPPER_UNICODE', 1, sqlite3_upper_unicode)
			self.db_cursor = self._db_connection.cursor()

			self._db_migrate()

			return

		# Open the database, open the cursor.
		self._db_connection = sqlite3.connect(sqlite_path, check_same_thread = False)
		self._db_connection.create_function('UPPER_UNICODE', 1, sqlite3_upper_unicode)
		self.db_cursor = self._db_connection.cursor()

		# Open the primary file.
		self._primary = open(primary_or_fragment_path, 'rb')

		# Discover the transaction log files.
		log_files = RegistryHelpers.DiscoverLogFiles(primary_or_fragment_path)

		# Open the transaction log files.
		self._log = None
		if log_files.log_path is not None:
			self._log = open(log_files.log_path, 'rb')

		self._log1 = None
		if log_files.log1_path is not None:
			self._log1 = open(log_files.log1_path, 'rb')

		self._log2 = None
		if log_files.log2_path is not None:
			self._log2 = open(log_files.log2_path, 'rb')

		# Create the hive object.
		try:
			self._hive = Registry.RegistryHive(self._primary)
		except RegistryFile.NotSupportedException:
			raise
		except RegistryFile.BaseBlockException:
			temp_obj = self._primary
			self._primary = RegistryFile.FragmentTranslator(temp_obj)
			temp_obj.close()

			self._is_hive_truncated = True
			self._is_rebuilt = True
		except Registry.RegistryException:
			self._is_hive_truncated = True
			self._is_rebuilt = False
		else:
			self._is_hive_truncated = False
			self._is_rebuilt = False

		self._recovered = False
		self._db_clear()

		if not self._is_hive_truncated:
			# Recover the hive, if required.
			if not no_recovery:
				try:
					recovery_result = self._hive.recover_auto(self._log, self._log1, self._log2)
				except Registry.AutoRecoveryException:
					pass
				else:
					self._recovered = recovery_result.recovered

			try:
				self._hive.walk_everywhere()
			except (RegistryFile.CellOffsetException, RegistryFile.ReadException):
				if self._recovered:
					raise

				# This is an edge case: a truncated dirty hive.
				self._is_hive_truncated = True
				self._is_rebuilt = False
				self._hive = Registry.RegistryHiveTruncated(self._primary)

				self._db_init()

				self._db_process_partial_data()
				self._db_process_deleted_data()
				return

			self._db_init()

			self._db_process_deleted_data()
			self._db_process_data()
		else:
			# Create the truncated hive object.
			self._hive = Registry.RegistryHiveTruncated(self._primary)

			self._db_init()

			self._db_process_partial_data()
			self._db_process_deleted_data()

	def __enter__(self):
		return self

	def __exit__(self, *args):
		self.close()

	def close(self):
		"""Close the hive and backing files, commit and close the database."""

		# Close (unlink) the hive object.
		self._hive = None

		# Close the primary file.
		if self._primary is not None:
			self._primary.close()

		# Close the transaction log files.
		if self._log is not None:
			self._log.close()

		if self._log1 is not None:
			self._log1.close()

		if self._log2 is not None:
			self._log2.close()

		# Commit and close the database.
		self._db_connection.commit()
		self._db_connection.close()

	def _db_clear(self):
		"""Remove the tables and indices."""

		self.db_cursor.execute('DROP TABLE IF EXISTS `hive`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `keys`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `values`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `security`')

	def _db_migrate(self):
		"""Upgrade an older database (created without the source columns) in place.
		New databases already contain the 'hive_path' and 'hive_generation' columns.
		"""

		self.db_cursor.execute('PRAGMA table_info(`keys`)')
		key_columns = [ row[1] for row in self.db_cursor.fetchall() ]
		if 'hive_path' not in key_columns:
			self.db_cursor.execute('ALTER TABLE `keys` ADD COLUMN `hive_path` TEXT')
		if 'hive_generation' not in key_columns:
			self.db_cursor.execute('ALTER TABLE `keys` ADD COLUMN `hive_generation` INTEGER')

		self.db_cursor.execute('PRAGMA table_info(`values`)')
		value_columns = [ row[1] for row in self.db_cursor.fetchall() ]
		if 'hive_path' not in value_columns:
			self.db_cursor.execute('ALTER TABLE `values` ADD COLUMN `hive_path` TEXT')
		if 'hive_generation' not in value_columns:
			self.db_cursor.execute('ALTER TABLE `values` ADD COLUMN `hive_generation` INTEGER')

		self._db_connection.commit()

	def _db_init(self):
		"""Create the tables and indices. Set up basic data about the hive."""

		self.db_cursor.execute(self.schema_hive)

		self.db_cursor.execute(self.schema_keys)

		self.db_cursor.execute('CREATE INDEX `keys_idx_name` ON `keys`(`name`)')
		self.db_cursor.execute('CREATE INDEX `keys_idx_parent_key_id` ON `keys`(`parent_key_id`)')

		self.db_cursor.execute(self.schema_values)

		self.db_cursor.execute('CREATE INDEX `values_idx_name` ON `values`(`name`)')
		self.db_cursor.execute('CREATE INDEX `values_idx_parent_key_id` ON `values`(`parent_key_id`)')

		self.db_cursor.execute(self.schema_security)

		# Insert data about the hive.
		last_written_timestamp = str(self._hive.registry_file.baseblock.effective_last_written_timestamp)
		if self._hive.registry_file.baseblock.effective_last_reorganized_timestamp is None:
			last_reorganized_timestamp = None
		else:
			last_reorganized_timestamp = str(self._hive.registry_file.baseblock.effective_last_reorganized_timestamp)

		offreg_serialization_timestamp = self._hive.registry_file.baseblock.get_offreg_serialization_timestamp()
		if offreg_serialization_timestamp is None or offreg_serialization_timestamp == 0:
			offreg_serialization_timestamp = None
		else:
			offreg_serialization_timestamp = str(offreg_serialization_timestamp)

		if self._recovered:
			recovered = 1
		else:
			recovered = 0

		if self._is_hive_truncated:
			truncated = 1
		else:
			truncated = 0

		if self._is_rebuilt:
			rebuilt = 1
		else:
			rebuilt = 0

		self.db_cursor.execute('INSERT INTO `hive` (`id`, `last_written_timestamp`, `last_reorganized_timestamp`, `offreg_serialization_timestamp`, `root_key_id`, `recovered`, `truncated`, `rebuilt`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			(0, last_written_timestamp, last_reorganized_timestamp, offreg_serialization_timestamp, None, recovered, truncated, rebuilt))

		# Set up the value ID counter, etc.
		self._value_id = 0
		self._root_found = False

	def _db_key_to_id(self, key, is_deleted = 0):
		"""Calculate and return the ID for a key."""

		hasher = sha256()

		deleted_status = str(is_deleted).encode()
		hasher.update(deleted_status)

		key_node_data = key.key_node.read_binary(0, 76 + key.key_node.get_key_name_length())
		hasher.update(key_node_data)

		return hasher.hexdigest()

	def _db_value_to_id(self, value, is_deleted = 0):
		"""Calculate and return the ID for a value. This should preserve the original order of values of a key."""

		curr_id = self._value_id
		self._value_id += 1
		return curr_id

	def _db_is_reallocated_value(self, value):
		"""Check if a deleted value has been reallocated."""

		if value.cell_relative_offset is None:
			return False

		value_offset = value.cell_relative_offset + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
		if not self._is_hive_truncated:
			return value_offset in self._hive.registry_file.cell_map_referenced
		else:
			return value_offset in self._hive.registry_file.cell_map_allocated

	def _db_is_reallocated_value_data(self, value):
		"""Check if deleted value data has been reallocated."""

		if value.key_value.is_data_inline():
			return False

		data_offset = value.key_value.get_data_offset() + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
		if not self._is_hive_truncated:
			return data_offset in self._hive.registry_file.cell_map_referenced
		else:
			return data_offset in self._hive.registry_file.cell_map_allocated

	def _db_store_security_info(self, owner_sid):
		"""Add new security information to the database and return its security row ID. If the same information already exists in the database, just return its security row ID."""

		self.db_cursor.execute('SELECT `rowid` FROM `security` WHERE `owner_sid` = ?', (owner_sid,))

		results = self.db_cursor.fetchall()
		for result in results:
			return result[0]

		self.db_cursor.execute('INSERT INTO `security` (`owner_sid`) VALUES (?)', (owner_sid,))
		return self.db_cursor.lastrowid

	def _db_add_key(self, key, is_deleted = 0):
		"""Add a key and its values to the database."""

		key_id = self._db_key_to_id(key, is_deleted)

		name = key.name()

		try:
			classname = key.classname()
		except (Registry.RegistryException, UnicodeDecodeError):
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

			classname = None

		try:
			security = key.security()
		except Registry.RegistryException:
			security = None

		security_rowid = None
		if security is not None:
			security_descriptor = security.descriptor()
			try:
				owner_sid = RegistryHelpers.ParseSecurityDescriptorRelative(security_descriptor).owner_sid
			except Exception:
				pass
			else:
				security_rowid = self._db_store_security_info(owner_sid)

		last_written_timestamp = str(key.key_node.get_last_written_timestamp())
		access_bits = key.access_bits()

		try:
			parent_key = key.parent()
		except Registry.RegistryException:
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

			parent_key_id = None
		else:
			if parent_key is not None:
				parent_key_offset = parent_key.cell_relative_offset + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
				if ((not self._is_hive_truncated) and parent_key_offset in self._hive.registry_file.cell_map_referenced) or \
					(self._is_hive_truncated and parent_key_offset in self._hive.registry_file.cell_map_allocated):
					parent_key_status = 0
				else:
					parent_key_status = 1

				invalid_parent_key = False
				if parent_key_status: # Validate a deleted parent key.
					try:
						RegistryRecover.ValidateKey(parent_key)
					except (Registry.RegistryException, UnicodeDecodeError, ValueError, OverflowError):
						invalid_parent_key = True

				if not invalid_parent_key:
					parent_key_id = self._db_key_to_id(parent_key, parent_key_status)
				else:
					parent_key_id = None

				if parent_key_id is not None and parent_key_id == key_id: # Invalid parent key.
					parent_key_id = None
			else:
				# This is the root key.
				parent_key_id = None
				if not self._root_found:
					self._root_found = True
					self.db_cursor.execute('UPDATE `hive` SET `root_key_id` = ? WHERE `id` = ?', (key_id, 0))
				else:
					# Two or more keys are marked as root, do not trust them.
					self.db_cursor.execute('UPDATE `hive` SET `root_key_id` = ? WHERE `id` = ?', (None, 0))

		self.db_cursor.execute('INSERT OR IGNORE INTO `keys` (`id`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id`, `security_rowid`, `hive_path`, `hive_generation`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			(key_id, is_deleted, name, classname, last_written_timestamp, access_bits, parent_key_id, security_rowid, self._hive_path, self._hive_generation))

		try:
			for value in key.values():
				if is_deleted and self._db_is_reallocated_value(value):
					continue

				self._db_add_value(value, key_id, is_deleted)
		except (Registry.RegistryException, UnicodeDecodeError):
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

		try:
			for value in key.remnant_values():
				if self._db_is_reallocated_value(value):
					continue

				self._db_add_value(value, key_id, 1)
		except (Registry.RegistryException, UnicodeDecodeError):
			pass

	def _db_add_value(self, value, parent_key_id, is_deleted = 0):
		"""Add a value to the database."""

		value_id = self._db_value_to_id(value, is_deleted)

		name = value.name()
		type_raw = value.type_raw()
		try:
			data_raw = value.data_raw()
		except Registry.RegistryException:
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

			data_raw = None

		if is_deleted and self._db_is_reallocated_value_data(value):
			data_raw = None

		self.db_cursor.execute('INSERT OR IGNORE INTO `values` (`id`, `is_deleted`, `name`, `type`, `data`, `parent_key_id`, `hive_path`, `hive_generation`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			(value_id, is_deleted, name, type_raw, data_raw, parent_key_id, self._hive_path, self._hive_generation))

	def _db_process_deleted_data(self):
		"""Add deleted keys and values from a normal hive or a truncated one to the database."""

		scanner = RegistryRecover.Scanner(self._hive)
		for item in scanner.scan():
			if type(item) is Registry.RegistryKey:
				self._db_add_key(item, 1)
			elif type(item) is Registry.RegistryValue:
				self._db_add_value(item, None, 1)

	def _db_process_partial_data(self):
		"""Add allocated keys and values from a truncated hive to the database."""

		for item in self._hive.scan():
			if type(item) is Registry.RegistryKey:
				self._db_add_key(item)
			elif type(item) is Registry.RegistryValue:
				self._db_add_value(item, None)

	def _db_process_data(self):
		"""Add allocated and referenced keys and values from a normal hive to the database."""

		def process_key(key):
			self._db_add_key(key)

			for subkey in key.subkeys():
				process_key(subkey)

		process_key(self._hive.root_key())

	def get_rowid(self, key_id):
		"""Convert a key ID to a row ID."""

		self.db_cursor.execute('SELECT `rowid` FROM `keys` WHERE `id` = ?', (key_id,))
		results = self.db_cursor.fetchall()
		for result in results:
			return result[0]

	def key(self, key_rowid):
		"""Get and return a key by its row ID (or None, if not found)."""

		self.db_cursor.execute('SELECT ' + _KEY_COLUMNS + ' FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		results = self.db_cursor.fetchall()

		for result in results:
			return Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6], hive_path = result[7], hive_generation = result[8])

	def subkeys(self, key_rowid):
		"""Get and yield subkeys of a key with a specific row ID."""

		self.db_cursor.execute('SELECT `id` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		p = self.db_cursor.fetchone()
		if p is not None:
			p = p[0]
			self.db_cursor.execute('SELECT ' + _KEY_COLUMNS + ' FROM `keys` WHERE `parent_key_id` = ? ORDER BY UPPER(`name`) ASC', (p,))
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6], hive_path = result[7], hive_generation = result[8])

	def subkeys_with_name(self, key_rowid, name):
		"""Get and yield subkeys with the given name. This method may yield two or more subkeys if a parent key (specified by its row ID) has deleted subkeys."""

		self.db_cursor.execute('SELECT `id` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		p = self.db_cursor.fetchone()
		if p is not None:
			p = p[0]
			self.db_cursor.execute('SELECT ' + _KEY_COLUMNS + ' FROM `keys` WHERE `parent_key_id` = ? AND UPPER_UNICODE(`name`) = UPPER_UNICODE(?) ORDER BY `is_deleted` ASC', (p, name))
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6], hive_path = result[7], hive_generation = result[8])

	def subkeys_unassociated(self):
		"""Get and yield unassociated (unlinked) subkeys."""

		root_key = self.root_key()
		if root_key is not None:
			p = root_key.rowid

			self.db_cursor.execute('SELECT ' + _KEY_COLUMNS + ' FROM `keys` WHERE `parent_key_id` IS NULL AND `rowid` != ? ORDER BY UPPER(`name`) ASC', (p,))
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6], hive_path = result[7], hive_generation = result[8])
		else:
			self.db_cursor.execute('SELECT ' + _KEY_COLUMNS + ' FROM `keys` WHERE `parent_key_id` IS NULL ORDER BY UPPER(`name`) ASC')
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6], hive_path = result[7], hive_generation = result[8])

	def security_info(self, key_rowid):
		"""Return security information for a key with a specific row ID."""

		self.db_cursor.execute('SELECT `security_rowid` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		security_rowid = self.db_cursor.fetchone()[0]

		owner_sid = None
		if security_rowid is not None:
			self.db_cursor.execute('SELECT `owner_sid` FROM `security` WHERE `rowid` = ?', (security_rowid,))
			owner_sid = self.db_cursor.fetchone()[0]

		return Security(rowid = security_rowid, owner_sid = owner_sid)

	def value(self, value_rowid):
		"""Get and return a value by its row ID (or None, if not found)."""

		self.db_cursor.execute('SELECT ' + _VALUE_COLUMNS + ' FROM `values` WHERE `rowid` = ?', (value_rowid,))
		results = self.db_cursor.fetchall()

		for result in results:
			return Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3], data = result[4], parent_key_id = result[5], hive_path = result[6], hive_generation = result[7])

	def values(self, key_rowid, use_original_order = False):
		"""Get and yield values of a key with a specific row ID."""

		self.db_cursor.execute('SELECT `id` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		p = self.db_cursor.fetchone()
		if p is not None:
			p = p[0]

			if not use_original_order:
				self.db_cursor.execute('SELECT ' + _VALUE_COLUMNS + ' FROM `values` WHERE `parent_key_id` = ? ORDER BY UPPER(`name`) ASC', (p,))
			else:
				self.db_cursor.execute('SELECT ' + _VALUE_COLUMNS + ' FROM `values` WHERE `parent_key_id` = ? ORDER BY UPPER(`id`) ASC', (p,))

			results = self.db_cursor.fetchall()

			for result in results:
				yield Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3], data = result[4], parent_key_id = result[5], hive_path = result[6], hive_generation = result[7])

	def values_unassociated(self):
		"""Get and yield all unassociated values. For normal hives, this will yield all deleted values; for truncated hives, this will yield all values.
		Note: unlike unassociated subkeys, unassociated values may be referenced by existing keys (here, the word 'unassociated' means that values were extracted without parsing keys).
		This method will yield unlinked instances of unassociated values.
		"""

		self.db_cursor.execute('SELECT ' + _VALUE_COLUMNS + ' FROM `values` WHERE `parent_key_id` IS NULL ORDER BY UPPER(`name`) ASC')
		results = self.db_cursor.fetchall()

		for result in results:
			yield Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3], data = result[4], parent_key_id = result[5], hive_path = result[6], hive_generation = result[7])

	def root_key(self):
		"""Get and return a root key (or None, if not found)."""

		self.db_cursor.execute('SELECT `root_key_id` FROM `hive` WHERE `id` = ?', (0,))
		p = self.db_cursor.fetchone()[0]
		if p is None:
			return

		self.db_cursor.execute('SELECT `rowid` FROM `keys` WHERE `id` = ?', (p,))
		p = self.db_cursor.fetchone()
		if p is None:
			return

		p = p[0]
		if p is not None:
			return self.key(p)

	def info(self):
		"""Get and return information about a hive."""

		self.db_cursor.execute('SELECT `last_written_timestamp`, `last_reorganized_timestamp`, `offreg_serialization_timestamp`, `recovered`, `truncated`, `rebuilt` FROM `hive` WHERE `id` = ?', (0,))
		results = self.db_cursor.fetchall()

		for result in results:
			if result[1] is None:
				ts_lr = None
			else:
				ts_lr = int(result[1])

			if result[2] is None:
				ts_offreg = None
			else:
				ts_offreg = int(result[2])

			return HiveInfo(last_written_timestamp = int(result[0]), last_reorganized_timestamp = ts_lr, offreg_serialization_timestamp = ts_offreg, recovered = result[3], truncated = result[4], rebuilt = result[5])


class YarpCompositeDB(object):
	"""A composite sqlite3 database combining two or more registry hives.

	Unlike several YarpDB databases opened separately, this class stores records of all hives in
	one database. Records sharing the same key/value name (and path) in different hives are kept as
	separate rows because each row also carries the source of its record: the hive path and the
	generation (the mount order, starting at 0).

	Single-hive semantics are preserved: within one hive, legitimate duplicate keys (for example,
	a live key and its deleted copy with the same name) remain separate rows. Records rejected while
	processing a hive (reallocated deleted records, unassociated records, and so on) are handled by
	the per-hive converter, and every stored row - read or recovered - carries the same source.
	"""

	schema_hives = ('CREATE TABLE `hives` ('
					'`generation` INTEGER PRIMARY KEY,'
					'`hive_path` TEXT,'
					'`last_written_timestamp` TEXT,'
					'`last_reorganized_timestamp` TEXT,'
					'`offreg_serialization_timestamp` TEXT,'
					'`root_key_rowid` INTEGER,'
					'`recovered` NUMERIC,'
					'`truncated` NUMERIC,'
					'`rebuilt` NUMERIC'
					')')
	"""Schema for the 'hives' table."""

	schema_keys = ('CREATE TABLE `keys` ('
					'`rowid` INTEGER PRIMARY KEY AUTOINCREMENT,'
					'`hive_generation` INTEGER,'
					'`hive_key_id` TEXT,'
					'`is_deleted` NUMERIC,'
					'`name` TEXT,'
					'`classname` TEXT,'
					'`last_written_timestamp` TEXT,'
					'`access_bits` INTEGER,'
					'`parent_key_rowid` INTEGER,'
					'`hive_path` TEXT'
					')')
	"""Schema for the composite 'keys' table. 'hive_key_id' is the key ID within its hive."""

	schema_values = ('CREATE TABLE `values` ('
					'`rowid` INTEGER PRIMARY KEY AUTOINCREMENT,'
					'`hive_generation` INTEGER,'
					'`hive_value_id` INTEGER,'
					'`is_deleted` NUMERIC,'
					'`name` TEXT,'
					'`type` INTEGER,'
					'`data` BLOB,'
					'`parent_key_rowid` INTEGER,'
					'`hive_path` TEXT'
					')')
	"""Schema for the composite 'values' table. 'hive_value_id' is the value ID within its hive."""

	def __init__(self, primary_paths, sqlite_path, no_recovery = False):
		"""Build a composite database at 'sqlite_path' from the hives listed in 'primary_paths'.
		'primary_paths' is a list of paths; the list index is used as the generation.
		When 'no_recovery' is True, transaction log files are not used to recover dirty hives.
		An existing database is cleared first.
		"""

		self._db_connection = sqlite3.connect(sqlite_path, check_same_thread = False)
		self._db_connection.create_function('UPPER_UNICODE', 1, sqlite3_upper_unicode)
		self.db_cursor = self._db_connection.cursor()

		self._db_clear()
		self.db_cursor.execute(self.schema_hives)
		self.db_cursor.execute(self.schema_keys)
		self.db_cursor.execute('CREATE INDEX `keys_idx_name` ON `keys`(`name`)')
		self.db_cursor.execute('CREATE INDEX `keys_idx_parent` ON `keys`(`parent_key_rowid`)')
		self.db_cursor.execute('CREATE INDEX `keys_idx_generation` ON `keys`(`hive_generation`)')
		self.db_cursor.execute(self.schema_values)
		self.db_cursor.execute('CREATE INDEX `values_idx_name` ON `values`(`name`)')
		self.db_cursor.execute('CREATE INDEX `values_idx_parent` ON `values`(`parent_key_rowid`)')
		self.db_cursor.execute('CREATE INDEX `values_idx_generation` ON `values`(`hive_generation`)')

		for generation, primary_path in enumerate(primary_paths):
			self._add_hive(generation, primary_path, no_recovery)

		self._db_connection.commit()

	def _db_clear(self):
		"""Remove the tables and indices."""

		self.db_cursor.execute('DROP TABLE IF EXISTS `hives`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `keys`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `values`')

	def _add_hive(self, generation, primary_path, no_recovery):
		"""Convert one hive into a temporary per-hive database and copy its rows with the source."""

		# A per-hive converter handles recovery, truncated hives and rejected records for us.
		per_hive = YarpDB(primary_path, ':memory:', no_recovery = no_recovery,
			hive_path = primary_path, hive_generation = generation)

		cur = per_hive.db_cursor

		cur.execute('SELECT `last_written_timestamp`, `last_reorganized_timestamp`, `offreg_serialization_timestamp`, `root_key_id`, `recovered`, `truncated`, `rebuilt` FROM `hive` WHERE `id` = ?', (0,))
		hive_row = cur.fetchone()

		# Copy keys and remember the mapping from a per-hive key ID to a composite row ID.
		key_rowid_map = dict()

		cur.execute('SELECT `id`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id`, `hive_path`, `hive_generation` FROM `keys`')
		keys_rows = cur.fetchall()
		# Two passes are required because a parent may be stored after its child.
		for key_row in keys_rows:
			cur_id, is_deleted, name, classname, ts, access_bits, parent_id, hive_path, hive_generation = key_row
			self.db_cursor.execute('INSERT INTO `keys` (`hive_generation`, `hive_key_id`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_rowid`, `hive_path`) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)',
				(generation, cur_id, is_deleted, name, classname, ts, access_bits, hive_path))
			key_rowid_map[cur_id] = self.db_cursor.lastrowid

		for key_row in keys_rows:
			cur_id, is_deleted, name, classname, ts, access_bits, parent_id, hive_path, hive_generation = key_row
			if parent_id is not None and parent_id in key_rowid_map:
				self.db_cursor.execute('UPDATE `keys` SET `parent_key_rowid` = ? WHERE `rowid` = ?',
					(key_rowid_map[parent_id], key_rowid_map[cur_id]))

		cur.execute('SELECT `id`, `is_deleted`, `name`, `type`, `data`, `parent_key_id`, `hive_path`, `hive_generation` FROM `values`')
		for value_row in cur.fetchall():
			value_id, is_deleted, name, vtype, data, parent_key_id, hive_path, hive_generation = value_row
			parent_rowid = key_rowid_map.get(parent_key_id)
			self.db_cursor.execute('INSERT INTO `values` (`hive_generation`, `hive_value_id`, `is_deleted`, `name`, `type`, `data`, `parent_key_rowid`, `hive_path`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
				(generation, value_id, is_deleted, name, vtype, data, parent_rowid, hive_path))

		root_key_rowid = None
		if hive_row is not None and hive_row[3] is not None:
			root_key_rowid = key_rowid_map.get(hive_row[3])

		self.db_cursor.execute('INSERT INTO `hives` (`generation`, `hive_path`, `last_written_timestamp`, `last_reorganized_timestamp`, `offreg_serialization_timestamp`, `root_key_rowid`, `recovered`, `truncated`, `rebuilt`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
			(generation, primary_path, hive_row[0] if hive_row is not None else None,
				hive_row[1] if hive_row is not None else None,
				hive_row[2] if hive_row is not None else None,
				root_key_rowid,
				hive_row[4] if hive_row is not None else 0,
				hive_row[5] if hive_row is not None else 0,
				hive_row[6] if hive_row is not None else 0))

		per_hive.close()

	def _row_to_key(self, result):
		return Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3],
			last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6],
			hive_path = result[7], hive_generation = result[8])

	def _row_to_value(self, result):
		return Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3],
			data = result[4], parent_key_id = result[5], hive_path = result[6], hive_generation = result[7])

	def hives(self):
		"""Yield HiveInfo-like records with the source (generation and path) for each mounted hive."""

		CompositeHiveInfo = namedtuple('CompositeHiveInfo', HiveInfo._fields + ( 'generation', 'hive_path', 'root_key_rowid' ))

		self.db_cursor.execute('SELECT `generation`, `hive_path`, `last_written_timestamp`, `last_reorganized_timestamp`, `offreg_serialization_timestamp`, `root_key_rowid`, `recovered`, `truncated`, `rebuilt` FROM `hives` ORDER BY `generation` ASC')
		for result in self.db_cursor.fetchall():
			generation, hive_path, ts_lw, ts_lr, ts_offreg, root_rowid, recovered, truncated, rebuilt = result
			yield CompositeHiveInfo(
				last_written_timestamp = int(ts_lw) if ts_lw is not None else None,
				last_reorganized_timestamp = int(ts_lr) if ts_lr is not None else None,
				offreg_serialization_timestamp = int(ts_offreg) if ts_offreg is not None else None,
				recovered = recovered, truncated = truncated, rebuilt = rebuilt,
				generation = generation, hive_path = hive_path, root_key_rowid = root_rowid)

	def root_keys(self):
		"""Yield the root key of every mounted hive, each carrying its source."""

		self.db_cursor.execute('SELECT {} FROM `keys` WHERE `rowid` IN (SELECT `root_key_rowid` FROM `hives` WHERE `root_key_rowid` IS NOT NULL) ORDER BY `hive_generation` ASC'.format(_COMPOSITE_KEY_COLUMNS))
		for result in self.db_cursor.fetchall():
			yield self._row_to_key(result)

	def key(self, key_rowid):
		"""Get and return a key by its composite row ID (or None, if not found)."""

		self.db_cursor.execute('SELECT {} FROM `keys` WHERE `rowid` = ?'.format(_COMPOSITE_KEY_COLUMNS), (key_rowid,))
		result = self.db_cursor.fetchone()
		if result is not None:
			return self._row_to_key(result)

	def subkeys(self, key_rowid):
		"""Yield subkeys of a key with a given composite row ID, ordered by name across all hives."""

		self.db_cursor.execute('SELECT {} FROM `keys` WHERE `parent_key_rowid` = ? ORDER BY UPPER(`name`) ASC, `hive_generation` ASC'.format(_COMPOSITE_KEY_COLUMNS), (key_rowid,))
		for result in self.db_cursor.fetchall():
			yield self._row_to_key(result)

	def subkeys_with_name(self, key_rowid, name):
		"""Yield subkeys with the given name. Same-named keys from different hives (and legitimate
		duplicate keys within one hive) are all returned, each carrying its source."""

		self.db_cursor.execute('SELECT {} FROM `keys` WHERE `parent_key_rowid` = ? AND UPPER_UNICODE(`name`) = UPPER_UNICODE(?) ORDER BY `is_deleted` ASC, `hive_generation` ASC'.format(_COMPOSITE_KEY_COLUMNS), (key_rowid, name))
		for result in self.db_cursor.fetchall():
			yield self._row_to_key(result)

	def keys_with_name(self, name):
		"""Yield every key (in every mounted hive) with the given name, each carrying its source."""

		self.db_cursor.execute('SELECT {} FROM `keys` WHERE UPPER_UNICODE(`name`) = UPPER_UNICODE(?) ORDER BY `hive_generation` ASC, `is_deleted` ASC'.format(_COMPOSITE_KEY_COLUMNS), (name,))
		for result in self.db_cursor.fetchall():
			yield self._row_to_key(result)

	def subkeys_unassociated(self):
		"""Yield unassociated (unlinked) keys of every mounted hive, each carrying its source."""

		self.db_cursor.execute('SELECT {} FROM `keys` k WHERE k.`parent_key_rowid` IS NULL AND k.`rowid` != (SELECT `root_key_rowid` FROM `hives` h WHERE h.`generation` = k.`hive_generation`) ORDER BY UPPER(k.`name`) ASC, k.`hive_generation` ASC'.format(_COMPOSITE_KEY_COLUMNS))
		for result in self.db_cursor.fetchall():
			yield self._row_to_key(result)

	def value(self, value_rowid):
		"""Get and return a value by its composite row ID (or None, if not found)."""

		self.db_cursor.execute('SELECT {} FROM `values` WHERE `rowid` = ?'.format(_COMPOSITE_VALUE_COLUMNS), (value_rowid,))
		result = self.db_cursor.fetchone()
		if result is not None:
			return self._row_to_value(result)

	def values(self, key_rowid, use_original_order = False):
		"""Yield values of a key with a given composite row ID."""

		if not use_original_order:
			query = 'SELECT {} FROM `values` WHERE `parent_key_rowid` = ? ORDER BY UPPER(`name`) ASC, `hive_generation` ASC'.format(_COMPOSITE_VALUE_COLUMNS)
		else:
			query = 'SELECT {} FROM `values` WHERE `parent_key_rowid` = ? ORDER BY `hive_value_id` ASC'.format(_COMPOSITE_VALUE_COLUMNS)

		self.db_cursor.execute(query, (key_rowid,))
		for result in self.db_cursor.fetchall():
			yield self._row_to_value(result)

	def values_with_name(self, name):
		"""Yield every value (in every mounted hive) with the given name, each carrying its source."""

		self.db_cursor.execute('SELECT {} FROM `values` WHERE UPPER_UNICODE(`name`) = UPPER_UNICODE(?) ORDER BY `hive_generation` ASC, `is_deleted` ASC'.format(_COMPOSITE_VALUE_COLUMNS), (name,))
		for result in self.db_cursor.fetchall():
			yield self._row_to_value(result)

	def values_unassociated(self):
		"""Yield unassociated values of every mounted hive, each carrying its source."""

		self.db_cursor.execute('SELECT {} FROM `values` WHERE `parent_key_rowid` IS NULL ORDER BY UPPER(`name`) ASC, `hive_generation` ASC'.format(_COMPOSITE_VALUE_COLUMNS))
		for result in self.db_cursor.fetchall():
			yield self._row_to_value(result)

	def close(self):
		"""Commit and close the database."""

		self._db_connection.commit()
		self._db_connection.close()

	def __enter__(self):
		return self

	def __exit__(self, *args):
		self.close()
