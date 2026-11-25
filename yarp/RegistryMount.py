# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements a high-level interface to mount (combine) two or more registry hives.
# When hives are mounted together, keys and values sharing the same name (and path) are kept as
# separate records and each record carries a source reference (the hive path and its generation),
# so query results can always be attributed to the original file.

from __future__ import unicode_literals, division

from collections import namedtuple
import os

from . import Registry, RegistryFile, RegistryHelpers

# A source record shared by every record (both readable and rejected ones) coming from a hive.
HiveSource = namedtuple('HiveSource', [ 'generation', 'path', 'hive' ])


class MountException(Registry.RegistryException):
	"""This exception is raised when a hive cannot be mounted."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)


class MountedHive(object):
	"""A registry hive mounted as part of a composite (multi-hive) view.

	The wrapped RegistryHive (or RegistryHiveTruncated) object is available in the 'hive' attribute.
	Every key and value produced by the wrapped hive carries the same HiveSource record in its
	registry_file.hive_source attribute and via its source() method.
	"""

	def __init__(self, hive, source):
		self.hive = hive
		self.source = source

		# Attach the source record to the primary file, so every RegistryKey/RegistryValue
		# built from this hive inherits it automatically (this also covers recovery scanners
		# and truncated hives, whose records are rejected or yielded in the same way).
		if getattr(hive, 'registry_file', None) is not None:
			hive.registry_file.hive_source = source

	@property
	def generation(self):
		return self.source.generation

	@property
	def path(self):
		return self.source.path

	def root_key(self):
		return self.hive.root_key()

	def find_key(self, path):
		return self.hive.find_key(path)

	def __str__(self):
		return 'MountedHive, generation: {}, path: {}'.format(self.source.generation, self.source.path)


class RegistryMount(object):
	"""A composite view of two or more registry hives mounted together.

	Hives are mounted in order; the first mounted hive gets generation 0, the next one gets
	generation 1, and so on. The generation disambiguates records of hives sharing the same path
	(for instance, a hive mounted twice or a path reused after remounting).

	Single-hive semantics are preserved: within one hive, legitimate duplicate keys (such as a live
	key and its deleted copy sharing a name) continue to be returned as separate records.
	"""

	def __init__(self, tolerate_minor_errors = True):
		self.tolerate_minor_errors = tolerate_minor_errors
		self._mounted_hives = []
		self._owned_files = set()

	def mount(self, primary_path_or_file, no_recovery = False):
		"""Mount a registry hive and return its MountedHive object.

	'primary_path_or_file' is either a path to a primary file or an open binary file object.
	When 'no_recovery' is True, transaction log files are not used to recover a dirty hive.
	"""

		generation = len(self._mounted_hives)

		owns_file = False
		if hasattr(primary_path_or_file, 'read'):
			primary_path = getattr(primary_path_or_file, 'name', None)
			file_object = primary_path_or_file
		else:
			primary_path = primary_path_or_file
			if not os.path.isfile(primary_path):
				raise MountException('Primary file does not exist: {}'.format(primary_path))

			file_object = open(primary_path, 'rb')
			owns_file = True
			self._owned_files.add(file_object)

		source = HiveSource(generation = generation, path = primary_path, hive = None)

		log = log1 = log2 = None
		log_objects = []
		if primary_path is not None and os.path.isfile(str(primary_path)):
			log_files = RegistryHelpers.DiscoverLogFiles(str(primary_path))
			if log_files.log_path is not None:
				log = open(log_files.log_path, 'rb')
				log_objects.append(log)
			if log_files.log1_path is not None:
				log1 = open(log_files.log1_path, 'rb')
				log_objects.append(log1)
			if log_files.log2_path is not None:
				log2 = open(log_files.log2_path, 'rb')
				log_objects.append(log2)

		try:
			hive = Registry.RegistryHive(file_object, self.tolerate_minor_errors)
		except RegistryFile.NotSupportedException:
			raise
		except (RegistryFile.BaseBlockException, Registry.RegistryException):
			if not owns_file:
				raise

			# This may be a truncated primary file or a registry fragment; try both fallbacks.
			temp_obj = file_object
			try:
				file_object = RegistryFile.FragmentTranslator(temp_obj)
			except RegistryFile.RegistryException:
				# Treat the file as a truncated primary file.
				file_object = temp_obj
			else:
				temp_obj.close()
				self._owned_files.discard(temp_obj)
				self._owned_files.add(file_object)

			hive = Registry.RegistryHiveTruncated(file_object)

		source = HiveSource(generation = generation, path = primary_path, hive = hive)
		mounted = MountedHive(hive, source)

		recovered = False
		if (not no_recovery) and isinstance(hive, Registry.RegistryHive):
			try:
				recovery_result = hive.recover_auto(log, log1, log2)
			except Registry.AutoRecoveryException:
				pass
			else:
				recovered = recovery_result.recovered

		mounted.recovered = recovered
		mounted.log_objects = log_objects

		self._mounted_hives.append(mounted)
		return mounted

	def hives(self):
		"""Yield the MountedHive objects in mount order (generation order)."""

		for mounted in self._mounted_hives:
			yield mounted

	def sources(self):
		"""Yield the HiveSource records of all mounted hives in generation order."""

		for mounted in self._mounted_hives:
			yield mounted.source

	def generations(self):
		"""Return the list of generations of mounted hives."""

		return [ mounted.generation for mounted in self._mounted_hives ]

	def source_of(self, generation):
		"""Return the HiveSource record for a given generation (or None, if no such hive is mounted)."""

		for mounted in self._mounted_hives:
			if mounted.generation == generation:
				return mounted.source

	def root_keys(self):
		"""Yield the root RegistryKey object of every mounted normal hive, each carrying its source.
		Truncated hives and registry fragments do not expose a root key and contribute nothing here;
		use the scan() method of their hive object to enumerate their records (with sources).
		"""

		for mounted in self._mounted_hives:
			if isinstance(mounted.hive, Registry.RegistryHive):
				yield mounted.hive.root_key()

	def find_key(self, path):
		"""Yield RegistryKey objects matching 'path' in every mounted hive.

		Each yielded key comes from a distinct hive and carries the source record of that hive.
		Hives without the key simply contribute nothing, so results never lose their origin.
		"""

		for mounted in self._mounted_hives:
			if not isinstance(mounted.hive, Registry.RegistryHive):
				continue # Truncated hives and fragments do not support path lookups.

			key = mounted.hive.find_key(path)
			if key is not None:
				yield key

	def find_subkeys(self, path, name):
		"""Yield RegistryKey objects: subkeys named 'name' under the key at 'path' in each hive.

		Legitimate duplicate subkeys within a single hive (live and deleted copies) are preserved.
		"""

		for mounted in self._mounted_hives:
			if not isinstance(mounted.hive, Registry.RegistryHive):
				continue

			parent = mounted.hive.find_key(path)
			if parent is None:
				continue

			name_upper = name.upper()
			for subkey in parent.subkeys():
				if subkey.name().upper() == name_upper:
					yield subkey

	def find_values(self, path, name = ''):
		"""Yield RegistryValue objects named 'name' of the key at 'path' in each mounted hive."""

		for mounted in self._mounted_hives:
			if not isinstance(mounted.hive, Registry.RegistryHive):
				continue

			key = mounted.hive.find_key(path)
			if key is None:
				continue

			name_upper = name.upper()
			for value in key.values():
				if value.name().upper() == name_upper:
					yield value

	def walk_everywhere(self):
		"""Run walk_everywhere() on every mounted normal hive (truncated hives are skipped)."""

		for mounted in self._mounted_hives:
			if isinstance(mounted.hive, Registry.RegistryHive):
				mounted.hive.walk_everywhere()

	def close(self):
		"""Close the primary and log file objects opened while mounting hives."""

		for file_object in self._owned_files:
			try:
				file_object.close()
			except (IOError, OSError, ValueError):
				pass

		self._owned_files.clear()

		for mounted in self._mounted_hives:
			for log_object in getattr(mounted, 'log_objects', []):
				try:
					log_object.close()
				except (IOError, OSError, ValueError):
					pass

	def __enter__(self):
		return self

	def __exit__(self, *args):
		self.close()

	def __len__(self):
		return len(self._mounted_hives)
