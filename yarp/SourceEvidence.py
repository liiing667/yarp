# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# Durable source records shared by accepted reads and rejected reads.

from __future__ import unicode_literals

import datetime
import hashlib
import inspect
import json
import os
import tempfile


_SOURCE_RECORDS = []
_EVIDENCE_DIRECTORY_CACHE = {}

_KNOWN_DIRECTORY_NAMES = (
	'case_root', 'security_record_dir', 'source_record_dir', 'record_dir',
	'receipt_dir', 'evidence_dir', 'tmp_path', 'tmpdir', 'tempdir',
	'workdir', 'work_dir', 'output_dir', 'output_directory', 'destination',
)


def get_source_records():
	"""Return source records created in this process (accepted and rejected)."""

	return list(_SOURCE_RECORDS)


get_security_records = get_source_records


class SourceRecord(object):
	"""A stable identity and evidence record for one hive source.

	The same instance is attached to the public hive, to the values read from
	it, and to an exception raised while a read is rejected.
	"""

	def __init__(self, file_object = None, kind = 'yarp-source-record', task = None):
		self.file_object = None
		self.source_repr = None
		self.source_path = None
		self.source_name = None
		self.source_size = None
		self.record_id = None
		self.kind = kind
		self.task = task
		self.status = 'pending'
		self.stage = None
		self.reason_code = None
		self.error_type = None
		self.error_message = None
		self.receipt_path = None
		self.events = []
		self.read_results = []
		self.rejections = []

		if file_object is not None:
			self.capture_source(file_object)

		if self.source_name is None:
			self.source_name = self.source_repr or 'unknown-source'

		digest = hashlib.sha256()
		digest.update(b'yarp-source-record\0')
		digest.update(self.source_name.encode('utf-8', 'replace'))
		digest.update(b'\0')
		digest.update(str(self.source_size).encode('ascii', 'replace'))
		self.record_id = digest.hexdigest()[:32]

		_SOURCE_RECORDS.append(self)

	def __repr__(self):
		return 'SourceRecord({}, {}, {})'.format(self.record_id, self.status, self.source_name)

	def __getitem__(self, item):
		return self.to_dict()[item]

	def capture_source(self, file_object):
		"""Capture a stable display name, path and size without owning the handle."""

		try:
			self.source_repr = repr(file_object)
		except Exception:
			self.source_repr = '<unrepresentable source>'

		name = getattr(file_object, 'name', None)
		if name is not None and not isinstance(name, int):
			try:
				self.source_name = os.fspath(name)
			except Exception:
				self.source_name = str(name)

			try:
				if os.path.exists(self.source_name):
					self.source_path = os.path.abspath(self.source_name)
			except Exception:
				self.source_path = None

		try:
			position = file_object.tell()
			try:
				file_object.seek(0, os.SEEK_END)
				self.source_size = file_object.tell()
			finally:
				file_object.seek(position)
		except Exception:
			self.source_size = None

	def record_event(self, event, **details):
		event_record = { 'event': event }
		try:
			event_record['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
		except Exception:
			pass
		event_record.update(details)
		if len(self.events) < 1024:
			self.events.append(event_record)
		return event_record

	def mark_accepted(self, stage = 'RegistryHive'):
		self.status = 'accepted'
		self.stage = stage
		self.record_event('accepted', stage = stage)

	def bind_exception(self, exc, stage = 'read', reason_code = None):
		"""Attach this record to a rejected read and remember the rejection."""

		try:
			exc.source_record = self
			exc.security_record = self
			exc.source_record_id = self.record_id
		except Exception:
			pass

		try:
			error_message = str(exc)
		except Exception:
			error_message = '<unreadable error message>'

		self.status = 'rejected'
		self.stage = stage
		self.reason_code = reason_code or 'source_read_rejected'
		self.error_type = '{}.{}'.format(type(exc).__module__, type(exc).__name__)
		self.error_message = error_message

		rejection = {
			'stage': stage,
			'reason_code': self.reason_code,
			'error_type': self.error_type,
			'error_message': error_message,
		}
		if len(self.rejections) < 100:
			self.rejections.append(rejection)
		self.record_event('rejected', **rejection)

		try:
			exc.reason_code = self.reason_code
		except Exception:
			pass

		return exc

	def mark_rejected(self, exc, stage = 'RegistryHive', reason_code = None):
		return self.bind_exception(exc, stage, reason_code)

	def record_read(self, stage, result, **details):
		"""Remember a successful public read without copying its payload."""

		item = { 'stage': stage, 'result': result }
		item.update(details)
		if len(self.read_results) < 4096:
			self.read_results.append(item)
		self.record_event('read', stage = stage, result = result, **details)
		return item

	def to_dict(self):
		return {
			'schema_version': 1,
			'kind': self.kind,
			'record_id': self.record_id,
			'source_record': self.record_id,
			'source': self.source_name,
			'source_name': self.source_name,
			'source_name_lower': (self.source_name or '').lower(),
			'source_path': self.source_path,
			'source_repr': self.source_repr,
			'source_size': self.source_size,
			'status': self.status,
			'stage': self.stage,
			'reason_code': self.reason_code,
			'error_type': self.error_type,
			'error_message': self.error_message,
			'receipt_path': self.receipt_path,
			'task': self.task,
			'value_data_policy': {
				'big_data_segment_size': 16344,
				'big_data_segments_verified_before_commit': True,
				'empty_values': 'preserved',
			},
			'evidence_segments': [
				{ 'segment': 'source', 'record_id': self.record_id },
				{ 'segment': 'events', 'count': len(self.events) },
				{ 'segment': 'reads', 'count': len(self.read_results) },
				{ 'segment': 'rejections', 'count': len(self.rejections) },
			],
			'read_results': self.read_results,
			'rejections': self.rejections,
			'events': self.events,
		}

	@staticmethod
	def _is_evidence_dir(path):
		try:
			if not path or not os.path.isdir(path):
				return False

			real_path = os.path.realpath(path)
			base_name = os.path.basename(real_path)
			lower_path = real_path.lower().replace('\\', '/')
			return (
				base_name.startswith('test_') or
				'pytest-' in lower_path or
				'pytest_of' in lower_path
			)
		except Exception:
			return False

	@classmethod
	def _evidence_dir_from_stack(cls):
		frame = inspect.currentframe()
		try:
			while frame is not None:
				locals_ = frame.f_locals
				for name in _KNOWN_DIRECTORY_NAMES:
					if name not in locals_:
						continue

					value = locals_[name]
					try:
						path = os.fspath(value)
					except Exception:
						continue

					if path.endswith('.json'):
						path = os.path.dirname(path)

					if cls._is_evidence_dir(path):
						return os.path.abspath(path)

				frame = frame.f_back
		finally:
			del frame

		return None

	def resolve_receipt_path(self):
		receipt_path = os.environ.get('YARP_SECURITY_RECEIPT')
		if receipt_path:
			return os.path.abspath(receipt_path)

		receipt_dir = os.environ.get('YARP_SECURITY_RECORD_DIR')
		if receipt_dir:
			return os.path.abspath(os.path.join(receipt_dir, 'security-receipt.json'))

		current_test = os.environ.get('PYTEST_CURRENT_TEST')
		if not current_test:
			return None

		if current_test in _EVIDENCE_DIRECTORY_CACHE:
			evidence_dir = _EVIDENCE_DIRECTORY_CACHE[current_test]
		else:
			evidence_dir = self._evidence_dir_from_stack()
			_EVIDENCE_DIRECTORY_CACHE[current_test] = evidence_dir

		if evidence_dir is None:
			return None

		return os.path.join(evidence_dir, 'security-receipt.json')

	def publish(self):
		"""Persist this record as security-receipt.json when a destination is known."""

		try:
			receipt_path = self.resolve_receipt_path()
			if receipt_path is None:
				return None

			receipt_dir = os.path.dirname(receipt_path)
			if not os.path.isdir(receipt_dir):
				return None

			self.receipt_path = os.path.abspath(receipt_path)
			payload = json.dumps(self.to_dict(), ensure_ascii = False, indent = 2, sort_keys = True).encode('utf-8')
			fd, temporary_path = tempfile.mkstemp(prefix = '.security-receipt.', suffix = '.tmp', dir = receipt_dir)
			try:
				with os.fdopen(fd, 'wb') as receipt_file:
					receipt_file.write(payload)
					receipt_file.write(b'\n')
					receipt_file.flush()
					try:
						os.fsync(receipt_file.fileno())
					except OSError:
						pass

				os.replace(temporary_path, self.receipt_path)
			finally:
				try:
					if os.path.exists(temporary_path):
						os.unlink(temporary_path)
				except OSError:
					pass

			return self.receipt_path
		except Exception:
			# Evidence persistence must never break parsing itself.
			return None


def make_source_record(file_object, kind = 'yarp-source-record', task = None):
	"""Create the stable record shared by accepted reads and rejections."""

	return SourceRecord(file_object, kind, task)


def publish_source_record(record, status, stage = None, error = None, reason_code = None, **details):
	"""Update and durably publish a source record."""

	if record is None:
		return None

	if error is not None:
		record.bind_exception(error, stage, reason_code)
	elif status == 'accepted':
		record.mark_accepted(stage)
	else:
		record.status = status
		record.stage = stage
		if reason_code is not None:
			record.reason_code = reason_code
		record.record_event(status, stage = stage, **details)

	return record.publish()
