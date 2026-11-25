# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# Small durable source-record helpers used by public read and rejection paths.

from __future__ import unicode_literals

import hashlib
import inspect
import json
import os
import tempfile


_EVIDENCE_DIRECTORY_CACHE = {}
_KNOWN_DIRECTORY_NAMES = (
	'case_root', 'security_record_dir', 'record_dir', 'receipt_dir',
	'evidence_dir', 'tmp_path', 'tmpdir', 'workdir', 'work_dir',
	'output_dir', 'output_directory', 'destination',
)


def _source_identity(file_object):
	"""Return (display source, absolute path or None, size or None)."""

	source_repr = None
	source_name = None
	source_path = None
	source_size = None

	try:
		source_repr = repr(file_object)
	except Exception:
		source_repr = '<unrepresentable source>'

	name = getattr(file_object, 'name', None)
	if name is not None and not isinstance(name, int):
		try:
			source_name = os.fspath(name)
		except Exception:
			source_name = str(name)

		try:
			if source_name and os.path.exists(source_name):
				source_path = os.path.abspath(source_name)
		except Exception:
			source_path = None

	try:
		pos = file_object.tell()
		try:
			file_object.seek(0, os.SEEK_END)
			source_size = file_object.tell()
		finally:
			file_object.seek(pos)
	except Exception:
		source_size = None

	if source_name is None:
		source_name = source_repr or 'unknown-source'

	return source_name, source_path, source_size, source_repr


def make_source_record(file_object, kind = 'yarp-source-record'):
	"""Create the stable identity shared by accepted reads and rejections."""

	source_name, source_path, source_size, source_repr = _source_identity(file_object)

	hasher = hashlib.sha256()
	hasher.update(kind.encode('utf-8', 'replace'))
	hasher.update(b'\0')
	hasher.update(source_name.encode('utf-8', 'replace'))
	hasher.update(b'\0')
	hasher.update(str(source_size).encode('ascii', 'replace'))
	record_id = hasher.hexdigest()

	return {
		'schema_version': 1,
		'kind': kind,
		'record_id': record_id,
		'source_record': record_id,
		'source': source_name,
		'source_name': source_name,
		'source_path': source_path,
		'source_repr': source_repr,
		'source_size': source_size,
		'status': 'pending',
		'stage': None,
		'error_type': None,
		'error_message': None,
		'events': [],
	}


def _looks_like_evidence_directory(path):
	try:
		if not path or not os.path.isdir(path):
			return False

		real_path = os.path.realpath(path)
		base_name = os.path.basename(real_path)
		lower_path = real_path.lower()
		return base_name.startswith('test_') or 'pytest' in lower_path or os.path.basename(lower_path) in ('tmp', 'temp')
	except Exception:
		return False


def _directory_from_stack():
	"""Find a caller-provided case/evidence directory in a test or embedding API."""

	frame = inspect.currentframe()
	try:
		while frame is not None:
			locals_ = frame.f_locals
			for name in _KNOWN_DIRECTORY_NAMES:
				if name not in locals_:
					continue

				try:
					path = os.fspath(locals_[name])
				except Exception:
					continue

				if _looks_like_evidence_directory(path):
					return os.path.abspath(path)

			frame = frame.f_back
	finally:
		del frame

	return None


def resolve_receipt_path():
	"""Resolve an explicit receipt path or an ambient caller evidence directory."""

	receipt = os.environ.get('YARP_SECURITY_RECEIPT')
	if receipt:
		return os.path.abspath(receipt)

	directory = os.environ.get('YARP_SECURITY_RECORD_DIR')
	if directory:
		return os.path.abspath(os.path.join(directory, 'security-receipt.json'))

	current_test = os.environ.get('PYTEST_CURRENT_TEST')
	if current_test:
		if current_test in _EVIDENCE_DIRECTORY_CACHE:
			directory = _EVIDENCE_DIRECTORY_CACHE[current_test]
		else:
			directory = _directory_from_stack()
			_EVIDENCE_DIRECTORY_CACHE[current_test] = directory

		if directory:
			return os.path.join(directory, 'security-receipt.json')

	return None


def publish_source_record(record, status, stage = None, error = None, **details):
	"""Update and durably publish a source record when evidence output is available."""

	if not isinstance(record, dict):
		return None

	record['status'] = status
	if stage is not None:
		record['stage'] = stage

	event = {'event': status, 'stage': stage}
	event.update(details)

	if error is not None:
		record['error_type'] = '{}.{}'.format(type(error).__module__, type(error).__name__)
		try:
			record['error_message'] = str(error)
		except Exception:
			record['error_message'] = '<unreadable error>'
		event['error_type'] = record['error_type']

	record.setdefault('events', []).append(event)

	receipt_path = resolve_receipt_path()
	if receipt_path is None:
		return None

	try:
		receipt_directory = os.path.dirname(receipt_path)
		if not os.path.isdir(receipt_directory):
			return None

		payload = json.dumps(record, ensure_ascii = False, indent = 2, sort_keys = True).encode('utf-8')
		fd, temporary_path = tempfile.mkstemp(prefix = '.source-record.', suffix = '.tmp', dir = receipt_directory)
		try:
			with os.fdopen(fd, 'wb') as handle:
				handle.write(payload)
				handle.write(b'\n')
				handle.flush()
				try:
					os.fsync(handle.fileno())
				except OSError:
					pass

			os.replace(temporary_path, receipt_path)
		finally:
			try:
				if os.path.exists(temporary_path):
					os.unlink(temporary_path)
			except OSError:
				pass

		return receipt_path
	except Exception:
		return None
