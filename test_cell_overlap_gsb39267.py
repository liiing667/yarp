# coding: utf-8

import os

import pytest

from yarp.RegistryFile import (
	CellOverlapError,
	PrimaryFile,
	PublicCellReader,
	SourceRecord,
)


def test_public_cell_reader_rejects_overlap_and_keeps_one_source_record():
	record = SourceRecord(source_id = 'source-39267')
	reader = PublicCellReader(b'x' * 128, source_record = record)

	first = reader.read_cell(32, 64, 'parent-a')
	assert first.accepted
	assert first.source_record is record

	with pytest.raises(CellOverlapError) as exc_info:
		reader.read_cell(48, 64, 'parent-b')

	assert exc_info.value.source_record is record
	assert exc_info.value.rejected_result.source_record is record

	rejected = reader.read_cell(48, 64, 'parent-b', raise_on_overlap = False)
	assert rejected.rejected
	assert rejected.source_record is record
	assert reader.rejections[-1].source_record is record


def test_same_parent_duplicate_and_deleted_gap_are_preserved():
	reader = PublicCellReader(b'x' * 128)

	first = reader.read_cell(16, 64, 'parent')
	duplicate = reader.read_cell(16, 64, 'parent')
	gap = reader.read_cell(48, 8, 'deleted-owner', deleted = True)

	assert first.accepted and duplicate.accepted
	assert gap.accepted and gap.status == 'deleted'

	with pytest.raises(CellOverlapError):
		reader.read_cell(24, 16, 'parent')

	legitimate = reader.read_cell(24, 8, 'parent', legitimate = True)
	assert legitimate.accepted


def test_primary_file_reads_carry_the_hive_source_record():
	hive_path = os.path.join(os.path.dirname(__file__), 'hives_for_tests', 'EmptyHive')
	with open(hive_path, 'rb') as handle:
		primary = PrimaryFile(handle)
		root_cell = primary.get_root_cell()

	assert primary.source_record is primary.cell_reader.source_record
	assert root_cell.source_record is primary.source_record
