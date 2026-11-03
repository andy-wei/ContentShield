"""数据集溯源与扫描器测试：哈希、版本对比、数据读取。"""

from __future__ import annotations

import json

import pytest

from app.training.provenance import (
    compute_dataset_fingerprint,
    compute_record_hash,
    diff_datasets,
)

# ==================== 哈希计算 ====================


class TestRecordHash:
    def test_deterministic(self):
        assert compute_record_hash("hello") == compute_record_hash("hello")

    def test_different_text_different_hash(self):
        assert compute_record_hash("hello") != compute_record_hash("world")

    def test_is_32_chars(self):
        assert len(compute_record_hash("x")) == 32

    def test_unicode(self):
        h = compute_record_hash("中文样本")
        assert len(h) == 32

    def test_empty_string(self):
        h = compute_record_hash("")
        assert len(h) == 32


class TestDatasetFingerprint:
    def test_same_records_same_fingerprint(self):
        records = ["a", "b", "c"]
        assert compute_dataset_fingerprint(records) == compute_dataset_fingerprint(records)

    def test_order_independent(self):
        """指纹与顺序无关（排序后再哈希）。"""
        fp1 = compute_dataset_fingerprint(["a", "b", "c"])
        fp2 = compute_dataset_fingerprint(["c", "b", "a"])
        assert fp1 == fp2

    def test_different_records_different_fingerprint(self):
        fp1 = compute_dataset_fingerprint(["a", "b"])
        fp2 = compute_dataset_fingerprint(["a", "x"])
        assert fp1 != fp2

    def test_empty_returns_empty(self):
        assert compute_dataset_fingerprint([]) == ""

    def test_duplicate_records(self):
        """重复记录应影响指纹。"""
        fp1 = compute_dataset_fingerprint(["a", "b"])
        fp2 = compute_dataset_fingerprint(["a", "a", "b"])
        assert fp1 != fp2


# ==================== 版本对比 ====================


class TestDiffDatasets:
    def test_added_records(self):
        old = ["a", "b"]
        new = ["a", "b", "c", "d"]
        diff = diff_datasets(old, new)
        assert diff["added_count"] == 2
        assert diff["removed_count"] == 0
        assert diff["unchanged_count"] == 2

    def test_removed_records(self):
        old = ["a", "b", "c"]
        new = ["a"]
        diff = diff_datasets(old, new)
        assert diff["added_count"] == 0
        assert diff["removed_count"] == 2
        assert diff["unchanged_count"] == 1

    def test_modified_records(self):
        """修改 = 删除旧的 + 新增新的。"""
        old = ["original text"]
        new = ["modified text"]
        diff = diff_datasets(old, new)
        assert diff["added_count"] == 1
        assert diff["removed_count"] == 1
        assert diff["unchanged_count"] == 0

    def test_identical_datasets(self):
        records = ["a", "b", "c"]
        diff = diff_datasets(records, records)
        assert diff["added_count"] == 0
        assert diff["removed_count"] == 0
        assert diff["unchanged_count"] == 3

    def test_empty_datasets(self):
        diff = diff_datasets([], [])
        assert diff["added_count"] == 0
        assert diff["removed_count"] == 0

    def test_from_empty(self):
        diff = diff_datasets([], ["a", "b"])
        assert diff["added_count"] == 2
        assert diff["removed_count"] == 0

    def test_hashes_are_strings(self):
        diff = diff_datasets(["a"], ["b"])
        assert all(isinstance(h, str) for h in diff["added"])
        assert all(isinstance(h, str) for h in diff["removed"])
        assert all(isinstance(h, str) for h in diff["unchanged"])


# ==================== 数据集读取 ====================


class TestReadRecords:
    def test_read_jsonl_text_field(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.jsonl"
        f.write_text('{"text": "hello"}\n{"text": "world"}\n', encoding="utf-8")
        records = read_records(str(f), "jsonl")
        assert records == ["hello", "world"]

    def test_read_jsonl_content_field(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.jsonl"
        f.write_text('{"content": "msg1"}\n{"content": "msg2"}\n', encoding="utf-8")
        records = read_records(str(f), "jsonl")
        assert records == ["msg1", "msg2"]

    def test_read_jsonl_messages_field(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.jsonl"
        f.write_text(
            json.dumps(
                {
                    "messages": [
                        {"role": "user", "content": "hi"},
                        {"role": "assistant", "content": "hello"},
                    ]
                }
            )
            + "\n",
            encoding="utf-8",
        )
        records = read_records(str(f), "jsonl")
        assert "hi" in records[0]
        assert "hello" in records[0]

    def test_read_jsonl_prompt_completion(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.jsonl"
        f.write_text('{"prompt": "Q?", "completion": "A."}\n', encoding="utf-8")
        records = read_records(str(f), "jsonl")
        assert "Q?" in records[0]
        assert "A." in records[0]

    def test_read_jsonl_invalid_line_fallback(self, tmp_path):
        """非 JSON 行应整行作为文本。"""
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.jsonl"
        f.write_text('{"text": "valid"}\nnot json line\n', encoding="utf-8")
        records = read_records(str(f), "jsonl")
        assert "valid" in records
        assert "not json line" in records

    def test_read_csv(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.csv"
        f.write_text("text,label\nhello,1\nworld,2\n", encoding="utf-8")
        records = read_records(str(f), "csv")
        assert records == ["hello", "world"]

    def test_read_txt(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.txt"
        f.write_text("line one\nline two\nline three\n", encoding="utf-8")
        records = read_records(str(f), "txt")
        assert records == ["line one", "line two", "line three"]

    def test_skip_empty_lines(self, tmp_path):
        from app.training.dataset_scanner import read_records

        f = tmp_path / "data.txt"
        f.write_text("a\n\n\nb\n", encoding="utf-8")
        records = read_records(str(f), "txt")
        assert records == ["a", "b"]

    def test_file_not_found(self):
        from app.training.dataset_scanner import read_records

        with pytest.raises(FileNotFoundError):
            read_records("/nonexistent/path", "jsonl")

    def test_unsupported_format(self, tmp_path):
        from app.training.dataset_scanner import read_records

        with pytest.raises(ValueError, match="不支持"):
            read_records(str(tmp_path / "x.xml"), "xml")
