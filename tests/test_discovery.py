"""Tests for file discovery logic."""

from pathlib import Path

from prom_alert_linter.discovery import resolve_paths

def test_resolve_paths_files(tmp_path: Path):
    f1 = tmp_path / "1.yaml"
    f2 = tmp_path / "2.yml"
    f1.write_text("")
    f2.write_text("")
    
    paths = resolve_paths([f1, f2])
    assert len(paths) == 2
    assert f1 in paths
    assert f2 in paths

def test_resolve_paths_dirs(tmp_path: Path):
    (tmp_path / "1.yaml").write_text("")
    (tmp_path / "2.txt").write_text("")
    
    paths = resolve_paths([tmp_path])
    assert len(paths) == 1
    assert "1.yaml" in str(paths[0])

def test_resolve_paths_recursive(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "3.yml").write_text("")
    
    paths = resolve_paths([tmp_path], recursive=True)
    assert len(paths) == 1
    assert "3.yml" in str(paths[0])

def test_deduplicates(tmp_path: Path):
    f1 = tmp_path / "1.yaml"
    f1.write_text("")
    
    paths = resolve_paths([f1, tmp_path])
    assert len(paths) == 1
