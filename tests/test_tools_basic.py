from sentinel_agent.tools.grep_scanner import GrepScannerTool
from sentinel_agent.tools.repo_mapper import RepoMapperTool


def test_grep_scanner_finds_patterns_in_sample():
    tool = GrepScannerTool()
    out = tool.execute(path="samples/vuln_sample.cpp")
    assert "Found" in out
    assert "strcpy" in out


def test_repo_mapper_maps_repo_root():
    tool = RepoMapperTool()
    out = tool.execute(directory=".", max_depth=2)
    assert "Repository:" in out
    assert "## File Tree" in out
