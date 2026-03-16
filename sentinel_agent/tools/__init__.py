"""Security analysis tools exposed to the agent."""

from .cppcheck import CppcheckTool
from .grep_scanner import GrepScannerTool
from .repo_mapper import RepoMapperTool
from .ast_parser import ASTParserTool
from .dependency_scanner import DependencyScannerTool
from .file_reader import FileReaderTool

TOOL_REGISTRY: dict[str, type] = {
    "cppcheck": CppcheckTool,
    "grep_scanner": GrepScannerTool,
    "repo_mapper": RepoMapperTool,
    "ast_parser": ASTParserTool,
    "dependency_scanner": DependencyScannerTool,
    "file_reader": FileReaderTool,
}

__all__ = [
    "CppcheckTool",
    "GrepScannerTool",
    "RepoMapperTool",
    "ASTParserTool",
    "DependencyScannerTool",
    "FileReaderTool",
    "TOOL_REGISTRY",
]
