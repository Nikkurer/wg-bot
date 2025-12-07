"""Pytest configuration and shared fixtures."""
import os
import sys
import tempfile

# Добавляем корневую директорию проекта в путь
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

