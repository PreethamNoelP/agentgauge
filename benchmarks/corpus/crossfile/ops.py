"""Helpers. remove_tree's only caller gates and handles it; remove_file's
does neither; remove_everything is never called by a tool."""

import os
import shutil


def remove_tree(path):
    shutil.rmtree(path)


def remove_file(path):
    os.remove(path)  # expect: human-oversight, error-handling


def remove_everything():
    shutil.rmtree("/")
