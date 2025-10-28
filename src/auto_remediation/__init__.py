"""
Auto-Remediation Module for AppSec Scanner

This module handles automatic code fixes for SAST findings and creates PRs.
"""

from .remediation import AutoRemediator

__all__ = ['AutoRemediator'] 