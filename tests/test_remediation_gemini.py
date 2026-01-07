import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from auto_remediation.remediation import AutoRemediator

class TestGeminiRemediation:
    """Test Gemini integration in AutoRemediator."""

    @patch('google.generativeai.GenerativeModel')
    @patch('google.generativeai.configure')
    def test_init_gemini(self, mock_configure, mock_model):
        """Test initialization with Gemini provider."""
        remediator = AutoRemediator(ai_provider='gemini', api_key='test-key')
        
        mock_configure.assert_called_with(api_key='test-key')
        mock_model.assert_called_with('gemini-1.5-flash')  # Default model
        assert remediator.ai_provider == 'gemini'

    @patch('google.generativeai.GenerativeModel')
    @patch('google.generativeai.configure')
    def test_generate_code_fix_gemini(self, mock_configure, mock_model):
        """Test code fix generation using Gemini."""
        # Setup mock
        mock_client = Mock()
        mock_response = Mock()
        mock_response.text = "fixed_code()"
        mock_client.generate_content.return_value = mock_response
        mock_model.return_value = mock_client

        remediator = AutoRemediator(ai_provider='gemini', api_key='test-key')
        
        # Test data
        finding = {
            'path': 'test.js',
            'start': {'line': 1},
            'check_id': 'test-check',
            'extra': {'message': 'Fix me'}
        }
        
        # Mock file operations
        with patch('auto_remediation.remediation._secure_read_file', return_value="bad_code()\n"):
            with patch('auto_remediation.remediation._secure_file_path', return_value="/abs/test.js"):
                result = remediator.generate_code_fix(finding, "/repo")

        # Verify
        assert result is not None
        assert result['fixed_line'] == "fixed_code()"
        mock_client.generate_content.assert_called_once()

    @patch('google.generativeai.GenerativeModel')
    @patch('google.generativeai.configure')
    def test_executive_summary_gemini(self, mock_configure, mock_model):
        """Test executive summary generation using Gemini."""
        # Setup mock
        mock_client = Mock()
        mock_response = Mock()
        mock_response.text = "Summary text"
        mock_client.generate_content.return_value = mock_response
        mock_model.return_value = mock_client

        remediator = AutoRemediator(ai_provider='gemini', api_key='test-key')
        
        findings = [{'severity': 'critical'}, {'severity': 'high'}]
        summary = remediator.generate_executive_summary(findings)
        
        assert summary == "Summary text"
        mock_client.generate_content.assert_called_once()
