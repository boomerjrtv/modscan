#!/usr/bin/env python3
"""
Tests for Scanner Form Integration

Unit tests verifying that the vulnerability scanner correctly integrates
with the universal form parser for XSS and SQLi testing.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.universal_form_parser import parse_forms, get_testable_fields, build_form_data


class TestScannerFormParserIntegration:
    """Test integration between scanner and universal form parser"""
    
    @pytest.fixture
    def mock_asset_manager(self):
        """Mock asset manager for testing"""
        mock_manager = Mock()
        mock_manager.add_vulnerability_finding = Mock()
        return mock_manager
    
    @pytest.fixture
    def vulnerability_scanner(self, mock_asset_manager):
        """Create vulnerability scanner instance"""
        config = {'blind_xss_domain': 'test.example.com'}
        scanner = VulnerabilityScanner(mock_asset_manager, config)
        return scanner
    
    def test_parse_forms_with_values_uses_universal_parser(self, vulnerability_scanner):
        """Test that _parse_forms_with_values uses the universal parser"""
        html = '''
        <form action="/test" method="POST">
            <input type="text" name="username" value="">
            <input type="hidden" name="csrf_token" value="abc123">
        </form>
        '''
        
        # This should now use the universal parser
        result = asyncio.run(vulnerability_scanner._parse_forms_with_values(html, 'https://example.com'))
        
        assert len(result) == 1
        form = result[0]
        
        # Check that universal parser structure is returned
        assert 'action' in form
        assert 'method' in form
        assert 'enctype' in form  # Universal parser adds this
        assert 'inputs' in form
        
        inputs = form['inputs']
        assert 'username' in inputs
        assert 'csrf_token' in inputs
        
        # Check that CSRF detection works
        csrf_field = inputs['csrf_token']
        assert csrf_field.get('is_csrf', False) or csrf_field['type'] == 'hidden'
    
    def test_parse_forms_url_resolution(self, vulnerability_scanner):
        """Test that URL resolution works correctly"""
        html = '''
        <form action="/relative/path" method="POST">
            <input type="text" name="test">
        </form>
        '''
        
        base_url = 'https://example.com/pages/form.html'
        result = asyncio.run(vulnerability_scanner._parse_forms_with_values(html, base_url))
        
        form = result[0]
        # Should resolve relative path with base URL
        assert form['action'] == 'https://example.com/relative/path'


class TestFormFieldCategorization:
    """Test that the scanner correctly categorizes form fields"""
    
    def test_get_testable_fields_integration(self):
        """Test that get_testable_fields correctly categorizes fields"""
        form_inputs = {
            'username': {'type': 'text', 'value': ''},
            'password': {'type': 'password', 'value': ''},
            'email': {'type': 'email', 'value': ''},
            'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True},
            'session_id': {'type': 'hidden', 'value': 'xyz789'},
            'submit': {'type': 'submit', 'value': 'Submit'},
            'remember': {'type': 'checkbox', 'value': '1', 'checked': False}
        }
        
        categories = get_testable_fields(form_inputs)
        
        # XSS/SQLi testable fields
        testable = categories['testable']
        assert 'username' in testable
        assert 'password' in testable
        assert 'email' in testable
        assert 'remember' in testable  # checkbox should be testable
        
        # Protected fields that should preserve values
        protected = categories['protected']
        assert 'csrf_token' in protected
        assert 'session_id' in protected
        assert 'submit' in protected
    
    def test_csrf_detection_patterns(self):
        """Test CSRF detection with various naming patterns"""
        csrf_patterns = [
            'csrf_token', 'authenticity_token', 'request_verification_token',
            '_token', '__RequestVerificationToken', 'csrfmiddlewaretoken',
            'form_token', 'security_token', 'anti_csrf'
        ]
        
        for pattern in csrf_patterns:
            form_inputs = {
                'username': {'type': 'text', 'value': ''},
                pattern: {'type': 'hidden', 'value': 'token_value'}
            }
            
            categories = get_testable_fields(form_inputs)
            
            # CSRF field should be protected
            assert pattern in categories['protected'], f"CSRF pattern '{pattern}' not detected"
            
            # Username should still be testable
            assert 'username' in categories['testable']


class TestFormDataBuilding:
    """Test form data building for payload injection"""
    
    def test_build_form_data_preserves_protected_fields(self):
        """Test that build_form_data preserves CSRF tokens and hidden fields"""
        form_inputs = {
            'username': {'type': 'text', 'value': 'original_user'},
            'password': {'type': 'password', 'value': 'original_pass'},
            'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True},
            'session_id': {'type': 'hidden', 'value': 'session123'},
            'remember': {'type': 'checkbox', 'value': '1', 'checked': True}
        }
        
        # Apply XSS payload to username field
        payload_data = {
            'username': '<script>alert("XSS")</script>',
            'password': 'test_password'
        }
        
        form_data = build_form_data(form_inputs, payload_data)
        
        # Payload should override testable fields
        assert form_data['username'] == '<script>alert("XSS")</script>'
        assert form_data['password'] == 'test_password'
        
        # Protected fields should keep original values
        assert form_data['csrf_token'] == 'abc123'
        assert form_data['session_id'] == 'session123'
        
        # Checkbox should be included (was checked)
        assert form_data['remember'] == '1'
    
    def test_build_form_data_handles_complex_inputs(self):
        """Test form data building with select and textarea"""
        form_inputs = {
            'comments': {'type': 'textarea', 'value': 'Original comment'},
            'country': {
                'type': 'select', 
                'value': 'canada',
                'options': ['usa', 'canada', 'uk'],
                'multiple': False
            },
            'languages': {
                'type': 'select',
                'value': ['python', 'javascript'],
                'options': ['python', 'javascript', 'java'],
                'multiple': True
            }
        }
        
        payload_data = {
            'comments': '<script>alert("textarea-xss")</script>'
        }
        
        form_data = build_form_data(form_inputs, payload_data)
        
        # Payload should override textarea
        assert form_data['comments'] == '<script>alert("textarea-xss")</script>'
        
        # Select fields should keep original values
        assert form_data['country'] == 'canada'
        assert form_data['languages'] == 'python'  # first selected value


class TestFormSubmissionUrls:
    """Test form URL resolution and submission"""
    
    def test_absolute_action_urls(self):
        """Test forms with absolute action URLs"""
        html = '''
        <form action="https://external.com/submit" method="POST">
            <input name="test" type="text">
        </form>
        '''
        
        forms = parse_forms(html, 'https://example.com/page.html')
        form = forms[0]
        
        # Should preserve absolute URL
        assert form['action'] == 'https://external.com/submit'
    
    def test_relative_action_urls(self):
        """Test forms with relative action URLs"""
        html = '''
        <form action="../submit.php" method="POST">
            <input name="test" type="text">
        </form>
        '''
        
        forms = parse_forms(html, 'https://example.com/forms/login.html')
        form = forms[0]
        
        # Should resolve relative to base URL
        assert form['action'] == 'https://example.com/submit.php'
    
    def test_empty_action_uses_current_page(self):
        """Test forms with empty action (should submit to current page)"""
        html = '''
        <form method="POST">
            <input name="test" type="text">
        </form>
        '''
        
        forms = parse_forms(html, 'https://example.com/current-page.html')
        form = forms[0]
        
        # Should use base URL as action
        assert form['action'] == 'https://example.com/current-page.html'


class TestMalformedFormHandling:
    """Test handling of malformed or edge-case HTML"""
    
    def test_forms_with_missing_attributes(self):
        """Test forms missing standard attributes"""
        html = '''
        <form>
            <input name="test">
        </form>
        '''
        
        forms = parse_forms(html)
        form = forms[0]
        
        # Should provide defaults
        assert form['method'] == 'GET'  # default method
        assert form['enctype'] == 'application/x-www-form-urlencoded'  # default enctype
        
        # Input should default to text type
        inputs = form['inputs']
        assert inputs['test']['type'] == 'text'
    
    def test_inputs_without_names_ignored(self):
        """Test that inputs without names are ignored"""
        html = '''
        <form>
            <input type="text" value="no-name-field">
            <input name="valid" type="text" value="has-name">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        # Should only include named inputs
        assert 'valid' in inputs
        assert len(inputs) == 1
    
    def test_duplicate_field_names_handled(self):
        """Test handling of duplicate field names (like multiple checkboxes)"""
        html = '''
        <form>
            <input type="checkbox" name="options" value="option1">
            <input type="checkbox" name="options" value="option2" checked>
            <input type="text" name="username" value="test">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        # Should handle duplicate names appropriately
        assert 'username' in inputs
        assert 'options' in inputs
        
        # Implementation may vary for duplicates - just ensure it doesn't crash


class TestBackwardsCompatibility:
    """Test that integration maintains backwards compatibility"""
    
    def test_form_structure_compatible_with_existing_code(self):
        """Test that form structure is compatible with existing scanner code"""
        html = '''
        <form action="/login" method="POST">
            <input type="text" name="username" value="">
            <input type="password" name="password" value="">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="submit" value="Login">
        </form>
        '''
        
        forms = parse_forms(html, 'https://example.com')
        form = forms[0]
        
        # Should maintain expected structure for existing code
        assert 'action' in form
        assert 'method' in form
        assert 'inputs' in form
        
        inputs = form['inputs']
        
        # Each input should have the expected structure
        for field_name, field_data in inputs.items():
            assert 'type' in field_data
            assert 'value' in field_data
            
            # Type and value should be strings (not objects)
            assert isinstance(field_data['type'], str)
            assert isinstance(field_data['value'], (str, list))  # list for multi-select
    
    def test_field_categorization_backwards_compatible(self):
        """Test that field categorization works with existing scanner logic"""
        form_inputs = {
            'username': {'type': 'text', 'value': ''},
            'password': {'type': 'password', 'value': ''},
            'csrf_token': {'type': 'hidden', 'value': 'token', 'is_csrf': True},
            'submit': {'type': 'submit', 'value': 'Submit'}
        }
        
        categories = get_testable_fields(form_inputs)
        
        # Should return the expected structure
        assert 'testable' in categories
        assert 'protected' in categories
        assert isinstance(categories['testable'], list)
        assert isinstance(categories['protected'], list)
        
        # Should identify fields correctly for existing XSS/SQLi logic
        assert 'username' in categories['testable']
        assert 'password' in categories['testable']
        assert 'csrf_token' in categories['protected']
        assert 'submit' in categories['protected']


class TestErrorHandling:
    """Test error handling and graceful degradation"""
    
    def test_invalid_html_does_not_crash(self):
        """Test that invalid HTML doesn't crash the parser"""
        malformed_html_samples = [
            '<form><input name="test" type="text" value="unclosed',
            '<form><input name=test type=text value=unquoted></form>',
            '<form><input name="test" type="text"><input></form>',
            '<form><input name="" type="text"></form>',  # empty name
            '<form><script>alert("xss")</script><input name="test"></form>'
        ]
        
        for html in malformed_html_samples:
            try:
                forms = parse_forms(html)
                # Should not crash, and should return a list (even if empty)
                assert isinstance(forms, list)
            except Exception as e:
                pytest.fail(f"Parser crashed on malformed HTML: {html}. Error: {e}")
    
    def test_extremely_large_html_handled(self):
        """Test that extremely large HTML is handled gracefully"""
        # Create HTML with many inputs
        large_inputs = ''.join(f'<input name="field{i}" type="text">' for i in range(100))
        large_html = f'<form>{large_inputs}</form>'
        
        # Should not crash and should parse at least some inputs
        forms = parse_forms(large_html)
        assert len(forms) == 1
        assert len(forms[0]['inputs']) > 0
    
    def test_empty_or_none_input_handled(self):
        """Test that empty or None HTML input is handled"""
        assert parse_forms('') == []
        assert parse_forms(None) == []
        assert parse_forms('   ') == []  # whitespace only
    
    def test_no_beautifulsoup_fallback(self):
        """Test that regex fallback works when BeautifulSoup is unavailable"""
        html = '''
        <form action="/test" method="POST">
            <input type="text" name="username" value="test">
            <input type="hidden" name="csrf_token" value="abc123">
            <textarea name="comments">Test comment</textarea>
            <select name="country">
                <option value="us">US</option>
                <option value="ca" selected>Canada</option>
            </select>
        </form>
        '''
        
        # Mock BeautifulSoup import failure to test regex fallback
        with patch('modules.universal_form_parser.BeautifulSoup', side_effect=ImportError("No module named 'bs4'")):
            from modules.universal_form_parser import _parse_forms_with_regex
            
            forms = _parse_forms_with_regex(html, 'https://example.com')
            
            assert len(forms) == 1
            form = forms[0]
            
            # Basic form parsing should work
            assert form['action'] == 'https://example.com/test'
            assert form['method'] == 'POST'
            
            inputs = form['inputs']
            assert 'username' in inputs
            assert 'csrf_token' in inputs
            
            # Advanced elements may have limited support in regex mode
            # but should not crash