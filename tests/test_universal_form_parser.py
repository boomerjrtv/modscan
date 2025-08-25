#!/usr/bin/env python3
"""
Tests for Universal Form Parser

Comprehensive test suite covering various HTML form structures,
input types, CSRF detection, and edge cases.
"""

import pytest
from modules.universal_form_parser import parse_forms, get_testable_fields, build_form_data


class TestBasicFormParsing:
    """Test basic form parsing functionality"""
    
    def test_simple_form(self):
        """Test parsing a simple form"""
        html = '''
        <form action="/submit" method="POST">
            <input type="text" name="username" value="">
            <input type="password" name="password" value="">
            <input type="submit" name="submit" value="Login">
        </form>
        '''
        
        forms = parse_forms(html)
        assert len(forms) == 1
        
        form = forms[0]
        assert form['action'] == '/submit'
        assert form['method'] == 'POST'
        assert form['enctype'] == 'application/x-www-form-urlencoded'
        
        inputs = form['inputs']
        assert 'username' in inputs
        assert inputs['username']['type'] == 'text'
        assert inputs['username']['value'] == ''
        
        assert 'password' in inputs
        assert inputs['password']['type'] == 'password'
        
        assert 'submit' in inputs
        assert inputs['submit']['type'] == 'submit'
    
    def test_form_with_absolute_action(self):
        """Test form with absolute action URL"""
        html = '''
        <form action="https://example.com/login" method="GET">
            <input name="q" type="search" value="">
        </form>
        '''
        
        forms = parse_forms(html)
        form = forms[0]
        
        assert form['action'] == 'https://example.com/login'
        assert form['method'] == 'GET'
    
    def test_form_with_relative_action_resolution(self):
        """Test relative action URL resolution with base_url"""
        html = '''
        <form action="../submit.php" method="POST">
            <input name="data" type="text">
        </form>
        '''
        
        base_url = 'https://example.com/forms/login.html'
        forms = parse_forms(html, base_url)
        form = forms[0]
        
        # Should resolve relative to base URL
        assert form['action'] == 'https://example.com/submit.php'
    
    def test_form_no_action_uses_base_url(self):
        """Test form without action uses base_url"""
        html = '''
        <form method="POST">
            <input name="test" type="text">
        </form>
        '''
        
        base_url = 'https://example.com/page.html'
        forms = parse_forms(html, base_url)
        form = forms[0]
        
        assert form['action'] == base_url
    
    def test_multiple_forms(self):
        """Test parsing multiple forms"""
        html = '''
        <form action="/login" method="POST">
            <input name="username" type="text">
        </form>
        <form action="/search" method="GET">
            <input name="query" type="search">
        </form>
        '''
        
        forms = parse_forms(html)
        assert len(forms) == 2
        
        assert forms[0]['action'] == '/login'
        assert forms[0]['method'] == 'POST'
        assert 'username' in forms[0]['inputs']
        
        assert forms[1]['action'] == '/search'
        assert forms[1]['method'] == 'GET'
        assert 'query' in forms[1]['inputs']


class TestInputTypes:
    """Test parsing various input types"""
    
    def test_text_inputs(self):
        """Test various text input types"""
        html = '''
        <form action="/submit">
            <input type="text" name="name" value="John">
            <input type="email" name="email" value="test@example.com">
            <input type="url" name="website" value="https://example.com">
            <input type="tel" name="phone" value="123-456-7890">
            <input type="search" name="query" value="search term">
            <input type="number" name="age" value="25">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['name']['type'] == 'text'
        assert inputs['name']['value'] == 'John'
        
        assert inputs['email']['type'] == 'email'
        assert inputs['email']['value'] == 'test@example.com'
        
        assert inputs['website']['type'] == 'url'
        assert inputs['website']['value'] == 'https://example.com'
        
        assert inputs['phone']['type'] == 'tel'
        assert inputs['age']['type'] == 'number'
        assert inputs['age']['value'] == '25'
    
    def test_checkbox_inputs(self):
        """Test checkbox inputs with checked states"""
        html = '''
        <form>
            <input type="checkbox" name="agree" value="yes" checked>
            <input type="checkbox" name="newsletter" value="subscribe">
            <input type="checkbox" name="options" value="option1" checked>
            <input type="checkbox" name="options" value="option2">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['agree']['type'] == 'checkbox'
        assert inputs['agree']['checked'] is True
        assert inputs['agree']['value'] == 'yes'
        
        assert inputs['newsletter']['type'] == 'checkbox'
        assert inputs['newsletter']['checked'] is False
        
        # Multiple checkboxes with same name should be handled
        # (implementation may vary - check what our parser does)
    
    def test_radio_inputs(self):
        """Test radio button inputs"""
        html = '''
        <form>
            <input type="radio" name="gender" value="male" checked>
            <input type="radio" name="gender" value="female">
            <input type="radio" name="color" value="red">
            <input type="radio" name="color" value="blue" checked>
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        # Radio buttons with same name should be handled appropriately
        # At minimum, we should capture the checked state
        gender_field = inputs.get('gender')
        if isinstance(gender_field, list):
            # If our parser returns lists for multiple inputs
            assert any(item.get('checked', False) for item in gender_field)
        else:
            # If parser returns single item (last one or checked one)
            assert gender_field['type'] == 'radio'
    
    def test_hidden_inputs(self):
        """Test hidden inputs"""
        html = '''
        <form>
            <input type="hidden" name="session_id" value="abc123">
            <input type="hidden" name="form_token" value="xyz789">
            <input type="text" name="visible" value="">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['session_id']['type'] == 'hidden'
        assert inputs['session_id']['value'] == 'abc123'
        
        assert inputs['form_token']['type'] == 'hidden'
        assert inputs['form_token']['value'] == 'xyz789'
    
    def test_file_inputs(self):
        """Test file input types"""
        html = '''
        <form enctype="multipart/form-data">
            <input type="file" name="upload">
            <input type="file" name="images" multiple>
        </form>
        '''
        
        forms = parse_forms(html)
        form = forms[0]
        inputs = form['inputs']
        
        assert form['enctype'] == 'multipart/form-data'
        assert inputs['upload']['type'] == 'file'
        assert 'images' in inputs
    
    def test_button_inputs(self):
        """Test button and submit inputs"""
        html = '''
        <form>
            <input type="submit" name="submit" value="Submit">
            <input type="button" name="cancel" value="Cancel">
            <input type="reset" name="reset" value="Reset">
            <input type="image" name="submit_image" src="submit.png">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['submit']['type'] == 'submit'
        assert inputs['cancel']['type'] == 'button'
        assert inputs['reset']['type'] == 'reset'
        assert inputs['submit_image']['type'] == 'image'


class TestComplexElements:
    """Test parsing select and textarea elements"""
    
    def test_textarea(self):
        """Test textarea parsing"""
        html = '''
        <form>
            <textarea name="comments">Default comment text</textarea>
            <textarea name="description"></textarea>
            <textarea name="notes">
                Multi-line
                text content
            </textarea>
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['comments']['type'] == 'textarea'
        assert inputs['comments']['value'] == 'Default comment text'
        
        assert inputs['description']['type'] == 'textarea'
        assert inputs['description']['value'] == ''
        
        # Multi-line content should be preserved/cleaned
        assert 'notes' in inputs
        assert inputs['notes']['type'] == 'textarea'
    
    def test_select_single(self):
        """Test single-select dropdown"""
        html = '''
        <form>
            <select name="country">
                <option value="us">United States</option>
                <option value="ca" selected>Canada</option>
                <option value="uk">United Kingdom</option>
            </select>
            <select name="color">
                <option value="red">Red</option>
                <option value="blue">Blue</option>
            </select>
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        country = inputs['country']
        assert country['type'] == 'select'
        assert country['multiple'] is False
        assert country['value'] == 'ca'  # selected option
        assert 'us' in country['options']
        assert 'ca' in country['options']
        assert 'uk' in country['options']
        
        # No selection should default to first option
        color = inputs['color']
        assert color['type'] == 'select'
        assert color['value'] == 'red'  # first option as default
        assert color['options'] == ['red', 'blue']
    
    def test_select_multiple(self):
        """Test multiple-select element"""
        html = '''
        <form>
            <select name="languages" multiple>
                <option value="python" selected>Python</option>
                <option value="javascript">JavaScript</option>
                <option value="java" selected>Java</option>
                <option value="cpp">C++</option>
            </select>
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        languages = inputs['languages']
        assert languages['type'] == 'select'
        assert languages['multiple'] is True
        
        # Should capture selected values as a list
        selected_values = languages['value']
        if isinstance(selected_values, list):
            assert 'python' in selected_values
            assert 'java' in selected_values
            assert len(selected_values) == 2
        
        assert 'python' in languages['options']
        assert 'cpp' in languages['options']
    
    def test_select_with_option_text_as_value(self):
        """Test select where option text is used as value"""
        html = '''
        <form>
            <select name="size">
                <option>Small</option>
                <option selected>Medium</option>
                <option>Large</option>
            </select>
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        size = inputs['size']
        assert size['type'] == 'select'
        assert size['value'] == 'Medium'  # option text used as value
        assert 'Small' in size['options']
        assert 'Large' in size['options']


class TestCSRFDetection:
    """Test CSRF token detection"""
    
    def test_common_csrf_field_names(self):
        """Test detection of common CSRF field names"""
        csrf_fields = [
            'csrf_token', 'authenticity_token', 'request_verification_token',
            '_token', '__RequestVerificationToken', 'csrfmiddlewaretoken',
            'csrf', 'xsrf', 'anti_csrf', 'csrf_hash', '_csrf'
        ]
        
        for field_name in csrf_fields:
            html = f'''
            <form>
                <input type="hidden" name="{field_name}" value="abc123">
                <input type="text" name="username">
            </form>
            '''
            
            forms = parse_forms(html)
            inputs = forms[0]['inputs']
            
            # Should mark as CSRF field
            csrf_field = inputs[field_name]
            assert csrf_field.get('is_csrf', False), f"Field '{field_name}' should be marked as CSRF"
    
    def test_csrf_case_insensitive(self):
        """Test CSRF detection is case-insensitive"""
        html = '''
        <form>
            <input type="hidden" name="CSRF_TOKEN" value="abc">
            <input type="hidden" name="Authenticity_Token" value="def">
            <input type="hidden" name="XsRf_ToKeN" value="ghi">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['CSRF_TOKEN'].get('is_csrf', False)
        assert inputs['Authenticity_Token'].get('is_csrf', False)
        assert inputs['XsRf_ToKeN'].get('is_csrf', False)
    
    def test_partial_csrf_matches(self):
        """Test CSRF detection with partial name matches"""
        html = '''
        <form>
            <input type="hidden" name="user_csrf_value" value="abc">
            <input type="hidden" name="form_token_check" value="def">
            <input type="hidden" name="anti_csrf_protection" value="ghi">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        assert inputs['user_csrf_value'].get('is_csrf', False)
        assert inputs['form_token_check'].get('is_csrf', False)
        assert inputs['anti_csrf_protection'].get('is_csrf', False)


class TestFieldCategorization:
    """Test the get_testable_fields function"""
    
    def test_basic_categorization(self):
        """Test basic field categorization"""
        form_inputs = {
            'username': {'type': 'text', 'value': ''},
            'password': {'type': 'password', 'value': ''},
            'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True},
            'session_id': {'type': 'hidden', 'value': 'xyz789'},
            'submit': {'type': 'submit', 'value': 'Login'},
            'email': {'type': 'email', 'value': ''}
        }
        
        categories = get_testable_fields(form_inputs)
        
        testable = categories['testable']
        protected = categories['protected']
        
        assert 'username' in testable
        assert 'password' in testable
        assert 'email' in testable
        
        assert 'csrf_token' in protected
        assert 'session_id' in protected
        assert 'submit' in protected
    
    def test_edge_case_field_types(self):
        """Test categorization of edge case field types"""
        form_inputs = {
            'search_query': {'type': 'search', 'value': ''},
            'website': {'type': 'url', 'value': ''},
            'age': {'type': 'number', 'value': ''},
            'upload': {'type': 'file', 'value': ''},
            'comments': {'type': 'textarea', 'value': ''},
            'country': {'type': 'select', 'value': 'US', 'options': ['US', 'CA']},
            'reset_btn': {'type': 'reset', 'value': 'Reset'},
            'cancel': {'type': 'button', 'value': 'Cancel'}
        }
        
        categories = get_testable_fields(form_inputs)
        
        testable = categories['testable']
        protected = categories['protected']
        
        # These should be testable
        assert 'search_query' in testable
        assert 'website' in testable
        assert 'age' in testable
        assert 'comments' in testable
        assert 'country' in testable
        
        # These should be protected
        assert 'reset_btn' in protected
        assert 'cancel' in protected
        
        # File uploads are typically testable but may need special handling
        # (depends on implementation choice)
    
    def test_unknown_field_types_default_testable(self):
        """Test that unknown field types default to testable"""
        form_inputs = {
            'unknown_field': {'type': 'custom-type', 'value': ''},
            'no_type_field': {'value': 'test'}  # missing type
        }
        
        categories = get_testable_fields(form_inputs)
        
        # Unknown types should default to testable for broader coverage
        assert 'unknown_field' in categories['testable']
        assert 'no_type_field' in categories['testable']


class TestFormDataBuilding:
    """Test the build_form_data function"""
    
    def test_basic_form_data_building(self):
        """Test basic form data building"""
        form_inputs = {
            'username': {'type': 'text', 'value': 'testuser'},
            'password': {'type': 'password', 'value': 'secret'},
            'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True},
            'remember': {'type': 'checkbox', 'value': '1', 'checked': True}
        }
        
        form_data = build_form_data(form_inputs)
        
        assert form_data['username'] == 'testuser'
        assert form_data['password'] == 'secret'
        assert form_data['csrf_token'] == 'abc123'
        assert form_data['remember'] == '1'
    
    def test_form_data_with_payloads(self):
        """Test form data building with payload overrides"""
        form_inputs = {
            'username': {'type': 'text', 'value': 'original'},
            'password': {'type': 'password', 'value': 'original'},
            'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True}
        }
        
        payload_data = {
            'username': 'injected_payload',
            'password': 'test_password'
        }
        
        form_data = build_form_data(form_inputs, payload_data)
        
        # Payloads should override original values
        assert form_data['username'] == 'injected_payload'
        assert form_data['password'] == 'test_password'
        
        # Protected fields should keep original values
        assert form_data['csrf_token'] == 'abc123'
    
    def test_checkbox_handling(self):
        """Test checkbox handling in form data building"""
        form_inputs = {
            'agree': {'type': 'checkbox', 'value': 'yes', 'checked': True},
            'newsletter': {'type': 'checkbox', 'value': 'subscribe', 'checked': False},
            'terms': {'type': 'checkbox', 'value': '', 'checked': True}  # empty value
        }
        
        form_data = build_form_data(form_inputs)
        
        # Checked checkbox should be included
        assert form_data['agree'] == 'yes'
        
        # Unchecked checkbox should not be included
        assert 'newsletter' not in form_data
        
        # Checked checkbox with empty value should default to '1'
        assert form_data['terms'] == '1'
    
    def test_radio_button_handling(self):
        """Test radio button handling"""
        form_inputs = {
            'gender': {'type': 'radio', 'value': 'male', 'checked': True},
            'color': {'type': 'radio', 'value': 'blue', 'checked': False}
        }
        
        form_data = build_form_data(form_inputs)
        
        # Only checked radio should be included
        assert form_data['gender'] == 'male'
        assert 'color' not in form_data
    
    def test_select_handling(self):
        """Test select element handling"""
        form_inputs = {
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
        
        form_data = build_form_data(form_inputs)
        
        # Single select should use selected value
        assert form_data['country'] == 'canada'
        
        # Multiple select should use first selected value for simplicity
        assert form_data['languages'] == 'python'


class TestEdgeCases:
    """Test edge cases and malformed HTML"""
    
    def test_empty_html(self):
        """Test empty HTML input"""
        assert parse_forms('') == []
        assert parse_forms(None) == []
    
    def test_no_forms(self):
        """Test HTML with no forms"""
        html = '''
        <html>
            <body>
                <p>No forms here</p>
                <div>Just content</div>
            </body>
        </html>
        '''
        
        assert parse_forms(html) == []
    
    def test_malformed_html(self):
        """Test malformed HTML"""
        html = '''
        <form action="/test">
            <input name="field1" type="text" value="test">
            <input name="field2" type="password" 
            <input name="field3" value="unclosed quotes
            <input name=field4 type=text value=unquoted>
        </form>
        '''
        
        # Parser should handle malformed HTML gracefully
        forms = parse_forms(html)
        assert len(forms) == 1
        
        # Should extract what it can
        inputs = forms[0]['inputs']
        assert 'field1' in inputs  # well-formed input
        assert 'field4' in inputs  # unquoted attributes
    
    def test_nested_forms_and_invalid_html(self):
        """Test nested forms (invalid HTML but sometimes seen)"""
        html = '''
        <form action="/outer">
            <input name="outer_field" type="text">
            <form action="/inner">
                <input name="inner_field" type="text">
            </form>
        </form>
        '''
        
        # Should handle gracefully, behavior may vary
        forms = parse_forms(html)
        assert len(forms) >= 1  # Should find at least one form
    
    def test_form_with_no_inputs(self):
        """Test form with no input elements"""
        html = '''
        <form action="/empty" method="POST">
            <p>This form has no inputs</p>
        </form>
        '''
        
        forms = parse_forms(html)
        assert len(forms) == 1
        
        form = forms[0]
        assert form['action'] == '/empty'
        assert form['method'] == 'POST'
        assert form['inputs'] == {}
    
    def test_inputs_without_names(self):
        """Test inputs without name attributes"""
        html = '''
        <form>
            <input type="text" value="no name">
            <input type="submit" value="Submit">
            <input type="hidden" name="valid" value="has name">
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        # Should only include inputs with name attributes
        assert 'valid' in inputs
        assert len([k for k in inputs.keys() if k]) == 1  # only named inputs
    
    def test_very_large_html(self):
        """Test handling of very large HTML (performance guard)"""
        # Create large HTML content
        large_html = '<form>' + ''.join('<input name="field{}" type="text">'.format(i) for i in range(1000)) + '</form>'
        
        # Should handle large content without crashing
        forms = parse_forms(large_html)
        assert len(forms) == 1
        
        # Should have truncated if size limit applied
        inputs = forms[0]['inputs']
        assert len(inputs) > 0  # Should parse some inputs
    
    def test_html_entities(self):
        """Test HTML entity decoding"""
        html = '''
        <form action="/test">
            <input name="field" value="&quot;quoted&quot; &amp; escaped">
            <textarea name="content">&lt;script&gt;alert('test');&lt;/script&gt;</textarea>
        </form>
        '''
        
        forms = parse_forms(html)
        inputs = forms[0]['inputs']
        
        # Should decode HTML entities
        assert '"quoted" & escaped' in inputs['field']['value']
        assert '<script>' in inputs['content']['value']