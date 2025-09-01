#!/usr/bin/env python3
"""
Universal HTML Form Parser

A target-agnostic form parsing utility that works across all web applications
without requiring target-specific logic. Supports graceful degradation when
BeautifulSoup is not available.

Key Features:
- Universal form parsing (action, method, inputs, enctype)
- CSRF token detection using common patterns
- Support for all input types, select, textarea elements
- Graceful fallback when BeautifulSoup unavailable
- Robust to malformed HTML and edge cases
- No target-specific assumptions
"""

import re
import html
from typing import List, Dict, Optional, Union, Any
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)

# Common CSRF token field name patterns (case-insensitive)
CSRF_PATTERNS = [
    'csrf', '_token', 'authenticity_token', 'request_verification_token', 
    'xsrf', '__requestverificationtoken', 'csrfmiddlewaretoken',
    '_csrf', 'csrf_token', 'token', 'form_token', 'security_token',
    'anti_csrf', 'csrf_hash', 'csrf_test_name'
]

# Universal security level detection patterns (works on any application)
SECURITY_LEVEL_PATTERNS = [
    # Generic security level indicators
    'security', 'level', 'difficulty', 'protection', 'mode',
    # Common values
    'low', 'medium', 'high', 'impossible', 'easy', 'hard',
    'basic', 'advanced', 'expert', 'beginner', 'intermediate',
    # Security modes
    'secure', 'insecure', 'safe', 'unsafe', 'strict', 'loose'
]

def _is_csrf_field(field_name: str) -> bool:
    """Check if field name matches common CSRF token patterns"""
    if not field_name:
        return False
    
    field_lower = field_name.lower()
    return any(pattern in field_lower for pattern in CSRF_PATTERNS)

def detect_security_level(html_content: str, cookies: Dict[str, str] = None) -> Optional[str]:
    """
    Universal security level detection - works on any web application
    Analyzes HTML content and cookies to determine security level
    """
    if not html_content:
        return None
    
    html_lower = html_content.lower()
    
    # Check cookies first (most reliable)
    if cookies:
        for cookie_name, cookie_value in cookies.items():
            if any(pattern in cookie_name.lower() for pattern in SECURITY_LEVEL_PATTERNS):
                # Extract security level from cookie value
                if any(level in cookie_value.lower() for level in ['low', 'medium', 'high', 'impossible']):
                    return next((level for level in ['low', 'medium', 'high', 'impossible'] 
                               if level in cookie_value.lower()), None)
    
    # Check HTML content for security level indicators
    security_patterns = [
        (r'security\s*level[:\s]*([^<\s,]+)', 1),
        (r'level[:\s]*([^<\s,]+)', 1),
        (r'difficulty[:\s]*([^<\s,]+)', 1),
        (r'protection[:\s]*([^<\s,]+)', 1),
        (r'mode[:\s]*([^<\s,]+)', 1)
    ]
    
    for pattern, group in security_patterns:
        matches = re.finditer(pattern, html_lower, re.IGNORECASE)
        for match in matches:
            level = match.group(group).strip()
            if level in ['low', 'medium', 'high', 'impossible', 'easy', 'hard', 'basic', 'advanced']:
                return level
    
    # Check for form fields that might indicate security settings
    form_security_patterns = [
        r'<input[^>]*name[^>]*security[^>]*value[^>]*([^"\'>\s]+)',
        r'<select[^>]*name[^>]*security.*?<option[^>]*selected[^>]*value[^>]*([^"\'>\s]+)',
        r'<input[^>]*name[^>]*level[^>]*value[^>]*([^"\'>\s]+)'
    ]
    
    for pattern in form_security_patterns:
        matches = re.finditer(pattern, html_lower, re.IGNORECASE)
        for match in matches:
            level = match.group(1).strip()
            if level in ['low', 'medium', 'high', 'impossible']:
                return level
    
    return None

def _resolve_action_url(action: str, base_url: Optional[str] = None) -> str:
    """Resolve form action to absolute URL if base_url provided"""
    if not action:
        return base_url or ''
    
    if base_url and not urlparse(action).scheme:
        return urljoin(base_url, action)
    
    return action

def _safe_get_attr(attrs_str: str, attr_name: str, default: str = '') -> str:
    """Safely extract attribute value from attribute string"""
    if not attrs_str:
        return default
    
    # Try quoted values first
    pattern = rf'{attr_name}\s*=\s*["\']([^"\']*)["\']'
    match = re.search(pattern, attrs_str, re.IGNORECASE)
    if match:
        return html.unescape(match.group(1))
    
    # Try unquoted values
    pattern = rf'{attr_name}\s*=\s*([^\s>]*)'
    match = re.search(pattern, attrs_str, re.IGNORECASE)
    if match:
        return html.unescape(match.group(1))
    
    return default

def _has_attr(attrs_str: str, attr_name: str) -> bool:
    """Check if attribute exists (for boolean attributes like checked, selected)"""
    if not attrs_str:
        return False
    return bool(re.search(rf'\b{attr_name}\b', attrs_str, re.IGNORECASE))

def _parse_forms_with_beautifulsoup(html_content: str, base_url: Optional[str] = None) -> List[Dict]:
    """Parse forms using BeautifulSoup when available"""
    try:
        from bs4 import BeautifulSoup
        
        # Limit HTML size for performance (first 5MB)
        if len(html_content) > 5 * 1024 * 1024:
            html_content = html_content[:5 * 1024 * 1024]
            logger.warning("HTML content truncated to 5MB for parsing performance")
        
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        
        for form_tag in soup.find_all('form'):
            # Extract form attributes
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')
            
            # Resolve action URL
            action = _resolve_action_url(action, base_url)
            
            inputs = {}
            
            # Process input elements
            for input_tag in form_tag.find_all('input'):
                name = input_tag.get('name')
                if not name:
                    continue
                
                input_type = input_tag.get('type', 'text').lower()
                value = input_tag.get('value', '')
                checked = input_tag.has_attr('checked')
                
                input_data = {
                    'type': input_type,
                    'value': value
                }
                
                if input_type in ['checkbox', 'radio']:
                    input_data['checked'] = checked
                
                # Mark CSRF tokens
                if _is_csrf_field(name):
                    input_data['is_csrf'] = True
                
                # Handle multiple inputs with same name (e.g., checkboxes)
                if name in inputs:
                    # Convert to list if not already
                    if not isinstance(inputs[name], list):
                        inputs[name] = [inputs[name]]
                    inputs[name].append(input_data)
                else:
                    inputs[name] = input_data
            
            # Process textarea elements
            for textarea_tag in form_tag.find_all('textarea'):
                name = textarea_tag.get('name')
                if not name:
                    continue
                
                value = textarea_tag.get_text() or textarea_tag.get('value', '')
                inputs[name] = {
                    'type': 'textarea',
                    'value': value
                }
            
            # Process select elements
            for select_tag in form_tag.find_all('select'):
                name = select_tag.get('name')
                if not name:
                    continue
                
                multiple = select_tag.has_attr('multiple')
                options = []
                selected_values = []
                
                for option_tag in select_tag.find_all('option'):
                    option_value = option_tag.get('value')
                    if option_value is None:
                        option_value = option_tag.get_text()
                    
                    options.append(option_value)
                    
                    if option_tag.has_attr('selected'):
                        selected_values.append(option_value)
                
                # If no option selected, use first option as default
                if not selected_values and options:
                    selected_values = [options[0]]
                
                select_data = {
                    'type': 'select',
                    'options': options,
                    'multiple': multiple
                }
                
                if multiple:
                    select_data['value'] = selected_values
                else:
                    select_data['value'] = selected_values[0] if selected_values else ''
                
                inputs[name] = select_data
            
            forms.append({
                'action': action,
                'method': method,
                'enctype': enctype,
                'inputs': inputs
            })
        
        return forms
        
    except ImportError:
        logger.debug("BeautifulSoup not available, falling back to regex parsing")
        return _parse_forms_with_regex(html_content, base_url)
    except Exception as e:
        logger.warning(f"BeautifulSoup parsing failed: {e}, falling back to regex")
        return _parse_forms_with_regex(html_content, base_url)

def _parse_forms_with_regex(html_content: str, base_url: Optional[str] = None) -> List[Dict]:
    """Fallback form parsing using regex when BeautifulSoup unavailable"""
    
    # Limit HTML size for performance
    if len(html_content) > 5 * 1024 * 1024:
        html_content = html_content[:5 * 1024 * 1024]
        logger.warning("HTML content truncated to 5MB for parsing performance")
    
    forms = []
    
    # Find form tags and their content
    form_pattern = r'<form([^>]*?)>(.*?)</form>'
    form_matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
    
    for form_attrs, form_content in form_matches:
        # Parse form attributes
        action = _safe_get_attr(form_attrs, 'action')
        method = _safe_get_attr(form_attrs, 'method', 'GET').upper()
        enctype = _safe_get_attr(form_attrs, 'enctype', 'application/x-www-form-urlencoded')
        
        # Resolve action URL
        action = _resolve_action_url(action, base_url)
        
        inputs = {}
        
        # Parse input elements
        input_pattern = r'<input([^>]*?)/?>'
        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        for input_attrs in input_matches:
            name = _safe_get_attr(input_attrs, 'name')
            if not name:
                continue
            
            input_type = _safe_get_attr(input_attrs, 'type', 'text').lower()
            value = _safe_get_attr(input_attrs, 'value')
            checked = _has_attr(input_attrs, 'checked')
            
            input_data = {
                'type': input_type,
                'value': value
            }
            
            if input_type in ['checkbox', 'radio']:
                input_data['checked'] = checked
            
            # Mark CSRF tokens
            if _is_csrf_field(name):
                input_data['is_csrf'] = True
            
            # Handle duplicates by name
            if name in inputs:
                if not isinstance(inputs[name], list):
                    inputs[name] = [inputs[name]]
                inputs[name].append(input_data)
            else:
                inputs[name] = input_data
        
        # Parse textarea elements
        textarea_pattern = r'<textarea([^>]*?)>(.*?)</textarea>'
        textarea_matches = re.findall(textarea_pattern, form_content, re.IGNORECASE | re.DOTALL)
        
        for textarea_attrs, textarea_content in textarea_matches:
            name = _safe_get_attr(textarea_attrs, 'name')
            if not name:
                continue
            
            # Clean up textarea content
            value = re.sub(r'<[^>]+>', '', textarea_content).strip()
            value = html.unescape(value)
            
            inputs[name] = {
                'type': 'textarea',
                'value': value
            }
        
        # Parse select elements (basic implementation)
        select_pattern = r'<select([^>]*?)>(.*?)</select>'
        select_matches = re.findall(select_pattern, form_content, re.IGNORECASE | re.DOTALL)
        
        for select_attrs, select_content in select_matches:
            name = _safe_get_attr(select_attrs, 'name')
            if not name:
                continue
            
            multiple = _has_attr(select_attrs, 'multiple')
            
            # Parse options
            option_pattern = r'<option([^>]*?)>([^<]*)</option>'
            option_matches = re.findall(option_pattern, select_content, re.IGNORECASE)
            
            options = []
            selected_values = []
            
            for option_attrs, option_text in option_matches:
                option_value = _safe_get_attr(option_attrs, 'value')
                if not option_value:
                    option_value = option_text.strip()
                
                option_value = html.unescape(option_value)
                options.append(option_value)
                
                if _has_attr(option_attrs, 'selected'):
                    selected_values.append(option_value)
            
            # Default to first option if none selected
            if not selected_values and options:
                selected_values = [options[0]]
            
            select_data = {
                'type': 'select',
                'options': options,
                'multiple': multiple
            }
            
            if multiple:
                select_data['value'] = selected_values
            else:
                select_data['value'] = selected_values[0] if selected_values else ''
            
            inputs[name] = select_data
        
        forms.append({
            'action': action,
            'method': method,
            'enctype': enctype,
            'inputs': inputs
        })
    
    return forms

def parse_forms(html_content: str, base_url: Optional[str] = None) -> List[Dict]:
    """
    Parse HTML forms and extract all form data universally.
    
    Args:
        html_content: Raw HTML content to parse
        base_url: Optional base URL for resolving relative actions
        
    Returns:
        List of form dictionaries with structure:
        {
            'action': 'https://example.com/submit',
            'method': 'POST',
            'enctype': 'application/x-www-form-urlencoded',
            'inputs': {
                'username': {'type': 'text', 'value': ''},
                'password': {'type': 'password', 'value': ''},
                'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True},
                'remember': {'type': 'checkbox', 'value': '1', 'checked': False},
                'country': {'type': 'select', 'value': 'US', 'options': ['US', 'CA', 'UK'], 'multiple': False},
                'comments': {'type': 'textarea', 'value': 'Default text'}
            }
        }
        
    Notes:
        - Uses BeautifulSoup if available, otherwise falls back to regex
        - Automatically detects CSRF tokens by common field name patterns
        - Resolves relative action URLs if base_url provided
        - Handles malformed HTML gracefully
        - No target-specific assumptions
    """
    
    if not html_content or not isinstance(html_content, str):
        return []
    
    try:
        # Try BeautifulSoup first for best results
        return _parse_forms_with_beautifulsoup(html_content, base_url)
    except Exception as e:
        logger.warning(f"Form parsing failed: {e}")
        return []

def get_testable_fields(form_inputs: Dict) -> Dict[str, List[str]]:
    """
    Categorize form inputs into testable and protected fields.
    
    Args:
        form_inputs: Dictionary of form inputs from parse_forms
        
    Returns:
        Dictionary with 'testable' and 'protected' field lists
        {
            'testable': ['username', 'email', 'search'],  # Safe to test with payloads
            'protected': ['csrf_token', 'submit_btn']     # Should preserve original values
        }
    """
    
    testable = []
    protected = []
    
    for field_name, field_data in form_inputs.items():
        if isinstance(field_data, list):
            # Handle multiple inputs with same name
            field_data = field_data[0] if field_data else {}
        
        field_type = field_data.get('type', 'text').lower()
        
        # Protected field types and CSRF detection
        if (field_type in ['hidden', 'submit', 'button', 'image', 'reset'] or 
            field_data.get('is_csrf', False) or
            _is_csrf_field(field_name)):
            protected.append(field_name)
        elif field_type in ['text', 'email', 'search', 'password', 'url', 'tel', 
                           'number', 'textarea', 'select']:
            testable.append(field_name)
        else:
            # Unknown types default to testable for broader coverage
            testable.append(field_name)
    
    return {
        'testable': testable,
        'protected': protected
    }

def build_form_data(form_inputs: Dict, payload_data: Dict[str, str] = None) -> Dict[str, str]:
    """
    Build form submission data preserving protected fields and applying payloads.
    
    Args:
        form_inputs: Dictionary of form inputs from parse_forms
        payload_data: Dictionary of field_name -> payload_value for testing
        
    Returns:
        Dictionary ready for form submission
    """
    
    if payload_data is None:
        payload_data = {}
    
    form_data = {}
    
    for field_name, field_data in form_inputs.items():
        if isinstance(field_data, list):
            # Handle multiple inputs - use first for simplicity
            field_data = field_data[0] if field_data else {}
        
        field_type = field_data.get('type', 'text').lower()
        field_value = field_data.get('value', '')
        
        # Use payload if provided, otherwise use original value
        if field_name in payload_data:
            form_data[field_name] = payload_data[field_name]
        elif field_type == 'checkbox':
            # Include checkbox only if checked
            if field_data.get('checked', False):
                form_data[field_name] = field_value or '1'
        elif field_type == 'radio':
            # Include radio only if checked
            if field_data.get('checked', False):
                form_data[field_name] = field_value
        elif field_type == 'select':
            # Use selected value(s)
            if field_data.get('multiple', False):
                # Multiple select - use first selected value for simplicity
                values = field_data.get('value', [])
                if values and isinstance(values, list):
                    form_data[field_name] = values[0]
            else:
                form_data[field_name] = field_data.get('value', '')
        else:
            # Standard fields (text, hidden, password, etc.)
            form_data[field_name] = field_value
    
    return form_data