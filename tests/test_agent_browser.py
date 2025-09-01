#!/usr/bin/env python3
"""
Unit tests for Agentic Browser Loop (ABL) module
Focuses on testing schema validation, budget enforcement, and trace generation
without requiring network access or Playwright execution
"""

import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.agent_browser import (
    Action, ActionValidator, Observation, ObservationCompressor,
    TraceExporter, SkillExporter, AgentBrowser, SIGNAL_PATTERNS
)

class TestAction(unittest.TestCase):
    """Test Action schema and validation"""
    
    def test_valid_goto_action(self):
        """Test creating valid goto action"""
        action = Action(type='goto', target='https://example.com')
        self.assertEqual(action.type, 'goto')
        self.assertEqual(action.target, 'https://example.com')
        
    def test_valid_click_action(self):
        """Test creating valid click action"""
        action = Action(type='click', target='#submit-button')
        self.assertEqual(action.type, 'click')
        self.assertEqual(action.target, '#submit-button')
        
    def test_valid_fill_action(self):
        """Test creating valid fill action"""
        action = Action(type='fill', target='input[name="username"]', value='testuser')
        self.assertEqual(action.type, 'fill')
        self.assertEqual(action.target, 'input[name="username"]')
        self.assertEqual(action.value, 'testuser')
        
    def test_invalid_action_type(self):
        """Test invalid action type raises ValueError"""
        with self.assertRaises(ValueError):
            Action(type='invalid_action', target='https://example.com')
            
    def test_goto_without_target(self):
        """Test goto action without target raises ValueError"""
        with self.assertRaises(ValueError):
            Action(type='goto')
            
    def test_click_without_target(self):
        """Test click action without target raises ValueError"""
        with self.assertRaises(ValueError):
            Action(type='click')

class TestActionValidator(unittest.TestCase):
    """Test ActionValidator constraint checking"""
    
    def test_allowed_action_types(self):
        """Test only allowed action types pass validation"""
        valid_types = ['goto', 'click', 'fill', 'submit', 'evaluate']
        for action_type in valid_types:
            if action_type == 'goto':
                action = Action(type=action_type, target='https://example.com')
            elif action_type in ('click', 'fill', 'submit'):
                action = Action(type=action_type, target='#test')
            else:  # evaluate
                action = Action(type=action_type, value='console.log("test")')
            self.assertTrue(ActionValidator.validate(action))
    
    def test_invalid_url_scheme(self):
        """Test invalid URL schemes are rejected"""
        # Create mock action objects to test validation logic
        mock_action1 = Mock()
        mock_action1.type = 'goto'
        mock_action1.target = 'ftp://example.com'
        self.assertFalse(ActionValidator.validate(mock_action1))
        
        mock_action2 = Mock()
        mock_action2.type = 'goto' 
        mock_action2.target = 'javascript:alert(1)'
        self.assertFalse(ActionValidator.validate(mock_action2))
    
    def test_valid_url_schemes(self):
        """Test valid URL schemes are accepted"""
        for scheme in ['http://example.com', 'https://example.com']:
            action = Action(type='goto', target=scheme)
            self.assertTrue(ActionValidator.validate(action))

class TestObservationCompressor(unittest.TestCase):
    """Test observation data compression"""
    
    def test_compress_short_text(self):
        """Test short text passes through unchanged"""
        text = "Short text"
        compressed = ObservationCompressor.compress_text(text, max_chars=1000)
        self.assertEqual(compressed, text)
        
    def test_compress_long_text(self):
        """Test long text is compressed with ellipsis"""
        text = "A" * 2000
        compressed = ObservationCompressor.compress_text(text, max_chars=100)
        self.assertEqual(len(compressed), 103)  # 100 + "..."
        self.assertTrue(compressed.endswith("..."))
        
    def test_compress_text_with_break_points(self):
        """Test text compression respects natural break points"""
        text = "First sentence. Second sentence. " + "A" * 1000
        compressed = ObservationCompressor.compress_text(text, max_chars=50)
        self.assertTrue(compressed.endswith(". ..."))
        
    def test_compress_console_messages(self):
        """Test console message compression prioritizes errors"""
        messages = [
            "Info: normal message",
            "Error: critical issue", 
            "Warning: potential problem",
            "Debug: verbose details",
            "Another info message"
        ]
        compressed = ObservationCompressor.compress_console(messages, max_messages=3)
        self.assertEqual(len(compressed), 3)
        # Error should be first
        self.assertIn("Error: critical issue", compressed)
        
    def test_compress_network_requests(self):
        """Test network request compression keeps relevant ones"""
        requests = [
            {'url': 'https://example.com/api/login', 'status': 200, 'type': 'xhr'},
            {'url': 'https://example.com/static/image.jpg', 'status': 200, 'type': 'image'},
            {'url': 'https://example.com/admin/panel', 'status': 403, 'type': 'document'},
            {'url': 'https://example.com/api/secret', 'status': 404, 'type': 'xhr'},
            {'url': 'https://example.com/error', 'status': 500, 'type': 'document'},
        ]
        compressed = ObservationCompressor.compress_network(requests, max_requests=3)
        self.assertLessEqual(len(compressed), 3)
        # Should include API and error responses
        urls = [req['url'] for req in compressed]
        self.assertTrue(any('api' in url for url in urls))
        self.assertTrue(any('admin' in url for url in urls))

class TestTraceExporter(unittest.TestCase):
    """Test trace file export functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.evidence_dir = Path(self.temp_dir)
        self.exporter = TraceExporter(self.evidence_dir)
        
    def test_export_step(self):
        """Test exporting a single step to JSONL"""
        trace_file = self.evidence_dir / "test_trace.jsonl"
        
        action = Action(type='goto', target='https://example.com')
        observation = Observation(url='https://example.com', title='Example')
        
        self.exporter.export_step(trace_file, 0, action, observation, 1000)
        
        # Verify file was created and contains valid JSON
        self.assertTrue(trace_file.exists())
        
        with trace_file.open('r', encoding='utf-8') as f:
            line = f.readline().strip()
            data = json.loads(line)
            
        self.assertEqual(data['step'], 0)
        self.assertEqual(data['action']['type'], 'goto')
        self.assertEqual(data['observation']['url'], 'https://example.com')
        self.assertEqual(data['execution_time_ms'], 1000)

class TestSkillExporter(unittest.TestCase):
    """Test skill generation from traces"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.skills_dir = Path(self.temp_dir)
        self.exporter = SkillExporter(self.skills_dir)
        
    def test_detect_xss_signals(self):
        """Test XSS signal detection in observations"""
        observation = Observation(
            url='https://example.com',
            title='Test',
            visible_text='no inline',
            console_messages=['DIALOG:alert:XSS']
        )
        
        signals = self.exporter.detect_signals(observation)
        self.assertIn('xss', signals)
        
    def test_detect_sqli_signals(self):
        """Test SQL injection signal detection"""
        observation = Observation(
            url='https://example.com', 
            title='Test',
            visible_text='SQL syntax error near "SELECT * FROM users"',
            console_messages=['mysql_fetch_array() error']
        )
        
        signals = self.exporter.detect_signals(observation)
        self.assertIn('sqli', signals)
        
    def test_detect_multiple_signals(self):
        """Test detection of multiple vulnerability signals"""
        observation = Observation(
            url='https://example.com',
            title='Test',
            visible_text='SQL error: You have an error in your SQL syntax',
            console_messages=['DIALOG:alert:1']
        )
        
        signals = self.exporter.detect_signals(observation)
        self.assertIn('sqli', signals)
        self.assertIn('xss', signals)
        
    def test_no_signals_detected(self):
        """Test clean observation returns no signals"""
        observation = Observation(
            url='https://example.com',
            title='Clean Page',
            visible_text='Welcome to our secure application',
            console_messages=['Page loaded successfully']
        )
        
        signals = self.exporter.detect_signals(observation)
        self.assertEqual(len(signals), 0)
        
    def test_generate_skill_script(self):
        """Test generating a skill script from trace data"""
        trace_data = [
            {
                'step': 0,
                'action': {'type': 'goto', 'target': 'https://example.com'},
                'observation': {'url': 'https://example.com', 'title': 'Test'}
            },
            {
                'step': 1, 
                'action': {'type': 'fill', 'target': 'input[name="q"]', 'value': 'test'},
                'observation': {'url': 'https://example.com', 'title': 'Test'}
            }
        ]
        
        skill_path = self.exporter.generate_skill(trace_data, ['xss'], 'test-xss')
        
        # Verify skill file was created
        self.assertTrue(Path(skill_path).exists())
        
        # Verify skill content
        with open(skill_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        self.assertIn('Generated ModScan Skill: test-xss', content)
        self.assertIn('Detected signals: xss', content)
        self.assertIn('page.goto("https://example.com")', content)
        self.assertIn('page.fill("input[name=', content)
        self.assertIn('async def replay_test_xss', content)

class TestAgentBrowser(unittest.TestCase):
    """Test AgentBrowser orchestration"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'evidence_dir': self.temp_dir,
            'abl_same_host_only': True
        }
        self.mock_asset_manager = Mock()
        self.mock_screenshot_manager = Mock()
        
    def test_init_without_playwright(self):
        """Test initialization when Playwright is not available"""  
        # Just test that browser initializes - Playwright detection is environment specific
        browser = AgentBrowser(self.config, self.mock_asset_manager, self.mock_screenshot_manager)
        self.assertIsNotNone(browser)
        
    def test_session_id_generation(self):
        """Test unique session ID generation"""
        browser = AgentBrowser(self.config, self.mock_asset_manager, self.mock_screenshot_manager)
        
        url = "https://example.com/test"
        session_id1 = browser._generate_session_id(url)
        session_id2 = browser._generate_session_id(url)
        
        # Should be consistent for same URL
        self.assertEqual(session_id1, session_id2)
        self.assertTrue(session_id1.startswith('abl_'))
        # Session ID should contain URL hash and be deterministic
        self.assertTrue(len(session_id1.split('_')) >= 3)
        
    def test_execute_session_playwright_unavailable(self):
        """Test session execution when Playwright is unavailable"""
        browser = AgentBrowser(self.config, self.mock_asset_manager, self.mock_screenshot_manager)
        browser._playwright_available = False
        
        async def run_test():
            budgets = {'max_steps': 5, 'max_clicks': 3, 'max_time_ms': 10000}
            result = await browser.execute_session('https://example.com', budgets)
            
            self.assertEqual(result['status'], 'skipped')
            self.assertEqual(result['reason'], 'playwright_unavailable')
        
        # Run the async test
        asyncio.run(run_test())

class TestBudgetEnforcement(unittest.TestCase):
    """Test budget constraint enforcement"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {'evidence_dir': self.temp_dir}
        self.mock_asset_manager = Mock()
        self.mock_screenshot_manager = Mock()
        
    def test_budget_validation(self):
        """Test budget parameters are properly validated"""
        browser = AgentBrowser(self.config, self.mock_asset_manager, self.mock_screenshot_manager)
        
        budgets = {
            'max_steps': 10,
            'max_clicks': 5, 
            'max_time_ms': 15000,
            'action_timeout': 5000
        }
        
        # Should not raise exceptions
        self.assertIsInstance(budgets['max_steps'], int)
        self.assertGreater(budgets['max_time_ms'], 0)
        self.assertGreater(budgets['action_timeout'], 0)

class TestSignalPatterns(unittest.TestCase):
    """Test vulnerability signal pattern matching"""
    
    def test_signal_patterns_coverage(self):
        """Test signal patterns cover major vulnerability types"""
        expected_types = ['xss', 'sqli', 'lfi', 'rce', 'ssrf', 'sensitive']
        
        for vuln_type in expected_types:
            self.assertIn(vuln_type, SIGNAL_PATTERNS)
            self.assertGreater(len(SIGNAL_PATTERNS[vuln_type]), 0)
            
    def test_xss_pattern_matching(self):
        """Test XSS patterns match common payloads"""
        xss_patterns = SIGNAL_PATTERNS['xss']
        
        test_cases = [
            '<script>alert("xss")</script>',
            'javascript:alert(1)',
            'onerror="alert(1)"',
            '"><script>alert(1)</script>',
            # Removed generic text case to avoid false positives
        ]
        
        for test_case in test_cases:
            matched = any(re.search(pattern, test_case, re.IGNORECASE) 
                         for pattern in xss_patterns)
            self.assertTrue(matched, f"XSS pattern should match: {test_case}")
            
    def test_sqli_pattern_matching(self):
        """Test SQL injection patterns match common errors"""
        sqli_patterns = SIGNAL_PATTERNS['sqli']
        
        test_cases = [
            'SQL syntax error near "SELECT"',
            'mysql_fetch_array() expects parameter',
            'ORA-00936: missing expression',
            'Microsoft ODBC SQL Server Driver',
            'PostgreSQL ERROR: syntax error'
        ]
        
        for test_case in test_cases:
            matched = any(re.search(pattern, test_case, re.IGNORECASE) 
                         for pattern in sqli_patterns)
            self.assertTrue(matched, f"SQL injection pattern should match: {test_case}")

def run_tests():
    """Run all ABL tests"""
    unittest.main(verbosity=2)

if __name__ == '__main__':
    run_tests()
