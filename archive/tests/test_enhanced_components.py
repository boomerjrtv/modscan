#!/usr/bin/env python3
"""
Unit Tests for Enhanced Vulnerability Scanner Components
Tests deterministic verifiers, knowledge base, attack graph, and telemetry
"""

import unittest
import asyncio
import aiohttp
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Import components to test
from deterministic_verifiers import DeterministicVerifiers, Evidence
from knowledge_base import KnowledgeBaseRetriever, KnowledgeDoc
from attack_graph import AttackGraph, Capability, CapabilityType
from telemetry import TelemetryCollector, ScanAttempt
from ai_planner import AIPlanner, TestPlan

class TestDeterministicVerifiers(unittest.TestCase):
    """Test deterministic vulnerability verifiers"""
    
    def setUp(self):
        self.verifiers = DeterministicVerifiers()
    
    def test_xss_context_analysis(self):
        """Test XSS context analysis"""
        content = '<div>User input: MODSCAN_XSS_12345</div>'
        context = self.verifiers._analyze_xss_context(content, 'MODSCAN_XSS_12345')
        
        self.assertEqual(context['location'], 'html_content')
        self.assertTrue(context['dangerous'])
        self.assertIn('MODSCAN_XSS_12345', context['surrounding'])
    
    def test_xss_context_script_tag(self):
        """Test XSS in script tag context"""
        content = '<script>var data = "MODSCAN_XSS_12345";</script>'
        context = self.verifiers._analyze_xss_context(content, 'MODSCAN_XSS_12345')
        
        self.assertEqual(context['location'], 'script_tag')
        self.assertTrue(context['dangerous'])
    
    def test_parameter_injection(self):
        """Test parameter injection in URL"""
        url = "http://example.com/test?id=1&name=test"
        result = self.verifiers._inject_parameter(url, 'id', "' OR 1=1--")
        
        self.assertIn("id=%27+OR+1%3D1--", result)
        self.assertIn("name=test", result)
    
    def test_content_similarity(self):
        """Test content similarity calculation"""
        content1 = "This is a test response with some content"
        content2 = "This is a test response with different content"
        content3 = "Completely different response entirely"
        
        sim1 = self.verifiers._content_similarity(content1, content2)
        sim2 = self.verifiers._content_similarity(content1, content3)
        
        self.assertGreater(sim1, sim2)  # More similar content should have higher score
        self.assertGreater(sim1, 0.5)   # Should be reasonably similar
        self.assertLess(sim2, 0.5)      # Should be less similar
    
    def test_dangerous_redirect_detection(self):
        """Test dangerous redirect detection"""
        # Test cases
        test_cases = [
            ("http://evil.com", "http://evil.com", True),
            ("//evil.com", "//evil.com", True),
            ("javascript:alert(1)", "javascript:alert(1)", True),
            ("data:text/html,<script>alert(1)</script>", "data:text/html,<script>alert(1)</script>", True),
            ("/internal/page", "/internal/page", False),  # Internal redirect
            ("", "", False),  # Empty
        ]
        
        for location, target, expected in test_cases:
            result = self.verifiers._is_dangerous_redirect(location, target)
            self.assertEqual(result, expected, f"Failed for {location} -> {target}")

class TestKnowledgeBase(unittest.TestCase):
    """Test knowledge base functionality"""
    
    def setUp(self):
        # Create temporary directory for test database
        self.temp_dir = Path(tempfile.mkdtemp())
        self.kb = KnowledgeBaseRetriever(self.temp_dir)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_vulnerability_category_normalization(self):
        """Test vulnerability category normalization"""
        test_cases = [
            ("xss_reflected", "xss"),
            ("sql_injection", "sqli"),
            ("server_side_request_forgery", "ssrf"),
            ("cross_site_request_forgery", "csrf"),
            ("insecure_direct_object_reference", "idor"),
            ("open_redirect", "open_redirect"),
            ("unknown_vulnerability", "unknown_vulnerability")
        ]
        
        for input_type, expected in test_cases:
            result = self.kb._normalize_vuln_category(input_type)
            self.assertEqual(result, expected, f"Failed for {input_type}")
    
    def test_cwe_mapping(self):
        """Test CWE mapping for vulnerability types"""
        test_cases = [
            ("xss", "CWE-79"),
            ("sqli", "CWE-89"),
            ("ssrf", "CWE-918"),
            ("open_redirect", "CWE-601"),
            ("idor", "CWE-639"),
            ("csrf", "CWE-352"),
        ]
        
        for vuln_type, expected_cwe in test_cases:
            result = self.kb._vuln_type_to_cwe(vuln_type)
            self.assertEqual(result, expected_cwe, f"Failed for {vuln_type}")
    
    def test_fts_query_building(self):
        """Test FTS query construction"""
        fingerprint = {
            'stack': ['php', 'mysql'],
            'params': ['id', 'name']
        }
        
        query = self.kb._build_fts_query("xss reflected", fingerprint)
        
        # Should contain relevant terms
        self.assertIn("xss", query.lower())
        self.assertIn("reflected", query.lower())
        # Technology terms might be added
        self.assertTrue(len(query) > 0)
    
    def test_fingerprint_boost_calculation(self):
        """Test fingerprint-based relevance boosting"""
        doc = KnowledgeDoc(
            id="test_doc",
            title="PHP XSS Vulnerability",
            type="payload_family",
            category="xss",
            content="PHP-based XSS attack vectors",
            payloads=["<script>alert(1)</script>"],
            metadata={"severity": "high", "report_count": 150}
        )
        
        fingerprint = {"stack": ["php", "apache"]}
        boost = self.kb._calculate_fingerprint_boost(doc, fingerprint)
        
        self.assertGreater(boost, 1.0)  # Should get boost for matching tech stack

class TestAttackGraph(unittest.TestCase):
    """Test attack graph and chaining functionality"""
    
    def setUp(self):
        self.graph = AttackGraph()
    
    def test_capability_addition(self):
        """Test adding capabilities to graph"""
        capability = Capability(
            id="test_capability",
            name="Test Capability",
            type=CapabilityType.ACCESS,
            description="Test capability for unit tests",
            requirements=[],
            provides=["test_access"],
            priority=0.8,
            complexity=0.3,
            stealth=0.7,
            reliability=0.9,
            vulnerability_type="test",
            attack_vector="test",
            payloads=["test_payload"],
            evidence_required=["test_evidence"]
        )
        
        self.assertTrue(self.graph.add_capability(capability))
        self.assertIn("test_capability", self.graph.capabilities)
        self.assertEqual(self.graph.capabilities["test_capability"].name, "Test Capability")
    
    def test_pathfinding_basic(self):
        """Test basic pathfinding between capabilities"""
        # Should find paths from info_disclosure to sqli_error_based
        paths = self.graph.find_attack_paths(
            current_capabilities=["info_disclosure"],
            target_capabilities=["sqli_error_based"],
            max_paths=5
        )
        
        self.assertGreater(len(paths), 0, "Should find at least one attack path")
        
        for path in paths:
            self.assertIn("info_disclosure", path.capabilities)
            self.assertIn("sqli_error_based", path.capabilities)
            self.assertGreater(path.success_probability, 0)
            self.assertGreater(path.estimated_time, 0)
    
    def test_next_action_suggestions(self):
        """Test next action suggestions"""
        current_capabilities = ["info_disclosure"]
        suggestions = self.graph.suggest_next_actions(current_capabilities)
        
        self.assertGreater(len(suggestions), 0, "Should provide suggestions")
        
        for capability_id, priority in suggestions:
            self.assertIn(capability_id, self.graph.capabilities)
            self.assertGreater(priority, 0)
            self.assertLessEqual(priority, 1.0)
    
    def test_condition_checking(self):
        """Test condition evaluation logic"""
        context = {
            'tech_stack': ['php', 'mysql'],
            'parameters': ['id', 'name'],
            'login_form': True
        }
        
        # Test various conditions
        test_cases = [
            ("sql_database_detected", True),
            ("injectable_parameter", True),
            ("login_form_injectable", True),
            ("nonexistent_condition", True),  # Default optimistic
        ]
        
        for condition, expected in test_cases:
            result = self.graph._check_condition(condition, context)
            self.assertEqual(result, expected, f"Failed for condition: {condition}")
    
    def test_graph_export_import(self):
        """Test graph export and import functionality"""
        # Export graph
        exported_data = self.graph.export_graph()
        
        self.assertIn('capabilities', exported_data)
        self.assertIn('edges', exported_data)
        self.assertIn('metadata', exported_data)
        
        # Create new graph and import
        new_graph = AttackGraph()
        new_graph.capabilities.clear()  # Start empty
        new_graph.edges.clear()
        
        success = new_graph.import_graph(exported_data)
        self.assertTrue(success)
        
        # Verify import
        self.assertEqual(len(new_graph.capabilities), len(self.graph.capabilities))
        self.assertEqual(len(new_graph.edges), len(self.graph.edges))

class TestTelemetry(unittest.TestCase):
    """Test telemetry and logging functionality"""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.telemetry = TelemetryCollector(self.temp_dir)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scan_attempt_logging(self):
        """Test scan attempt logging"""
        attempt = ScanAttempt(
            timestamp="2024-01-01T12:00:00Z",
            correlation_id="test-123",
            target="http://example.com",
            action_id="test_action",
            method="GET",
            request_summary={"param": "id", "payload": "' OR 1=1--"},
            response_summary={"status": 200, "length": 1024},
            evidence_hits=["sql_error_detected"],
            confidence_score=0.9,
            success=True,
            source_docs=["doc_1"],
            runtime_ms=250,
            proxy_used=None,
            vulnerability_type="sqli"
        )
        
        self.telemetry.log_attempt(attempt)
        
        # Verify file exists and contains data
        self.assertTrue(self.telemetry.attempts_log_path.exists())
        
        with open(self.telemetry.attempts_log_path, 'r') as f:
            logged_data = f.read()
            self.assertIn("test-123", logged_data)
            self.assertIn("sql_error_detected", logged_data)
    
    def test_artifact_storage(self):
        """Test artifact storage"""
        content = "<html><body>Test content with SQL error</body></html>"
        
        artifact = self.telemetry.store_artifact(
            content=content,
            artifact_type="html_response",
            metadata={"test": True}
        )
        
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact.type, "html_response")
        self.assertEqual(artifact.size_bytes, len(content.encode()))
        self.assertTrue(Path(artifact.path).exists())
    
    def test_session_stats(self):
        """Test session statistics tracking"""
        # Log some attempts to generate stats
        for i in range(5):
            attempt = ScanAttempt(
                timestamp="2024-01-01T12:00:00Z",
                correlation_id=f"test-{i}",
                target="http://example.com",
                action_id=f"action_{i}",
                method="GET",
                request_summary={},
                response_summary={},
                evidence_hits=[],
                confidence_score=0.8 if i % 2 == 0 else 0.0,
                success=i % 2 == 0,
                source_docs=[],
                runtime_ms=100 + i * 10,
                proxy_used=None
            )
            self.telemetry.log_attempt(attempt)
        
        stats = self.telemetry.get_session_stats()
        
        self.assertEqual(stats['attempts_total'], 5)
        self.assertEqual(stats['attempts_success'], 3)  # 0, 2, 4 are successful
        self.assertAlmostEqual(stats['success_rate'], 0.6, places=1)
        self.assertGreater(stats['average_response_time'], 100)
    
    def test_fluent_logging_api(self):
        """Test fluent logging API"""
        from telemetry import log_scan_attempt
        
        # Test fluent interface
        attempt = log_scan_attempt("http://test.com", "xss_test") \
            .with_payload("<script>alert(1)</script>") \
            .with_request(method="GET", param="search") \
            .with_response(status=200, length=2048) \
            .with_evidence("script_reflected_in_response") \
            .success(0.95) \
            .commit()
        
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt.target, "http://test.com")
        self.assertEqual(attempt.payload, "<script>alert(1)</script>")
        self.assertTrue(attempt.success)
        self.assertEqual(attempt.confidence_score, 0.95)

class TestAIPlanner(unittest.TestCase):
    """Test AI planner functionality"""
    
    def setUp(self):
        self.config = {"gemini_api_key": "test_key"}
        self.planner = AIPlanner(self.config)
    
    def test_fingerprint_building(self):
        """Test target fingerprint construction"""
        fingerprint = self.planner.build_fingerprint(
            url="http://example.com/test",
            tech_stack=["php", "mysql"],
            params=["id", "name"],
            headers={"Server": "Apache/2.4"}
        )
        
        self.assertEqual(fingerprint['base_url'], "http://example.com/test")
        self.assertIn("php", fingerprint['stack'])
        self.assertIn("mysql", fingerprint['stack'])
        self.assertIn("id", fingerprint['params'])
    
    def test_json_schema_validation(self):
        """Test JSON schema validation"""
        valid_plan = {
            "plan_version": "1.0",
            "target": {
                "base_url": "http://example.com",
                "stack": ["php"],
                "assumptions": ["Has SQL injection"]
            },
            "actions": [{
                "id": "act-001",
                "vuln_class": "xss.reflected",
                "endpoint": "/search",
                "method": "GET",
                "param": "q",
                "payloads": ["<script>alert(1)</script>"],
                "mutations": [],
                "headers": {},
                "evidence_checks": {
                    "reflects_marker": True,
                    "regex_any": ["<script>"],
                    "status_any": [200]
                },
                "priority": 0.8,
                "source_docs": ["doc1"]
            }],
            "oob": {"enabled": False},
            "reporting": {"artifacts": ["html"]}
        }
        
        self.assertTrue(self.planner._validate_plan_schema(valid_plan))
    
    def test_invalid_json_schema(self):
        """Test invalid JSON schema rejection"""
        invalid_plan = {
            "plan_version": "1.0",
            "target": {},  # Missing required base_url
            "actions": []  # Empty actions array
        }
        
        self.assertFalse(self.planner._validate_plan_schema(invalid_plan))
    
    def test_json_extraction(self):
        """Test JSON extraction from AI response"""
        response_with_json = '''Here is the test plan:
        
        {
            "plan_version": "1.0",
            "target": {"base_url": "http://test.com"},
            "actions": []
        }
        
        This plan should work well.'''
        
        extracted = self.planner._extract_json_from_response(response_with_json)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted['plan_version'], "1.0")
        self.assertEqual(extracted['target']['base_url'], "http://test.com")

def run_async_test(coro):
    """Helper to run async test functions"""
    return asyncio.get_event_loop().run_until_complete(coro)

class TestIntegration(unittest.TestCase):
    """Integration tests for enhanced scanner components"""
    
    def test_knowledge_base_to_planner_flow(self):
        """Test flow from knowledge base to AI planner"""
        # Create temp knowledge base
        temp_dir = Path(tempfile.mkdtemp())
        try:
            kb = KnowledgeBaseRetriever(temp_dir)
            
            # Query knowledge base
            docs = kb.get_relevant_docs("xss", {"stack": ["php"]}, k=3)
            
            # Should get some docs
            self.assertGreater(len(docs), 0)
            
            # Should have XSS-related content
            xss_docs = [doc for doc in docs if 'xss' in doc.category.lower()]
            self.assertGreater(len(xss_docs), 0)
            
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_verifiers_to_telemetry_flow(self):
        """Test flow from verifiers to telemetry"""
        # Create temp telemetry
        temp_dir = Path(tempfile.mkdtemp())
        try:
            from telemetry import log_scan_attempt
            
            # Simulate verification result
            log_scan_attempt("http://test.com", "xss_verification") \
                .with_payload("<script>alert(1)</script>") \
                .with_evidence("script_reflected") \
                .success(0.9) \
                .commit()
            
            # Should have logged the attempt
            from telemetry import get_session_stats
            stats = get_session_stats()
            self.assertGreater(stats['attempts_total'], 0)
            
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.WARNING)  # Reduce noise during tests
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestDeterministicVerifiers,
        TestKnowledgeBase,
        TestAttackGraph,
        TestTelemetry,
        TestAIPlanner,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, trace in result.failures:
            print(f"  - {test}: {trace.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, trace in result.errors:
            print(f"  - {test}: {trace.split('Exception:')[-1].strip()}")