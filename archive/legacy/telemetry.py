#!/usr/bin/env python3
"""
Telemetry, Artifacts, and Structured Logging System
Comprehensive logging and evidence collection for vulnerability scanning
"""

import json
import logging
import time
import hashlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import uuid
import gzip

logger = logging.getLogger(__name__)

@dataclass
class ScanAttempt:
    """Single scan attempt record for detailed telemetry"""
    timestamp: str
    correlation_id: str
    target: str
    action_id: str
    method: str
    request_summary: Dict[str, Any]
    response_summary: Dict[str, Any]
    evidence_hits: List[str]
    confidence_score: float
    success: bool
    source_docs: List[str]
    runtime_ms: int
    proxy_used: Optional[str]
    error_message: Optional[str] = None
    vulnerability_type: Optional[str] = None
    payload: Optional[str] = None
    
    def __post_init__(self):
        if isinstance(self.timestamp, datetime):
            self.timestamp = self.timestamp.isoformat()

@dataclass
class Artifact:
    """Evidence artifact (HTML, headers, screenshots, etc.)"""
    id: str
    type: str  # 'html_response', 'http_headers', 'screenshot', 'har_file'
    path: str
    size_bytes: int
    content_hash: str
    created_at: str
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        if isinstance(self.created_at, datetime):
            self.created_at = self.created_at.isoformat()

class TelemetryCollector:
    """
    High-performance telemetry collection with structured logging.
    Stores attempt logs, artifacts, and performance metrics.
    """
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path(__file__).parent
        self.runs_dir = self.base_dir / "runs"
        self.artifacts_dir = self.base_dir / "artifacts"
        self.telemetry_dir = self.base_dir / "telemetry"
        
        # Create directories
        for dir_path in [self.runs_dir, self.artifacts_dir, self.telemetry_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Current session info
        self.session_id = self._generate_session_id()
        self.session_start = datetime.now(timezone.utc)
        
        # Performance tracking
        self.metrics = {
            'attempts_total': 0,
            'attempts_success': 0,
            'vulnerabilities_found': 0,
            'false_positives': 0,
            'average_response_time': 0.0,
            'total_runtime': 0.0
        }
        
        # File handles for efficient logging
        self._attempts_file = None
        self._init_log_files()
        
        logger.info(f"Telemetry session started: {self.session_id}")
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = uuid.uuid4().hex[:8]
        return f"session_{timestamp}_{random_suffix}"
    
    def _init_log_files(self):
        """Initialize log files for current session"""
        self.attempts_log_path = self.runs_dir / f"{self.session_id}_attempts.jsonl"
        self.session_log_path = self.runs_dir / f"{self.session_id}_session.json"
        
        # Write session metadata
        session_metadata = {
            'session_id': self.session_id,
            'start_time': self.session_start.isoformat(),
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
            'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}",
            'working_directory': str(self.base_dir)
        }
        
        with open(self.session_log_path, 'w') as f:
            json.dump(session_metadata, f, indent=2)
    
    def log_attempt(self, attempt: ScanAttempt):
        """Log a single scan attempt with structured data"""
        try:
            # Update metrics
            self.metrics['attempts_total'] += 1
            if attempt.success:
                self.metrics['attempts_success'] += 1
            if attempt.vulnerability_type:
                self.metrics['vulnerabilities_found'] += 1
            
            self.metrics['total_runtime'] += attempt.runtime_ms
            if self.metrics['attempts_total'] > 0:
                self.metrics['average_response_time'] = (
                    self.metrics['total_runtime'] / self.metrics['attempts_total']
                )
            
            # Write to JSONL file (one line per attempt)
            attempt_json = json.dumps(asdict(attempt), separators=(',', ':'))
            with open(self.attempts_log_path, 'a', encoding='utf-8') as f:
                f.write(attempt_json + '\n')
            
        except Exception as e:
            logger.error(f"Failed to log attempt: {e}")
    
    def store_artifact(self, content: Union[str, bytes], artifact_type: str,
                      metadata: Dict[str, Any] = None, file_extension: str = None) -> Optional[Artifact]:
        """
        Store an artifact (HTML, headers, screenshot) with metadata.
        
        Args:
            content: Raw content to store
            artifact_type: Type of artifact ('html_response', 'http_headers', etc.)
            metadata: Additional metadata
            file_extension: File extension (auto-detected if None)
            
        Returns:
            Artifact object or None if storage fails
        """
        try:
            # Generate artifact ID and hash
            artifact_id = self._generate_artifact_id(artifact_type)
            
            if isinstance(content, str):
                content_bytes = content.encode('utf-8')
            else:
                content_bytes = content
            
            content_hash = hashlib.sha256(content_bytes).hexdigest()[:16]
            
            # Determine file extension
            if not file_extension:
                file_extension = self._get_file_extension(artifact_type)
            
            # Create artifact file path
            artifact_filename = f"{artifact_id}_{content_hash}.{file_extension}"
            artifact_path = self.artifacts_dir / artifact_filename
            
            # Store content (compressed for large artifacts)
            if len(content_bytes) > 10240:  # 10KB threshold
                with gzip.open(f"{artifact_path}.gz", 'wb') as f:
                    f.write(content_bytes)
                artifact_path = f"{artifact_path}.gz"
            else:
                with open(artifact_path, 'wb') as f:
                    f.write(content_bytes)
            
            # Create artifact record
            artifact = Artifact(
                id=artifact_id,
                type=artifact_type,
                path=str(artifact_path),
                size_bytes=len(content_bytes),
                content_hash=content_hash,
                created_at=datetime.now(timezone.utc).isoformat(),
                metadata=metadata or {}
            )
            
            return artifact
            
        except Exception as e:
            logger.error(f"Failed to store artifact: {e}")
            return None
    
    def _generate_artifact_id(self, artifact_type: str) -> str:
        """Generate unique artifact ID"""
        timestamp = int(time.time() * 1000)  # milliseconds
        type_prefix = artifact_type.replace('_', '').lower()[:4]
        random_suffix = uuid.uuid4().hex[:6]
        return f"{type_prefix}_{timestamp}_{random_suffix}"
    
    def _get_file_extension(self, artifact_type: str) -> str:
        """Get appropriate file extension for artifact type"""
        extensions = {
            'html_response': 'html',
            'http_headers': 'json',
            'screenshot': 'png',
            'har_file': 'har',
            'curl_command': 'sh',
            'raw_request': 'txt',
            'raw_response': 'txt',
            'payload_list': 'json',
            'evidence_data': 'json'
        }
        return extensions.get(artifact_type, 'dat')
    
    @contextmanager
    def track_operation(self, operation_name: str, target: str = "", 
                       extra_metadata: Dict[str, Any] = None):
        """
        Context manager to track operation duration and results.
        
        Usage:
            with telemetry.track_operation("sql_injection_test", target_url) as tracker:
                result = perform_sqli_test()
                tracker.set_result(result)
        """
        correlation_id = str(uuid.uuid4())
        start_time = time.time()
        metadata = extra_metadata or {}
        
        class OperationTracker:
            def __init__(self):
                self.result = None
                self.success = False
                self.error = None
                self.evidence = []
                self.artifacts = []
            
            def set_result(self, result, success=True):
                self.result = result
                self.success = success
            
            def set_error(self, error):
                self.error = str(error)
                self.success = False
            
            def add_evidence(self, evidence_item):
                self.evidence.append(evidence_item)
            
            def add_artifact(self, artifact):
                self.artifacts.append(artifact)
        
        tracker = OperationTracker()
        
        try:
            yield tracker
        except Exception as e:
            tracker.set_error(e)
            raise
        finally:
            end_time = time.time()
            runtime_ms = int((end_time - start_time) * 1000)
            
            # Create scan attempt record
            attempt = ScanAttempt(
                timestamp=datetime.now(timezone.utc).isoformat(),
                correlation_id=correlation_id,
                target=target,
                action_id=operation_name,
                method="TRACK",
                request_summary=metadata,
                response_summary={"result": str(tracker.result) if tracker.result else None},
                evidence_hits=[str(e) for e in tracker.evidence],
                confidence_score=1.0 if tracker.success else 0.0,
                success=tracker.success,
                source_docs=[],
                runtime_ms=runtime_ms,
                proxy_used=metadata.get('proxy'),
                error_message=tracker.error
            )
            
            self.log_attempt(attempt)
    
    def create_scan_attempt(self, target: str, action_id: str, method: str = "GET",
                          vulnerability_type: str = None) -> 'ScanAttemptBuilder':
        """Create a scan attempt builder for fluent logging"""
        return ScanAttemptBuilder(self, target, action_id, method, vulnerability_type)
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get current session statistics"""
        current_time = datetime.now(timezone.utc)
        session_duration = (current_time - self.session_start).total_seconds()
        
        stats = self.metrics.copy()
        stats.update({
            'session_id': self.session_id,
            'session_duration_seconds': session_duration,
            'attempts_per_minute': (self.metrics['attempts_total'] / max(session_duration / 60, 0.1)),
            'success_rate': (self.metrics['attempts_success'] / max(self.metrics['attempts_total'], 1)),
            'artifacts_stored': len(list(self.artifacts_dir.glob('*'))),
            'log_file_size_mb': (self.attempts_log_path.stat().st_size / 1024 / 1024) if self.attempts_log_path.exists() else 0
        })
        
        return stats
    
    def export_session_report(self, output_path: Path = None) -> str:
        """Export comprehensive session report"""
        if not output_path:
            output_path = self.telemetry_dir / f"{self.session_id}_report.json"
        
        report = {
            'session_info': {
                'session_id': self.session_id,
                'start_time': self.session_start.isoformat(),
                'end_time': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': (datetime.now(timezone.utc) - self.session_start).total_seconds()
            },
            'statistics': self.get_session_stats(),
            'files': {
                'attempts_log': str(self.attempts_log_path),
                'artifacts_directory': str(self.artifacts_dir),
                'session_metadata': str(self.session_log_path)
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Session report exported to: {output_path}")
        return str(output_path)
    
    def cleanup_old_sessions(self, days_to_keep: int = 30):
        """Clean up old session data"""
        cutoff_time = datetime.now(timezone.utc).timestamp() - (days_to_keep * 24 * 3600)
        
        cleaned_files = 0
        for log_file in self.runs_dir.glob('session_*'):
            try:
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    cleaned_files += 1
            except OSError:
                continue
        
        # Clean up orphaned artifacts
        for artifact_file in self.artifacts_dir.glob('*'):
            try:
                if artifact_file.stat().st_mtime < cutoff_time:
                    artifact_file.unlink()
            except OSError:
                continue
        
        logger.info(f"Cleaned up {cleaned_files} old session files")

class ScanAttemptBuilder:
    """Fluent builder for creating scan attempt records"""
    
    def __init__(self, collector: TelemetryCollector, target: str, 
                action_id: str, method: str, vulnerability_type: str = None):
        self.collector = collector
        self.target = target
        self.action_id = action_id
        self.method = method
        self.vulnerability_type = vulnerability_type
        
        # Initialize with defaults
        self.correlation_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.request_summary = {}
        self.response_summary = {}
        self.evidence_hits = []
        self.source_docs = []
        self.proxy_used = None
        self.payload = None
        self.error_message = None
        self.success = False
        self.confidence_score = 0.0
    
    def with_request(self, **kwargs) -> 'ScanAttemptBuilder':
        """Add request details"""
        self.request_summary.update(kwargs)
        return self
    
    def with_response(self, status: int = None, length: int = None, **kwargs) -> 'ScanAttemptBuilder':
        """Add response details"""
        response_data = kwargs
        if status is not None:
            response_data['status_code'] = status
        if length is not None:
            response_data['content_length'] = length
        self.response_summary.update(response_data)
        return self
    
    def with_evidence(self, *evidence_items) -> 'ScanAttemptBuilder':
        """Add evidence items"""
        self.evidence_hits.extend(str(item) for item in evidence_items)
        return self
    
    def with_payload(self, payload: str) -> 'ScanAttemptBuilder':
        """Set the payload used"""
        self.payload = payload
        return self
    
    def with_proxy(self, proxy: str) -> 'ScanAttemptBuilder':
        """Set proxy used"""
        self.proxy_used = proxy
        return self
    
    def with_source_docs(self, *doc_ids) -> 'ScanAttemptBuilder':
        """Add source document IDs"""
        self.source_docs.extend(doc_ids)
        return self
    
    def success(self, confidence: float = 1.0) -> 'ScanAttemptBuilder':
        """Mark as successful with confidence score"""
        self.success = True
        self.confidence_score = min(1.0, max(0.0, confidence))
        return self
    
    def failure(self, error: str = None) -> 'ScanAttemptBuilder':
        """Mark as failed with optional error"""
        self.success = False
        self.confidence_score = 0.0
        if error:
            self.error_message = error
        return self
    
    def commit(self) -> ScanAttempt:
        """Build and log the scan attempt"""
        runtime_ms = int((time.time() - self.start_time) * 1000)
        
        attempt = ScanAttempt(
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=self.correlation_id,
            target=self.target,
            action_id=self.action_id,
            method=self.method,
            request_summary=self.request_summary,
            response_summary=self.response_summary,
            evidence_hits=self.evidence_hits,
            confidence_score=self.confidence_score,
            success=self.success,
            source_docs=self.source_docs,
            runtime_ms=runtime_ms,
            proxy_used=self.proxy_used,
            error_message=self.error_message,
            vulnerability_type=self.vulnerability_type,
            payload=self.payload
        )
        
        self.collector.log_attempt(attempt)
        return attempt

# Global telemetry collector
telemetry = TelemetryCollector()

def log_scan_attempt(target: str, action_id: str, method: str = "GET",
                    vulnerability_type: str = None) -> ScanAttemptBuilder:
    """
    Create a new scan attempt for logging.
    
    Usage:
        log_scan_attempt("http://target.com", "xss_test") \
            .with_payload("<script>alert(1)</script>") \
            .with_response(status=200, length=1024) \
            .with_evidence("script_reflected") \
            .success(0.9) \
            .commit()
    """
    return telemetry.create_scan_attempt(target, action_id, method, vulnerability_type)

def store_artifact(content: Union[str, bytes], artifact_type: str,
                  metadata: Dict[str, Any] = None) -> Optional[Artifact]:
    """Store an evidence artifact"""
    return telemetry.store_artifact(content, artifact_type, metadata)

def track_operation(operation_name: str, target: str = "", **kwargs):
    """Context manager for operation tracking"""
    return telemetry.track_operation(operation_name, target, kwargs)

def get_session_stats() -> Dict[str, Any]:
    """Get current session statistics"""
    return telemetry.get_session_stats()

def export_session_report(output_path: Path = None) -> str:
    """Export session report"""
    return telemetry.export_session_report(output_path)

if __name__ == "__main__":
    # Test the telemetry system
    logging.basicConfig(level=logging.INFO)
    
    # Test scan attempt logging
    log_scan_attempt("http://192.168.1.42/dvwa/vulnerabilities/sqli/", "sqli_error_test") \
        .with_payload("' OR 1=1--") \
        .with_request(method="GET", param="id") \
        .with_response(status=200, length=2048) \
        .with_evidence("mysql_error_in_response") \
        .with_source_docs("h1_stats_sql_injection") \
        .success(0.95) \
        .commit()
    
    # Test artifact storage
    html_content = "<html><body>SQL error: mysql_fetch_array()</body></html>"
    artifact = store_artifact(html_content, "html_response", {"target": "DVWA SQLi"})
    if artifact:
        print(f"Stored artifact: {artifact.id} at {artifact.path}")
    
    # Test operation tracking
    with track_operation("xss_reflection_test", "http://example.com") as tracker:
        time.sleep(0.1)  # Simulate work
        tracker.set_result("XSS reflected in response", success=True)
        tracker.add_evidence("script_tag_reflected")
    
    # Print session stats
    stats = get_session_stats()
    print(f"\nSession Stats:")
    print(f"  Total attempts: {stats['attempts_total']}")
    print(f"  Success rate: {stats['success_rate']:.1%}")
    print(f"  Average response time: {stats['average_response_time']:.1f}ms")
    
    # Export report
    report_path = export_session_report()
    print(f"Report exported to: {report_path}")