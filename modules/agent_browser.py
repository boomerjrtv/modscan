#!/usr/bin/env python3
"""
Agentic Browser Loop (ABL) Module - Universal browser automation for exploration

A lightweight, universal browser automation system that integrates with ModScan's
existing Playwright capabilities while maintaining target-agnostic principles.
Produces structured traces and generates replayable skills when signals are detected.
"""

import asyncio
import json
import logging
import re
import time
import os
from .browser_runtime import get_launch_options, extend_args, detect_lan_ip, setup_observers
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, urlparse

# Import universal form parser for CSRF-aware handling
from .universal_form_parser import parse_forms

logger = logging.getLogger(__name__)

# Signal patterns for skill generation (universal vulnerability indicators)
SIGNAL_PATTERNS = {
    'xss': [
        r'<script[^>]*>.*?alert\([^)]*\).*?</script>',
        r'javascript:alert\([^)]*\)',
        r'onerror\s*=\s*["\']alert\([^)]*\)["\']',
        r'"><script>alert\(',
        r'XSS.*?executed',
        r'eval\(.*?alert\(',
    ],
    'sqli': [
        r'SQL.*?syntax.*?error',
        r'mysql_fetch_array\(\)',
        r'ORA-\d+:',
        r'Microsoft.*?ODBC.*?SQL',
        r'PostgreSQL.*?ERROR',
        r'SQLite.*?error',
        r'You have an error in your SQL syntax',
        r'Warning.*?mysql_.*\(\)',
        r'valid MySQL result',
        r'MySQLSyntaxErrorException',
    ],
    'lfi': [
        r'root:x:\d+:\d+:',
        r'\[boot loader\]',
        r'<\?php.*?\?>',
        r'include.*?failed to open stream',
        r'Warning.*?include\(',
        r'No such file or directory.*?include',
    ],
    'rce': [
        r'uid=\d+\(.*?\) gid=\d+\(.*?\)',
        r'total \d+.*?drwx',
        r'Microsoft Windows \[Version',
        r'Linux.*?\d+\.\d+\.\d+',
        r'command not found',
        r'is not recognized as an internal',
    ],
    'ssrf': [
        r'Connection refused.*?localhost',
        r'No route to host.*?127\.0\.0\.1',
        r'Connection timed out.*?169\.254',
        r'Internal Server Error.*?192\.168',
    ],
    'sensitive': [
        r'password\s*[:=]\s*[^\s]+',
        r'api[_-]?key\s*[:=]\s*[^\s]+',
        r'secret[_-]?key\s*[:=]\s*[^\s]+',
        r'private[_-]?key\s*[:=]',
        r'BEGIN RSA PRIVATE KEY',
        r'database[_-]?password\s*[:=]',
        r'admin[_-]?password\s*[:=]',
    ]
}

@dataclass
class Action:
    """Universal browser action schema with validation"""
    type: str  # goto, click, fill, submit, evaluate, wait_for_selector, wait_for_url
    target: Optional[str] = None  # URL for goto, selector/text/label for others
    value: Optional[str] = None   # Text for fill, JS for evaluate, pattern for wait_for_url
    selector_strategy: str = 'auto'  # auto, text, role, label, css, xpath
    timeout: int = 5000  # Per-action timeout in ms
    allow_navigation: bool = True  # For click/submit actions
    
    def __post_init__(self):
        """Validate action on creation"""
        if not ActionValidator.validate(self):
            raise ValueError(f"Invalid action: {self}")

class ActionValidator:
    """Validates actions against universal safety constraints"""
    
    ALLOWED_TYPES = {'goto', 'click', 'fill', 'submit', 'evaluate', 'wait_for_selector', 'wait_for_url'}
    ALLOWED_SCHEMES = {'http', 'https'}
    
    @classmethod
    def validate(cls, action: Action) -> bool:
        """Validate action meets safety constraints"""
        if action.type not in cls.ALLOWED_TYPES:
            logger.warning(f"Invalid action type: {action.type}")
            return False
            
        if action.type == 'goto':
            if not action.target:
                logger.warning("goto action requires target URL")
                return False
            try:
                parsed = urlparse(action.target)
                if parsed.scheme not in cls.ALLOWED_SCHEMES:
                    logger.warning(f"Invalid scheme in URL: {parsed.scheme}")
                    return False
            except Exception as e:
                logger.warning(f"Invalid URL: {e}")
                return False
                
        elif action.type in ('click', 'fill', 'wait_for_selector'):
            if not action.target:
                logger.warning(f"{action.type} action requires target selector")
                return False
                
        elif action.type == 'evaluate' and not action.value:
            logger.warning("evaluate action requires JavaScript code")
            return False
        elif action.type == 'wait_for_url' and not action.value:
            logger.warning("wait_for_url action requires value (substring or regex)")
            return False
            
        return True

@dataclass 
class Observation:
    """Browser observation with compressed, token-efficient data"""
    url: str
    title: str
    status_code: Optional[int] = None
    forms_summary: List[Dict] = None
    visible_text: str = ""
    console_messages: List[str] = None
    network_requests: List[Dict] = None
    screenshot_path: Optional[str] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.forms_summary is None:
            self.forms_summary = []
        if self.console_messages is None:
            self.console_messages = []
        if self.network_requests is None:
            self.network_requests = []

class ObservationCompressor:
    """Compresses observations to stay token-efficient"""
    
    @staticmethod
    def compress_text(text: str, max_chars: int = 1000) -> str:
        """Compress visible text to key information"""
        if not text:
            return ""
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        if len(text) <= max_chars:
            return text
            
        # Try to find natural break points
        for break_point in ['. ', '! ', '? ', '\n', ' ']:
            if break_point in text[:max_chars]:
                pos = text[:max_chars].rfind(break_point)
                if pos > max_chars // 2:
                    return text[:pos + len(break_point)] + "..."
                    
        return text[:max_chars] + "..."
    
    @staticmethod
    def compress_console(messages: List[str], max_messages: int = 5) -> List[str]:
        """Keep only most relevant console messages"""
        if not messages:
            return []
        
        # Prioritize error messages
        errors = [msg for msg in messages if 'error' in msg.lower()]
        warnings = [msg for msg in messages if 'warn' in msg.lower()]
        others = [msg for msg in messages if 'error' not in msg.lower() and 'warn' not in msg.lower()]
        
        result = errors[:max_messages//2] + warnings[:max_messages//3] + others[:max_messages//3]
        return result[:max_messages]
    
    @staticmethod
    def compress_network(requests: List[Dict], max_requests: int = 10) -> List[Dict]:
        """Keep only most relevant network requests"""
        if not requests:
            return []
        
        # Filter to key request types and status codes
        relevant = []
        for req in requests:
            if any(key in req.get('url', '').lower() for key in ['api', 'login', 'auth', 'admin']):
                relevant.append({
                    'url': req.get('url', '')[:100],
                    'status': req.get('status'),
                    'type': req.get('type', 'unknown')
                })
            elif req.get('status', 200) >= 400:
                relevant.append({
                    'url': req.get('url', '')[:100],
                    'status': req.get('status'),
                    'type': req.get('type', 'unknown')
                })
                
        return relevant[:max_requests]

class TraceExporter:
    """Exports structured traces in JSONL format"""
    
    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(exist_ok=True, parents=True)
        
    def export_step(self, trace_file: Path, step_index: int, action: Action, 
                   observation: Observation, execution_time_ms: int):
        """Export a single step to JSONL trace file"""
        step_data = {
            'step': step_index,
            'timestamp': datetime.now().isoformat(),
            'action': asdict(action),
            'observation': asdict(observation),
            'execution_time_ms': execution_time_ms
        }
        
        with trace_file.open('a', encoding='utf-8') as f:
            f.write(json.dumps(step_data, ensure_ascii=False) + '\n')
            
        logger.debug(f"Exported step {step_index} to {trace_file}")

class SkillExporter:
    """Generates deterministic Playwright replay scripts from signals"""
    
    def __init__(self, skills_dir: Path):
        self.skills_dir = skills_dir
        self.skills_dir.mkdir(exist_ok=True, parents=True)
        
    def detect_signals(self, observation: Observation) -> List[str]:
        """Detect vulnerability signals in observation.
        XSS is ONLY signaled on actual dialog events (strong evidence)."""
        signals = []
        text_to_check = f"{observation.visible_text} {' '.join(observation.console_messages)}"
        
        # Pattern-based signals for non-XSS types
        for signal_type, patterns in SIGNAL_PATTERNS.items():
            if signal_type == 'xss':
                continue  # XSS handled strictly via dialog events only
            for pattern in patterns:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    signals.append(signal_type)
                    break
        
        # Strict XSS signal: require dialog event captured during browsing
        has_dialog = any(str(m).startswith('DIALOG:') for m in (observation.console_messages or []))
        if has_dialog:
            signals.append('xss')
        
        return signals
    
    def generate_skill(self, trace_data: List[Dict], signals: List[str], 
                      skill_name: str) -> str:
        """Generate a deterministic Playwright skill script"""
        skill_path = self.skills_dir / f"{skill_name}.py"
        
        script_lines = [
            '#!/usr/bin/env python3',
            '"""',
            f'Generated ModScan Skill: {skill_name}',
            f'Detected signals: {", ".join(signals)}',
            f'Generated: {datetime.now().isoformat()}',
            '',
            'Usage:',
            f'  python tools/skills/{skill_name}.py',
            '',
            'This script replays browser actions that triggered vulnerability signals.',
            'Modify the target URL and authentication as needed.',
            '"""',
            '',
            'import asyncio',
            'from playwright.async_api import async_playwright',
            '',
            f'async def replay_{skill_name.replace("-", "_")}():',
            '    """Replay the detected vulnerability interaction"""',
            '    async with async_playwright() as p:',
            '        browser = await p.chromium.launch(headless=True)',
            '        page = await browser.new_page()',
            '        ',
            '        try:'
        ]
        
        # Generate replay steps from trace
        for step in trace_data:
            action = step.get('action', {})
            a_type = action.get('type')
            strat = (action.get('selector_strategy') or 'auto').lower()
            if a_type == 'goto':
                script_lines.append(f'            await page.goto("{action.get("target", "")}")')
            elif a_type == 'click':
                selector = action.get('target', '')
                if strat == 'text':
                    script_lines.append(f'            await page.get_by_text("{selector}", exact=False).first.click()')
                elif strat == 'label':
                    script_lines.append(f'            await page.get_by_label("{selector}").click()')
                elif strat == 'role':
                    if ':' in selector:
                        r, n = selector.split(':', 1)
                        script_lines.append(f'            await page.get_by_role("{r}", name="{n}").click()')
                    else:
                        script_lines.append(f'            await page.get_by_role("button", name="{selector}").click()')
                elif strat == 'xpath':
                    script_lines.append(f'            await page.locator("xpath={selector}").click()')
                else:
                    script_lines.append(f'            await page.click("{selector}")')
            elif a_type == 'fill':
                selector = action.get('target', '')
                value = action.get('value', '')
                if strat == 'label':
                    script_lines.append(f'            await page.get_by_label("{selector}").fill("{value}")')
                elif strat == 'xpath':
                    script_lines.append(f'            await page.locator("xpath={selector}").fill("{value}")')
                else:
                    script_lines.append(f'            await page.fill("{selector}", "{value}")')
            elif a_type == 'submit':
                selector = action.get('target', 'form')
                script_lines.append(f'            await page.locator("{selector}").press("Enter")')
            elif a_type == 'wait_for_selector':
                selector = action.get('target', '')
                script_lines.append(f'            await page.wait_for_selector("{selector}")')
            elif a_type == 'wait_for_url':
                patt = action.get('value', '')
                script_lines.append('            # wait for URL change containing pattern')
                script_lines.append(f'            while "{patt}" not in page.url:')
                script_lines.append('                await page.wait_for_timeout(100)')
            elif a_type == 'evaluate':
                js_code = (action.get('value', '') or '').replace('"', '\\"')
                script_lines.append(f'            await page.evaluate("{js_code}")')
                
        script_lines.extend([
            '            ',
            '            # Wait for response and capture evidence',
            '            await page.wait_for_timeout(2000)',
            '            content = await page.content()',
            f'            print(f"Skill {skill_name} completed - captured {{len(content)}} chars")',
            '            ',
            '        except Exception as e:',
            '            print(f"Skill execution failed: {e}")',
            '        finally:',
            '            await browser.close()',
            '',
            'if __name__ == "__main__":',
            f'    asyncio.run(replay_{skill_name.replace("-", "_")}())'
        ])
        
        skill_content = '\n'.join(script_lines)
        with skill_path.open('w', encoding='utf-8') as f:
            f.write(skill_content)
            
        logger.info(f"Generated skill script: {skill_path}")
        return str(skill_path)

class AgentBrowser:
    """Main ABL orchestrator with budgets and safety constraints"""
    
    def __init__(self, config: Dict, asset_manager=None, screenshot_manager=None):
        self.config = config
        self.asset_manager = asset_manager
        self.screenshot_manager = screenshot_manager
        
        # Initialize components
        self.evidence_dir = Path(config.get('evidence_dir', 'evidence'))
        self.trace_exporter = TraceExporter(self.evidence_dir)
        self.skill_exporter = SkillExporter(Path('tools/skills'))
        
        # Safety and budget configuration
        self.allowed_hosts = set()  # Populated during execution
        self.same_host_only = config.get('abl_same_host_only', True)
        self._session_console: List[str] = []
        self._session_network: List[Dict[str, Any]] = []
        
        # Check if Playwright is available
        self._playwright_available = False
        try:
            import playwright
            self._playwright_available = True
        except ImportError:
            logger.warning("Playwright not available - ABL will skip execution")

        # Live view / debugging configuration via environment
        opts = get_launch_options()
        self._headless = bool(opts['headless'])
        self._devtools = bool(opts['devtools'])
        self._rdp_port = opts['rdp_port']
        self._rdp_addr = opts['rdp_addr']
            
    async def execute_session(self, start_url: str, budgets: Dict) -> Dict:
        """Execute an ABL session with budget constraints"""
        if not self._playwright_available:
            logger.info("Skipping ABL session - Playwright not available")
            return {'status': 'skipped', 'reason': 'playwright_unavailable'}
            
        session_id = self._generate_session_id(start_url)
        trace_file = self.evidence_dir / f'trace_{session_id}.jsonl'
        
        # Initialize allowed hosts
        parsed_start = urlparse(start_url)
        self.allowed_hosts.add(parsed_start.netloc)
        
        session_start = time.time()
        max_time_ms = budgets.get('max_time_ms', 15000)
        max_steps = budgets.get('max_steps', 12)
        max_clicks = budgets.get('max_clicks', 8)
        
        logger.info(f"Starting ABL session {session_id} with budgets: {budgets}")
        
        steps_taken = 0
        clicks_taken = 0
        trace_data = []
        
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                # Configure browser for stealth and speed
                base_args = [
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    '--disable-gpu'
                ]
                launch_args = extend_args(base_args, get_launch_options()['args'])

                browser = await p.chromium.launch(
                    headless=self._headless,
                    devtools=self._devtools,
                    args=launch_args
                )

                if self._rdp_port:
                    ip = detect_lan_ip()
                    logger.info(f"🔎 DevTools listening: http://{ip}:{self._rdp_port}  (chrome://inspect -> Add target)")
                
                # Apply proxy if configured
                proxy_config = None
                if hasattr(self.config, 'get') and 'proxy_selector' in self.config:
                    # Integration point for ProxyManager
                    pass  # Proxy support can be added here
                
                page = await browser.new_page()

                # Attach observers for console and network
                setup_observers(page, self._session_console, self._session_network)
                # Capture alert/prompt/confirm events as strong XSS signals and auto-accept
                try:
                    def _on_dialog(d):
                        try:
                            self._session_console.append(f"DIALOG:{getattr(d, 'type', '')}:{getattr(d, 'message', '')}")
                        except Exception:
                            pass
                        try:
                            # Accept to avoid blocking the page
                            asyncio.create_task(d.accept())
                        except Exception:
                            pass
                    page.on("dialog", _on_dialog)
                except Exception:
                    pass
                
                # Configure page timeouts
                page.set_default_timeout(budgets.get('action_timeout', 5000))
                
                try:
                    # Initial navigation
                    action = Action(type='goto', target=start_url)
                    observation = await self._execute_action(page, action, session_id)
                    
                    self.trace_exporter.export_step(
                        trace_file, steps_taken, action, observation, 
                        int((time.time() - session_start) * 1000)
                    )
                    
                    trace_data.append({
                        'step': steps_taken,
                        'action': asdict(action),
                        'observation': asdict(observation)
                    })
                    
                    steps_taken += 1
                    
                    # Simple exploration policy (can be replaced with AI later)
                    while (steps_taken < max_steps and 
                           clicks_taken < max_clicks and
                           (time.time() - session_start) * 1000 < max_time_ms):
                        
                        next_action = await self._plan_next_action(
                            trace_data, observation, budgets
                        )
                        
                        if not next_action:
                            break
                            
                        step_start = time.time()
                        observation = await self._execute_action(page, next_action, session_id)
                        execution_time = int((time.time() - step_start) * 1000)
                        
                        self.trace_exporter.export_step(
                            trace_file, steps_taken, next_action, observation, execution_time
                        )
                        
                        trace_data.append({
                            'step': steps_taken,
                            'action': asdict(next_action),
                            'observation': asdict(observation)
                        })
                        
                        steps_taken += 1
                        if next_action.type == 'click':
                            clicks_taken += 1
                            
                        # Check for signals and generate skills
                        signals = self.skill_exporter.detect_signals(observation)
                        if signals:
                            skill_name = f"{session_id}-{'-'.join(signals)}"
                            skill_path = self.skill_exporter.generate_skill(
                                trace_data, signals, skill_name
                            )
                            logger.info(f"Generated skill for signals {signals}: {skill_path}")
                        
                finally:
                    await browser.close()
                    
        except Exception as e:
            logger.error(f"ABL session {session_id} failed: {e}")
            return {
                'status': 'error',
                'session_id': session_id, 
                'error': str(e),
                'steps_taken': steps_taken
            }
        
        session_duration = int((time.time() - session_start) * 1000)
        
        return {
            'status': 'completed',
            'session_id': session_id,
            'steps_taken': steps_taken,
            'clicks_taken': clicks_taken,
            'duration_ms': session_duration,
            'trace_file': str(trace_file)
        }
    
    async def _execute_action(self, page, action: Action, session_id: str) -> Observation:
        """Execute a browser action and capture observation"""
        try:
            if action.type == 'goto':
                # Enforce host allowlist
                try:
                    target_host = urlparse(action.target).netloc
                    if self.same_host_only and target_host not in self.allowed_hosts:
                        return Observation(url=action.target or '', title='', error='disallowed_host')
                except Exception:
                    pass
                response = await page.goto(action.target)
                status_code = response.status if response else None
            elif action.type == 'click':
                await self._perform_click(page, action)
                status_code = None
            elif action.type == 'fill':
                await self._perform_fill(page, action)
                status_code = None
            elif action.type == 'submit':
                await page.locator(action.target or 'form').press('Enter')
                status_code = None
            elif action.type == 'evaluate':
                await page.evaluate(action.value or '')
                status_code = None
            elif action.type == 'wait_for_selector':
                await page.wait_for_selector(action.target, timeout=action.timeout)
                status_code = None
            elif action.type == 'wait_for_url':
                # Simple wait for substring in URL
                pattern = action.value or ''
                end_time = time.time() + max(0.1, action.timeout / 1000)
                while time.time() < end_time:
                    if pattern and pattern in page.url:
                        break
                    await page.wait_for_timeout(100)
                status_code = None
            else:
                raise ValueError(f"Unknown action type: {action.type}")
                
            # Capture observation
            url = page.url
            # Enforce navigation constraints after action
            try:
                current_host = urlparse(url).netloc
                if self.same_host_only and self.allowed_hosts and current_host not in self.allowed_hosts:
                    return Observation(url=url, title='', error='navigated_to_disallowed_host')
            except Exception:
                pass
            title = await page.title()
            content = await page.content()
            
            # Parse forms using universal form parser
            forms_summary = []
            try:
                forms = parse_forms(content, url)
                forms_summary = [
                    {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'fields': len(form.get('inputs', []))
                    }
                    for form in forms[:5]  # Limit to 5 forms
                ]
            except Exception as e:
                logger.debug(f"Form parsing failed: {e}")
            
            # Capture visible text (compressed)
            try:
                visible_text = await page.evaluate('''
                    () => document.body ? document.body.innerText : ""
                ''')
                visible_text = ObservationCompressor.compress_text(visible_text)
            except:
                visible_text = ""
            
            # Capture console/network (compressed)
            console_messages = ObservationCompressor.compress_console(self._session_console[-20:], max_messages=6)
            network_requests = ObservationCompressor.compress_network(self._session_network[-50:], max_requests=12)
            
            # Capture screenshot via ScreenshotManager if available  
            screenshot_path = None
            if self.screenshot_manager:
                try:
                    screenshot_path = await self.screenshot_manager.capture_url(url)
                except Exception as e:
                    logger.debug(f"Screenshot capture failed: {e}")
            else:
                # Fallback to direct screenshot if Playwright page is available
                try:
                    shot_file = self.evidence_dir / f"shot_{session_id}_{int(time.time()*1000)}.png"
                    await page.screenshot(path=str(shot_file))
                    screenshot_path = str(shot_file)
                except Exception:
                    pass
            
            return Observation(
                url=url,
                title=title,
                status_code=status_code,
                forms_summary=forms_summary,
                visible_text=visible_text,
                console_messages=console_messages,
                network_requests=network_requests,
                screenshot_path=screenshot_path
            )
            
        except Exception as e:
            return Observation(
                url=getattr(page, 'url', action.target or ''),
                title="",
                error=str(e)
            )
    
    async def _plan_next_action(self, history: List[Dict], current_obs: Observation, 
                              budgets: Dict) -> Optional[Action]:
        """AI-driven action planning with safe fallback heuristic.
        If GEMINI_API_KEY present and abl_ai_planner_enabled, ask LLM for next action.
        """
        if not current_obs or current_obs.error:
            return None

        # Attempt AI planner
        try:
            if bool(self.config.get('abl_ai_planner_enabled')):
                import os as _os
                import google.generativeai as genai  # type: ignore
                key = self.config.get('gemini_api_key') or _os.environ.get('GEMINI_API_KEY')
                if key:
                    genai.configure(api_key=key)
                    prompt = build_llm_prompt(current_obs, history, budgets, list(self.allowed_hosts))
                    # Call in thread to avoid blocking loop
                    import asyncio as _asyncio
                    def _call():
                        try:
                            m = genai.GenerativeModel('gemini-1.5-flash')
                            r = m.generate_content(prompt)
                            return r.text if hasattr(r, 'text') else str(r)
                        except Exception as e:
                            return f"ERROR: {e}"
                    raw = await _asyncio.to_thread(_call)
                    # Extract JSON
                    import json as _json
                    txt = (raw or '').strip()
                    s, e = txt.find('{'), txt.rfind('}')
                    if s != -1 and e != -1 and e > s:
                        data = _json.loads(txt[s:e+1])
                        # Validate
                        try:
                            cand = Action(**{
                                'type': data.get('type'),
                                'target': data.get('target'),
                                'value': data.get('value'),
                                'selector_strategy': data.get('selector_strategy') or 'auto',
                                'timeout': int(data.get('timeout') or budgets.get('action_timeout', 5000)),
                                'allow_navigation': bool(data.get('allow_navigation') if data.get('allow_navigation') is not None else True)
                            })
                            return cand
                        except Exception:
                            pass
        except Exception:
            pass

        # Fallback heuristic policy
        if current_obs.forms_summary and len(history) <= 2:
            return Action(type='fill', target='input[type="text"]:first', value='test', selector_strategy='css')
        if len(current_obs.forms_summary) > 0 and any('fill' in str(step) for step in history[-2:]):
            return Action(type='submit', target='form:first', selector_strategy='css')
        return None
    
    def _generate_session_id(self, start_url: str) -> str:
        """Generate a unique session identifier"""
        import hashlib
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        url_hash = hashlib.md5(start_url.encode()).hexdigest()[:8]
        return f"abl_{timestamp}_{url_hash}"

    async def _perform_click(self, page, action: Action) -> None:
        """Click using strategy-aware selection with safe defaults"""
        strat = (action.selector_strategy or 'auto').lower()
        tgt = action.target or ''
        timeout = action.timeout
        if strat == 'css':
            await page.click(tgt, timeout=timeout)
            return
        if strat == 'text':
            await page.get_by_text(tgt, exact=False).first.click(timeout=timeout)
            return
        if strat == 'label':
            await page.get_by_label(tgt).click(timeout=timeout)
            return
        if strat == 'role':
            # Allow "role:name" pattern, e.g., "button:Submit"
            role_name = 'button'
            name = tgt
            if ':' in tgt:
                parts = tgt.split(':', 1)
                role_name, name = parts[0] or 'button', parts[1]
            await page.get_by_role(role_name, name=name).click(timeout=timeout)
            return
        if strat == 'xpath':
            await page.locator(f'xpath={tgt}').click(timeout=timeout)
            return
        # auto strategy: try text -> role(button) -> css
        try:
            await page.get_by_text(tgt, exact=False).first.click(timeout=timeout)
            return
        except Exception:
            try:
                await page.get_by_role('button', name=tgt).click(timeout=timeout)
                return
            except Exception:
                await page.click(tgt, timeout=timeout)

    async def _perform_fill(self, page, action: Action) -> None:
        """Fill using strategy-aware selection with label-first heuristic"""
        strat = (action.selector_strategy or 'auto').lower()
        tgt = action.target or ''
        val = action.value or ''
        timeout = action.timeout
        if strat == 'css':
            await page.fill(tgt, val, timeout=timeout)
            return
        if strat == 'label':
            await page.get_by_label(tgt).fill(val, timeout=timeout)
            return
        if strat == 'text':
            # Treat as placeholder/aria-label text fallback
            await page.locator(f'input[placeholder*="{tgt}"]').first.fill(val, timeout=timeout)
            return
        if strat == 'xpath':
            await page.locator(f'xpath={tgt}').fill(val, timeout=timeout)
            return
        # auto strategy: label -> css
        try:
            await page.get_by_label(tgt).fill(val, timeout=timeout)
        except Exception:
            await page.fill(tgt, val, timeout=timeout)

# ---- AI Planner Scaffolding (JSON schema for LLM decisions) ----

ACTION_JSON_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AgentBrowserAction",
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": [
            "goto", "click", "fill", "submit", "evaluate", "wait_for_selector", "wait_for_url"
        ]},
        "target": {"type": ["string", "null"]},
        "value": {"type": ["string", "null"]},
        "selector_strategy": {"type": "string", "enum": [
            "auto", "text", "role", "label", "css", "xpath"
        ], "default": "auto"},
        "timeout": {"type": "integer", "minimum": 100, "maximum": 60000, "default": 5000},
        "allow_navigation": {"type": "boolean", "default": True}
    },
    "required": ["type"],
    "additionalProperties": False
}

def build_llm_prompt(observation: Observation, history: List[Dict[str, Any]], budgets: Dict[str, Any], allowed_hosts: List[str]) -> str:
    """Create a compact instruction for an LLM to choose a safe next action"""
    obs = {
        'url': observation.url,
        'title': observation.title[:120],
        'text': observation.visible_text[:500],
        'forms': observation.forms_summary[:3],
        'console': observation.console_messages[:4],
        'network': observation.network_requests[:5]
    }
    prompt = (
        "You are a cautious web testing agent. Propose exactly one next action "
        "in strict JSON that conforms to this schema. Stay on these hosts: "
        f"{allowed_hosts}. Budgets: steps<=%d, clicks<=%d, time<=%dms. "
        "Never navigate off-host. Prefer filling simple forms (label-based) then submit. "
        "Avoid destructive actions. Use selector_strategy label/text/css.\n\n"
        "Schema:\n" + json.dumps(ACTION_JSON_SCHEMA, ensure_ascii=False) + "\n\n"
        "CurrentObservation:\n" + json.dumps(obs, ensure_ascii=False) + "\n\n"
        "HistoryLength: %d. Respond with JSON only, no prose."
    )
    return prompt % (
        budgets.get('max_steps', 10),
        budgets.get('max_clicks', 5),
        budgets.get('max_time_ms', 15000),
        len(history)
    )
