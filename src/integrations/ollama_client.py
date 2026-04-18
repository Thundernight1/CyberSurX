"""Ollama local LLM integration - replaces physical devices"""
import requests
import json
from typing import Dict, List, Optional, Generator
import subprocess

class OllamaClient:
    """Local LLM client using Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url
        self.model = model
        self.api_generate = f"{base_url}/api/generate"
        self.api_chat = f"{base_url}/api/chat"
    
    def check_ollama(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def list_models(self) -> List[str]:
        """List available local models"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
            return []
        except:
            return []
    
    def analyze_vulnerability(self, scan_results: Dict) -> Dict:
        """Use local LLM to analyze scan results"""
        if not self.check_ollama():
            return {
                "status": "error",
                "error": "Ollama not running. Start with: ollama serve"
            }
        
        prompt = f"""Analyze these security scan results and identify vulnerabilities:

Scan Type: {scan_results.get('scan_type', 'unknown')}
Target: {scan_results.get('target', 'unknown')}
Findings: {json.dumps(scan_results.get('findings', []), indent=2)}

Provide:
1. Vulnerability severity (Critical/High/Medium/Low)
2. Potential impact
3. Remediation steps
"""
        
        try:
            response = requests.post(
                self.api_generate,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "status": "success",
                    "analysis": result.get("response", ""),
                    "model": self.model,
                    "scan_id": scan_results.get("id")
                }
            else:
                return {
                    "status": "error",
                    "error": f"Ollama returned {response.status_code}",
                    "details": response.text
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def generate_exploit_payload(self, vulnerability_type: str, target_info: Dict) -> Dict:
        """Generate proof-of-concept payload using local LLM"""
        if not self.check_ollama():
            return {
                "status": "error",
                "error": "Ollama not running"
            }
        
        prompt = f"""Generate a safe proof-of-concept {vulnerability_type} payload for security testing.

Target: {target_info.get('host', 'localhost')}
Port: {target_info.get('port', '80')}
Service: {target_info.get('service', 'unknown')}

Rules:
- Only generate payloads for authorized testing
- Include clear safety warnings
- Provide detection methods

Payload:"""
        
        try:
            response = requests.post(
                self.api_generate,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "status": "success",
                    "payload_type": vulnerability_type,
                    "payload": result.get("response", ""),
                    "target": target_info,
                    "model": self.model
                }
            else:
                return {
                    "status": "error",
                    "error": f"Ollama error: {response.status_code}"
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def stream_chat(self, messages: List[Dict]) -> Generator[str, None, None]:
        """Stream chat response for interactive agent"""
        if not self.check_ollama():
            yield "Error: Ollama not running"
            return
        
        try:
            response = requests.post(
                self.api_chat,
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": True
                },
                stream=True,
                timeout=120
            )
            
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            yield data["message"]["content"]
                    except:
                        pass
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def generate_report(self, scan_data: Dict, report_type: str = "executive") -> Dict:
        """Generate security report using local LLM"""
        if not self.check_ollama():
            return {
                "status": "error", 
                "error": "Ollama not running"
            }
        
        findings = scan_data.get("findings", [])
        
        if report_type == "executive":
            prompt = f"""Create an executive summary security report for management:

Total Findings: {len(findings)}
Critical: {sum(1 for f in findings if f.get('severity') == 'critical')}
High: {sum(1 for f in findings if f.get('severity') == 'high')}
Medium: {sum(1 for f in findings if f.get('severity') == 'medium')}

Write a 3-paragraph executive summary suitable for C-level presentation."""
        else:
            prompt = f"""Create a detailed technical security report:

Findings: {json.dumps(findings, indent=2)}

Include:
1. Technical analysis
2. Remediation steps
3. CVSS scoring
4. Proof of concept"""
        
        try:
            response = requests.post(
                self.api_generate,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "status": "success",
                    "report": result.get("response", ""),
                    "type": report_type,
                    "model": self.model,
                    "generated_at": "now"
                }
            else:
                return {"status": "error", "error": f"Ollama error: {response.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

# Quick test
if __name__ == "__main__":
    client = OllamaClient()
    print("Ollama running:", client.check_ollama())
    print("Models:", client.list_models())
