import ssl
import socket
from urllib.parse import urlparse

class DataInTransitAuditor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []

    def run_audit(self):
        """Runs the audit to verify TLS 1.2+ configuration."""
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname or self.target_url
        port = parsed_url.port or 443

        context = ssl.create_default_context()
        
        # We explicitly allow older TLS versions to check if the server accepts them,
        # but modern Python might restrict this. For this mock/demonstration,
        # we will simply try to connect and report the negotiated protocol.
        
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    if version in ["TLSv1.2", "TLSv1.3"]:
                        self.findings.append({
                            "status": "PASS",
                            "component": f"Endpoint: {hostname}",
                            "finding": f"Strong TLS protocol negotiated: {version}. Cipher: {cipher[0]}"
                        })
                    else:
                        self.findings.append({
                            "status": "FAIL",
                            "component": f"Endpoint: {hostname}",
                            "finding": f"Weak TLS protocol negotiated: {version}. HIPAA requires TLS 1.2+."
                        })
        except Exception as e:
            self.findings.append({
                "status": "ERROR",
                "component": f"Endpoint: {hostname}",
                "finding": f"Failed to connect or negotiate TLS: {e}"
            })

        return self.findings

if __name__ == "__main__":
    auditor = DataInTransitAuditor("https://www.google.com")
    print(auditor.run_audit())
