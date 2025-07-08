"""
Scanner Engine Module - Core scanning functionality

This module provides the core scanning functionality for the port scanner application.
It is responsible for testing if ports are open and identifying service information.
"""

# Step 1: Import necessary modules
import socket          # For creating network connections to test ports
import logging         # For logging scan progress and errors
from typing import List, Dict, Callable, Optional, Tuple, TYPE_CHECKING, Any  # Type hints
import time            # For timing operations
import random          # For randomizing port scan order to avoid detection
import ssl             # For SSL/TLS certificate grabbing
import re              # For parsing banner responses
import struct          # For handling binary data in protocol responses
import ipaddress       # For IP address validation

from colorama import Fore  # For colored terminal output

# Step 2: Set up type checking to avoid circular imports
if TYPE_CHECKING:
    from scanner_tool.threading_module import ThreadingModule

# Step 3: Configure logging
logger = logging.getLogger(__name__)

# Step 4: Define common service to port mappings dictionary
# This provides a quick lookup for common services without relying on socket.getservbyport()
SERVICE_MAP = {
    # FTP
    21: "FTP",
    # SSH
    22: "SSH",
    # Telnet
    23: "Telnet",
    # SMTP
    25: "SMTP",
    # DNS
    53: "DNS",
    # HTTP
    80: "HTTP",
    # POP3
    110: "POP3",
    # NTP
    123: "NTP",
    # NetBIOS
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    # IMAP
    143: "IMAP",
    # LDAP
    389: "LDAP",
    # HTTPS
    443: "HTTPS",
    # SMB
    445: "SMB",
    # IMAPS
    993: "IMAPS",
    # POP3S
    995: "POP3S",
    # PPTP
    1723: "PPTP",
    # MySQL
    3306: "MySQL",
    # RDP
    3389: "RDP",
    # VNC
    5900: "VNC",
    # HTTP Proxy
    8080: "HTTP-Proxy"
}

class ScannerEngine:
    """
    Core scanning engine that handles port scanning and service identification.
    This class contains methods to test individual ports and scan multiple ports
    using multithreading for improved performance.
    """
    
    def __init__(self):
        """
        Step 5: Initialize the scanner engine with default timeout.
        The timeout determines how long to wait for a response when testing a port.
        """
        self.timeout = 1.0  # Default socket timeout in seconds
        self.banner_timeout = 3.0  # Longer timeout for banner grabbing
        self.ssl_timeout = 5.0  # Even longer timeout for SSL certificate retrieval
        
    def test_port(self, host: str, port: int) -> bool:
        """
        Step 6: Test if a specific port is open on the target host.
        This is the most basic operation - connecting to a specific port to see if it responds.
        
        Args:
            host: The hostname or IP address to scan
            port: The port number to scan
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            # Step 6.1: Create a new socket for this connection attempt
            # AF_INET specifies IPv4, SOCK_STREAM specifies TCP connection
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)  # Set socket timeout
            
            # Step 6.2: Attempt to connect to the port
            # connect_ex returns 0 if connection succeeds, error code otherwise
            result = s.connect_ex((host, port))
            s.close()  # Always close socket to free resources
            
            # Step 6.3: Return True if connection succeeded (port is open)
            return result == 0
            
        except Exception as e:
            # Log errors but continue scanning other ports
            logger.debug(f"Error scanning port {port}: {e}")
            return False
            
    def fetch_service_info(self, port: int) -> str:
        """
        Step 7: Fetch service information for a specific port number.
        This helps identify what service might be running on an open port.
        
        Args:
            port: The port number
            
        Returns:
            str: The service name associated with the port
        """
        try:
            # Step 7.1: First check our own map for common services (faster)
            if port in SERVICE_MAP:
                return SERVICE_MAP[port]
                
            # Step 7.2: Then try socket.getservbyport for less common services
            return socket.getservbyport(port)
        except (socket.error, OSError):
            # Return "Unknown" if service can't be identified
            return "Unknown"
    
    def grab_banner(self, host: str, port: int, service: str) -> Dict[str, Any]:
        """
        Grab service banner, version information, and other details from an open port.
        
        Args:
            host: The hostname or IP address of the target
            port: The port number that is open
            service: The identified service name
            
        Returns:
            Dict[str, Any]: Banner information including version, server details, etc.
        """
        banner_info = {
            "banner": "",
            "version": "",
            "server": "",
            "ssl_cert": {}
        }
        
        try:
            # Handle SSL/TLS services first
            if service in ["HTTPS", "IMAPS", "POP3S", "SMTPS"] or port in [443, 465, 636, 993, 995]:
                ssl_info = self.get_ssl_info(host, port)
                if ssl_info:
                    banner_info["ssl_cert"] = ssl_info
            
            # Handle HTTP/HTTPS
            if service in ["HTTP", "HTTPS"] or port in [80, 443, 8080, 8443]:
                http_info = self.grab_http_banner(host, port, service == "HTTPS" or port == 443)
                if http_info:
                    banner_info.update(http_info)
            
            # Handle FTP
            elif service == "FTP" or port == 21:
                ftp_banner = self.grab_protocol_banner(host, port)
                if ftp_banner:
                    banner_info["banner"] = ftp_banner
                    # Extract version from FTP banner if available
                    version_match = re.search(r'(\d+\.\d+\.\d+)', ftp_banner)
                    if version_match:
                        banner_info["version"] = version_match.group(1)
            
            # Handle SSH
            elif service == "SSH" or port == 22:
                ssh_banner = self.grab_protocol_banner(host, port)
                if ssh_banner:
                    banner_info["banner"] = ssh_banner
                    # Extract SSH version
                    version_match = re.search(r'SSH-(\d+\.\d+)-([^\s]+)', ssh_banner)
                    if version_match:
                        banner_info["version"] = f"{version_match.group(1)} {version_match.group(2)}"
            
            # Handle SMTP
            elif service == "SMTP" or port == 25:
                smtp_banner = self.grab_protocol_banner(host, port)
                if smtp_banner:
                    banner_info["banner"] = smtp_banner
                    # Extract SMTP server and version
                    server_match = re.search(r'ESMTP ([^\s]+)', smtp_banner)
                    if server_match:
                        banner_info["server"] = server_match.group(1)
            
            # Handle other services with a generic banner grab
            elif not banner_info["banner"]:
                generic_banner = self.grab_protocol_banner(host, port)
                if generic_banner:
                    banner_info["banner"] = generic_banner
            
        except Exception as e:
            logger.debug(f"Error grabbing banner for {host}:{port} - {e}")
        
        return banner_info
    
    def grab_protocol_banner(self, host: str, port: int) -> str:
        """
        Grab a generic protocol banner by connecting and reading the initial response.
        
        Args:
            host: The hostname or IP address to connect to
            port: The port number to connect to
            
        Returns:
            str: The banner string if available, empty string otherwise
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.banner_timeout)
            s.connect((host, port))
            
            # Some protocols send data immediately upon connection
            banner = ""
            try:
                # Wait for up to 2 seconds for initial data
                s.settimeout(2.0)
                data = s.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                # For protocols that don't send data immediately, try sending a newline
                try:
                    s.send(b"\r\n")
                    s.settimeout(2.0)
                    data = s.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except:
                    pass
            finally:
                s.close()
                
            return banner
        except Exception as e:
            logger.debug(f"Error grabbing protocol banner for {host}:{port} - {e}")
            return ""
    
    def grab_http_banner(self, host: str, port: int, use_ssl: bool = False) -> Dict[str, str]:
        """
        Grab HTTP server information by sending a HTTP HEAD request.
        
        Args:
            host: The hostname or IP address to connect to
            port: The port number to connect to
            use_ssl: Whether to use SSL/TLS for the connection
            
        Returns:
            Dict[str, str]: HTTP server information
        """
        http_info = {
            "banner": "",
            "server": "",
            "version": ""
        }
        
        try:
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.banner_timeout)
            s.connect((host, port))
            
            # Wrap socket with SSL if needed
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    s = context.wrap_socket(s, server_hostname=host)
                except Exception as e:
                    logger.debug(f"SSL wrapping failed for {host}:{port} - {e}")
                    s.close()
                    return http_info
            
            # Send HTTP HEAD request
            s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Port Scanner\r\nConnection: close\r\n\r\n".encode())
            
            # Receive and process response
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    
                    # Avoid reading too much data
                    if len(response) > 8192:
                        break
                except socket.timeout:
                    break
            
            s.close()
            
            if response:
                # Decode response and extract headers
                resp_text = response.decode('utf-8', errors='ignore')
                http_info["banner"] = resp_text.split('\r\n\r\n')[0]  # Just the headers
                
                # Extract server information
                server_match = re.search(r'Server: ([^\r\n]+)', resp_text)
                if server_match:
                    server = server_match.group(1).strip()
                    http_info["server"] = server
                    
                    # Try to extract version from server header
                    version_match = re.search(r'(\d+\.\d+\.\d+)', server)
                    if version_match:
                        http_info["version"] = version_match.group(1)
        
        except Exception as e:
            logger.debug(f"Error grabbing HTTP banner for {host}:{port} - {e}")
        
        return http_info
    
    def get_ssl_info(self, host: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information for a host:port."""
        ssl_info = {
            "valid": False,
            "issued_to": "Unknown",
            "issued_by": "Unknown",
            "valid_from": "",
            "valid_until": "",
            "version": "",
            "serial_number": "",
            "signature_algorithm": ""
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        return ssl_info
                    
                    ssl_info["valid"] = True
                    
                    # Get subject (issued to)
                    if 'subject' in cert and cert['subject']:
                        subject_parts = []
                        for field in cert['subject']:
                            for key, value in field:
                                if key in ['commonName', 'organizationName', 'organizationalUnitName']:
                                    subject_parts.append(value)
                        ssl_info["issued_to"] = " / ".join(filter(None, subject_parts))
                    
                    # Get issuer
                    if 'issuer' in cert and cert['issuer']:
                        issuer_parts = []
                        for field in cert['issuer']:
                            for key, value in field:
                                if key in ['commonName', 'organizationName']:
                                    issuer_parts.append(value)
                        ssl_info["issued_by"] = " / ".join(filter(None, issuer_parts))
                    
                    # Get validity dates
                    if 'notBefore' in cert:
                        ssl_info["valid_from"] = cert['notBefore']
                    if 'notAfter' in cert:
                        ssl_info["valid_until"] = cert['notAfter']
                    
                    # Get version and serial number
                    if 'version' in cert:
                        ssl_info["version"] = f"v{cert['version']}"
                    if 'serialNumber' in cert:
                        ssl_info["serial_number"] = cert['serialNumber']
                    
                    # Get signature algorithm
                    if 'signatureAlgorithm' in cert:
                        ssl_info["signature_algorithm"] = cert['signatureAlgorithm']
                    
        except (socket.error, ssl.SSLError, ssl.CertificateError) as e:
            logger.debug(f"Error grabbing SSL information for {host}:{port} - {e}")
            ssl_info["error"] = str(e)
        
        return ssl_info
    
    def scan_port_worker(self, host: str, port: int, progress_callback: Optional[Callable] = None) -> Tuple[int, bool, str, Dict[str, Any]]:
        """
        Step 8: Worker function that scans a single port.
        This is the function that will be executed by each thread.
        
        Args:
            host: The hostname or IP address to scan
            port: The port number to scan
            progress_callback: Optional callback function to update progress
            
        Returns:
            Tuple[int, bool, str, Dict[str, Any]]: Port number, open status, service name, and banner information
        """
        # Step 8.1: Test if port is open
        is_open = self.test_port(host, port)
        
        # Step 8.2: Get service info if port is open
        service = self.fetch_service_info(port) if is_open else ""
        
        # Step 8.3: Grab banner information if port is open
        banner_info = {}
        if is_open:
            banner_info = self.grab_banner(host, port, service)
        
        # Step 8.4: Call progress callback if provided
        # This updates the UI with scan progress
        if progress_callback:
            progress_callback(port, is_open)
            
        # Step 8.5: Log open ports for debugging
        if is_open:
            version_info = f" ({banner_info.get('version', '')})" if banner_info.get('version') else ""
            logger.info(f"Port {port} is {Fore.GREEN}open{Fore.RESET} ({service}{version_info})")
            
        # Step 8.6: Return results tuple for this port
"""
Scanner Engine Module - Core scanning functionality

This module provides the core scanning functionality for the port scanner application.
It is responsible for testing if ports are open and identifying service information.
"""

# Step 1: Import necessary modules
import socket          # For creating network connections to test ports
import logging         # For logging scan progress and errors
from typing import List, Dict, Callable, Optional, Tuple, TYPE_CHECKING, Any  # Type hints
import time            # For timing operations
import random          # For randomizing port scan order to avoid detection
import ssl             # For SSL/TLS certificate grabbing
import re              # For parsing banner responses
import struct          # For handling binary data in protocol responses

from colorama import Fore  # For colored terminal output

# Step 2: Set up type checking to avoid circular imports
if TYPE_CHECKING:
    from scanner_tool.threading_module import ThreadingModule

# Step 3: Configure logging
logger = logging.getLogger(__name__)

# Step 4: Define common service to port mappings dictionary
# This provides a quick lookup for common services without relying on socket.getservbyport()
SERVICE_MAP = {
    # FTP
    21: "FTP",
    # SSH
    22: "SSH",
    # Telnet
    23: "Telnet",
    # SMTP
    25: "SMTP",
    # DNS
    53: "DNS",
    # HTTP
    80: "HTTP",
    # POP3
    110: "POP3",
    # NTP
    123: "NTP",
    # NetBIOS
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    # IMAP
    143: "IMAP",
    # LDAP
    389: "LDAP",
    # HTTPS
    443: "HTTPS",
    # SMB
    445: "SMB",
    # IMAPS
    993: "IMAPS",
    # POP3S
    995: "POP3S",
    # PPTP
    1723: "PPTP",
    # MySQL
    3306: "MySQL",
    # RDP
    3389: "RDP",
    # VNC
    5900: "VNC",
    # HTTP Proxy
    8080: "HTTP-Proxy"
}

class ScannerEngine:
    """
    Core scanning engine that handles port scanning and service identification.
    This class contains methods to test individual ports and scan multiple ports
    using multithreading for improved performance.
    """
    
    def __init__(self):
        """
        Step 5: Initialize the scanner engine with default timeout.
        The timeout determines how long to wait for a response when testing a port.
        """
        self.timeout = 1.0  # Default socket timeout in seconds
        self.banner_timeout = 3.0  # Longer timeout for banner grabbing
        self.ssl_timeout = 5.0  # Even longer timeout for SSL certificate retrieval
        
    def test_port(self, host: str, port: int) -> bool:
        """
        Step 6: Test if a specific port is open on the target host.
        This is the most basic operation - connecting to a specific port to see if it responds.
        
        Args:
            host: The hostname or IP address to scan
            port: The port number to scan
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            # Step 6.1: Create a new socket for this connection attempt
            # AF_INET specifies IPv4, SOCK_STREAM specifies TCP connection
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)  # Set socket timeout
            
            # Step 6.2: Attempt to connect to the port
            # connect_ex returns 0 if connection succeeds, error code otherwise
            result = s.connect_ex((host, port))
            s.close()  # Always close socket to free resources
            
            # Step 6.3: Return True if connection succeeded (port is open)
            return result == 0
            
        except Exception as e:
            # Log errors but continue scanning other ports
            logger.debug(f"Error scanning port {port}: {e}")
            return False
            
    def fetch_service_info(self, port: int) -> str:
        """
        Step 7: Fetch service information for a specific port number.
        This helps identify what service might be running on an open port.
        
        Args:
            port: The port number
            
        Returns:
            str: The service name associated with the port
        """
        try:
            # Step 7.1: First check our own map for common services (faster)
            if port in SERVICE_MAP:
                return SERVICE_MAP[port]
                
            # Step 7.2: Then try socket.getservbyport for less common services
            return socket.getservbyport(port)
        except (socket.error, OSError):
            # Return "Unknown" if service can't be identified
            return "Unknown"
    
    def grab_banner(self, host: str, port: int, service: str) -> Dict[str, Any]:
        """
        Grab service banner, version information, and other details from an open port.
        
        Args:
            host: The hostname or IP address of the target
            port: The port number that is open
            service: The identified service name
            
        Returns:
            Dict[str, Any]: Banner information including version, server details, etc.
        """
        banner_info = {
            "banner": "",
            "version": "",
            "server": "",
            "ssl_cert": {}
        }
        
        try:
            # Handle SSL/TLS services first
            if service in ["HTTPS", "IMAPS", "POP3S", "SMTPS"] or port in [443, 465, 636, 993, 995]:
                ssl_info = self.get_ssl_info(host, port)
                if ssl_info:
                    banner_info["ssl_cert"] = ssl_info
            
            # Handle HTTP/HTTPS
            if service in ["HTTP", "HTTPS"] or port in [80, 443, 8080, 8443]:
                http_info = self.grab_http_banner(host, port, service == "HTTPS" or port == 443)
                if http_info:
                    banner_info.update(http_info)
            
            # Handle FTP
            elif service == "FTP" or port == 21:
                ftp_banner = self.grab_protocol_banner(host, port)
                if ftp_banner:
                    banner_info["banner"] = ftp_banner
                    # Extract version from FTP banner if available
                    version_match = re.search(r'(\d+\.\d+\.\d+)', ftp_banner)
                    if version_match:
                        banner_info["version"] = version_match.group(1)
            
            # Handle SSH
            elif service == "SSH" or port == 22:
                ssh_banner = self.grab_protocol_banner(host, port)
                if ssh_banner:
                    banner_info["banner"] = ssh_banner
                    # Extract SSH version
                    version_match = re.search(r'SSH-(\d+\.\d+)-([^\s]+)', ssh_banner)
                    if version_match:
                        banner_info["version"] = f"{version_match.group(1)} {version_match.group(2)}"
            
            # Handle SMTP
            elif service == "SMTP" or port == 25:
                smtp_banner = self.grab_protocol_banner(host, port)
                if smtp_banner:
                    banner_info["banner"] = smtp_banner
                    # Extract SMTP server and version
                    server_match = re.search(r'ESMTP ([^\s]+)', smtp_banner)
                    if server_match:
                        banner_info["server"] = server_match.group(1)
            
            # Handle other services with a generic banner grab
            elif not banner_info["banner"]:
                generic_banner = self.grab_protocol_banner(host, port)
                if generic_banner:
                    banner_info["banner"] = generic_banner
            
        except Exception as e:
            logger.debug(f"Error grabbing banner for {host}:{port} - {e}")
        
        return banner_info
    
    def grab_protocol_banner(self, host: str, port: int) -> str:
        """
        Grab a generic protocol banner by connecting and reading the initial response.
        
        Args:
            host: The hostname or IP address to connect to
            port: The port number to connect to
            
        Returns:
            str: The banner string if available, empty string otherwise
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.banner_timeout)
            s.connect((host, port))
            
            # Some protocols send data immediately upon connection
            banner = ""
            try:
                # Wait for up to 2 seconds for initial data
                s.settimeout(2.0)
                data = s.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                # For protocols that don't send data immediately, try sending a newline
                try:
                    s.send(b"\r\n")
                    s.settimeout(2.0)
                    data = s.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except:
                    pass
            finally:
                s.close()
                
            return banner
        except Exception as e:
            logger.debug(f"Error grabbing protocol banner for {host}:{port} - {e}")
            return ""
    
    def grab_http_banner(self, host: str, port: int, use_ssl: bool = False) -> Dict[str, str]:
        """
        Grab HTTP server information by sending a HTTP HEAD request.
        
        Args:
            host: The hostname or IP address to connect to
            port: The port number to connect to
            use_ssl: Whether to use SSL/TLS for the connection
            
        Returns:
            Dict[str, str]: HTTP server information
        """
        http_info = {
            "banner": "",
            "server": "",
            "version": ""
        }
        
        try:
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.banner_timeout)
            s.connect((host, port))
            
            # Wrap socket with SSL if needed
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    s = context.wrap_socket(s, server_hostname=host)
                except Exception as e:
                    logger.debug(f"SSL wrapping failed for {host}:{port} - {e}")
                    s.close()
                    return http_info
            
            # Send HTTP HEAD request
            s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Port Scanner\r\nConnection: close\r\n\r\n".encode())
            
            # Receive and process response
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    
                    # Avoid reading too much data
                    if len(response) > 8192:
                        break
                except socket.timeout:
                    break
            
            s.close()
            
            if response:
                # Decode response and extract headers
                resp_text = response.decode('utf-8', errors='ignore')
                http_info["banner"] = resp_text.split('\r\n\r\n')[0]  # Just the headers
                
                # Extract server information
                server_match = re.search(r'Server: ([^\r\n]+)', resp_text)
                if server_match:
                    server = server_match.group(1).strip()
                    http_info["server"] = server
                    
                    # Try to extract version from server header
                    version_match = re.search(r'(\d+\.\d+\.\d+)', server)
                    if version_match:
                        http_info["version"] = version_match.group(1)
        
        except Exception as e:
            logger.debug(f"Error grabbing HTTP banner for {host}:{port} - {e}")
        
        return http_info
    
    def get_ssl_info(self, host: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information for a host:port."""
        ssl_info = {
            "valid": False,
            "issued_to": "Unknown",
            "issued_by": "Unknown",
            "valid_from": "",
            "valid_until": "",
            "version": "",
            "serial_number": "",
            "signature_algorithm": ""
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        return ssl_info
                    
                    ssl_info["valid"] = True
                    
                    # Get subject (issued to)
                    if 'subject' in cert and cert['subject']:
                        subject_parts = []
                        for field in cert['subject']:
                            for key, value in field:
                                if key in ['commonName', 'organizationName', 'organizationalUnitName']:
                                    subject_parts.append(value)
                        ssl_info["issued_to"] = " / ".join(filter(None, subject_parts))
                    
                    # Get issuer
                    if 'issuer' in cert and cert['issuer']:
                        issuer_parts = []
                        for field in cert['issuer']:
                            for key, value in field:
                                if key in ['commonName', 'organizationName']:
                                    issuer_parts.append(value)
                        ssl_info["issued_by"] = " / ".join(filter(None, issuer_parts))
                    
                    # Get validity dates
                    if 'notBefore' in cert:
                        ssl_info["valid_from"] = cert['notBefore']
                    if 'notAfter' in cert:
                        ssl_info["valid_until"] = cert['notAfter']
                    
                    # Get version and serial number
                    if 'version' in cert:
                        ssl_info["version"] = f"v{cert['version']}"
                    if 'serialNumber' in cert:
                        ssl_info["serial_number"] = cert['serialNumber']
                    
                    # Get signature algorithm
                    if 'signatureAlgorithm' in cert:
                        ssl_info["signature_algorithm"] = cert['signatureAlgorithm']
                    
        except (socket.error, ssl.SSLError, ssl.CertificateError) as e:
            logger.debug(f"Error grabbing SSL information for {host}:{port} - {e}")
            ssl_info["error"] = str(e)
        
        return ssl_info
    
    def scan_port_worker(self, host: str, port: int, progress_callback: Optional[Callable] = None) -> Tuple[int, bool, str, Dict[str, Any]]:
        """
        Step 8: Worker function that scans a single port.
        This is the function that will be executed by each thread.
        
        Args:
            host: The hostname or IP address to scan
            port: The port number to scan
            progress_callback: Optional callback function to update progress
            
        Returns:
            Tuple[int, bool, str, Dict[str, Any]]: Port number, open status, service name, and banner information
        """
        # Step 8.1: Test if port is open
        is_open = self.test_port(host, port)
        
        # Step 8.2: Get service info if port is open
        service = self.fetch_service_info(port) if is_open else ""
        
        # Step 8.3: Grab banner information if port is open
        banner_info = {}
        if is_open:
            banner_info = self.grab_banner(host, port, service)
        
        # Step 8.4: Call progress callback if provided
        # This updates the UI with scan progress
        if progress_callback:
            progress_callback(port, is_open)
            
        # Step 8.5: Log open ports for debugging
        if is_open:
            version_info = f" ({banner_info.get('version', '')})" if banner_info.get('version') else ""
            logger.info(f"Port {port} is {Fore.GREEN}open{Fore.RESET} ({service}{version_info})")
            
        # Step 8.6: Return results tuple for this port
        return port, is_open, service, banner_info
    
    def scan_ports(
        self, 
        host: str, 
        ports: List[int], 
        threading_module: 'ThreadingModule', 
        thread_count: int = 10,
        progress_callback: Optional[Callable] = None
    ) -> Dict[int, Dict[str, Any]]:
        """
        Step 9: Scan a list of ports on the target host using multithreading.
        This is the main scanning function that orchestrates the multithreaded scanning process.
        
        Args:
            host: The hostname or IP address to scan
            ports: List of port numbers to scan
            threading_module: ThreadingModule instance for managing threads
            thread_count: Number of threads to use for scanning
            progress_callback: Optional callback function to update progress
            
        Returns:
            Dict[int, Dict[str, Any]]: Dictionary of open ports with service and banner information
        """
        # Step 9.1: Import multiprocessing to get CPU count
        import multiprocessing
        import os
        
        # Step 9.2: Get the number of CPU cores available
        # This helps determine optimal thread count
        cpu_count = multiprocessing.cpu_count()
        
        # Step 9.3: Calculate optimal thread count based on CPU cores
        # For I/O bound operations like network scanning, 2x CPU cores is optimal
        max_recommended_threads = cpu_count * 2
        
        # Step 9.4: Cap the user-specified thread count to the optimal value
        # Too many threads can degrade performance
        if thread_count > max_recommended_threads:
            warning_msg = f"Requested {thread_count} threads exceeds the recommended maximum of {max_recommended_threads}"
            logger.warning(warning_msg)
            logger.warning(f"Limiting thread count to {max_recommended_threads} for optimal performance")
            thread_count = max_recommended_threads
            # If there's a progress callback, use it to show the warning
            if progress_callback:
                progress_callback(0, f"WARNING: {warning_msg}. Using {max_recommended_threads} threads instead.")
        
        # Step 9.5: The final thread count should not exceed the number of ports
        # No point in having more threads than tasks
        effective_thread_count = min(thread_count, len(ports))
        
        logger.info(f"Using {effective_thread_count} threads on a system with {cpu_count} CPU cores")
        
        # Step 9.6: Shuffle ports to avoid sequential scanning patterns
        # This makes the scan less detectable as an attack
        random.shuffle(ports)
        
        # Step 9.7: Create scanning tasks
        # Each task is a tuple of (function, arguments)
        tasks = []
        for port in ports:
            tasks.append((self.scan_port_worker, (host, port, progress_callback)))
        
        # Step 9.8: Execute scans with threads
        # This is where the ThreadingModule does the heavy lifting
        results = threading_module.execute_tasks(tasks, effective_thread_count)
        
        # Step 9.9: Collect results of open ports
        open_ports = {}
        for port, is_open, service, banner_info in results:
            if is_open:
                # Store service and banner information in a structured format
                port_data = {
                    "service": service,
                    "banner": banner_info.get("banner", ""),
                    "version": banner_info.get("version", ""),
                    "server": banner_info.get("server", ""),
                    "ssl_cert": banner_info.get("ssl_cert", {})
                }
                open_ports[port] = port_data
                
        # Step 9.10: Return dictionary of open ports and their detailed information
        return open_ports
        
    def ping_host(self, host: str) -> bool:
        """
        Step 10: Check if a host is up using a socket connection.
        This is a quick way to check if the target is reachable before scanning.
        
        Args:
            host: The hostname or IP address to check
            
        Returns:
            bool: True if host is up, False otherwise
        """
        try:
            # Step 10.1: Try to connect to common ports first (HTTP/HTTPS)
            for port in [80, 443]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)  # Short timeout for fast check
                result = s.connect_ex((host, port))
                s.close()
                if result == 0:
                    return True
            
            # Step 10.2: If no successful connection, try echo service
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((host, 7))  # Try echo service port
            s.close()
            
            return result == 0
            
        except Exception as e:
            logger.debug(f"Error pinging host {host}: {e}")
            return False

    def validate_port_range(self, port_range: str) -> List[int]:
        """
        Validate and parse port range string into a list of ports.
        
        Args:
            port_range: String containing port numbers and ranges (e.g., "80,443,8000-8100")
            
        Returns:
            List[int]: List of valid port numbers
            
        Raises:
            ValueError: If port range is invalid
        """
        if not port_range:
            raise ValueError("Port range cannot be empty")
        
        valid_ports = set()
        parts = port_range.split(',')
        
        for part in parts:
            part = part.strip()
            try:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if start < 1 or end > 65535:
                        raise ValueError(f"Ports must be between 1 and 65535: {part}")
                    if start > end:
                        raise ValueError(f"Invalid range (start > end): {part}")
                    valid_ports.update(range(start, end + 1))
                else:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port must be between 1 and 65535: {port}")
                    valid_ports.add(port)
            except ValueError as e:
                if "invalid literal for int()" in str(e):
                    raise ValueError(f"Invalid port number format: {part}")
                raise
        
        # Convert to sorted list
        return sorted(list(valid_ports))
