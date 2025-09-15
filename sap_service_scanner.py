#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Modular SAP Service Port Scanner

This script provides a modular framework for scanning various SAP services.
It uses the pysap library to craft authentic SAP packets for service detection.
New services can be easily added by implementing the SAPServiceBase class.

Usage:
    python sap_service_scanner.py -t <target_ip> -s <service_name> [options]
    
Example:
    python sap_service_scanner.py -t 192.168.1.100 -s rfc_gateway -p 00
"""

import argparse
import socket
import sys
import time
import abc

try:
    from scapy.all import *
    from scapy.config import conf
    from scapy.supersocket import StreamSocket
    from scapy.layers.inet import TCP
    from pysap.SAPRFC import SAPRFC
    from pysap.SAPNI import SAPNI, SAPNIStreamSocket
    from pysap.SAPRouter import SAPRoutedStreamSocket
    from pysap.SAPMS import SAPMS, SAPMSLogon
except ImportError as e:
    print("[!] Error: Required library not found: %s" % str(e))
    print("[!] Please install required packages: pip install pysap scapy")
    sys.exit(1)


# Base class for SAP service scanners
class SAPServiceBase(object):
    """
    Abstract base class for SAP service scanners.
    Implement this class to add support for new SAP services.
    """
    __metaclass__ = abc.ABCMeta
    
    def __init__(self, target_host, timeout=5, verbose=False):
        """
        Initialize the service scanner
        
        Args:
            target_host (str): Target IP address or hostname
            timeout (int): Connection timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.target_host = target_host
        self.timeout = timeout
        self.verbose = verbose
        
        # Configure scapy for SAP protocols
        conf.L3Socket = StreamSocket
        bind_layers(TCP, SAPNI)
        bind_layers(SAPNI, SAPRFC)
    
    @abc.abstractmethod
    def get_service_name(self):
        """Return the name of this service"""
        pass
    
    @abc.abstractmethod
    def get_default_port(self, instance='00'):
        """Return the default port for this service given an instance"""
        pass
    
    @abc.abstractmethod
    def craft_packet(self, instance='00'):
        """Craft the service-specific packet for detection"""
        pass
    
    @abc.abstractmethod
    def is_valid_response(self, response):
        """Analyze response to determine if service is running"""
        pass
    
    def scan(self, instance='00', custom_port=None):
        """
        Scan the target for this service
        
        Args:
            instance (str): Service instance (e.g., '00', '01')
            custom_port (int): Override default port
            
        Returns:
            bool: True if service detected, False otherwise
        """
        port = custom_port if custom_port else self.get_default_port(instance)
        
        if self.verbose:
            print("[+] Scanning %s:%d for %s service..." % (self.target_host, port, self.get_service_name()))
        
        packet = self.craft_packet(instance)
        if not packet:
            return False
        
        try:
            # Create socket connection using pysap's SAPNIStreamSocket
            if self.verbose:
                print("[+] Establishing connection to %s:%d" % (self.target_host, port))
            
            # Note: SAPNIStreamSocket.get_nisocket() doesn't accept timeout parameter
            # We need to handle timeout at the socket level
            socket_conn = SAPNIStreamSocket.get_nisocket(self.target_host, port)
            
            # Set socket timeout after connection
            if hasattr(socket_conn, 'settimeout'):
                socket_conn.settimeout(self.timeout)
            elif hasattr(socket_conn, 'ins') and hasattr(socket_conn.ins, 'settimeout'):
                socket_conn.ins.settimeout(self.timeout)
            
            if self.verbose:
                print("[+] Connection established, sending %s packet..." % self.get_service_name())
            
            # Send packet and receive response
            response = socket_conn.sr(packet)
            
            if response:
                if self.verbose:
                    print("[+] Received response from target")
                    print("[+] Response details: %s" % str(response))
                
                # Check if response indicates active service
                if self.is_valid_response(response):
                    print("[+] %s service DETECTED on %s:%d" % (self.get_service_name(), self.target_host, port))
                    socket_conn.close()
                    return True
                else:
                    if self.verbose:
                        print("[-] Response received but doesn't indicate %s service" % self.get_service_name())
            else:
                if self.verbose:
                    print("[-] No response received from target")
            
            socket_conn.close()
            return False
            
        except socket.timeout:
            if self.verbose:
                print("[-] Connection timeout to %s:%d" % (self.target_host, port))
            return False
        except socket.error as e:
            if self.verbose:
                print("[-] Connection error to %s:%d: %s" % (self.target_host, port, str(e)))
            return False
        except Exception as e:
            if self.verbose:
                print("[!] Error during scan: %s" % str(e))
            return False


class RFCGatewayService(SAPServiceBase):
    """SAP RFC Gateway service scanner"""
    
    def get_service_name(self):
        return "SAP RFC Gateway"
    
    def get_default_port(self, instance='00'):
        return 3300 + int(instance)
    
    def craft_packet(self, instance='00'):
        """
        Craft GW_NORMAL_CLIENT packet with OPCODE 0x03
        
        Args:
            instance (str): Instance number (e.g., '00', '01')
            
        Returns:
            SAPRFC: Crafted packet ready to send
        """
        try:
            instance = instance.zfill(2)  # Ensure 2-digit format
            
            # Create GW_NORMAL_CLIENT packet based on expGWanon.py implementation
            packet = SAPRFC(
                version=2,
                req_type='GW_NORMAL_CLIENT',  # This corresponds to OPCODE 0x03
                address=self.target_host,
                service='sapgw%s' % instance,
                codepage=4103,
                lu='sapserve',
                tp='sapgw%s' % instance,
                conversation_id=' ' * 8,
                appc_header_version=6,
                accept_info='EINFO+PING+CONN_EINFO',
                idx=-1,
            )
            
            if self.verbose:
                print("[+] Crafted GW_NORMAL_CLIENT packet for %s:%d" % (self.target_host, self.get_default_port(instance)))
                
            return packet
            
        except Exception as e:
            print("[!] Error crafting packet: %s" % str(e))
            return None
    
    def is_valid_response(self, response):
        """
        Analyze response to determine if it's from an RFC Gateway service
        
        Args:
            response: Response packet from target
            
        Returns:
            bool: True if valid RFC Gateway response
        """
        try:
            # Basic checks for valid RFC Gateway response
            if response and hasattr(response, 'req_type'):
                # Look for specific response patterns that indicate RFC Gateway
                if 'GW_' in str(response.req_type) or response.req_type in ['GW_NORMAL_CLIENT']:
                    return True
            
            # Additional checks based on response analysis
            if response:
                response_str = str(response)
                gateway_indicators = ['gateway', 'rfc', 'sapgw', 'gw_']
                if any(indicator in response_str.lower() for indicator in gateway_indicators):
                    return True
            
            return False
            
        except Exception as e:
            if self.verbose:
                print("[!] Error analyzing response: %s" % str(e))
            return False


# Example of how to add a new service - SAP Message Server
class MessageServerService(SAPServiceBase):
    """SAP Message Server service scanner (example implementation)"""
    
    def get_service_name(self):
        return "SAP Message Server"
    
    def get_default_port(self, instance='00'):
        # Message Server typically runs on port 36XX for external connections or 39XX for internal connections
        return 3600 + int(instance)
    
    def craft_packet(self, instance='00'):
        """
        Craft Message Server packet using SAPMS from pysap library
        
        Args:
            instance (str): SAP instance number
            
        Returns:
            SAPMS: Crafted Message Server packet ready to send
        """
        try:
            instance = instance.zfill(2)  # Ensure 2-digit format
            
            # Create a basic Message Server packet for detection
            # Based on nmap service probe pattern for Message Server
            try:
                # Try creating SAPMS packet with minimal configuration
                ms_packet = SAPMS()
                
                # Alternative: Use raw packet data based on nmap MessageServer probe
                # This is the pattern from nmap-service-probes for Message Server detection
                raw_ms_probe = (
                    '\x00\x00\x00\x72**MESSAGE**\x00\x04\x00MSG_SERVER\x00\x00'
                    'msxxi.c\x00%s: MsSndName failed\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x02\x01\x2D' + ' ' * 32 + '\x00\x00\x05\x00\x68\x03'
                )
                
                # If SAPMS() fails, we'll use the raw probe data
                if not ms_packet:
                    ms_packet = raw_ms_probe
                    
            except Exception as e:
                if self.verbose:
                    print("[!] SAPMS creation failed: %s, using raw probe" % str(e))
                # Fallback to raw Message Server probe packet
                ms_packet = (
                    '\x00\x00\x00\x72**MESSAGE**\x00\x04\x00MSG_SERVER\x00\x00'
                    'msxxi.c\x00scanner: MsSndName probe\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x02\x01\x2D' + ' ' * 32 + 
                    '\x00\x00\x05\x00\x68\x03'
                )
            
            if self.verbose:
                print("[+] Crafted SAPMS packet for %s:%d" % (self.target_host, self.get_default_port(instance)))
                
            return ms_packet
            
        except Exception as e:
            print("[!] Error crafting Message Server packet: %s" % str(e))
            return None
    
    def is_valid_response(self, response):
        """
        Analyze response to determine if it's from a Message Server
        
        Based on typical Message Server response patterns and the
        nmap service probe patterns for Message Server detection
        
        Args:
            response: Response packet from target
            
        Returns:
            bool: True if valid Message Server response
        """
        try:
            # Check for SAPMS response patterns
            if response and hasattr(response, 'logon'):
                # Look for Message Server logon response
                if hasattr(response.logon, 'type'):
                    return True
            
            # Check for typical Message Server response indicators
            if response:
                response_str = str(response).lower()
                ms_indicators = ['message', 'sapms', 'msg_server', '**message**']
                if any(indicator in response_str for indicator in ms_indicators):
                    return True
                
                # Check for specific Message Server response patterns from nmap probes
                if 'release no =' in response_str or 'system name =' in response_str:
                    return True
            
            return False
            
        except Exception as e:
            if self.verbose:
                print("[!] Error analyzing Message Server response: %s" % str(e))
            return False


# Service registry - add new services here
AVAILABLE_SERVICES = {
    'rfc_gateway': RFCGatewayService,
    'message_server': MessageServerService,
    # Add more services here as they are implemented
}


def list_services():
    """List all available services"""
    print("Available SAP services:")
    for service_name, service_class in AVAILABLE_SERVICES.items():
        # Create a temporary instance to get service info
        temp_instance = service_class('dummy')
        print("  %-15s - %s" % (service_name, temp_instance.get_service_name()))


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Modular SAP Service Port Scanner using pysap library",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  # Scan RFC Gateway on port 3300
  python %(prog)s -t 192.168.1.100 -s rfc_gateway -i 00
  
  # Scan with verbose output and custom timeout
  python %(prog)s -t sap-server.com -s rfc_gateway -i 01 -v --timeout 10
  
  # List available services
  python %(prog)s --list-services"""
    )
    
    parser.add_argument(
        '-t', '--target', 
        help='Target IP address or hostname'
    )
    
    parser.add_argument(
        '-s', '--service',
        choices=AVAILABLE_SERVICES.keys(),
        help='SAP service to scan for'
    )
    
    parser.add_argument(
        '-i', '--instance',
        default='00',
        help='SAP instance number (default: 00)'
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='Custom port (overrides default service port)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Connection timeout in seconds (default: 5)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--list-services',
        action='store_true',
        help='List available services and exit'
    )
    
    args = parser.parse_args()
    
    # Handle service listing
    if args.list_services:
        list_services()
        return
    
    # Validate required arguments
    if not args.target:
        print("[!] Error: Target (-t) is required")
        parser.print_help()
        sys.exit(1)
    
    if not args.service:
        print("[!] Error: Service (-s) is required")
        print("\nUse --list-services to see available services")
        sys.exit(1)
    
    # Validate instance
    try:
        instance_num = int(args.instance)
        if instance_num < 0 or instance_num > 99:
            print("[!] Error: Instance must be between 00 and 99")
            sys.exit(1)
    except ValueError:
        print("[!] Error: Instance must be a valid number")
        sys.exit(1)
    
    # Get service class
    service_class = AVAILABLE_SERVICES[args.service]
    
    # Create service instance
    service = service_class(
        target_host=args.target,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    print("Modular SAP Service Scanner")
    print("Target: %s" % args.target)
    print("Service: %s" % service.get_service_name())
    print("Instance: %s" % args.instance.zfill(2))
    if args.port:
        print("Port: %d (custom)" % args.port)
    else:
        print("Port: %d (default)" % service.get_default_port(args.instance))
    print("-" * 50)
    
    # Run scan
    start_time = time.time()
    result = service.scan(instance=args.instance, custom_port=args.port)
    end_time = time.time()
    
    print("-" * 50)
    port = args.port if args.port else service.get_default_port(args.instance)
    if result:
        print("[+] RESULT: %s service found on %s:%d" % (service.get_service_name(), args.target, port))
    else:
        print("[-] RESULT: No %s service detected on %s:%d" % (service.get_service_name(), args.target, port))
    
    print("[*] Scan completed in %.2f seconds" % (end_time - start_time))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print("[!] Unexpected error: %s" % str(e))
        sys.exit(1)
