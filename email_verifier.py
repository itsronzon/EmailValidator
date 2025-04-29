import re
import socket
import logging
import dns.resolver
from dns.exception import DNSException
from dns.resolver import NXDOMAIN, NoAnswer, Timeout

logger = logging.getLogger(__name__)

class EmailVerifier:
    """
    Class for verifying email addresses through multiple checks:
    - Syntax validation using regex
    - Domain existence verification
    - MX record checking
    """
    
    def __init__(self):
        # RFC 5322 compliant regex for email validation
        self.email_regex = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0  # 5 second timeout for DNS queries
        self.resolver.lifetime = 5.0  # 5 second lifetime for DNS queries
    
    def verify_email(self, email):
        """
        Verifies an email address through multiple checks
        
        Args:
            email (str): The email address to verify
            
        Returns:
            dict: Results of the verification process
        """
        results = {
            'email': email,
            'is_valid_format': False,
            'has_valid_domain': False,
            'has_mx_records': False,
            'verification_steps': [],
            'is_deliverable': False
        }
        
        # Step 1: Syntax Check
        syntax_result = self._check_syntax(email)
        results['verification_steps'].append({
            'step': 'syntax_check',
            'passed': syntax_result['passed'],
            'message': syntax_result['message']
        })
        results['is_valid_format'] = syntax_result['passed']
        
        # If syntax check failed, don't proceed further
        if not syntax_result['passed']:
            return results
        
        # Extract domain from email
        domain = email.split('@')[-1]
        
        # Step 2: Domain Check
        domain_result = self._check_domain(domain)
        results['verification_steps'].append({
            'step': 'domain_check',
            'passed': domain_result['passed'],
            'message': domain_result['message']
        })
        results['has_valid_domain'] = domain_result['passed']
        
        # If domain check failed, don't proceed further
        if not domain_result['passed']:
            return results
        
        # Step 3: MX Record Check
        mx_result = self._check_mx_records(domain)
        results['verification_steps'].append({
            'step': 'mx_check',
            'passed': mx_result['passed'],
            'message': mx_result['message']
        })
        results['has_mx_records'] = mx_result['passed']
        
        # Final verdict
        results['is_deliverable'] = (
            results['is_valid_format'] and 
            results['has_valid_domain'] and 
            results['has_mx_records']
        )
        
        return results
    
    def _check_syntax(self, email):
        """Validates email syntax using regex"""
        try:
            # Check email length
            if len(email) > 254:
                return {
                    'passed': False,
                    'message': 'Email is too long (max 254 characters)'
                }
            
            # Check email format using regex
            if not self.email_regex.match(email):
                return {
                    'passed': False,
                    'message': 'Invalid email format'
                }
            
            # Basic checks for common mistakes
            if email.count('@') != 1:
                return {
                    'passed': False, 
                    'message': 'Email must contain exactly one @ symbol'
                }
            
            local_part, domain = email.split('@')
            
            if not local_part:
                return {
                    'passed': False,
                    'message': 'Local part (before @) cannot be empty'
                }
                
            if not domain:
                return {
                    'passed': False,
                    'message': 'Domain part (after @) cannot be empty'
                }
                
            if '..' in local_part or '..' in domain:
                return {
                    'passed': False,
                    'message': 'Email cannot contain consecutive dots'
                }
            
            if not '.' in domain:
                return {
                    'passed': False,
                    'message': 'Domain must have at least one dot'
                }
            
            return {
                'passed': True,
                'message': 'Email format is valid'
            }
            
        except Exception as e:
            logger.exception("Error in syntax check")
            return {
                'passed': False,
                'message': f'Syntax check error: {str(e)}'
            }
    
    def _check_domain(self, domain):
        """Verifies that the domain exists"""
        try:
            # Try to resolve the domain's A record
            socket.gethostbyname(domain)
            return {
                'passed': True,
                'message': f'Domain {domain} exists and resolves to an IP address'
            }
        except socket.gaierror:
            try:
                # Fall back to checking MX records directly
                # Some domains might not have A records but still have MX records
                mx_records = self.resolver.resolve(domain, 'MX')
                if mx_records:
                    return {
                        'passed': True,
                        'message': f'Domain {domain} exists with MX records'
                    }
                return {
                    'passed': False,
                    'message': f'Domain {domain} could not be resolved'
                }
            except (NXDOMAIN, NoAnswer):
                return {
                    'passed': False,
                    'message': f'Domain {domain} does not exist'
                }
            except Timeout:
                return {
                    'passed': False,
                    'message': f'Timeout while checking domain {domain}'
                }
            except DNSException as e:
                return {
                    'passed': False,
                    'message': f'DNS error for domain {domain}: {str(e)}'
                }
        except Exception as e:
            logger.exception(f"Error checking domain {domain}")
            return {
                'passed': False,
                'message': f'Domain check error: {str(e)}'
            }
    
    def _check_mx_records(self, domain):
        """Checks if the domain has MX records for receiving email"""
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            if mx_records:
                mx_hosts = [mx.exchange.to_text() for mx in mx_records]
                return {
                    'passed': True,
                    'message': f'Domain has {len(mx_records)} MX records: {", ".join(mx_hosts)}'
                }
            return {
                'passed': False,
                'message': f'No MX records found for domain {domain}'
            }
        except NXDOMAIN:
            return {
                'passed': False,
                'message': f'Domain {domain} does not exist'
            }
        except NoAnswer:
            return {
                'passed': False,
                'message': f'No MX records found for domain {domain}'
            }
        except Timeout:
            return {
                'passed': False,
                'message': f'Timeout while checking MX records for {domain}'
            }
        except DNSException as e:
            return {
                'passed': False,
                'message': f'Error checking MX records: {str(e)}'
            }
        except Exception as e:
            logger.exception(f"Error checking MX records for {domain}")
            return {
                'passed': False,
                'message': f'MX record check error: {str(e)}'
            }
