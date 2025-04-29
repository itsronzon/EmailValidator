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
    - Disposable email detection
    - Common patterns evaluation
    - Deliverability scoring
    """
    
    def __init__(self):
        # RFC 5322 compliant regex for email validation
        self.email_regex = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0  # 5 second timeout for DNS queries
        self.resolver.lifetime = 5.0  # 5 second lifetime for DNS queries
        
        # List of known disposable email domains
        self.disposable_domains = [
            'mailinator.com', 'tempmail.com', 'throwawaymail.com', 'yopmail.com', 
            'guerrillamail.com', '10minutemail.com', 'temp-mail.org', 'dispostable.com',
            'sharklasers.com', 'trashmail.com', 'temporary-mail.net', 'mailnesia.com',
            'tempr.email', 'emailondeck.com', 'tempinbox.com', 'getnada.com',
            'maildrop.cc', 'fake-email.com', 'mailinator.net', 'mailinator.org'
        ]
        
        # Approximate likelihood scoring weights
        self.score_weights = {
            'syntax': 15,             # Base score for valid syntax
            'domain_exists': 20,      # Score for domain existing
            'mx_records': 25,         # Score for having MX records
            'disposable_domain': -30, # Penalty for disposable domains
            'popular_domain': 15,     # Bonus for common email providers
            'name_pattern': 10        # Bonus for standard name patterns
        }
        
        # Common/popular email provider domains
        self.popular_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'gmx.com',
            'yandex.com', 'live.com', 'comcast.net', 'verizon.net', 'att.net',
            'msn.com', 'me.com', 'mac.com', 'fastmail.com', 'mail.ru'
        ]
    
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
            'is_disposable': False,
            'score': 0,            # Score from 0-100 indicating likelihood of deliverability
            'score_details': {},   # Detailed breakdown of the score
            'verification_steps': [],
            'is_deliverable': False
        }
        
        # Initialize score details
        score_details = {
            'syntax': 0,
            'domain_exists': 0,
            'mx_records': 0,
            'disposable_domain': 0,
            'popular_domain': 0,
            'name_pattern': 0
        }
        
        # Step 1: Syntax Check
        syntax_result = self._check_syntax(email)
        results['verification_steps'].append({
            'step': 'syntax_check',
            'passed': syntax_result['passed'],
            'message': syntax_result['message']
        })
        results['is_valid_format'] = syntax_result['passed']
        
        # Add to score if syntax is valid
        if syntax_result['passed']:
            score_details['syntax'] = self.score_weights['syntax']
        
        # If syntax check failed, don't proceed further but still calculate score
        if not syntax_result['passed']:
            results['score_details'] = score_details
            results['score'] = sum(score_details.values())
            return results
        
        # Extract domain and local part from email
        local_part, domain = email.split('@')
        
        # Step 2: Domain Check
        domain_result = self._check_domain(domain)
        results['verification_steps'].append({
            'step': 'domain_check',
            'passed': domain_result['passed'],
            'message': domain_result['message']
        })
        results['has_valid_domain'] = domain_result['passed']
        
        # Add to score if domain exists
        if domain_result['passed']:
            score_details['domain_exists'] = self.score_weights['domain_exists']
        
        # Step 3: MX Record Check
        mx_result = self._check_mx_records(domain)
        results['verification_steps'].append({
            'step': 'mx_check',
            'passed': mx_result['passed'],
            'message': mx_result['message']
        })
        results['has_mx_records'] = mx_result['passed']
        
        # Add to score if MX records exist
        if mx_result['passed']:
            score_details['mx_records'] = self.score_weights['mx_records']
        
        # Step 4: Check if disposable email
        disposable_result = self._check_disposable_email(domain)
        results['verification_steps'].append({
            'step': 'disposable_check',
            'passed': not disposable_result['is_disposable'],
            'message': disposable_result['message']
        })
        results['is_disposable'] = disposable_result['is_disposable']
        
        # Adjust score for disposable domains
        if disposable_result['is_disposable']:
            score_details['disposable_domain'] = self.score_weights['disposable_domain']
        
        # Step 5: Check if domain is from a popular provider
        popular_result = self._check_popular_domain(domain)
        results['verification_steps'].append({
            'step': 'popular_domain_check',
            'passed': popular_result['is_popular'],
            'message': popular_result['message']
        })
        
        # Add to score if it's a popular domain
        if popular_result['is_popular']:
            score_details['popular_domain'] = self.score_weights['popular_domain']
        
        # Step 6: Check if the email follows common patterns
        pattern_result = self._check_email_pattern(local_part)
        results['verification_steps'].append({
            'step': 'pattern_check',
            'passed': pattern_result['is_common_pattern'],
            'message': pattern_result['message']
        })
        
        # Add to score if it follows a common pattern
        if pattern_result['is_common_pattern']:
            score_details['name_pattern'] = self.score_weights['name_pattern']
        
        # Calculate final score (ensure it's between 0-100)
        final_score = sum(score_details.values())
        results['score'] = max(0, min(100, final_score))
        results['score_details'] = score_details
        
        # Set deliverability based on all checks
        # Basic deliverability still requires the three fundamental checks
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
    
    def _check_disposable_email(self, domain):
        """Check if the email domain is a known disposable email provider"""
        try:
            is_disposable = domain.lower() in self.disposable_domains
            
            if is_disposable:
                return {
                    'is_disposable': True,
                    'message': f'Domain {domain} is a known disposable email provider'
                }
            else:
                return {
                    'is_disposable': False,
                    'message': f'Domain {domain} is not a known disposable email provider'
                }
        except Exception as e:
            logger.exception(f"Error checking if {domain} is disposable")
            # Default to false if there's an error
            return {
                'is_disposable': False,
                'message': f'Could not determine if {domain} is a disposable domain: {str(e)}'
            }
    
    def _check_popular_domain(self, domain):
        """Check if the domain is a popular email provider"""
        try:
            is_popular = domain.lower() in self.popular_domains
            
            if is_popular:
                return {
                    'is_popular': True,
                    'message': f'Domain {domain} is a popular email provider'
                }
            else:
                return {
                    'is_popular': False,
                    'message': f'Domain {domain} is not a common email provider'
                }
        except Exception as e:
            logger.exception(f"Error checking if {domain} is a popular domain")
            # Default to false if there's an error
            return {
                'is_popular': False,
                'message': f'Could not determine if {domain} is a popular domain: {str(e)}'
            }
    
    def _check_email_pattern(self, local_part):
        """
        Checks if the local part of the email follows common patterns.
        Common patterns include:
        - first.last
        - firstlast
        - first_last
        - first.m.last
        - first-last
        - first_initial + last (jsmith)
        - first + last_initial (johns)
        """
        try:
            # Check for standard name patterns with separators
            has_separator = any(sep in local_part for sep in ['.', '_', '-'])
            
            # Check for standard pattern of first+last or similar
            parts = re.split(r'[._-]', local_part)
            
            # Heuristic: if we have 2-3 parts and they seem like name components
            if 2 <= len(parts) <= 3 and all(len(part) >= 1 for part in parts):
                return {
                    'is_common_pattern': True,
                    'message': 'Email follows a common name pattern (e.g., first.last)'
                }
            
            # Check for common first+last without separator
            # If it's not just numbers or random chars but looks like a name
            if not re.match(r'^[0-9]+$', local_part) and len(local_part) >= 4:
                # Heuristic: most random strings would be shorter or contain numbers
                not_random_looking = re.match(r'^[a-zA-Z]+$', local_part)
                if not_random_looking:
                    return {
                        'is_common_pattern': True,
                        'message': 'Email appears to follow a standard naming pattern'
                    }
            
            # If no patterns match, it could be a less common format
            return {
                'is_common_pattern': False,
                'message': 'Email does not follow common name patterns'
            }
        except Exception as e:
            logger.exception(f"Error analyzing email pattern: {local_part}")
            # Default to false if there's an error
            return {
                'is_common_pattern': False,
                'message': f'Could not analyze email pattern: {str(e)}'
            }
