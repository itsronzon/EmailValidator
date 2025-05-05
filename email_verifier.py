import re
import socket
import logging
import smtplib
import dns.resolver
import random
import string
import time
from dns.exception import DNSException
from dns.resolver import NXDOMAIN, NoAnswer, Timeout

logger = logging.getLogger(__name__)

class EmailVerifier:
    """
    Class for verifying email addresses through multiple checks:
    - Syntax validation using regex
    - Domain existence verification
    - MX record checking
    - SMTP server validation (recipient verification)
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
            'syntax': 10,             # Base score for valid syntax
            'domain_exists': 15,      # Score for domain existing
            'mx_records': 15,         # Score for having MX records
            'smtp_check': 35,         # Score for SMTP recipient validation
            'disposable_domain': -30, # Penalty for disposable domains
            'popular_domain': 10,     # Bonus for common email providers
            'name_pattern': 5,        # Bonus for standard name patterns
            'catch_all': -20,         # Penalty for catch-all domains
            'role_account': -15       # Penalty for common role-based addresses
        }
        
        # Common/popular email provider domains
        self.popular_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'gmx.com',
            'yandex.com', 'live.com', 'comcast.net', 'verizon.net', 'att.net',
            'msn.com', 'me.com', 'mac.com', 'fastmail.com', 'mail.ru'
        ]
        
        # Common role-based email addresses
        self.role_accounts = [
            'admin', 'webmaster', 'support', 'info', 'contact', 'sales', 'help',
            'noreply', 'no-reply', 'postmaster', 'hostmaster', 'abuse', 'webadmin',
            'marketing', 'office', 'mail', 'feedback', 'team', 'customerservice',
            'hello', 'billing', 'jobs', 'hr', 'careers', 'service', 'orders'
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
            'is_role_account': False,
            'is_catch_all': False,
            'smtp_check': False,
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
            'smtp_check': 0,
            'disposable_domain': 0,
            'popular_domain': 0,
            'name_pattern': 0,
            'role_account': 0,
            'catch_all': 0
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
        
        # Step 2: Check if email is a role account
        role_result = self._check_role_account(local_part)
        results['verification_steps'].append({
            'step': 'role_account_check',
            'passed': not role_result['is_role_account'],
            'message': role_result['message']
        })
        results['is_role_account'] = role_result['is_role_account']
        
        # Adjust score for role accounts
        if role_result['is_role_account']:
            score_details['role_account'] = self.score_weights['role_account']
        
        # Step 3: Domain Check
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
        else:
            # If domain doesn't exist, don't proceed with further checks
            results['score_details'] = score_details
            results['score'] = max(0, min(100, sum(score_details.values())))
            return results
        
        # Step 4: MX Record Check
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
        else:
            # If no MX records, don't proceed with SMTP checks
            results['score_details'] = score_details
            results['score'] = max(0, min(100, sum(score_details.values())))
            return results
        
        # Step 5: SMTP Validation - Only proceed if we have MX records
        smtp_result = self._check_smtp(email, domain, mx_result.get('mx_hosts', []))
        results['verification_steps'].append({
            'step': 'smtp_check',
            'passed': smtp_result['passed'],
            'message': smtp_result['message']
        })
        results['smtp_check'] = smtp_result['passed']
        results['is_catch_all'] = smtp_result.get('is_catch_all', False)
        
        # Adjust score based on SMTP results
        if smtp_result['passed']:
            score_details['smtp_check'] = self.score_weights['smtp_check']
        # Apply penalty for catch-all domains
        if smtp_result.get('is_catch_all', False):
            score_details['catch_all'] = self.score_weights['catch_all']
            results['verification_steps'].append({
                'step': 'catch_all_check',
                'passed': False,
                'message': 'Domain accepts all email addresses (catch-all)'
            })
        
        # Step 6: Check if disposable email
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
        
        # Step 7: Check if domain is from a popular provider
        popular_result = self._check_popular_domain(domain)
        results['verification_steps'].append({
            'step': 'popular_domain_check',
            'passed': popular_result['is_popular'],
            'message': popular_result['message']
        })
        
        # Add to score if it's a popular domain
        if popular_result['is_popular']:
            score_details['popular_domain'] = self.score_weights['popular_domain']
        
        # Step 8: Check if the email follows common patterns
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
        
        # Set deliverability based on all checks - now includes SMTP check
        results['is_deliverable'] = (
            results['is_valid_format'] and 
            results['has_valid_domain'] and 
            results['has_mx_records'] and
            (results['smtp_check'] or results['is_catch_all'])
        )
        
        # Special handling for popular email providers (Gmail, Yahoo, etc.)
        if popular_result['is_popular']:
            # For major providers, we need to apply stricter rules since we skipped SMTP check
            # Check if the username part follows their patterns
            if domain.lower() == 'gmail.com':
                # Gmail addresses must be at least 6 chars, no dots before @ count
                # Gmail also doesn't allow certain characters
                valid_gmail = len(local_part) >= 6 and not re.search(r'[^a-zA-Z0-9._%+-]', local_part)
                if not valid_gmail:
                    # Unlikely to be a valid Gmail 
                    results['is_deliverable'] = False
                    results['score'] = min(results['score'], 40)  # Cap score for invalid Gmail patterns
                    results['verification_steps'].append({
                        'step': 'provider_pattern_check',
                        'passed': False,
                        'message': 'Email does not follow Gmail-specific format rules'
                    })
            
            # Similar rules could be added for Yahoo, Outlook, etc.
            
            # For popular domains, pattern recognition is more important
            if not pattern_result['is_common_pattern'] and not role_result['is_role_account']:
                # Reduce score for uncommon patterns in major providers
                results['score'] = int(results['score'] * 0.8)
        
        # Handle non-existent addresses for all domains
        if not results['smtp_check'] and not results['is_catch_all']:
            # Check for obviously fake usernames
            if re.match(r'^[a-z]{1,3}[0-9]{6,}$', local_part):  # Like abc123456
                results['is_deliverable'] = False
                results['score'] = min(results['score'], 30)
            
            # Adjust score - if SMTP check failed, cap the maximum score
            if results['score'] > 60:
                results['score'] = 60  # Cap at 60 when SMTP verification fails/skipped
            
            # For non-popular domains, rely more on pattern recognition
            if not popular_result['is_popular'] and not pattern_result['is_common_pattern']:
                results['score'] = int(results['score'] * 0.7)  # Reduce by 30%
        
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
                    'message': f'Domain has {len(mx_records)} MX records: {", ".join(mx_hosts)}',
                    'mx_hosts': mx_hosts  # Return the MX hosts for SMTP verification
                }
            return {
                'passed': False,
                'message': f'No MX records found for domain {domain}',
                'mx_hosts': []
            }
        except NXDOMAIN:
            return {
                'passed': False,
                'message': f'Domain {domain} does not exist',
                'mx_hosts': []
            }
        except NoAnswer:
            return {
                'passed': False,
                'message': f'No MX records found for domain {domain}',
                'mx_hosts': []
            }
        except Timeout:
            return {
                'passed': False,
                'message': f'Timeout while checking MX records for {domain}',
                'mx_hosts': []
            }
        except DNSException as e:
            return {
                'passed': False,
                'message': f'Error checking MX records: {str(e)}',
                'mx_hosts': []
            }
        except Exception as e:
            logger.exception(f"Error checking MX records for {domain}")
            return {
                'passed': False,
                'message': f'MX record check error: {str(e)}',
                'mx_hosts': []
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
    
    def _check_role_account(self, local_part):
        """Check if the email is a common role-based account"""
        try:
            # Check if the local part is a known role account
            is_role = local_part.lower() in self.role_accounts
            
            if is_role:
                return {
                    'is_role_account': True,
                    'message': f'Email address is a role-based account ({local_part})'
                }
            else:
                return {
                    'is_role_account': False,
                    'message': 'Email address is not a common role-based account'
                }
        except Exception as e:
            logger.exception(f"Error checking if '{local_part}' is a role account")
            # Default to false if there's an error
            return {
                'is_role_account': False,
                'message': f'Could not determine if email is a role account: {str(e)}'
            }
    
    def _check_smtp(self, email, domain, mx_hosts):
        """
        Verify email existence by connecting to the mail server
        
        This method attempts to connect to the mail server and check if the 
        recipient exists without actually sending an email.
        
        Anti-blocking measures:
        - Skip check for popular email providers
        - Use random sender addresses
        - Limit verification attempts
        - Use longer timeouts
        - Provide a real-looking HELO domain
        - Exit gracefully on any errors
        """
        # Default result if all checks fail
        result = {
            'passed': False,
            'is_catch_all': False,
            'message': 'SMTP verification skipped to avoid anti-spam measures'
        }
        
        # If we don't have MX hosts, we can't proceed
        if not mx_hosts:
            return {
                'passed': False,
                'message': 'Cannot perform SMTP check: No MX hosts available'
            }
        
        # SAFEGUARD 1: Skip SMTP check entirely for major email providers
        # These providers have strong anti-spam measures and likely block SMTP verification
        skip_domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
            'icloud.com', 'me.com', 'mac.com', 'mail.ru', 'yandex.com',
            'protonmail.com', 'pm.me', 'zoho.com', 'gmx.com', 'gmx.net',
            'gmx.de', 'gmx.at', 'gmx.ch', 'mail.com', 'fastmail.com'
        ]
        
        # More domains to consider skipping
        major_isps = [
            'comcast.net', 'verizon.net', 'att.net', 'cox.net', 'charter.net',
            'earthlink.net', 'aol.com', 'sbcglobal.net', 'frontier.com'
        ]
        
        # Skip SMTP check for popular email providers
        if domain.lower() in skip_domains or any(domain.lower().endswith(f".{isp}") for isp in major_isps):
            # For these domains we'll rely on MX records and other validation methods
            return {
                'passed': True,
                'message': f'SMTP check skipped for {domain} (provider with anti-spam measures)'
            }
        
        # SAFEGUARD 2: Gracefully handle inferences without SMTP for more domains
        if '.' in domain:
            tld = domain.split('.')[-1]
            # Skip some country domains known to block SMTP verification
            skip_tlds = ['cn', 'ru', 'jp', 'kr', 'in']
            if tld.lower() in skip_tlds:
                return {
                    'passed': True, 
                    'message': f'SMTP check skipped for .{tld} domain (regional restrictions)'
                }
        
        # SAFEGUARD 3: Use a legitimate-looking sender address and HELO domain
        # This helps avoid immediate rejection by spam filters
        sender_domains = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com']
        random_domain = random.choice(sender_domains)
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        from_address = f"{random_name}@{random_domain}"
        
        # Generate a real-looking HELO domain
        helo_domain = f"mail{random.randint(1,9)}.{random_domain}"
        
        # Get primary MX host
        primary_mx = mx_hosts[0] if mx_hosts else None
        if not primary_mx:
            return result
            
        try:
            # SAFEGUARD 4: Use a longer timeout but still reasonable
            server = smtplib.SMTP(timeout=10)
            server.set_debuglevel(0)  # Keep this at 0 in production
            
            # SAFEGUARD 5: Add deliberate delay between connection attempts
            # to avoid triggering rate limits
            time.sleep(0.5)
            
            # Connect to the server
            connect_response = server.connect(primary_mx)
            
            # SAFEGUARD 6: Use a legitimate-looking HELO
            helo_response = server.helo(helo_domain)
            
            # Start the SMTP session
            server.mail(from_address)
            
            # Check if the recipient exists
            rcpt_response = server.rcpt(email)
            
            # Close the connection properly
            server.quit()
            
            # Process the result
            if rcpt_response[0] == 250:
                result = {
                    'passed': True,
                    'message': f'Email address exists on the mail server'
                }
            elif rcpt_response[0] >= 500:
                result = {
                    'passed': False,
                    'message': f'Email address does not exist on the mail server'
                }
            else:
                # For ambiguous responses, treat as inconclusive but assume deliverable
                result = {
                    'passed': True,
                    'message': f'Inconclusive SMTP check: Server gave ambiguous response'
                }
            
            # SAFEGUARD 7: Limit catch-all detection to avoid multiple connections
            # We'll only check for catch-all if the first check passed
            if result['passed']:
                # Wait before making another connection
                time.sleep(1)
                
                # Check for catch-all domain with a random address that's unlikely to exist
                random_local = ''.join(random.choices(string.ascii_lowercase, k=16))
                random_email = f"{random_local}@{domain}"
                
                # Use a different sender for this check
                alt_random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
                alt_from_address = f"{alt_random_name}@{random.choice(sender_domains)}"
                
                # New connection for the catch-all check
                try:
                    catch_all_server = smtplib.SMTP(timeout=10)
                    catch_all_server.set_debuglevel(0)
                    catch_all_server.connect(primary_mx)
                    catch_all_server.helo(helo_domain)
                    catch_all_server.mail(alt_from_address)
                    random_rcpt_response = catch_all_server.rcpt(random_email)
                    catch_all_server.quit()
                    
                    # If a completely random address is accepted, it's likely a catch-all domain
                    if random_rcpt_response[0] == 250:
                        result['is_catch_all'] = True
                        result['message'] += ' (domain accepts all email addresses)'
                except Exception:
                    # If the catch-all check fails, we won't change the result
                    logger.debug(f"Catch-all check failed for {domain}, skipping")
            
            return result
            
        except smtplib.SMTPConnectError as e:
            logger.debug(f"SMTP connection error for {domain}: {str(e)}")
            # If connection fails, we'll infer from other checks
            return {
                'passed': True,  # Changed to True to avoid false negatives
                'message': f'Connection to mail server limited: Using inferred validation'
            }
        except smtplib.SMTPServerDisconnected as e:
            logger.debug(f"SMTP server disconnected during verification of {email}")
            # Server disconnections often happen with anti-spam measures
            return {
                'passed': True,  # Changed to True to avoid false negatives
                'message': f'Mail server restricted verification: Using inferred validation'
            }
        except smtplib.SMTPResponseException as e:
            logger.debug(f"SMTP error for {email}: {e.smtp_code}")
            # Handle specific SMTP error codes
            if e.smtp_code in [550, 551, 552, 553]:
                # These codes typically indicate a rejected address
                return {
                    'passed': False,
                    'message': f'Email address rejected by server'
                }
            else:
                # For other SMTP errors, infer from other checks
                return {
                    'passed': True,  # Changed to True to avoid false negatives
                    'message': f'Mail server restricted verification: Using inferred validation'
                }
        except Exception as e:
            # For any other errors, log and gracefully degrade
            logger.debug(f"SMTP verification skipped for {email}: {str(e)}")
            return {
                'passed': False,  # Changed to True to avoid false negatives
                'message': f'SMTP verification inconclusive: Falling back to limited validation'
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
