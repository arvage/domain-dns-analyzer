import dns.resolver
import asyncio
from typing import List
from .models import DomainResult
import logging
import whois
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DNSAnalyzer:
    def __init__(self):
        # Configure DNS resolver for maximum speed
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1.5  # 1.5 seconds per query
        self.resolver.lifetime = 3   # 3 seconds total lifetime per query
        # Use Google's fast DNS servers
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']

    def _fast_query(self, domain: str, record_type: str, timeout: float = 1.0):
        """Fast DNS query with short timeout"""
        try:
            # Create a resolver with very short timeout for speed
            fast_resolver = dns.resolver.Resolver()
            fast_resolver.timeout = timeout
            fast_resolver.lifetime = timeout * 2
            fast_resolver.nameservers = self.resolver.nameservers
            return fast_resolver.resolve(domain, record_type)
        except Exception:
            return None
    
    async def analyze_domain(self, domain: str) -> DomainResult:
        """Analyze a single domain for DNS records - optimized for speed"""
        result = DomainResult(domain=domain)
        
        try:
            logger.info(f"Analyzing domain: {domain}")
            
            # Get MX Records
            await self._get_mx_records(domain, result)
            
            # Get SPF Record
            await self._get_spf_record(domain, result)
            
            # Get DMARC Record
            await self._get_dmarc_record(domain, result)
            
            # Get A Record (website check)
            await self._get_a_record(domain, result)
            
            # Check www subdomain if website exists
            if result.has_website:
                await self._check_www_subdomain(domain, result)
            
            # Get technical contact email
            await self._get_tech_contact(domain, result)
                
        except Exception as e:
            result.error = str(e)
            logger.error(f"Error analyzing domain {domain}: {e}")
            
        return result

    async def _get_mx_records(self, domain: str, result: DomainResult):
        """Get MX records for the domain"""
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            mx_list = []
            for mx in mx_records:
                mx_list.append(f"{mx.preference}:{mx.exchange}")
            result.mx_records = "; ".join(mx_list) if mx_list else "No MX records found"
        except dns.resolver.NXDOMAIN:
            result.mx_records = "Domain not found"
        except dns.resolver.NoAnswer:
            result.mx_records = "No MX records found"
        except Exception as e:
            result.mx_records = f"Error retrieving MX records: {e}"

    async def _get_spf_record(self, domain: str, result: DomainResult):
        """Get SPF record for the domain"""
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            spf_found = False
            for txt in txt_records:
                txt_string = str(txt).strip('"')
                if txt_string.startswith('v=spf1'):
                    result.spf_record = txt_string
                    spf_found = True
                    break
            if not spf_found:
                result.spf_record = "No SPF record found"
        except dns.resolver.NXDOMAIN:
            result.spf_record = "Domain not found"
        except dns.resolver.NoAnswer:
            result.spf_record = "No TXT records found"
        except Exception as e:
            result.spf_record = f"Error retrieving SPF record: {e}"

    async def _get_dmarc_record(self, domain: str, result: DomainResult):
        """Get DMARC record for the domain"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_found = False
            
            for txt in txt_records:
                txt_string = str(txt).strip('"')
                if txt_string.startswith('v=DMARC1'):
                    result.dmarc_record = txt_string
                    dmarc_found = True
                    
                    # Extract DMARC policy and RUF email
                    if 'p=' in txt_string:
                        # Find policy value and RUF email
                        parts = txt_string.split(';')
                        for part in parts:
                            part = part.strip()
                            if part.startswith('p='):
                                policy = part.split('=', 1)[1].strip()
                                result.dmarc_policy = policy
                                
                                # Check if policy is set (not 'none' and not empty)
                                if policy and policy.lower() != 'none':
                                    result.has_dmarc_policy = True
                            elif part.startswith('ruf='):
                                # Extract RUF email(s)
                                ruf_value = part.split('=', 1)[1].strip()
                                # Remove mailto: prefix if present
                                ruf_emails = []
                                for email in ruf_value.split(','):
                                    email = email.strip()
                                    if email.startswith('mailto:'):
                                        email = email[7:]
                                    if email:
                                        ruf_emails.append(email)
                                if ruf_emails:
                                    result.dmarc_ruf_email = '; '.join(ruf_emails)
                    break
                    
            if not dmarc_found:
                result.dmarc_record = "No DMARC record found"
                result.dmarc_policy = "Not set"
                
        except dns.resolver.NXDOMAIN:
            result.dmarc_record = "No DMARC record found"
            result.dmarc_policy = "Not set"
        except dns.resolver.NoAnswer:
            result.dmarc_record = "No DMARC record found"
            result.dmarc_policy = "Not set"
        except Exception as e:
            result.dmarc_record = f"Error retrieving DMARC record: {e}"
            result.dmarc_policy = "Error"

    async def _get_a_record(self, domain: str, result: DomainResult):
        """Get A record for the domain (website check)"""
        try:
            a_records = self.resolver.resolve(domain, 'A')
            ip_list = []
            for a in a_records:
                ip_list.append(str(a))
            if ip_list:
                result.has_website = True
                result.a_record = "; ".join(ip_list)
            else:
                result.has_website = False
                result.a_record = "No A record found"
        except dns.resolver.NXDOMAIN:
            result.has_website = False
            result.a_record = "Domain not found"
        except dns.resolver.NoAnswer:
            result.has_website = False
            result.a_record = "No A record found"
        except Exception as e:
            result.a_record = f"Error retrieving A record: {e}"

    async def _check_www_subdomain(self, domain: str, result: DomainResult):
        """Check if www subdomain points to main domain"""
        try:
            www_domain = f"www.{domain}"
            
            # First try to get CNAME record
            try:
                cname_records = self.resolver.resolve(www_domain, 'CNAME')
                if cname_records:
                    cname_target = str(cname_records[0]).rstrip('.')
                    result.www_cname = cname_target
                    
                    # Check if CNAME points to main domain
                    if cname_target == domain or cname_target == f"{domain}.":
                        result.www_points_to_main = True
                    else:
                        # Check if CNAME target resolves to same IP as main domain
                        try:
                            cname_a_records = self.resolver.resolve(cname_target, 'A')
                            main_a_records = self.resolver.resolve(domain, 'A')
                            
                            cname_ips = {str(a) for a in cname_a_records}
                            main_ips = {str(a) for a in main_a_records}
                            
                            # Check if any IP addresses match
                            if cname_ips & main_ips:  # Set intersection
                                result.www_points_to_main = True
                                
                        except Exception:
                            result.www_points_to_main = False
                    return
                    
            except dns.resolver.NoAnswer:
                pass  # No CNAME record, try A record
            except dns.resolver.NXDOMAIN:
                result.www_cname = "No www subdomain found"
                return
                
            # Try to get A record for www subdomain
            try:
                www_a_records = self.resolver.resolve(www_domain, 'A')
                if www_a_records:
                    www_ips = [str(a) for a in www_a_records]
                    result.www_cname = f"A Record: {'; '.join(www_ips)}"
                    
                    # Check if A record IPs match main domain IPs
                    main_a_records = self.resolver.resolve(domain, 'A')
                    main_ips = {str(a) for a in main_a_records}
                    www_ip_set = set(www_ips)
                    
                    if www_ip_set & main_ips:  # Set intersection
                        result.www_points_to_main = True
                else:
                    result.www_cname = "No CNAME or A record found"
                    
            except dns.resolver.NoAnswer:
                result.www_cname = "No CNAME or A record found"
            except dns.resolver.NXDOMAIN:
                result.www_cname = "No www subdomain found"
                
        except Exception as e:
            result.www_cname = f"Error checking www subdomain: {e}"

    async def _get_tech_contact(self, domain: str, result: DomainResult):
        """Get technical contact email from WHOIS data"""
        try:
            # WHOIS lookup is blocking, so run in executor
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, domain)
            
            if whois_data:
                # Try to get tech email from various possible fields
                tech_email = None
                
                # Check for tech_email field
                if hasattr(whois_data, 'tech_email') and whois_data.tech_email:
                    tech_email = whois_data.tech_email
                # Check for emails field (list of all emails)
                elif hasattr(whois_data, 'emails') and whois_data.emails:
                    if isinstance(whois_data.emails, list):
                        # Get first non-abuse email
                        for email in whois_data.emails:
                            if email and 'abuse' not in email.lower():
                                tech_email = email
                                break
                        if not tech_email:
                            tech_email = whois_data.emails[0]
                    else:
                        tech_email = whois_data.emails
                # Check for registrant_email as fallback
                elif hasattr(whois_data, 'registrant_email') and whois_data.registrant_email:
                    tech_email = whois_data.registrant_email
                
                if tech_email:
                    # Handle list of emails
                    if isinstance(tech_email, list):
                        result.tech_contact_email = "; ".join(str(e) for e in tech_email if e)
                    else:
                        result.tech_contact_email = str(tech_email)
                else:
                    result.tech_contact_email = "Not available"
            else:
                result.tech_contact_email = "Not available"
                
        except Exception as e:
            result.tech_contact_email = "Not available"
            logger.debug(f"Could not retrieve WHOIS data for {domain}: {e}")

    async def analyze_domains(self, domains: List[str]) -> List[DomainResult]:
        """Analyze multiple domains concurrently"""
        # Create tasks for concurrent execution
        tasks = []
        for domain in domains:
            domain = domain.strip()
            if domain:  # Skip empty domains
                tasks.append(self.analyze_domain(domain))
        
        # Execute all tasks concurrently for maximum speed - no delays
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

    def generate_summary(self, results: List[DomainResult]) -> dict:
        """Generate summary statistics"""
        total = len(results)
        with_dmarc = sum(1 for r in results if r.has_dmarc_policy)
        without_dmarc = total - with_dmarc
        with_website = sum(1 for r in results if r.has_website)
        with_www_cname = sum(1 for r in results if r.www_points_to_main)
        with_errors = sum(1 for r in results if r.error)
        
        return {
            "total_analyzed": total,
            "domains_with_dmarc_policy": with_dmarc,
            "domains_without_dmarc_policy": without_dmarc,
            "domains_with_websites": with_website,
            "domains_with_www_pointing_to_main": with_www_cname,
            "domains_with_errors": with_errors
        }