import json
import logging
import os
from .base import *

log = logging.getLogger(__name__)


class TechnicalReferenceTableForm(ComponentForm):

    json_file_path = forms.CharField(
        label='JSON File Path (optional - leave empty to auto-detect normalized.json)',
        required=False,
        help_text='Path to normalized.json file. If empty, will try to find normalized.json in engagement directory.'
    )
    json_content = forms.CharField(
        label='JSON Content (alternative to file path)',
        widget=forms.Textarea,
        required=False,
        help_text='Paste JSON content directly here as an alternative to file path'
    )
    field_order = ['name', 'json_file_path', 'json_content', 'pageBreakBefore', 'showTitle']


class Component(BaseComponent):

    default_name = 'Technical Reference Table'
    formClass = TechnicalReferenceTableForm
    fieldList = {
        'json_file_path': StringField(templatable=False),
        'json_content': StringField(templatable=False),
    }
    htmlTemplate = 'componentTemplates/Technical_Reference_Table.html'
    iconType = 'fas fa-table'
    iconColor = 'var(--blue)'

    def preprocess(self, context):
        '''
        Read normalized.json and generate markdown table with Target, Service, Version, Status
        '''
        import json
        
        # Try to get JSON data
        json_data = None
        
        # First, try to read from json_content field if provided
        json_content = getattr(self, 'json_content', '') or context.get('json_content', '')
        if json_content:
            try:
                json_data = json.loads(json_content)
                log.debug('Loaded JSON from json_content field')
            except json.JSONDecodeError as e:
                log.error(f'Invalid JSON in json_content: {e}')
        
        # If not found, try to read from file path
        if json_data is None:
            json_file_path = getattr(self, 'json_file_path', '') or context.get('json_file_path', '')
            
            # If no path specified, try to find normalized.json in engagement directory
            if not json_file_path:
                try:
                    engagement = self.engagement
                    if engagement:
                        from django.conf import settings
                        # Try engagement_files directory first (where engagementFileUpload stores it)
                        engagement_files_dir = os.path.join(settings.BASE_DIR, 'engagement_files')
                        engagement_file_path = os.path.join(engagement_files_dir, f'normalized_{engagement.id}.json')
                        
                        # Also try writehat/engagement_files/ (one level up from BASE_DIR)
                        writehat_engagement_files = os.path.join(settings.BASE_DIR, '..', 'engagement_files')
                        writehat_file_path = os.path.abspath(os.path.join(writehat_engagement_files, f'normalized_{engagement.id}.json'))
                        
                        # Try common locations for normalized.json
                        possible_paths = [
                            engagement_file_path,  # First check engagement_files directory (BASE_DIR/engagement_files)
                            writehat_file_path,   # Check writehat/engagement_files/ (one level up from BASE_DIR)
                            os.path.join(settings.BASE_DIR, '..', '..', 'engagement_files', f'normalized_{engagement.id}.json'),  # From workspace root
                            f'/tmp/normalized_{engagement.id}.json',
                            f'/var/www/writehat/normalized_{engagement.id}.json',
                            os.path.join(os.path.expanduser('~'), f'normalized_{engagement.id}.json'),
                        ]
                        for path in possible_paths:
                            if os.path.exists(path):
                                json_file_path = path
                                log.debug(f'Found normalized.json at: {json_file_path}')
                                break
                except (AttributeError, Exception) as e:
                    log.debug(f'Could not auto-detect normalized.json: {e}')
            
            # Try to read from file path if specified
            if json_file_path and os.path.exists(json_file_path):
                try:
                    with open(json_file_path, 'r', encoding='utf-8') as f:
                        json_data = json.load(f)
                    log.debug(f'Loaded JSON from file: {json_file_path}')
                except (IOError, json.JSONDecodeError) as e:
                    log.error(f'Error reading JSON file {json_file_path}: {e}')
        
        # Generate markdown tables from JSON data
        table_markdown = ''
        if json_data:
            table_markdown = self._generate_tables(json_data)
        else:
            log.warning('No JSON data available for Technical Reference Table')
            table_markdown = '*No data available. Please upload normalized.json or provide JSON content.*'
        
        context['table_markdown'] = table_markdown
        return context
    
    def _generate_tables(self, json_data):
        '''
        Generate multiple markdown tables from JSON data:
        1. Ports table: Target, Service, Version, Status
        2. Hosts table: Hostname, IP Addresses, Subdomain, Technologies
        3. Vulnerabilities table: Hostname, Severity, Title, Source
        '''
        tables = []
        
        # Generate ports table
        ports_table = self._generate_ports_table(json_data)
        if ports_table:
            tables.append("## Ports\n\n" + ports_table)
        
        # Generate hosts table
        hosts_table = self._generate_hosts_table(json_data)
        if hosts_table:
            tables.append("## Hosts\n\n" + hosts_table)
        
        # Generate vulnerabilities table
        vulnerabilities_table = self._generate_vulnerabilities_table(json_data)
        if vulnerabilities_table:
            tables.append("## Vulnerabilities\n\n" + vulnerabilities_table)
        
        # Generate vulnerabilities summary table
        vuln_summary_table = self._generate_vulnerabilities_summary_table(json_data)
        if vuln_summary_table:
            tables.append("## Vulnerabilities Summary\n\n" + vuln_summary_table)
        
        if not tables:
            return '*No valid data found in JSON.*'
        
        return '\n\n'.join(tables)
    
    def _generate_ports_table(self, json_data):
        '''
        Generate ports markdown table
        Headers: Target, Service, Version, Status
        Omit rows where any field is null
        
        Expected structure: normalized.json with hosts array containing ports arrays
        '''
        # Handle different JSON structures
        rows = []
        
        # If it's a list, iterate through items
        if isinstance(json_data, list):
            rows = json_data
        # If it's a dict, try to extract a list
        elif isinstance(json_data, dict):
            # Check for normalized.json structure: hosts array
            if 'hosts' in json_data and isinstance(json_data['hosts'], list):
                # Extract ports from each host
                for host in json_data['hosts']:
                    if isinstance(host, dict) and 'ports' in host:
                        ports = host.get('ports', [])
                        if isinstance(ports, list):
                            for port in ports:
                                if isinstance(port, dict):
                                    # Create a flattened row from host + port data
                                    # Use port hostname first, fall back to host hostname
                                    hostname = port.get('hostname') or host.get('hostname')
                                    service_name = port.get('service_name')
                                    # Prefer service_version, fall back to service_product, or empty string
                                    service_version = port.get('service_version') or port.get('service_product') or ''
                                    
                                    # Only add row if we have required fields
                                    if hostname and service_name:
                                        row = {
                                            'hostname': hostname,
                                            'service_name': service_name,
                                            'service_version': service_version,
                                            'service_product': port.get('service_product', ''),
                                            'protocol': port.get('protocol', 'tcp'),
                                            'port': port.get('port')
                                        }
                                        rows.append(row)
            # Try common keys
            elif 'data' in json_data and isinstance(json_data['data'], list):
                rows = json_data['data']
            elif 'results' in json_data and isinstance(json_data['results'], list):
                rows = json_data['results']
            elif 'items' in json_data and isinstance(json_data['items'], list):
                rows = json_data['items']
            else:
                # If it's a dict of dicts, convert to list
                rows = [v for v in json_data.values() if isinstance(v, dict)]
        
        # Generate markdown table
        table_lines = ['| Target | Service | Version | Status |', '|--------|---------|---------|--------|']
        
        for row in rows:
            if not isinstance(row, dict):
                continue
            
            # Extract fields - try various possible field names
            target = self._get_field(row, ['hostname', 'target', 'host', 'ip', 'domain', 'subdomain'])
            service = self._get_field(row, ['service_name', 'service', 'name', 'port_service'])
            # Version can be empty string (which is acceptable), but not None
            version = row.get('service_version') or row.get('service_product') or row.get('version') or row.get('banner') or row.get('product') or ''
            if version is None:
                version = ''
            # Status: if port exists, it's open. Otherwise check status field
            status = None
            if 'port' in row and row['port'] is not None:
                status = 'open'
            else:
                status = self._get_field(row, ['status', 'state', 'open', 'closed'])
            
            # Skip row if target, service, or status is null/empty (version can be empty)
            if target is None or service is None or status is None:
                continue
            
            # Escape pipe characters in values
            target = str(target).replace('|', '\\|')
            service = str(service).replace('|', '\\|')
            version = str(version).replace('|', '\\|')
            status = str(status).replace('|', '\\|')
            
            table_lines.append(f'| {target} | {service} | {version} | {status} |')
        
        if len(table_lines) == 2:  # Only headers and separator
            return None
        
        return '\n'.join(table_lines)
    
    def _generate_hosts_table(self, json_data):
        '''
        Generate hosts markdown table
        Headers: Hostname, IP Addresses, Subdomain, Technologies, URLs
        '''
        rows = []
        
        if isinstance(json_data, dict) and 'hosts' in json_data:
            for host in json_data['hosts']:
                if not isinstance(host, dict):
                    continue
                
                hostname = host.get('hostname')
                if not hostname:
                    continue
                
                # Get IP addresses
                ip_addresses = host.get('ip_addresses', [])
                ip_str = ', '.join(ip_addresses) if ip_addresses else 'N/A'
                
                # Get subdomain status
                subdomain = 'Yes' if host.get('subdomain') else 'No'
                
                # Extract technologies from web_analysis
                technologies = []
                web_analysis = host.get('web_analysis', {})
                if 'webanalyze' in web_analysis:
                    webanalyze = web_analysis['webanalyze']
                    if isinstance(webanalyze, dict) and 'technologies' in webanalyze:
                        tech_list = webanalyze['technologies']
                        if isinstance(tech_list, list):
                            technologies = [t.get('name', '') for t in tech_list if isinstance(t, dict) and t.get('name')]
                
                # Also check gowitness for technologies
                if 'gowitness' in web_analysis and isinstance(web_analysis['gowitness'], list):
                    for gowitness_item in web_analysis['gowitness']:
                        if isinstance(gowitness_item, dict) and 'technologies' in gowitness_item:
                            tech_list = gowitness_item['technologies']
                            if isinstance(tech_list, list):
                                for tech in tech_list:
                                    if tech not in technologies:
                                        technologies.append(tech)
                
                tech_str = ', '.join(technologies) if technologies else 'None detected'
                
                # Get URLs count
                urls = host.get('urls', [])
                url_count = len(urls) if isinstance(urls, list) else 0
                
                rows.append({
                    'hostname': hostname,
                    'ip_addresses': ip_str,
                    'subdomain': subdomain,
                    'technologies': tech_str,
                    'urls': str(url_count)
                })
        
        if not rows:
            return None
        
        # Generate markdown table
        table_lines = ['| Hostname | IP Addresses | Subdomain | Technologies | URLs |', 
                      '|----------|---------------|-----------|--------------|------|']
        
        for row in rows:
            hostname = str(row['hostname']).replace('|', '\\|')
            ip_addresses = str(row['ip_addresses']).replace('|', '\\|')
            subdomain = str(row['subdomain']).replace('|', '\\|')
            technologies = str(row['technologies']).replace('|', '\\|')
            urls = str(row['urls']).replace('|', '\\|')
            
            table_lines.append(f'| {hostname} | {ip_addresses} | {subdomain} | {technologies} | {urls} |')
        
        return '\n'.join(table_lines)
    
    def _generate_vulnerabilities_table(self, json_data):
        '''
        Generate vulnerabilities markdown table
        Headers: Hostname, Severity, Title, Description, Source
        Includes vulnerabilities from hosts and git_repositories
        '''
        rows = []
        
        # Process vulnerabilities from hosts
        if isinstance(json_data, dict) and 'hosts' in json_data:
            for host in json_data['hosts']:
                if not isinstance(host, dict):
                    continue
                
                hostname = host.get('hostname')
                vulnerabilities = host.get('vulnerabilities', [])
                
                if not hostname or not isinstance(vulnerabilities, list):
                    continue
                
                for vuln in vulnerabilities:
                    if not isinstance(vuln, dict):
                        continue
                    
                    severity = vuln.get('severity', 'unknown')
                    
                    # Skip vulnerabilities with "info" severity
                    if severity and str(severity).lower() == 'info':
                        continue
                    
                    title = vuln.get('title', '')
                    description = vuln.get('description', '')
                    source = vuln.get('source', vuln.get('scanner', 'unknown'))
                    
                    # Truncate description if too long
                    if len(description) > 100:
                        description = description[:97] + '...'
                    
                    # Skip if missing critical fields
                    if not title:
                        continue
                    
                    rows.append({
                        'hostname': hostname,
                        'severity': severity,
                        'title': title,
                        'description': description,
                        'source': source
                    })
        
        # Process vulnerabilities from git_repositories
        if isinstance(json_data, dict) and 'git_repositories' in json_data:
            git_repos = json_data['git_repositories']
            if isinstance(git_repos, list):
                for repo in git_repos:
                    if not isinstance(repo, dict):
                        continue
                    
                    repository_name = repo.get('repository', 'unknown')
                    findings = repo.get('findings', {})
                    
                    if not isinstance(findings, dict):
                        continue
                    
                    # Iterate through different finding types (gitleaks, trufflehog, trivy, etc.)
                    for finding_type, finding_list in findings.items():
                        if not isinstance(finding_list, list):
                            continue
                        
                        for finding in finding_list:
                            if not isinstance(finding, dict):
                                continue
                            
                            # Extract finding information
                            source = finding.get('source', finding_type)
                            rule_id = finding.get('rule_id', '')
                            description = finding.get('description', '')
                            
                            # Use rule_id as title, or description if rule_id is empty
                            title = rule_id if rule_id else description[:50] + '...' if description else 'Git Finding'
                            
                            # Truncate description if too long
                            if len(description) > 100:
                                description = description[:97] + '...'
                            
                            # Format hostname as "Repository: <repo_name>"
                            hostname = f"Repository: {repository_name}"
                            
                            # Git findings typically don't have severity, so use "git" or source
                            severity = finding.get('severity', 'git')
                            
                            rows.append({
                                'hostname': hostname,
                                'severity': severity,
                                'title': title,
                                'description': description,
                                'source': source
                            })
        
        if not rows:
            return None
        
        # Generate markdown table
        table_lines = ['| Hostname | Severity | Title | Description | Source |',
                      '|----------|----------|-------|-------------|--------|']
        
        for row in rows:
            hostname = str(row['hostname']).replace('|', '\\|')
            severity = str(row['severity']).replace('|', '\\|')
            title = str(row['title']).replace('|', '\\|')
            description = str(row['description']).replace('|', '\\|')
            source = str(row['source']).replace('|', '\\|')
            
            table_lines.append(f'| {hostname} | {severity} | {title} | {description} | {source} |')
        
        return '\n'.join(table_lines)
    
    def _generate_vulnerabilities_summary_table(self, json_data):
        '''
        Generate vulnerabilities summary markdown table
        Headers: Metric, Value
        '''
        if not isinstance(json_data, dict) or 'vulnerabilities_summary' not in json_data:
            return None
        
        summary = json_data['vulnerabilities_summary']
        if not isinstance(summary, dict):
            return None
        
        rows = []
        
        # Total vulnerabilities
        total = summary.get('total', 0)
        if total:
            rows.append({'metric': 'Total Vulnerabilities', 'value': str(total)})
        
        # Total hosts affected
        total_hosts = summary.get('total_hosts_affected', 0)
        if total_hosts:
            rows.append({'metric': 'Total Hosts Affected', 'value': str(total_hosts)})
        
        # Severity breakdown
        severity_breakdown = summary.get('severity_breakdown', {})
        if isinstance(severity_breakdown, dict):
            for severity, count in severity_breakdown.items():
                if count:
                    rows.append({'metric': f'Severity: {severity.capitalize()}', 'value': str(count)})
        
        # Sources
        sources = summary.get('sources', {})
        if isinstance(sources, dict):
            for source, count in sources.items():
                if count:
                    rows.append({'metric': f'Source: {source.capitalize()}', 'value': str(count)})
        
        if not rows:
            return None
        
        # Generate markdown table
        table_lines = ['| Metric | Value |', '|--------|-------|']
        
        for row in rows:
            metric = str(row['metric']).replace('|', '\\|')
            value = str(row['value']).replace('|', '\\|')
            table_lines.append(f'| {metric} | {value} |')
        
        return '\n'.join(table_lines)
    
    def _get_field(self, row, possible_keys):
        '''
        Try to get a field value using various possible key names
        Returns None if not found or if value is null/empty
        '''
        for key in possible_keys:
            if key in row:
                value = row[key]
                # Return None if value is None, empty string, or empty
                if value is None or (isinstance(value, str) and not value.strip()):
                    return None
                return value
        return None
