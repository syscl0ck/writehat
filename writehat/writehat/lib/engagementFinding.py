import json
from django.db import models
from writehat.models import *
from writehat.lib.finding import *
from writehat.validation import isValidJSONList
from django.core.exceptions import ValidationError
from writehat.lib.findingForm import CVSSEngagementFindingForm, DREADEngagementFindingForm
from django.http import QueryDict


log = logging.getLogger(__name__)

class EngagementFinding():

    # holds the fgroup model once it's been instantiated
    _fgroup_object = None

    # override in child class
    formClass = None

    @classmethod
    def new(cls, postData, findingGroupParent):

        engagementFinding = cls()
        form = cls.formClass(postData)
        engagementFinding.updateFromForm(form)
        engagementFinding.clean_fields()
        engagementFinding.findingGroup = findingGroupParent

        return engagementFinding


    @classmethod
    def get_child(cls, id):
        '''
        Tries different types of EngagementFindings until one is found
        Ideally, this should instead be something like:
        EngagementFinding.objects.filter(scoringType='CVSS')
        '''

        finding = None
        try: 
            finding = CVSSEngagementFinding.objects.get(id=id) 
        except CVSSEngagementFinding.DoesNotExist:
            pass

        try:
            finding = DREADEngagementFinding.objects.get(id=id)
        except DREADEngagementFinding.DoesNotExist:
            pass

        try:
            finding = ProactiveEngagementFinding.objects.get(id=id)
        except ProactiveEngagementFinding.DoesNotExist:
            pass

        if finding is None:
            raise FindingError(f"engagementFinding UUID {str(id)} does not exist")
        else:
            log.debug(f'EngagementFinding.get() called, found a {finding.scoringType} class with UUID {id}')
            return finding


    @classmethod
    def from_database(cls, databaseFindingId, findingGroup):
        '''
        Given a database finding, clone it to the appropriate engagement finding class
        '''

        databaseFinding = BaseDatabaseFinding.get_child(id=databaseFindingId)
        if databaseFinding.scoringType == 'CVSS':
            engagementFinding = databaseFinding.clone(
                destinationClass=CVSSEngagementFinding,
                name=databaseFinding.name
            )
        elif databaseFinding.scoringType == 'DREAD':
            engagementFinding = databaseFinding.clone(
                destinationClass=DREADEngagementFinding,
                name=databaseFinding.name
            )
        elif databaseFinding.scoringType == 'PROACTIVE':
            engagementFinding = databaseFinding.clone(
                destinationClass=ProactiveEngagementFinding,
                name=databaseFinding.name
            )
        else:
            raise FindingError(f'Unknown scoringType "{databaseFinding.scoringType}"')

        engagementFinding.findingGroup = findingGroup

        return engagementFinding


def create_finding_from_data(finding_data, finding_group=None, engagement_id=None):
    '''
    Automatically create an engagement finding from a data dictionary.
    
    This function encapsulates the logic used by the findings.json upload feature,
    allowing programmatic creation of findings without file uploads.
    
    Args:
        finding_data (dict): Dictionary containing finding data. Supports common field names:
            - name or title or finding: Finding name
            - description or background: Finding description
            - background: Background information
            - remediation or recommendation: Remediation steps
            - references: References
            - affectedResources or affected_resources: Affected resources
            - proofOfConcept or proof_of_concept or poc: Proof of concept
            - toolsUsed or tools_used: Tools used
            - For CVSS findings: vector, cvss, severity, cvssAV, cvssAC, etc.
            - Any other fields will be passed through as strings
        
        finding_group: BaseFindingGroup instance or UUID string. If None, will attempt
            to get the first finding group from the engagement.
        
        engagement_id: UUID string of engagement. Required if finding_group is None.
    
    Returns:
        Created EngagementFinding instance
    
    Raises:
        FindingError: If finding_group cannot be determined or finding creation fails
    
    Example:
        finding_data = {
            'name': 'SQL Injection Vulnerability',
            'description': 'The application is vulnerable to SQL injection...',
            'severity': 'HIGH',
            'remediation': 'Use parameterized queries...'
        }
        finding = create_finding_from_data(finding_data, engagement_id='<uuid>')
    '''
    from writehat.lib.findingGroup import BaseFindingGroup
    from writehat.lib.findingCategory import DatabaseFindingCategory
    
    # Get or resolve finding group
    if finding_group is None:
        if engagement_id is None:
            raise FindingError("Either finding_group or engagement_id must be provided")
        
        from writehat.lib.engagement import Engagement
        engagement = Engagement.get(id=engagement_id)
        if engagement.fgroups:
            finding_group = engagement.fgroups[0]
        else:
            # Create a default CVSS finding group
            from writehat.lib.findingGroup import CVSSFindingGroup
            finding_group = CVSSFindingGroup()
            finding_group.engagementParent = engagement_id
            finding_group.name = 'Findings'
            finding_group.save()
    
    # Resolve finding group if it's a UUID string
    if isinstance(finding_group, str):
        finding_group = BaseFindingGroup.get_child(id=finding_group)
    
    if not isinstance(finding_data, dict):
        raise FindingError(f"finding_data must be a dict, got {type(finding_data)}")
    
    # Map finding data to POST-like format
    finding_post_data = {}
    
    # Name field - required
    finding_name = (
        finding_data.get('name') or 
        finding_data.get('title') or 
        finding_data.get('finding') or
        'Unnamed Finding'
    )
    finding_post_data['name'] = finding_name
    
    # Description/background fields
    if 'description' in finding_data:
        finding_post_data['description'] = str(finding_data['description'])
    elif 'background' in finding_data:
        finding_post_data['description'] = str(finding_data['background'])
    
    if 'background' in finding_data:
        finding_post_data['background'] = str(finding_data['background'])
    
    if 'remediation' in finding_data:
        finding_post_data['remediation'] = str(finding_data['remediation'])
    elif 'recommendation' in finding_data:
        finding_post_data['remediation'] = str(finding_data['recommendation'])
    
    if 'references' in finding_data:
        finding_post_data['references'] = str(finding_data['references'])
    
    if 'affectedResources' in finding_data:
        finding_post_data['affectedResources'] = str(finding_data['affectedResources'])
    elif 'affected_resources' in finding_data:
        finding_post_data['affectedResources'] = str(finding_data['affected_resources'])
    
    if 'proofOfConcept' in finding_data:
        finding_post_data['proofOfConcept'] = str(finding_data['proofOfConcept'])
    elif 'proof_of_concept' in finding_data or 'poc' in finding_data:
        finding_post_data['proofOfConcept'] = str(finding_data.get('proof_of_concept') or finding_data.get('poc'))
    
    if 'toolsUsed' in finding_data:
        finding_post_data['toolsUsed'] = str(finding_data['toolsUsed'])
    elif 'tools_used' in finding_data:
        finding_post_data['toolsUsed'] = str(finding_data['tools_used'])
    
    # Copy other fields as strings (skip internal processing fields)
    for key, value in finding_data.items():
        if key not in finding_post_data and value is not None:
            if not key.startswith('_'):
                finding_post_data[key] = str(value)
    
    # Set findingGroup - required field
    finding_post_data['findingGroup'] = str(finding_group.id)
    
    # For CVSS findings, extract CVSS data and provide defaults
    if finding_group.findingClass.__name__ in ['CVSSEngagementFinding', 'CVSSFinding']:
        # Try to extract CVSS vector or individual CVSS fields
        if 'vector' in finding_data or 'cvss' in finding_data:
            cvss_vector = finding_data.get('vector') or finding_data.get('cvss') or ''
            # Extract CVSS fields from vector if it's in CVSS:3.1 format
            if cvss_vector.startswith('CVSS:'):
                try:
                    from writehat.lib.cvss import CVSS
                    cvss_obj = CVSS(cvss_vector)
                    cvss_dict = cvss_obj.dict
                    for key, value in cvss_dict.items():
                        if key not in finding_post_data:
                            finding_post_data[key] = value
                except Exception as e:
                    log.warning(f'Could not parse CVSS vector {cvss_vector}: {e}')
        
        # Try to extract individual CVSS fields (case-insensitive)
        cvss_field_mappings = {
            'av': 'cvssAV', 'attack_vector': 'cvssAV',
            'ac': 'cvssAC', 'attack_complexity': 'cvssAC',
            'pr': 'cvssPR', 'privileges_required': 'cvssPR',
            'ui': 'cvssUI', 'user_interaction': 'cvssUI',
            's': 'cvssS', 'scope': 'cvssS',
            'c': 'cvssC', 'confidentiality': 'cvssC',
            'i': 'cvssI', 'integrity': 'cvssI',
            'a': 'cvssA', 'availability': 'cvssA',
        }
        
        for json_key, cvss_field in cvss_field_mappings.items():
            if json_key in finding_data and cvss_field not in finding_post_data:
                finding_post_data[cvss_field] = str(finding_data[json_key]).upper()
        
        # Map severity to CVSS if severity is provided but CVSS fields aren't
        if 'severity' in finding_data:
            severity = str(finding_data['severity']).upper()
            # If we have severity but no CVSS impact scores, infer from severity
            if 'cvssC' not in finding_post_data and 'cvssI' not in finding_post_data and 'cvssA' not in finding_post_data:
                if severity in ['CRITICAL', 'HIGH']:
                    finding_post_data['cvssC'] = 'H'
                    finding_post_data['cvssI'] = 'H'
                    finding_post_data['cvssA'] = 'H'
                elif severity in ['MEDIUM', 'MODERATE']:
                    finding_post_data['cvssC'] = 'L'
                    finding_post_data['cvssI'] = 'L'
                    finding_post_data['cvssA'] = 'L'
                elif severity in ['LOW', 'INFORMATIONAL', 'INFO']:
                    finding_post_data['cvssC'] = 'N'
                    finding_post_data['cvssI'] = 'N'
                    finding_post_data['cvssA'] = 'N'
        
        # Mandatory CVSS fields (must be provided) - using first valid choice as default
        cvss_mandatory_defaults = {
            'cvssAV': 'N',  # Attack Vector: Network
            'cvssAC': 'L',  # Attack Complexity: Low
            'cvssPR': 'N',  # Privileges Required: None
            'cvssUI': 'N',  # User Interaction: None
            'cvssS': 'U',   # Scope: Unchanged
            'cvssC': 'N',   # Confidentiality: None
            'cvssI': 'N',   # Integrity: None
            'cvssA': 'N',   # Availability: None
        }
        # Optional CVSS fields (can be 'X' for Not Defined)
        cvss_optional_defaults = {
            'cvssE': 'X',   # Exploitability
            'cvssRL': 'X',  # Remediation Level
            'cvssRC': 'X',  # Report Confidence
            'cvssCR': 'X',  # Confidentiality Requirement
            'cvssIR': 'X',  # Integrity Requirement
            'cvssAR': 'X',  # Availability Requirement
            'cvssMAV': 'X',  # Modified Attack Vector
            'cvssMAC': 'X',  # Modified Attack Complexity
            'cvssMPR': 'X',  # Modified Privileges Required
            'cvssMUI': 'X',  # Modified User Interaction
            'cvssMS': 'X',   # Modified Scope
            'cvssMC': 'X',   # Modified Confidentiality
            'cvssMI': 'X',   # Modified Integrity
            'cvssMA': 'X',   # Modified Availability
        }
        # Apply mandatory defaults only if not already set
        for field, default_value in cvss_mandatory_defaults.items():
            if field not in finding_post_data or not finding_post_data.get(field):
                finding_post_data[field] = default_value
        # Then apply optional defaults
        for field, default_value in cvss_optional_defaults.items():
            if field not in finding_post_data or not finding_post_data.get(field):
                finding_post_data[field] = default_value
        
        # Category is required - use root category if missing
        if 'categoryID' not in finding_post_data or not finding_post_data['categoryID']:
            root_category = DatabaseFindingCategory.getRootNode()
            finding_post_data['categoryID'] = str(root_category.id)
    
    # Convert dict to QueryDict to match what Django forms expect from POST data
    post_querydict = QueryDict('', mutable=True)
    for key, value in finding_post_data.items():
        post_querydict[key] = value
    
    # Create the finding
    finding = finding_group.findingClass.new(
        postData=post_querydict,
        findingGroupParent=str(finding_group.id)
    )
    finding.save()
    log.info(f'Created finding: {finding.name} (ID: {finding.id})')
    
    return finding


    # One of you superclass experts, feel free to make this a magical 3 liner ;)
    def populateForm(self, formClass=None):
        '''
        Copy data from self into self._form_object
        '''

        log.debug(f'{self.className}.populateForm() called')

        if formClass is None:
            formClass = self.formClass

        initialFormData = dict()
        validFormFields = self._formFields(formClass=formClass)

        for label,value in self._modelToForm().items():
            if label in validFormFields:
                initialFormData.update({label: value})

        try:
            self._form_object = formClass(
                initial=initialFormData,
                engagementParent=self.fgroup.engagementParent,
                scoringType=self.fgroup.scoringType
            )
        except TypeError:
            # if this happens, try without the engagementParent
            self._form_object = formClass(
                initial=initialFormData
            )

        return self._form_object


    @property
    def parent(self):

        return self.fgroup.engagement


    @property
    def url(self):
        return f"/engagements/fgroup/finding/edit/{self.id}"



class DREADEngagementFinding(EngagementFinding, DREADFinding):

    findingGroup = models.UUIDField(editable=False, null=True)
    description = MarkdownField(max_length=30000, null=True, blank=True)
    affectedResources = MarkdownField(max_length=30000, null=True, blank=True)
    _dreadImpact = models.TextField(max_length=200, blank=True, null=True, default=str, validators=[isValidJSONList])
    descDamage = MarkdownField(max_length=30000, null=True, blank=True)
    descReproducibility = MarkdownField(max_length=30000, null=True, blank=True)
    descExploitability = MarkdownField(max_length=30000, null=True, blank=True)
    descAffectedUsers = MarkdownField(max_length=30000, null=True, blank=True)
    descDiscoverability = MarkdownField(max_length=30000, null=True, blank=True)
    formClass = DREADEngagementFindingForm


    @property
    def dreadImpact(self):

        log.debug(f'Getting {self.className}.dreadImpact')

        try:
            l = isValidJSONList(self._dreadImpact)
        except ValidationError:
            l = []

        log.debug(f'   {l}')
        return l


    @property
    def _modelFields(self):
        '''
        Returns list of valid field names in model
        '''

        modelFields = super()._modelFields
        modelFields.remove('_dreadImpact')

        return modelFields + ['dreadImpact']


    @dreadImpact.setter
    def dreadImpact(self, dreadImpact):

        log.debug(f'Setting {self.className}.dreadImpact')

        l = json.dumps(dreadImpact)
        isValidJSONList(l)
        log.debug(f'   {l}')
        self._dreadImpact = l


    # I wish we didn't have to define this in both classes, so I am leaving the CVSS/DREAD
    # branch in place in case we redesign the heirarchy later
    @property
    def fgroup(self):

        if self._fgroup_object is None:
            # Importing here to prevent circular import
            from writehat.lib.findingGroup import DREADFindingGroup
            self._fgroup_object = DREADFindingGroup.objects.get(id=self.findingGroup)

        return self._fgroup_object

    @property
    def impact(self):
        choices = {}
        for c in self.formClass.choicesStride:
            choices[c[0]] = c[1]
        for i in self.dreadImpact:
            yield choices[i]
    



class CVSSEngagementFinding(EngagementFinding, CVSSFinding):

    findingGroup = models.UUIDField(editable=False, null=True)
    description = MarkdownField(max_length=30000, null=True, blank=True)
    affectedResources = MarkdownField(max_length=30000, null=True, blank=True)
    proofOfConcept = MarkdownField(max_length=30000, null=True, blank=True)
    formClass = CVSSEngagementFindingForm


    def updateFromPostData(self, postData, blankForm):

        log.debug(f"engagementFindingEdit.updateFromPostData with form {blankForm}")

        form = blankForm(postData)
        self.updateFromForm(form)


    @classmethod
    def list(cls, FindingGroup):
        findings = cls.objects.filter(FindingGroup=FindingGroup)
        for f in findings:
            f.populateForm()
            f.clean_fields()

        return findings

    # I wish we didn't have to define this in both classes, so I am leaving the CVSS/DREAD
    # branch in place in case we redesign the heirarchy later
    @property
    def fgroup(self):

        if self._fgroup_object is None:
            # Importing here to prevent circular import
            from writehat.lib.findingGroup import CVSSFindingGroup
            self._fgroup_object = CVSSFindingGroup.objects.get(id=self.findingGroup)

        return self._fgroup_object



class ProactiveEngagementFinding(EngagementFinding, ProactiveFinding):

    findingGroup = models.UUIDField(editable=False, null=True)
    description = MarkdownField(max_length=30000, null=True, blank=True)
    affectedResources = MarkdownField(max_length=30000, null=True, blank=True)
    formClass = ProactiveEngagementFindingForm

    @property
    def fgroup(self):

        if self._fgroup_object is None:
            # Importing here to prevent circular import
            from writehat.lib.findingGroup import ProactiveFindingGroup
            self._fgroup_object = ProactiveFindingGroup.objects.get(id=self.findingGroup)

        return self._fgroup_object
