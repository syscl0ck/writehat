# May Odyn smile on your Chain and Thorim empower your Chomp

import json
import base64
import logging
import uuid as uuidlib

# django
from django.conf import settings
from django.shortcuts import render, redirect
from django.utils.html import escape
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.views.decorators.http import require_http_methods
from django.utils.datastructures import MultiValueDictKeyError
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.clickjacking import xframe_options_exempt
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib import messages


# WRITEHAT

from writehat import validation

from writehat.lib.util import *
from writehat.lib.dread import *
from writehat.lib.errors import *
from writehat.lib.figure import *
from writehat.lib.report import *
from writehat.lib.finding import *
from writehat.lib.resolve import *
from writehat.lib.customer import *
from writehat.lib.dbImport import *
from writehat.lib.dbExport import *
from writehat.lib.revision import *
from writehat.lib.engagement import *
from writehat.lib.findingForm import *
from writehat.components.base import *
from writehat.lib.findingGroup import *
from writehat.lib.pageTemplate import *
from writehat.lib.findingCategory import *
from writehat.lib.engagementFinding import *
from writehat.lib.excel import generateExcel


# Selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium.common.exceptions import InvalidCookieDomainException, TimeoutException




log = logging.getLogger(__name__)

####RENDERING VIEWS####

# WIP homepage
@login_required
def home(request):

    return render(request,"pages/home.html", {})



# Just a redirect to home
def index(request):

    return HttpResponseRedirect('/engagements')


# Validation - returns allowed characters
@require_http_methods(['GET'])
@csrf_exempt
def validationWhitelists(request):

    return JsonResponse({
        'names': list(validation.allowed_for_names),
        'strict_names': list(validation.allowed_for_strict_names),
    })


# Returns CVSS details
@require_http_methods(['POST'])
@csrf_exempt
def validationCVSS(request):

    post_data = request.POST.dict()
    cvss_data = CVSS.fromDict(post_data)

    return JsonResponse({
        'vector': cvss_data.vector,
        'severity': cvss_data.severity,
        'score': cvss_data.score,
    })

def intOrFail(maybeInt):
    try:
        x = int(maybeInt)
    except ValueError:
        raise DreadValidationError('cannot convert value to integer')
    if x > 10:
        raise DreadValidationError('value is out of valid range')
    return x
 
# Returns DREAD details 
# There is probably a more efficient way to do this
@require_http_methods(['POST'])
@csrf_exempt
def validationDREAD(request):
    d = {}
    # a bit ugly in exchange for maximum security
    #try:
    d['dreadDamage'] = intOrFail(request.POST['dreadDamage'])
    d['dreadReproducibility'] = intOrFail(request.POST['dreadReproducibility'])
    d['dreadExploitability'] = intOrFail(request.POST['dreadExploitability'])
    d['dreadAffectedUsers'] = intOrFail(request.POST['dreadAffectedUsers'])
    d['dreadDiscoverability'] = intOrFail(request.POST['dreadDiscoverability'])
#except MultiValueDictKeyError:
    #    raise DreadValidationError('missing required parameter')

    # validate input and assign to dict
    dread = DREAD(DREAD.createVector(d))


    return JsonResponse({
        'severity': dread.severity,
        'score': dread.score,
    })




# Given a reportID, get the JSON object containing the list of associated components
@require_http_methods(['GET'])
@csrf_protect
def reportEdit(request,uuid):
    log.debug("reportEdit() called; UUID: {0}".format(uuid))
    log.debug("Found {0} available components".format(len(settings.VALID_COMPONENTS)))

    report = Report.get(id=uuid)
    report.populateForm()

    return render(request,"pages/reportEdit.html", \
        {
            "report": report,
            "engagement": report.engagement,
            "componentsList": settings.VALID_COMPONENTS,

        })

@require_http_methods(['GET'])
def reportRevisions(request, uuid):
    log.debug("reportRevisions() called; UUID: {0}".format(uuid))
    log.debug("Found {0} available components".format(len(settings.VALID_COMPONENTS)))

    report = Report.get(id=uuid)

    return render(request, "pages/reportRevisions.html", {
        "report": report,
        "engagement": report.engagement,
        "revisions": report.revisions
    })

@require_http_methods(['GET'])
@csrf_protect
def componentReviewStatus(request,uuid):
    log.debug("componentReviewStatus() called; UUID: {0}".format(uuid))
    log.debug("Found {0} available components".format(len(settings.VALID_COMPONENTS)))

    report = Report.get(id=uuid)

    try:
        engagement = Engagement.get(id=report.engagementParent)
    except (AttributeError, Engagement.DoesNotExist):
        engagement = ''

    return render(request,"pages/componentReviewStatus.html", \
        {
            "report": report,
            "engagement": engagement,
            "componentsList": settings.VALID_COMPONENTS,
            "currentUser": { "id": request.user.id, "name": f"{request.user.first_name} {request.user.last_name}" },
        })


# Renders the component editing form
@csrf_protect
@require_http_methods(['GET'])
def componentEdit(request,uuid,form=None):

    log.debug("componentEdit() called; UUID: {0}".format(uuid))
    #try:
    component = BaseComponent.get(uuid)
    #except:
    #return HttpResponse('Security Violation!')

    return render(request,"pages/componentEdit.html", {"component": component})



# The handler for saving incoming report component data
@csrf_protect
@require_http_methods(['POST'])
def componentSave(request,uuid):

    log.debug("componentSave() called; UUID: {0}".format(uuid))
    log.debug("Form data: {0}".format(request.POST))

    try:
        component = BaseComponent.get(uuid)
        log.debug("BaseComponent.get instantiated")

        component.updateFromForm(request.POST)
        log.debug("Form data applied to component")

        component.save()
        log.debug("Component saved")

        message = "Sucessfully Saved!"
        log.debug("Rendering response")
        return render(request,"pages/componentEdit.html", {"component": component})

    except ComponentFormError:
        response = HttpResponse('Invalid Form')
        response.status_code = 400
        return response  

    except ComponentError: 
        response = HttpResponse('Invalid Component')
        response.status_code = 500
        return response

# The handler for updating a component's status field
@csrf_protect
@require_http_methods(['POST'])
def componentStatusUpdate(request,uuid):
    log.debug("componentStatusUpdate() called; UUID: {0}".format(uuid))
    log.debug("Form data: {0}".format(request.body))

    try:
        component = BaseComponent.get(uuid)
        log.debug("BaseComponent.get instantiated")

        component.updateFromForm(json.loads(request.body), selective=True)
        log.debug("Form data applied to component")

        component.save()
        log.debug("Component saved")

        message = "Sucessfully Saved!"
        return JsonResponse({"component": uuid, "status": component.reviewStatus}, safe=False)

    except ComponentFormError:
        response = HttpResponse('Invalid Form')
        response.status_code = 400
        return response  

    except ComponentError: 
        response = HttpResponse('Invalid Component')
        response.status_code = 500
        return response

# The handler to process incoming POST requests creating new reports
@csrf_protect
@require_http_methods(['POST'])
def reportCreate(request, uuid=None, fromTemplate=False):


    log.debug(f"reportCreate with engagementParent uuid: {uuid}")

    jsondata = request.body
    if not validation.isValidJSON(jsondata):
        response = HttpResponse('Invalid Data!')
        log.warning("Invalid JSON data in request body")
        log.debug(f"  jsondata: {jsondata}")
        response.status_code = 400
        return response
    decodedJson = json.loads(jsondata)

    # Validate that required keys are present in JSON
    if not all([k in decodedJson for k in \
        ['name', 'reportComponents']]):
        response = HttpResponse('Invalid Data!')
        response.status_code = 400
        return response

    try:
        reportName = decodedJson['name']
        log.debug(f"reportName: {reportName}")
        reportComponents = decodedJson['reportComponents']
        status = decodedJson.get('status')
        # Everything is validated, lets instantiate the report
        report = None
        if uuid:
            log.debug(f"saving report (with engagementParent) reportComponents: {reportComponents}")
            report = Report.new(name=reportName, components=reportComponents, engagementParent=uuid, status=status)
        #    report.engagementParent = uuid
       #     report.save()
        else:
            if fromTemplate:
                report = SavedReport.new(name=reportName, components=reportComponents, status=status)
            else:
                report = Report.new(name=reportName, components=reportComponents, status=status)

    except ReportValidationError:
        log.warn("reportCreate() threw ReportValidationError")
        response = HttpResponse('Invalid Data!')
        response.status_code = 400
        return response

    log.debug(f"Returning HttpResponse; report.id: {report.id}")
    response = HttpResponse(report.id)
    response.status_code = 200
    return response



# Loads the page where a user can select the components they want in their new reports
@csrf_protect
@require_http_methods(['GET'])
def reportNew(request, uuid):

    componentList = settings.VALID_COMPONENTS
    engagement = Engagement.get(id=uuid)
    log.debug(f'Detected components: {componentList}')

    return render(request,"pages/reportNew.html", {
        "componentsList": componentList,
        "engagement": engagement,
        "report": BaseReport
    })



# Deletes the report with the specified UUID
@csrf_protect
@require_http_methods(['GET','POST'])
def reportDelete(request, uuid, fromTemplate=False):


    if fromTemplate:
        try:
            report = SavedReport.objects.get(id=uuid)
            returnUrl = ""
        except SavedReport.DoesNotExist:
            log.debug(f'No savedReport found with ID {uuid}')
            response.status_code = 400
    else:
        try:
            report = Report.objects.get(id=uuid)
        except Report.DoesNotExist:
            log.debug(f'No report found with ID {uuid}')
            response.status_code = 400
    name = escape(report.name)
    report.delete()
    response = HttpResponse(f'Successfully deleted report "{name}"')
    response.status_code = 200
    return response


@csrf_protect
@require_http_methods(['GET','POST'])
def templateDelete(request,uuid):
    return reportDelete(request,uuid,fromTemplate=True)


@csrf_protect
@require_http_methods(['POST'])
def templateUpdate(request,uuid):
    return reportUpdate(request,uuid,fromTemplate=True)


@csrf_protect
@require_http_methods(['POST'])
def reportUpdate(request,uuid,fromTemplate=False):

    try:
        # Get the JSON from the HTTP POST
        reportJSON = json.loads(request.body)

        componentJSON = reportJSON.get('reportComponents', None)
        reportName = reportJSON.get('name', None)
        reportPageTemplate = reportJSON.get('pageTemplateID', None)
        reportFindings = reportJSON.get('reportFindings', None)
        reportStatus = reportJSON.get('status', None)

        if componentJSON is not None:
            log.debug("In reportUpdate()")
            log.debug(f"name: {reportName}")
            log.debug("componentJSON:")
            [ log.debug("  {0}".format(k)) for k in componentJSON ]

        # Instantiate a Report object
        if fromTemplate:
            log.debug("fromTemplate is true:")
            report = SavedReport.get(id=uuid)
            report.update(componentJSON, reportName, reportPageTemplate, status=reportStatus)
        else:
            log.debug("fromTemplate is false:")
            # Update the report
            report = Report.get(id=uuid)
            report.update(componentJSON, reportName, reportPageTemplate, reportFindings, status=reportStatus)


    except ReportValidationError as e:
        if len(str(e)) == 0:
            e = "UNDEFINED"
        error_msg = f"Component Validation Error ({e})"
        log.error(error_msg)
        response = HttpResponse(escape(error_msg), content_type='text/html')
        response.status_code = 400
        return response

    # Add to the list for new components to create
    # Send back the same JSON object but with missing UUIDS for the new components
    components = json.loads(report._components)
    return JsonResponse(components, safe=False)



# Displays the list of existing reports and allows for the creation of a new one
@require_http_methods(['GET'])
def reportsHome(request):

    reports = []
    for r in Report.objects.all():
        # since we're sorting by modifiedDate
        # we need to make sure it exists, otherwise things break
        if r.modifiedDate:
            report = Report.get(id=r.id)
            reports.append(report)

    return render(request,"pages/reports.html", {'reports':reports})


def getReport(reportId):

    try:
        report = Report.get(id=reportId)
    except Report.DoesNotExist:
        report = SavedReport.get(id=reportId)

    return report


def getFinding(findingId):
    '''
    Given a finding UUID, retrieve the finding
    regardless of scoringType or whether it's an 
    EngagementFinding or DatabaseFinding
    '''

    finding = None

    for findingType in (
        EngagementFinding,
        BaseDatabaseFinding
    ):
        try:
            finding = findingType.get_child(id=findingId)
            break
        except FindingError:
            continue

    return finding


def getEngagement(engagementId):

    try:
        engagement = Engagement.get(id=engagementId)
    except Engagement.DoesNotExist:
        engagement = None
    return engagement



# returns a list of finding GUIDs for a report
@csrf_exempt
@require_http_methods(['POST'])
def getReportFindings(request):

    engagementID = request.POST.get('engagementID', None)
    reportID = request.POST.get('reportID', None)

    if engagementID and reportID:
        report = Report.get(id=reportID, engagementParent=engagementID)
        return JsonResponse([str(f.id) for f in report.findings], safe=False)

    else:
        response = HttpResponse('Missing parameters: must have "engagementID" and "reportID"')
        response.status_code = 400
        return response


# returns a list of finding GUIDs for a report
@csrf_exempt
@require_http_methods(['GET'])
def getReportComponents(request, uuid):

    report = getReport(uuid)
    return JsonResponse([{'id': c.id, 'name': c.name} for c in report.components], safe=False)


# Renders the requested pane in panes/*.html
@csrf_protect 
@require_http_methods(['POST'])
def renderPane(request, pane):

    itemIDs = json.loads(request.body)

    # sanitize pane parameter to prevent LFI
    bad_chars = str.maketrans(dict.fromkeys('./'))
    pane = pane.translate(bad_chars)

    # reports
    try:
        report = getReport(itemIDs['reportID'])
        report.populateForm()
    except KeyError:
        report = ''
    # components
    try:
        component = BaseComponent.get(itemIDs['componentID'])
    except KeyError:
        component = ''
    # findings
    try:
        finding = getFinding(itemIDs['findingID'])
    except KeyError:
        finding = ''

    try:
        engagement = getEngagement(itemIDs['engagementID'])
    except KeyError:
        engagement = ''

    response = render(request,'panes/{}.html'.format(pane), \
        {
            'report': report,
            'finding': finding,
            'component': component,
            'componentsList': settings.VALID_COMPONENTS,
            'findingsTree': (getFindingsTree('findings') if pane == 'categoryBrowse' else '')
        })

    return response



# Renders the requested modal in modals/*.html
@csrf_protect 
@require_http_methods(['POST'])
def renderModal(request, modal):

    itemIDs = json.loads(request.body)

    # sanitize modal parameter to prevent LFI
    bad_chars = str.maketrans(dict.fromkeys('./'))
    modal = modal.translate(bad_chars)

    # report
    try:
        try:
            report = Report.get(id=itemIDs['reportID'])
        except Report.DoesNotExist:
            report = SavedReport.get(id=itemIDs['reportID'])
    except KeyError:
        report = ''
    try:
        component = BaseComponent.get(itemIDs['componentID'])
        if not report:
            report = component.getReportParent
    except KeyError:
        component = ''

    # engagement
    engagement = itemIDs.get('engagementID', '')
    if engagement:
        engagement = Engagement.get(id=engagement)

    # findingGroup
    findingImportForm = None
    fgroupID = itemIDs.get('fgroupID', '').strip()

    if fgroupID:
        fgroup = BaseFindingGroup.get_child(id=itemIDs['fgroupID'])
        fgroup.populateForm(formClass=EditFgroupForm)
        editFgroupForm = fgroup.form
        if modal == 'findingDatabaseSelect':
            findingImportForm = FindingImportForm(scoringType=fgroup.scoringType)
    else:
        fgroup = ''
        editFgroupForm = EditFgroupForm

    response = render(request, f'modals/{modal}.html', \
        {
            'modalName': modal,
            'engagement': engagement,
            'report': report,
            'component': component,
            'componentsList': settings.VALID_COMPONENTS,
            'findingImportForm': findingImportForm,
            'NewFgroupForm': NewFgroupForm,
            'EditFgroupForm': editFgroupForm,
            'savedReportImportForm': SavedReportImportForm,
            'categoryAddForm': CategoryAddForm,
            'customerForm': CustomerForm(auto_id=CustomerForm.auto_id_str),
            'categoryEditForm': CategoryAddForm(auto_id='id_edit_%s')
        })

    return response



@csrf_protect
@require_http_methods(['POST'])
# GET the report ID from the URL
def reportClone(request,uuid):
    
    try:
        report = Report.get(id=uuid)
    except Report.DoesNotExist:
        report = SavedReport.get(id=uuid)

    clonedReport = report.clone(templatableOnly=False)
    return HttpResponse(clonedReport.id)



# Generate the HTML for the report
@csrf_protect
@xframe_options_exempt
@require_http_methods(['POST', 'GET'])
# GET the report ID from the URL
def reportGenerate(request,uuid):
    '''
    Render/preview a Report, SavedReport, or Component
    '''

    try:
        # TODO: Make 'page-break' div between sections optional (perhaps by
        # adding 'break-before' to BaseComponent?)

        try:
            report = Report.get(id=uuid)
        except Report.DoesNotExist:
            report = SavedReport.get(id=uuid)

        return HttpResponse(report.render(), content_type='text/html; charset=utf-8')

    except SavedReport.DoesNotExist:
        log.debug("UUID did not match any reports; trying components")

        # Render a single component
        component = BaseComponent.get(uuid)
        # remove the page break since we're just previewing
        component.pageBreakBefore = False

        # Instantiate the component's report, then remove all other components
        try:
            report = Report.get(id=component.reportParent)
        except Report.DoesNotExist:
            report = SavedReport.get(id=component.reportParent)
        components = [component]
        report.components = components
        response = HttpResponse(report.render(), content_type='text/html; charset=utf-8')
        return response 

@csrf_protect
@require_http_methods(['POST', 'GET'])
# GET the report ID from the URL
def reportGeneratePdf(request,uuid):
    '''
    Render/preview a Report, SavedReport, or Component directly to PDF
    '''

    try:
        report = Report.get(id=uuid)
    except Report.DoesNotExist:
        report = SavedReport.get(id=uuid)

    # These two arguments are required for Chrome's PrintToPDF to function
    # NOTE: --no-sandbox and --disable-dev-shm-usage are only needed when running in Docker
    ch = webdriver.ChromeOptions()
    for a in ['--disable-extensions', '--headless', '--no-sandbox',
            '--disable-dev-shm-usage', '--ignore-certificate-errors',
            '--allow-running-insecure-content']:
        ch.add_argument(a)
    
    # Connect to Chrome with the specified arguments
    browser = webdriver.Remote(command_executor="http://chrome:4444/wd/hub", options=ch)

    # Navigate to /login first to set the request's domain; otherwise, setting 
    # the cookie will fail 
    uri_base = "https://nginx"
    login_uri = f"{uri_base}/login"
    log.debug(f"login_uri: {login_uri}")
    browser.get(login_uri)

    cookie = request.COOKIES.get("sessionid")
    cookie_dict = {'name': 'sessionid', 'value': cookie}
    log.debug(f"cookie_dict: {cookie_dict}")

    try:
        browser.add_cookie(cookie_dict)
        log.debug("added clookie")
    except InvalidCookieDomainException:
        log.debug("Got InvalidCookieDomainException")
        pass

    uri_path = request.path.replace("/generatePdf", "/generate")
    uri = f"{uri_base}/{uri_path}"
    log.debug(f"Requesting uri: {uri}")
    browser.get(uri)

    try:
        # Wait for page to finish rendering, assuming less than one minute
        log.debug("Waiting for request to finish")
        timeout = getattr(settings, "SELENIUM_TIMEOUT", 120)
        WebDriverWait(browser, timeout).until(expected_conditions.presence_of_element_located((By.ID, "finished_loading")))
    except TimeoutException as e:
        log.debug(f"Timeout of {timeout} seconds exceeded when attempting to render report with id {report.id} to PDF")
        messages.add_message(request, messages.ERROR, "PDF took too long to render! Please contact a web administrator for more information")
        return redirect(f"/engagements/report/{report.id}/edit", uuid=report.id)
    finally:
        # Send request to Selenium to call Page.printToPDF
        log.debug("Finished loading")
        resource = f"/session/{browser.session_id}/chromium/send_command_and_get_result"
        url = f"{browser.command_executor._url}{resource}"
        body = json.dumps({'cmd': 'Page.printToPDF', 'params': {'printBackground': True}})
        response = browser.command_executor._request('POST', url, body)

        # Display browser logs
        log.debug("Selenium logs:")
        log.debug(browser.get_log("driver"))
        log.debug(browser.get_log("browser"))

        # Close the browser
        browser.quit()

    # Base64-decode PDF response and render to HttpResponse
    response = HttpResponse(base64.b64decode(response.get('value').get('data')), content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="{}.pdf"'.format(report.name.replace('"', ''))

    return response

# load the new database finding form with the cvss form
def findingCvssNew(request):
    log.debug("Called findingCvssNew")
    form = CVSSDatabaseFindingForm
    return render(request,"pages/findingNew.html",{"form":form,"scoringType":"CVSS"})

# load the new database finding form with the dread form
def findingDreadNew(request):
    log.debug("Called findingDreadNew")
    form = DREADDatabaseFindingForm
    return render(request,"pages/findingNew.html",{"form":form,"scoringType":"DREAD"})


# load the new database finding form with the dread form
def findingProactiveNew(request):
    log.debug("Called findingProactiveNew")
    form = ProactiveDatabaseFindingForm
    return render(request,"pages/findingNew.html",{"form":form,"scoringType":"PROACTIVE"})


# Edit an existing "findings database" entry. Should be very similiar to findingsView, except with all the editing tools loaded.
@csrf_protect
@require_http_methods(['POST', 'GET'])
def findingEdit(request,uuid):

    finding = BaseDatabaseFinding.get_child(id=uuid)
    if request.method == 'GET':
        # instantiate a cvssFinding object by passing in an instance of the model
        finding.populateForm()
        #log.info(cvssFinding.form.data)
        #log.info(str(cvssFinding.form['categoryID']))
        return render(request,"pages/findingEdit.html",{'finding': finding})

    elif request.method == 'POST':
        finding.updateFromPostData(request.POST)
        log.debug(f'views.py finding edit save...')
        finding.save()
        return HttpResponse(finding.id)


@csrf_protect
@require_http_methods(['POST'])
def findingDelete(request,uuid):

    try:
        databaseFinding = BaseDatabaseFinding.get_child(id=uuid)
        databaseFinding.delete()
        return HttpResponse(databaseFinding.id)

    except FindingError:
        log.debug(f'No finding found with ID {uuid}')
        response.status_code = 400
        return response


# This is where NEW findings requests are send via POST. Existing findings will get sent to findingEdit as a post. 
@csrf_protect
@require_http_methods(['POST'])
def findingCreate(request):

    # we need to know the form type, its passed in via a hidden form field
    if 'scoringType' in request.POST:
        scoringType = request.POST['scoringType']
    else:
        raise FindingCreateError("Missing 'scoringType' parameter")
    # for security, check the value or form type. Anything other than CVSSForm or DREADForm creates and error        
    if scoringType == 'CVSS':
        finding = CVSSDatabaseFinding.new(request.POST)
    elif scoringType == 'DREAD':
        finding = DREADDatabaseFinding.new(request.POST)
    elif scoringType == 'PROACTIVE':
        finding = ProactiveDatabaseFinding.new(request.POST)
    else:
        raise FindingCreateError("Invalid 'scoringType' parameter")
       
    finding.save()
    log.debug(f'Created new DatabaseFinding, UUID: {finding.id}')
    # Return the ID to be handled by javascript on the findingNew page
    # return HttpResponse(finding.id)
    return HttpResponse(finding.id)


# make way to RETRIEVE the details individual per image
@csrf_protect
@require_http_methods(['POST'])
def findingFigureEdit(request, uuid):
    '''
    Updates a finding's list of figures
    '''
    
    findingParent = uuid
    successfulUpdateCount = 0
       
    try: 
        parsedJSON = json.loads(request.body)
    except json.JSONDecodeError:
        raise ImagesUploadError("JSON parsing of image attributes failed")

    # get finding's current list of figures
    old_figures = []
    try:
        for figure in ImageModel.objects.filter(findingParent=findingParent):
            old_figures.append(figure)
    except ImageModel.DoesNotExist:
        pass

    # make sure finding is valid
    try:
        EngagementFinding.get_child(id=uuid)
        log.debug(f"findingFigureEdit called with findingParent {findingParent}")
    except FindingError:
        log.debug(f"findingFigureEdit aborted - finding ID invalid")
        raise ImagesUploadError(f'findingParent "{findingParent}" does not exist')


    # create / update / save new / existing figures
    for order, figure in enumerate(parsedJSON):
        if 'guid' in figure:
            try:
                imageModel = ImageModel.get(id=figure['guid'])
            except ImageModel.DoesNotExist:
                log.debug(f"findingFigureEdit called with missing figureID, tried: {figure['guid']}")
                continue
            if 'size' in figure:
                imageModel.size = figure['size']
            if 'caption' in figure:
                imageModel.caption = figure['caption']
            imageModel.order = order
            imageModel.findingParent = findingParent
            try:
                imageModel.save()
                successfulUpdateCount += 1
                log.debug(f"findingFigureEdit called; successfully saved imageModel {imageModel.id}, with parentID: {findingParent}")
            except:
                log.debug(f"findingFigureEdit failed to save for imageModel {imageModel.id}, with parentID: {findingParent}")

        else:
            log.debug(f"findingFigureEdit called with missing figureID")

    # handle deleted figures - this helps prevent orphans in the database
    new_figures = [f['guid'] for f in parsedJSON]
    for figure in old_figures:
        if str(figure.id) not in new_figures:
            log.debug(f'Deleting figure {figure.id}')
            figure.delete()

    return HttpResponse(f"updated {successfulUpdateCount:,} figures")



@csrf_protect
@require_http_methods(['POST'])
def imageUpload(request):

    log.debug(f"imageUpload called")
    
    extensionToContentType = {'png':'image/png',
                              'jpg':'image/jpeg',
                              'jpeg':'image/jpeg',}

    # check if a file is present
    if request.FILES['file']:
    
        imageModel = ImageModel()
        uploadedFile = request.FILES['file']
        
        
        # retreive and validate the content type of the image (based on the extension)
        extension = uploadedFile.name.split(".")[1].lower()
        contentType = str(extensionToContentType.get(extension ,"error"))
        log.debug(f"Image uploaded with content-type {contentType}")
        imageModel.contentType = contentType
        log.debug(f"imageUpload called with content-type {contentType}")
        if contentType == "error": 
            raise ImagesUploadError("Invalid file extension for uploaded image")
        
        imageModel.data = uploadedFile.read()
        if 'findingParent' in request.POST:
            findingParent = request.POST["findingParent"]
            try:
                CVSSEngagementFinding.get(id=findingParent)
                log.debug(f"imageUpload called with findingParent {findingParent}")
            except CVSSEngagementFinding.DoesNotExist:
                log.debug(f"imageUpload aborted - finding ID invalid")
                raise ImagesUploadError(f'findingParent "{findingParent}" does not exist')
            imageModel.findingParent = request.POST["findingParent"]
            if 'order' in request.POST:
                imageModel.order = request.POST['order']
            else:
                raise ImagesUploadError("Files attached to findings must specifiy order")
        else:
             log.debug(f"imageUpload called with no findingParent")

        if 'caption' in request.POST:
            imageModel.caption = request.POST["caption"]
        if 'size' in request.POST:
            imageModel.size = request.POST["size"]


        imageModel.save()
        log.debug(f"imageUpload successfully saved with resulting ID: {imageModel.id}")
        return HttpResponse(imageModel.id)

    else:
        raise ImagesUploadError("File data not present")


# render the image
@require_http_methods(['GET'])
def imageLoad(request,uuid):
    try:
        imageModel = ImageModel.objects.get(id=uuid)
    except ImageModel.DoesNotExist:
        log.debug(f"imageLoad called with invalid uuid, tried: {uuid}")
        raise ImagesUploadError("Image with specified ID not found")
    log.debug(f"image successfully loaded with ID: {imageModel.id}")
    return HttpResponse(imageModel.data, content_type=imageModel.contentType)


@require_http_methods(['GET'])
def imageMeta(request,uuid):
    try:
        imageModel = ImageModel.get(id=uuid)
    except ImageModel.DoesNotExist:
        log.debug(f"imageMeta called with invalid uuid, tried: {uuid}")
        raise ImagesUploadError("Image with specified ID not found")
    log.debug(f"image metadata successfully loaded with ID: {imageModel.id}")
    imageModelDict = {}
    if imageModel.findingParent:
        imageModelDict['findingParent'] = str(imageModel.findingParent)
    if imageModel.caption:
        imageModelDict['caption'] = imageModel.caption
    if imageModel.size:
        imageModelDict['size'] = imageModel.size
    if imageModel.order:
        imageModelDict['order'] = imageModel.order
    return JsonResponse(imageModelDict)



# Displays the list of existing findings and allows for the creation of a new one
@csrf_protect 
@require_http_methods(['GET', 'POST'])
def findingsList(request):

    findingsTree = getFindingsTree('findings')

    if request.method == 'GET':

        return render(request,"pages/findings.html",{'findingsTree':findingsTree})
        #  findingsList = '{"Web Application":{"Authentication":{"6367f5d6-ee87-42b8-b8d7-3f362330b863":"Authentication Bypass"}},"System Security": {"6367f5d6-ee87-42b8-b8d7-3f362330b863": "LLMNR Enabled"},}'

    elif request.method == 'POST':
        return JsonResponse(findingsTree)





# add a new category to the tree. UUID is for the existing parent item in the tree
@csrf_protect
@require_http_methods(['POST'])
def findingCategoryAdd(request):

    # ensure that the POST parameter categoryName is present
    try:
        categoryName = request.POST["categoryName"]
        try:
            parentUUID = request.POST["categoryParent"]
        except KeyError:
            parentUUID = None
    except MultiValueDictKeyError:
        raise CategoryValidationError("Required parameters for category creation not present in POST data")

    # if categoryParent is blank, create in root
    if not parentUUID:
        parentCategory = DatabaseFindingCategory.getRootNode()
        log.info(parentCategory)
        parentUUID = parentCategory.id

    # ensure that the POST parameter categoryName has nothing malicious in it
    try:
        validation.isValidName(categoryName)
    except ValidationError:
        response = HttpResponse("Invalid Category Name",status=400)
        return response

    # create the new category
    newCategory = DatabaseFindingCategory(name=categoryName, categoryParent=parentUUID)
    newCategory.save()

    #return the ID of the new category
    return HttpResponse(newCategory.id)



@csrf_protect
@require_http_methods(['POST'])
def findingCategoryEdit(request,uuid):
    try:
        category = DatabaseFindingCategory.objects.get(id=uuid)

    except DatabaseFindingCategory.DoesNotExist:
        raise CategoryError("Cannot locate specified category")

       # ensure that the POST parameter categoryName is present
    try:
        categoryName = request.POST["categoryName"]
        try:
            parentUUID = request.POST["categoryParent"]
            if len(parentUUID) == 0:
                parentUUID = None
        except KeyError:
            parentUUID = None
    except MultiValueDictKeyError:
        raise CategoryValidationError("Required parameters for category creation not present in POST data")  
        
    # ensure that the POST parameter categoryName has nothing malicious in it
    try:
        validation.isValidName(categoryName)
    except ValidationError:
        response = HttpResponse("Invalid Category Name",status=400)
        return response


    # if categoryParent is blank, create in root
    if not parentUUID:
        parentCategory = DatabaseFindingCategory.getRootNode()
        log.info(parentCategory)
        parentUUID = parentCategory.id

    # prevents infinite loops via circular inheratance!
    try:
        validation.isValidParent(uuid,parentUUID)     
    except ValidationError:
        response = HttpResponse("Circular reference detected",status=400)
        return response
   
    category.name = categoryName
    category.categoryParent = parentUUID
    category.save()

    return HttpResponse("Successfully edited category")



# used to remove a category from the tree
@csrf_protect
@require_http_methods(['POST'])
def findingCategoryDelete(request, uuid):
    
    # attempt to load the specified category
    try:
        toDelete = DatabaseFindingCategory.objects.get(id=uuid)

    except DatabaseFindingCategory.DoesNotExist:
        raise CategoryRemoveError("Cannot locate specified category")


    # Check and see if this category has children. If it does, deny the deletion
    categoryChildren = DatabaseFindingCategory.objects.filter(categoryParent=uuid)
    cvssFinding = CVSSDatabaseFinding.objects.filter(categoryID=uuid)
    dreadFinding = DREADDatabaseFinding.objects.filter(categoryID=uuid)
    proactiveFinding = ProactiveDatabaseFinding.objects.filter(categoryID=uuid)

    if categoryChildren.exists():
        response = HttpResponse("Cannot remove categories with child categories", status=400)
        return response

    if cvssFinding.exists() or dreadFinding.exists() or proactiveFinding.exists():
        response = HttpResponse("Cannot remove categories with child findings", status=400)
        return response

    # actually remove the category
    toDelete.delete()

    response = HttpResponse("Successfully deleted category")
    response.status = 200
    return response




# check the last modified timestamp of a model
@csrf_protect 
@require_http_methods(['GET','POST'])
def timestamp(request,uuid):

    hint = request.POST.get('hint', '')
    if hint and not isValidModelHint(hint):
        raise ValidationError("hint value contains invalid characters or is empty")

    p = resolve(uuid,hint)

    return HttpResponse(p.modifiedDate)


@csrf_protect
@require_http_methods(['POST'])
def revisionLoad(request):
    id = request.POST["UUID"]
    version = request.POST["version"]
    fieldName = request.POST["fieldName"]
    log.debug("Views.loadRevision called; UUID: %s (fieldName: %s, version: %s)" % (id,fieldName,version))
    try:
        p = Revision.objects.get(parentId=id,fieldName=fieldName,version=version)
    except Revision.DoesNotExist:
        raise RevisionError("Revision does not exist for this ID/fieldname/version combo")
    return HttpResponse(escape(p.fieldText))


#@require_http_methods(['GET'])
#def revisionsList(request,uuid):
#    log.debug(f"Revision.getVersionList called; uuid: {uuid}")
#    return HttpResponse(escape(Revision.listRevisions(uuid)))


@require_http_methods(['POST'])
def revisionsList(request):
    uuid = request.POST["uuid"]
    isComponent = json.loads(request.POST["isComponent"].lower())
    field = request.POST["field"]
    log.debug(f"Revision.getVersionList called; uuid: {uuid}")
    return JsonResponse(Revision.listRevisions(uuid,isComponent,field))


def revisionGetText(id,isComponent,fieldName,version):
    try:
        p = Revision.objects.get(parentId=id,fieldName=fieldName,version=version)
        text = p.fieldText
        print(text)
    except Revision.DoesNotExist:
        raise RevisionError("Revision does not exist for this ID/fieldname/version combo")
    return text



@csrf_protect
@require_http_methods(['POST'])
def revisionCompare(request):
    id = request.POST["uuid"]

    # todo: validate all user input
    currentText = request.POST["currentText"]
    toVersion = request.POST["toVersion"]
    fromVersion = str(request.POST["fromVersion"])
    toVersion = str(request.POST["toVersion"])
    fieldName = request.POST["fieldName"]
    isComponent = bool(request.POST["isComponent"])

    log.debug("Views.revisionCompare called; UUID: %s (fieldName: %s, toVersion: %s, fromVersion: %s)" % (id,fieldName,toVersion,fromVersion))


    if int(fromVersion) == -1:
        fromText = currentText
    else:
        fromText = revisionGetText(id,isComponent,fieldName,fromVersion)

    if int(toVersion) == -1:
        toText = currentText
    else:
        toText = revisionGetText(id,isComponent,fieldName,toVersion)

    diffHTML = Revision.diff(fromText,toText)
   # diffJSON = Revision.diff(toText,fromText)

    diffJSON = {}
    diffJSON['unifiedDiff'] = base64.urlsafe_b64encode(bytes(diffHTML,'utf-8')).decode('ascii')
    diffJSON['fromText'] = base64.urlsafe_b64encode(bytes(fromText,'utf-8')).decode('ascii')
    return JsonResponse(diffJSON)

@require_http_methods(['GET'])
def engagementNew(request):
    log.debug(f"engagementNew called")
    return render(request,"pages/engagementNew.html",{"form": EngagementForm})


@csrf_protect
@require_http_methods(['POST'])
def engagementCreate(request):
    
    p = Engagement.new(request.POST)
    p.name = request.POST.getlist("name")[0]
    p.save()
    response = HttpResponse(escape(p.name))
    response.status_code = 200
    log.debug(f'engagementCreate called, resulting engagement UUID: {p.id}')

    '''
    response = HttpResponse()
    response.status_code = 400
    log.debug(f'engagementCreate called, failed to create engagement')
    '''

    return response



@csrf_protect
@require_http_methods(['GET', 'POST'])
def engagementEdit(request,uuid):

    engagement = Engagement.get(id=uuid)

    if request.method == 'GET':
        # instantiate a cvssFinding object by passing in an instance of the model
        #findingsForm = CVSSForm(engagementId=engagement.id)
        log.debug(f'engagementEdit (GET) called, loading data for engagement with UUID: {engagement.id}')
        return render(request,"pages/engagementEdit.html",{
            'engagement': engagement,
            'findingDownloadExcel': f'/engagements/{engagement.id}/excel',
            'fgroupAdd': f'/engagements/'

        })
        # "form":form,"isApproved":cvssFinding.isApproved

    elif request.method == 'POST':
        log.debug(f'engagementEdit (POST) called, attempting to save data for engagement with UUID: {engagement.id}')
        engagement.updateFromPostData(request.POST)
        engagement.save()
        return HttpResponseRedirect('/engagements')


@csrf_protect
def engagementClone(request,uuid):

    log.debug(f'engagementClone called, Cloning: {uuid}')

    try:
        engagement = Engagement.get(id=uuid)
        engagementClone = engagement.clone()
        engagementClone.save()

    except Engagement.DoesNotExist:
        log.debug(f'engagementClone called, failed for  UUID: {p.id} (DOES NOT EXIST)')
        raise EngagementError("Specified Engagement does not exist")

    return HttpResponseRedirect("/engagements")


@csrf_protect
def engagementDelete(request,uuid):
    try:
        p = Engagement.get(id=uuid)

        # delete all findings groups associated with the engagement
        for findingGroup in p.fgroups:
            findingGroup.delete()
        p.delete()
        log.debug(f'engagementDelete called, succeeded for  UUID: {p.id}')
    except Engagement.DoesNotExist:
        log.debug(f'engagementDelete called, failed for  UUID: {p.id} (DOES NOT EXIST)')
        raise EngagementError("Specified Engagement does not exist")
    return HttpResponseRedirect("/engagements")


# Displays the list of existing reports and allows for the creation of a new one
@csrf_protect
@require_http_methods(['GET', 'POST'])
def engagementsList(request):
    engagements = Engagement.objects.all()
    if request.method == 'GET':
        log.debug(f'enagagementsList (GET) called')
        return render(request,"pages/engagements.html",{'engagements':engagements})

    elif request.method == 'POST':
        engagementsList = []
        for engagement in engagements:
            engagementsList.append(str(engagement.id))
        log.debug(f'enagagementsList (POST) called')
        return JsonResponse(engagementsList)


#commenting out for now. we decided we didnt want to clone the object, just pre-populate the form
# create a new engagementFinding based a findings database finding UUID and return the engagementfinding UUID
#def engagementCVSSFindingImport(request,uuid):
#    newEngagementFinding = CVSSDatabaseFinding.get(uuid).clone(name='',destinationClass=CVSSEngagementFinding)
#    return HttpResponse(newEngagementFinding.id)



# create a new Finding group (fgroup)
@csrf_protect
@require_http_methods(['POST'])
def engagementFgroupCreate(request,uuid,gtype):

    if gtype == "dread":
        p = DREADFindingGroup.new(uuid=uuid,postData=request.POST)
    elif gtype == "cvss":
        p = CVSSFindingGroup.new(uuid=uuid,postData=request.POST)
    elif gtype == "proactive":
        p = ProactiveFindingGroup.new(uuid=uuid,postData=request.POST)
    else:
        raise EngagementFgroupError("Fgroup type is not valid")

    p.save()
    log.debug(f'engagementFgroupCreate called, resulting Fgroup UUID {p.id} assigned to parent (engagement) id of {uuid}')
    return HttpResponse(p.id)


# Edit the name of a findingGroup
@csrf_protect
@require_http_methods(['POST'])
def engagementFgroupEdit(request,uuid):

    fgroup = BaseFindingGroup.get_child(id=uuid)
    log.debug(f'engagementFgroupEdit called, attempting to save data for Fgroup with UUID: {fgroup.id}')
    fgroup.updateFromPostData(request.POST, formClass=EditFgroupForm)
    fgroup.save()
    response = HttpResponse(f"Successfully updated findingsGroup {escape(str(uuid))}")
    response.status = 200
    return response


# Review which of the group's findings haven't been filled in
@csrf_exempt
def engagementFgroupStatus(request,uuid):

    fgroup = BaseFindingGroup.get_child(id=uuid)
    return render(request,"pages/findingGroupStatus.html",
                {
                    "fgroup":     fgroup,
                    "engagement": fgroup.engagement
                }
            )


# List all findingGroups (fgroups) associated with an engagement
@csrf_protect
@require_http_methods(['POST'])
def engagementFgroupList(request,uuid):
    fgroupsDict = {}
    log.debug(f"engagementFgroupList called for UUID {uuid}; request.method: {request.method}")

    CVSSFGroupList = []
    CVSSFgroups = CVSSFindingGroup.objects.filter(engagementParent=uuid)
    log.debug(list(CVSSFgroups))
    for i in CVSSFgroups:
        CVSSFGroupList.append({'id':str(i.id),'name':str(i.name)})
    fgroupsDict['CVSS'] = CVSSFGroupList

    DreadFGroupList = []
    DreadFgroups = DREADFindingGroup.objects.filter(engagementParent=uuid)
    log.debug(list(DreadFgroups))
    for i in DreadFgroups:
        DreadFGroupList.append({'id':str(i.id),'name':str(i.name)})
    fgroupsDict['DREAD'] = DreadFGroupList
    return JsonResponse(fgroupsDict)



@csrf_protect
@require_http_methods(['POST'])
def engagementFgroupDelete(request,uuid):

    fgroup = BaseFindingGroup.get_child(id=uuid)
    #fgroupChildren = fgroup.findingClass.objects.filter(findingGroup=uuid)
    #if fgroupChildren:
    #    log.debug(f"engagementFgroupDelete called for UUID {uuid}; DENIED:children detected")
   #     raise EngagementFgroupError("Could not delete: Children found")
    #else:
    #    log.debug(f"engagementFgroupDelete called for UUID {uuid}; Proceeding no children")
    # actually remove the findingsGroup
    fgroup.delete()
    response = HttpResponse(f"Successfully deleted findingsGroup {escape(str(uuid))}")
    response.status = 200
    return response



@csrf_protect
def engagementDelete(request,uuid):
    try:
        p = Engagement.get(id=uuid)
        p.delete()
        log.debug(f'engagementDelete called, succeeded for  UUID: {p.id}')
    except Engagement.DoesNotExist:
        log.debug(f'engagementDelete called, failed for  UUID: {p.id} (DOES NOT EXIST)')
        raise EngagementError("Specified Engagement does not exist")
    return HttpResponseRedirect("/engagements")



# Deletes the engagementFinding with the specified UUID
@csrf_protect
@require_http_methods(['GET', 'POST'])
def engagementFindingDelete(request,uuid):

    try:
        cvssEngagementFinding = CVSSEngagementFinding.get(uuid)
        name = cvssEngagementFinding.name
        cvssEngagementFinding.delete()
        response = HttpResponse(f'Successfully deleted cvssEngagementFinding "{escape(name)}"')
        response.status_code = 200
        return HttpResponseRedirect('/engagements/edit/%s' % str(cvssEngagementFinding.engagementParent))

    except CVSSEngagementFinding.DoesNotExist:
        log.debug(f'No report found with ID {uuid}')
        response.status_code = 400
        return response



    

#load an engagementFinding form up with data from a databaseFinding based on its UUID
@require_http_methods(['GET'])
def engagementFindingImport(request, fgroup, uuid):

    log.debug(f"engagementFindingImport called for findingGroup {fgroup} and uuid {uuid}")
    p = EngagementFinding.from_database(uuid, fgroup)

    p.populateForm()
    return render(
        request,
        'panes/engagementFindingNew.html',
        {
            "findingsForm": p.form,
            "categoryID": p.categoryID
        }
    )



#load an engagementFinding form up with data from a databaseFinding based on its UUID
@require_http_methods(['GET'])
def engagementFindingExport(request, uuid):

    log.debug(f"engagementFindingExport called for finding uuid {uuid}")
    p = EngagementFinding.get_child(id=uuid)

    if p.scoringType == 'CVSS':
         formClass = CVSSDatabaseFinding.formClass
    elif p.scoringType == 'DREAD':
        formClass = DREADDatabaseFinding.formClass
    elif p.scoringType == 'PROACTIVE':
        formClass = ProactiveDatabaseFinding.formClass

    p.populateForm(formClass=formClass)
    return render(
        request,
        'pages/findingNew.html',
        {
            "form": p.form,
            "categoryID": p.categoryID
        }
    )



#def engagementDREADFindingImport(request,uuid):
    #
#    newEngagementFinding = Finding.get(uuid).clone(name='',destinationClass=EngagementFinding)
#    return HttpResponse(newEngagementFinding)

# Given a findingGroup, return UUIDS for all associated engagmentFindings
@csrf_protect
def engagementFindingList(request,uuid):
    log.debug(f"engagementFindingList called for findingGroup {uuid}; request.method: {request.method}")


    engagementFindings = CVSSEngagementFinding.objects.filter(findingGroup=uuid)
    log.debug(list(engagementFindings))
    if request.method == 'GET':
        return render(request,"panes/engagementFindingsListManual.html",{'engagementFindings':engagementFindings})

    elif request.method == 'POST':
        engagementFindingsList = []
        for i in engagementFindings:
            log.debug("  Finding: {0}".format(i.id))
            engagementFindingsList.append(str(i.id))
        return JsonResponse(engagementFindingsList)


# Export all of the findings for this engagement to Excel format
@csrf_protect
@require_http_methods(['GET'])
def engagementFindingExcel(request,uuid):
    log.debug(f"engagementFindingExcel called for engagement UUID {uuid}; request.method: {request.method}")
    fgroups = Engagement.get(id=uuid).fgroups
    log.debug(list(fgroups))

    CVSSEngagementFindings = []
    DREADEngagementFindings = []
    ProactiveEngagementFindings = []
    for fgroup in fgroups:
        if fgroup.scoringType == "CVSS":
            CVSSEngagementFindings += fgroup.findings
        elif fgroup.scoringType == 'DREAD':
            DREADEngagementFindings += fgroup.findings
        elif fgroup.scoringType == 'PROACTIVE':
            ProactiveEngagementFindings += fgroup.findings

        else:
            raise EngagementError('Excel Export error: scoringType incorrectly assigned to findingGroup')


    # prepare response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )

    response['Content-Disposition'] = f'attachment; filename=Engagement_{str(uuid)}.xlsx'
 
    
    # get finished workbook from excel.py
    workbook = generateExcel(
        CVSSEngagementFindings,
        DREADEngagementFindings,
        ProactiveEngagementFindings
    )
    workbook.save(response)
    return response




@csrf_protect
@require_http_methods(['POST', 'GET'])
def engagementFindingEdit(request, uuid):

    log.info(f"engagementFindingEdit called for UUID {uuid}; request.method: {request.method}")

    finding = EngagementFinding.get_child(uuid)
    
    if request.method == 'GET':
        finding.populateForm()
        return render(
            request,
            "pages/engagementFindingEdit.html",
            {
                'finding': finding,
            }
        )

    elif request.method == 'POST':
        log.debug(f"engagementFindingEdit POST request")
        finding.updateFromPostData(request.POST,finding.formClass)
        finding.save()
        return HttpResponse(finding.id)


# Deletes the engagementFinding with the specified UUID
@csrf_protect
@require_http_methods(['GET', 'POST'])
def engagementFindingDelete(request,uuid):
    log.debug(f"engagementFindingDelete called for finding ID: {uuid}")
    finding = EngagementFinding.get_child(uuid)

    name = finding.name
    finding.delete()
    log.debug(f"engagementFindingDelete sucesfully delete finding of type ({finding.className}) with name: {name}")
    response = HttpResponse(f'Successfully deleted finding of type ({escape(finding.className)}) with name "{escape(name)}"')
    response.status_code = 200
    return HttpResponseRedirect(f'/engagements/edit/{finding.fgroup.engagementParent}')



def engagementFindingNew(request, uuid):

    # discover the type of finding and load the appropriate page
    fgroup = BaseFindingGroup.get_child(id=uuid)
    findingsForm = fgroup.findingForm
    log.debug(f"engagementFindingNew called and used findingsForm class {findingsForm.className}")
    return render(
        request,
        "pages/engagementFindingNew.html",
        {
            "findingsForm": findingsForm,
            "fgroup": fgroup,
            "engagement": fgroup.engagement
        }
    )


@csrf_protect
def reportsList(request, uuid):
    log.debug(f"reportList called for UUID {uuid}; request.method: {request.method}")
    reports = Report.objects.filter(engagementParent=uuid)
    log.debug(f"reports: {reports}")
    if request.method == 'GET':
        return render(request, "panes/reportsList.html", {'engagementReports': engagementReports})
    
    elif request.method == 'POST':
        reportsList = []
        for report in reports:
            log.debug(f"  Report: {report.id}")
            reportsList.append({'id': str(report.id), 'name': report.name})
        return JsonResponse(reportsList, safe=False)


@csrf_protect
@require_http_methods(['POST'])
def engagementFindingCreate(request, uuid):

    fgroup = BaseFindingGroup.get_child(id=uuid)
    p = fgroup.findingClass.new(postData=request.POST, findingGroupParent=uuid)
    p.save()
    log.debug(f'engagementFindingCreate called, resolved to type ({fgroup.scoringType}) resulting engagementFinding UUID {p.id} and parent (fgroup) id of {uuid}')
    return HttpResponse(p.id)


@csrf_protect
@require_http_methods(['POST'])
def engagementFileUpload(request):
    '''
    Handle file uploads for engagements:
    - normalized.json: Populate Table components for Table of Tables
    - findings.json: Populate findings section
    - executive_summary.md: Populate Container - Executive Summary section
    '''
    log.debug('engagementFileUpload called')

    try:
        engagement_id = request.POST.get('engagementID')
        report_id = request.POST.get('reportID')

        if not engagement_id or not report_id:
            response = HttpResponse('Missing engagementID or reportID')
            response.status_code = 400
            return response

        # Get the report
        report = Report.get(id=report_id)
        if str(report.engagementParent) != str(engagement_id):
            response = HttpResponse('Report does not belong to engagement')
            response.status_code = 400
            return response

        # Get the current full component tree - we'll modify it and save at the end
        components_json = json.loads(report._components)
        components_updated = False
        
        # Helper function to check if a component UUID already exists in the JSON tree
        def component_exists_in_json(uuid_str, components_list):
            """Recursively check if a component UUID exists in the component tree"""
            for comp in components_list:
                if comp.get('uuid') == uuid_str:
                    return True
                if 'children' in comp and comp['children']:
                    if component_exists_in_json(uuid_str, comp['children']):
                        return True
            return False
        
        # Helper function to get all existing UUIDs from the JSON tree
        def get_all_component_uuids(components_list):
            """Recursively get all component UUIDs from the tree"""
            uuids = set()
            for comp in components_list:
                if 'uuid' in comp:
                    uuids.add(comp['uuid'])
                if 'children' in comp and comp['children']:
                    uuids.update(get_all_component_uuids(comp['children']))
            return uuids
        
        # Track created findings to add to report
        created_finding_uuids = []
        # Get existing findings as strings
        existing_finding_uuids = [str(uuid) for uuid in report.finding_uuids]

        # Process normalized.json - populate Table components
        if 'normalized_json' in request.FILES:
            normalized_file = request.FILES['normalized_json']
            if normalized_file.name == 'normalized.json':
                try:
                    file_content = normalized_file.read().decode('utf-8')
                    normalized_data = json.loads(file_content)
                    
                    # Extract tables from normalized_data - handle both list and dict formats
                    tables_list = None
                    if isinstance(normalized_data, list):
                        tables_list = normalized_data
                    elif isinstance(normalized_data, dict):
                        # Try common keys for tables
                        if 'tables' in normalized_data and isinstance(normalized_data['tables'], list):
                            tables_list = normalized_data['tables']
                        elif 'data' in normalized_data and isinstance(normalized_data['data'], list):
                            tables_list = normalized_data['data']
                        else:
                            # If it's a dict, try to use values that are dicts with table-like structure
                            # (have 'caption' or 'text' keys)
                            potential_tables = []
                            for key, value in normalized_data.items():
                                if isinstance(value, dict) and ('caption' in value or 'text' in value):
                                    potential_tables.append(value)
                            if potential_tables:
                                tables_list = potential_tables
                            else:
                                # Last resort: treat each dict value as a potential table
                                tables_list = [v for v in normalized_data.values() if isinstance(v, dict)]
                    
                    # Helper function to convert dict to HTML table markdown
                    def dict_to_table_markdown(data, title=None):
                        """Convert a dict to HTML table markdown format"""
                        if not isinstance(data, dict):
                            return ''
                        
                        # Create a two-column table: Key | Value
                        lines = ['| Key | Value |', '|-----|-------|']
                        for key, value in data.items():
                            # Skip nested dicts and lists - handle them separately
                            if isinstance(value, (dict, list)):
                                value_str = f"({len(value)} items)" if isinstance(value, list) else "(nested object)"
                            else:
                                value_str = str(value) if value is not None else ''
                            # Escape pipe characters
                            key_str = str(key).replace('|', '\\|')
                            value_str = value_str.replace('|', '\\|')
                            lines.append(f'| {key_str} | {value_str} |')
                        return '\n'.join(lines)
                    
                    # Update existing Table components based on normalized data
                    if tables_list:
                        log.info(f'Processing {len(tables_list)} tables from normalized.json')
                        for idx, table_data in enumerate(tables_list):
                            if not isinstance(table_data, dict):
                                log.warning(f'Table {idx+1} is not a dict, skipping')
                                continue
                                
                            # Get or generate caption
                            target_caption = table_data.get('caption', '')
                            if not target_caption:
                                # Try to create a meaningful caption from keys or title
                                if 'name' in table_data:
                                    target_caption = str(table_data['name'])
                                elif 'title' in table_data:
                                    target_caption = str(table_data['title'])
                                else:
                                    # Use the key from normalized_data that this came from
                                    target_caption = f'Data Table {idx+1}'
                            
                            log.debug(f'Processing table {idx+1}: caption="{target_caption}", data keys: {list(table_data.keys())}')
                            
                            # Convert data to table format if not already in table format
                            table_text = table_data.get('text', '')
                            if not table_text:
                                table_text = dict_to_table_markdown(table_data, target_caption)
                            
                            # Find existing Table component by caption
                            table_component = None
                            
                            # Check flattened components first (most reliable)
                            for component in report.flattened_components:
                                if component.type == 'TableComponent':
                                    component_caption = getattr(component, 'caption', '') or ''
                                    if component_caption == target_caption:
                                        table_component = component
                                        break
                            
                            if table_component:
                                # Update existing table directly
                                table_component._model['text'] = table_text
                                table_component._model['caption'] = target_caption
                                table_component.save()
                                components_updated = True
                                # Check if component is already in JSON - if not, add it
                                if not component_exists_in_json(str(table_component.id), components_json):
                                    log.debug(f'Table component {table_component.id} exists but not in JSON, adding it')
                                    components_json.append({
                                        'uuid': str(table_component.id),
                                        'type': 'TableComponent'
                                    })
                                    components_updated = True
                            else:
                                # Create new Table component
                                log.debug(f'Creating new table component')
                                table_component = BaseComponent.new(
                                    componentType='TableComponent',
                                    reportParent=report_id
                                )
                                table_component._model['text'] = table_text
                                table_component._model['caption'] = target_caption
                                table_component._model['name'] = table_data.get('name', target_caption)
                                table_component.save()
                                log.debug(f'Created table component: {table_component.id}')
                                
                                # Add new component to the JSON tree (at root level) only if it doesn't exist
                                if not component_exists_in_json(str(table_component.id), components_json):
                                    components_json.append({
                                        'uuid': str(table_component.id),
                                        'type': 'TableComponent'
                                    })
                                    components_updated = True
                                    log.debug(f'Added table to components_json, total components: {len(components_json)}')
                                else:
                                    log.debug(f'Table component {table_component.id} already exists in JSON, skipping')

                        log.info(f'Processed normalized.json: {len(tables_list)} tables')
                    else:
                        log.warning(f'Could not extract tables from normalized.json. Type: {type(normalized_data)}')
                except json.JSONDecodeError as e:
                    log.error(f'Invalid JSON in normalized.json: {e}')
                    response = HttpResponse(f'Invalid JSON in normalized.json: {e}')
                    response.status_code = 400
                    return response
                except Exception as e:
                    log.error(f'Error processing normalized.json: {e}')
                    import traceback
                    log.error(traceback.format_exc())
                    response = HttpResponse(f'Error processing normalized.json: {e}')
                    response.status_code = 500
                    return response

        # Process findings.json - populate findings
        if 'findings_json' in request.FILES:
            findings_file = request.FILES['findings_json']
            if findings_file.name == 'findings.json':
                try:
                    file_content = findings_file.read().decode('utf-8')
                    findings_data = json.loads(file_content)
                    log.info(f'Loaded findings.json: root type={type(findings_data).__name__}')
                    if isinstance(findings_data, dict):
                        log.info(f'  Top-level keys: {list(findings_data.keys())}')
                    
                    # Extract findings from findings_data - handle both list and dict formats
                    findings_list = None
                    if isinstance(findings_data, list):
                        findings_list = findings_data
                    elif isinstance(findings_data, dict):
                        # Check for categories array first (most common structure)
                        if 'categories' in findings_data:
                            if isinstance(findings_data['categories'], list):
                                # categories is an array - each category becomes a finding
                                log.info(f'Found categories array with {len(findings_data["categories"])} categories')
                                findings_list = []
                                for category in findings_data['categories']:
                                    if isinstance(category, dict):
                                        # Convert category to finding format
                                        category_finding = {}
                                        # Map category name to finding name
                                        category_finding['name'] = category.get('category') or category.get('name') or 'Unnamed Category'
                                        # Use severity if available
                                        if 'severity' in category:
                                            category_finding['severity'] = category['severity']
                                        # Combine description and detailed_description for the description field
                                        description_parts = []
                                        if category.get('description'):
                                            description_parts.append(category['description'])
                                        if category.get('detailed_description'):
                                            description_parts.append('\n\n' + category['detailed_description'])
                                        if description_parts:
                                            category_finding['description'] = '\n'.join(description_parts)
                                        # Convert key_risks to background or include in description
                                        if category.get('key_risks'):
                                            risks_text = 'Key Risks:\n' + '\n'.join(['- ' + risk for risk in category['key_risks']])
                                            if 'description' in category_finding:
                                                category_finding['description'] += '\n\n' + risks_text
                                            else:
                                                category_finding['description'] = risks_text
                                        # Convert recommendations to remediation
                                        if category.get('recommendations'):
                                            category_finding['remediation'] = '\n'.join(['- ' + rec for rec in category['recommendations']])
                                        
                                        # Extract and format affected resources
                                        affected_resources = []
                                        
                                        # Handle findings array (for exposed services, vulnerabilities, TLS/SSL issues)
                                        if category.get('findings') and isinstance(category['findings'], list):
                                            findings_array = category['findings']
                                            
                                            # Check what type of findings we have
                                            if findings_array and isinstance(findings_array[0], dict):
                                                first_finding = findings_array[0]
                                                
                                                # Exposed Services: hostname:port/service format
                                                if 'hostname' in first_finding and 'port' in first_finding:
                                                    for finding in findings_array:
                                                        hostname = finding.get('hostname', '')
                                                        port = finding.get('port', '')
                                                        service = finding.get('service', '')
                                                        if hostname and port:
                                                            resource_str = f"{hostname}:{port}"
                                                            if service:
                                                                resource_str += f" ({service})"
                                                            affected_resources.append(f"- {resource_str}")
                                                
                                                # TLS/SSL Issues: hostname with finding details
                                                elif 'hostname' in first_finding and 'finding' in first_finding:
                                                    unique_hosts = {}
                                                    for finding in findings_array:
                                                        hostname = finding.get('hostname', '')
                                                        finding_detail = finding.get('finding', '')
                                                        finding_id = finding.get('id', '')
                                                        if hostname:
                                                            if hostname not in unique_hosts:
                                                                unique_hosts[hostname] = []
                                                            detail_str = f"{hostname}"
                                                            if finding_id:
                                                                detail_str += f" - {finding_id}"
                                                            if finding_detail:
                                                                detail_str += f": {finding_detail}"
                                                            if detail_str not in unique_hosts[hostname]:
                                                                unique_hosts[hostname].append(detail_str)
                                                    
                                                    for hostname, details in sorted(unique_hosts.items()):
                                                        for detail in details:
                                                            affected_resources.append(f"- {detail}")
                                                
                                                # Vulnerabilities: hostname with title/CVE
                                                elif 'hostname' in first_finding and 'title' in first_finding:
                                                    for finding in findings_array:
                                                        hostname = finding.get('hostname', '')
                                                        title = finding.get('title', '')
                                                        cves = finding.get('cves', [])
                                                        resource_str = f"- {hostname}"
                                                        if title:
                                                            resource_str += f": {title}"
                                                        if cves:
                                                            resource_str += f" ({', '.join(cves)})"
                                                        affected_resources.append(resource_str)
                                        
                                        # Handle repositories_affected (for Git-related findings)
                                        if category.get('repositories_affected'):
                                            repo_count = category['repositories_affected']
                                            affected_resources.append(f"- **Repositories Affected:** {repo_count}")
                                            
                                            # Add top secret types if available
                                            if category.get('top_secret_types'):
                                                affected_resources.append("\n**Top Secret Types:**")
                                                for secret_type in category['top_secret_types']:
                                                    type_name = secret_type.get('type', 'Unknown')
                                                    type_count = secret_type.get('count', 0)
                                                    affected_resources.append(f"  - {type_name}: {type_count}")
                                            
                                            # Add severity breakdown if available
                                            if category.get('severity_breakdown'):
                                                affected_resources.append("\n**Severity Breakdown:**")
                                                for severity, count in category['severity_breakdown'].items():
                                                    affected_resources.append(f"  - {severity}: {count}")
                                        
                                        # Handle CDN breakdown
                                        if category.get('cdn_breakdown'):
                                            affected_resources.append("**CDN Types:**")
                                            for cdn_name, cdn_count in category['cdn_breakdown'].items():
                                                affected_resources.append(f"- {cdn_name}: {cdn_count}")
                                        
                                        # Set affectedResources if we collected any
                                        if affected_resources:
                                            category_finding['affectedResources'] = '\n'.join(affected_resources)
                                        
                                        # Add count information to description if available (if not already in affectedResources)
                                        if category.get('count') and not affected_resources:
                                            count_info = f"\n\nAffected Items: {category['count']}"
                                            if 'description' in category_finding:
                                                category_finding['description'] += count_info
                                            else:
                                                category_finding['description'] = count_info
                                        
                                        findings_list.append(category_finding)
                                log.info(f'Converted {len(findings_list)} categories to findings')
                            elif isinstance(findings_data['categories'], dict):
                                # Extract findings from categories dict structure (legacy support)
                                all_findings = []
                                
                                def extract_findings_recursive(data, category_path=""):
                                    """Recursively extract findings from nested category structures"""
                                    findings = []
                                    if isinstance(data, list):
                                        # This is a list of findings
                                        for finding in data:
                                            if isinstance(finding, dict):
                                                if category_path:
                                                    finding['_category_path'] = category_path
                                                findings.append(finding)
                                    elif isinstance(data, dict):
                                        # Check if this dict itself looks like a finding (has finding-like keys)
                                        finding_keys = ['name', 'title', 'description', 'severity', 'cvss', 'vector', 'finding']
                                        if any(key in data for key in finding_keys):
                                            # This dict is a finding
                                            if category_path:
                                                data['_category_path'] = category_path
                                            findings.append(data)
                                        elif 'findings' in data:
                                            # Has a 'findings' key
                                            if isinstance(data['findings'], list):
                                                for finding in data['findings']:
                                                    if isinstance(finding, dict):
                                                        finding_path = category_path
                                                        if finding_path:
                                                            finding_path += " / "
                                                        finding_path += data.get('name', '')
                                                        if finding_path:
                                                            finding['_category_path'] = finding_path
                                                        findings.append(finding)
                                            elif isinstance(data['findings'], dict):
                                                # Recursively process nested findings
                                                findings.extend(extract_findings_recursive(data['findings'], category_path))
                                        else:
                                            # Process each value in the dict
                                            for key, value in data.items():
                                                if isinstance(value, (dict, list)):
                                                    new_path = category_path
                                                    if new_path:
                                                        new_path += " / "
                                                    new_path += key
                                                    findings.extend(extract_findings_recursive(value, new_path))
                                    return findings
                                
                                all_findings = extract_findings_recursive(findings_data['categories'])
                                log.info(f'Extracted {len(all_findings)} findings from categories dict')
                                if all_findings:
                                    findings_list = all_findings
                        # Try common keys for findings (if not already set)
                        elif 'findings' in findings_data and isinstance(findings_data['findings'], list):
                            findings_list = findings_data['findings']
                        elif 'data' in findings_data and isinstance(findings_data['data'], list):
                            findings_list = findings_data['data']
                        else:
                            # If it's a dict, try to use values that are dicts with finding-like structure
                            # (have 'name' or 'title' keys) - but skip 'summary' and other metadata
                            potential_findings = []
                            for key, value in findings_data.items():
                                # Skip summary and other metadata fields
                                if key in ['summary', 'generated_at', 'metadata']:
                                    continue
                                if isinstance(value, dict) and ('name' in value or 'title' in value or 'category' in value):
                                    potential_findings.append(value)
                            if potential_findings:
                                findings_list = potential_findings
                            else:
                                # Last resort: treat each dict value as a potential finding (excluding summary)
                                findings_list = [v for k, v in findings_data.items() 
                                                if isinstance(v, dict) and k not in ['summary', 'generated_at', 'metadata']]
                    
                    # Find or create Findings component
                    findings_component = None
                    finding_group = None
                    
                    # First, try to find existing FindingsList component
                    for component in report.flattened_components:
                        if component.type == 'FindingsList':
                            findings_component = component
                            # Get the finding group from the component if it exists
                            if hasattr(component, 'findingGroup') and component.findingGroup:
                                try:
                                    finding_group = BaseFindingGroup.get_child(id=component.findingGroup)
                                except EngagementFgroupError:
                                    pass
                            break
                    
                    # If no finding group from component, try to get the first finding group from engagement
                    if not finding_group:
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
                    
                    # Link FindingsList component to finding group if it exists but isn't linked
                    if findings_component and not findings_component.findingGroup:
                        findings_component._model['findingGroup'] = str(finding_group.id)
                        findings_component.save()
                        components_updated = True
                    
                    # Process findings_list - expect a list of finding objects
                    if findings_list and finding_group:
                        log.info(f'Processing {len(findings_list)} findings from findings.json (finding group: {finding_group.id})')
                        for idx, finding_data in enumerate(findings_list):
                            if not isinstance(finding_data, dict):
                                log.warning(f'Skipping finding that is not a dict: {type(finding_data)}')
                                continue
                            
                            log.debug(f'Processing finding {idx+1}/{len(findings_list)}: keys={list(finding_data.keys())}')
                            
                            # Create the finding using the automated helper function
                            try:
                                from writehat.lib.engagementFinding import create_finding_from_data
                                finding = create_finding_from_data(
                                    finding_data=finding_data,
                                    finding_group=finding_group
                                )
                                # Track the finding UUID to add to report
                                created_finding_uuids.append(str(finding.id))
                            except Exception as e:
                                log.error(f'Error creating finding: {e}')
                                import traceback
                                log.error(traceback.format_exc())
                                # Continue with other findings even if one fails
                                continue
                    else:
                        if not findings_list:
                            log.warning(f'Could not extract findings from findings.json. Type: {type(findings_data)}')
                        if not finding_group:
                            log.warning('No finding group available for findings.json')
                    
                    log.info(f'Processed findings.json, created {len(created_finding_uuids)} findings')
                    # Verify findings are accessible from the engagement
                    if created_finding_uuids and finding_group:
                        from writehat.lib.engagement import Engagement
                        engagement = Engagement.get(id=engagement_id)
                        total_findings = sum(len(fg.findings) for fg in engagement.fgroups)
                        log.info(f'Engagement now has {total_findings} total findings across {len(engagement.fgroups)} finding groups')
                except json.JSONDecodeError as e:
                    log.error(f'Invalid JSON in findings.json: {e}')
                    response = HttpResponse(f'Invalid JSON in findings.json: {e}')
                    response.status_code = 400
                    return response
                except Exception as e:
                    log.error(f'Error processing findings.json: {e}')
                    import traceback
                    log.error(traceback.format_exc())
                    # Don't fail the whole request if findings processing fails

        # Process executive_summary.md - populate Executive Summary Container
        if 'executive_summary_md' in request.FILES:
            executive_file = request.FILES['executive_summary_md']
            if executive_file.name == 'executive_summary.md':
                executive_content = executive_file.read().decode('utf-8')
                
                # Find or create Container component named "Executive Summary"
                exec_summary_container = None
                exec_summary_markdown = None
                container_in_json = None
                
                # First, try to find existing Container named "Executive Summary"
                for component in report.flattened_components:
                    if component.type == 'ContainerComponent' and component.name == 'Executive Summary':
                        exec_summary_container = component
                        # Check if it has a Markdown child
                        if hasattr(component, 'children') and component.children:
                            for child in component.children:
                                if child.type == 'MarkdownComponent':
                                    exec_summary_markdown = child
                                    break
                        break
                
                # Find the container in the JSON structure
                def find_container_in_json(components):
                    for comp in components:
                        if comp.get('uuid') == str(exec_summary_container.id) if exec_summary_container else None:
                            return comp
                        if 'children' in comp:
                            found = find_container_in_json(comp['children'])
                            if found:
                                return found
                    return None
                
                if exec_summary_container:
                    container_in_json = find_container_in_json(components_json)
                    
                    # Update existing container's markdown child or create one
                    if exec_summary_markdown:
                        # Update existing markdown component directly
                        exec_summary_markdown._model['text'] = executive_content
                        exec_summary_markdown.save()
                    else:
                        # Create Markdown component inside container
                        exec_summary_markdown = BaseComponent.new(
                            componentType='MarkdownComponent',
                            reportParent=report_id,
                            databaseParent=str(exec_summary_container.id)
                        )
                        exec_summary_markdown._model['text'] = executive_content
                        exec_summary_markdown._model['name'] = 'Executive Summary'
                        exec_summary_markdown.save()
                        
                        # Add to container's children in JSON structure
                        if container_in_json:
                            if 'children' not in container_in_json:
                                container_in_json['children'] = []
                            container_in_json['children'].append({
                                'uuid': str(exec_summary_markdown.id),
                                'type': 'MarkdownComponent'
                            })
                        components_updated = True
                else:
                    # Create new Container with Markdown child
                    exec_summary_container = BaseComponent.new(
                        componentType='ContainerComponent',
                        reportParent=report_id
                    )
                    exec_summary_container._model['name'] = 'Executive Summary'
                    exec_summary_container.save()
                    
                    exec_summary_markdown = BaseComponent.new(
                        componentType='MarkdownComponent',
                        reportParent=report_id,
                        databaseParent=str(exec_summary_container.id)
                    )
                    exec_summary_markdown._model['text'] = executive_content
                    exec_summary_markdown._model['name'] = 'Executive Summary'
                    exec_summary_markdown.save()
                    
                    # Add to report components - append to root level only if it doesn't exist
                    if not component_exists_in_json(str(exec_summary_container.id), components_json):
                        components_json.append({
                            'uuid': str(exec_summary_container.id),
                            'type': 'ContainerComponent',
                            'children': [{
                                'uuid': str(exec_summary_markdown.id),
                                'type': 'MarkdownComponent'
                            }]
                        })
                        components_updated = True
                        log.info('Processed executive_summary.md')
                    else:
                        log.info('Executive Summary container already exists in JSON, skipping append')

        # Final deduplication pass - remove duplicate UUIDs from components_json
        def deduplicate_components(components_list):
            """Recursively remove duplicate components by UUID"""
            seen_uuids = set()
            deduplicated = []
            for comp in components_list:
                comp_uuid = comp.get('uuid')
                if comp_uuid and comp_uuid in seen_uuids:
                    log.warning(f'Found duplicate component UUID {comp_uuid} ({comp.get("type", "unknown")}), removing duplicate')
                    continue
                if comp_uuid:
                    seen_uuids.add(comp_uuid)
                # Recursively deduplicate children
                if 'children' in comp and comp['children']:
                    comp['children'] = deduplicate_components(comp['children'])
                deduplicated.append(comp)
            return deduplicated
        
        if components_updated:
            original_count = len(get_all_component_uuids(components_json))
            components_json = deduplicate_components(components_json)
            deduplicated_count = len(get_all_component_uuids(components_json))
            if original_count != deduplicated_count:
                log.info(f'Deduplicated components: {original_count} -> {deduplicated_count} unique components')
        
        # Collect all finding UUIDs (existing + newly created)
        findings_to_update = None
        if created_finding_uuids:
            all_finding_uuids = existing_finding_uuids + created_finding_uuids
            log.info(f'Adding {len(created_finding_uuids)} new findings to report. Total findings: {len(all_finding_uuids)}')
            findings_to_update = all_finding_uuids  # Already strings
        
        # Update the report with the complete component tree and findings if we made changes
        if components_updated or findings_to_update:
            if findings_to_update:
                log.info(f'Updating report with {len(findings_to_update)} findings')
            if components_updated:
                log.info(f'Updating report with {len(components_json)} components')
            # Always pass componentJSON (either updated or original) if we're updating findings
            # Otherwise only pass if components_updated is True
            if components_updated:
                report.update(componentJSON=components_json, findings=findings_to_update)
            elif findings_to_update:
                # Only update findings, components stay the same
                report.update(findings=findings_to_update)
            # Force a refresh of the report's component cache
            report._component_objects = None
            log.info('Report updated successfully')

        response = HttpResponse('Files uploaded and processed successfully')
        response.status_code = 200
        return response

    except Exception as e:
        log.error(f'Error in engagementFileUpload: {e}')
        import traceback
        log.error(traceback.format_exc())
        response = HttpResponse(f'Error processing files: {e}')
        response.status_code = 500
        return response


# Displays the list of existing reports and allows for the creation of a new one
@csrf_protect
@require_http_methods(['GET', 'POST'])
def customersList(request):

    customers = Customer.objects.all()

    if request.method == 'GET':
        log.debug(f'customersList (GET) called')
        return render(request,"pages/customers.html",{'customers': customers})

    elif request.method == 'POST':
        log.debug(f'customersList (POST) called')
        return JsonResponse([str(c.id) for c in customers])


@csrf_protect
@require_http_methods(['POST'])
def customerCreate(request):
    
    c = Customer()
    c.updateFromPostData(request.POST)
    c.save()
    response = HttpResponse(escape(c.id))
    response.status_code = 200
    log.debug(f'customerCreate called, resulting customer UUID: {c.id}')

    return response


# Edit an existing "findings database" entry. Should be very similiar to findingsView, except with all the editing tools loaded.
@csrf_protect
@require_http_methods(['POST', 'GET'])
def customerEdit(request, uuid):

    customer = Customer.get(id=uuid)
    if request.method == 'GET':
        customer.populateForm()
        return render(request,"pages/customerEdit.html", {'customer': customer})

    elif request.method == 'POST':
        customer.updateFromPostData(request.POST)
        customer.save()
        return HttpResponse(customer.id)


@csrf_protect
@require_http_methods(['POST'])
def customerDelete(request, uuid):

    log.debug(f'Deleting customer with {uuid}')

    try:
        customer = Customer.get(id=uuid)
        log.debug(customer._json)
        customer.delete()
        return HttpResponse(customer.id)

    except Customer.DoesNotExist:
        log.debug(f'No customer found with ID {uuid}')
        response.status_code = 400
        return response



@require_http_methods(['GET'])
def templatesList(request):

    savedReports = []
    for r in SavedReport.objects.all():
        if r.modifiedDate:
            savedReport = SavedReport.get(id=r.id)
            savedReports.append(savedReport)

    pageTemplates = list(PageTemplate.objects.all())

    return render(
        request,
        "pages/savedReports.html",
        {
            'reports': savedReports,
            'pages': pageTemplates
        }
    )



# Saves a current report to a SavedReport 
@csrf_protect
@require_http_methods(['POST'])
def reportSaveToTemplate(request,uuid):

    # response = HttpResponse()
    #try:
    report = Report.objects.get(id=uuid)
    log.debug(f"reportSaveToTemplate; report.id: {report.id}")
    savedReport = report.clone(destinationClass=SavedReport)
    savedReport.simpleRedact(report.engagement.customer)
    savedReport.save()

    return HttpResponse(savedReport.id)

    #except Report.DoesNotExist:
    #log.debug(f'No report found with ID {uuid}')
    #response.status_code = 400
    #return response


# Clones a SavedReport to an engagement
@csrf_protect 
@require_http_methods(['POST'])
def reportCreateFromTemplate(request,uuid):

    engagementID = str(uuidlib.UUID(request.POST['engagementID']))
    savedReport = SavedReport.objects.get(id=uuid)
    log.debug(f"reportCreateFromTemplate; savedReport.id: {savedReport.id}")
    report = savedReport.clone(name=savedReport.name, destinationClass=Report)
    report.engagementParent = engagementID
    report.save()

    return HttpResponse(report.id)


# Loads the page where a user can select the components they want in their new reports (for templates)
@require_http_methods(['GET'])
def templateNew(request):
    log.debug(f"templateNew called;")
    componentList = settings.VALID_COMPONENTS
    return render(
        request,"pages/savedReportNew.html",
        {
            "componentsList": componentList,
            "report": BaseReport
        }
    )


      # Loads the page where a user can select the components they want in their new reports

@csrf_protect
@require_http_methods(['POST'])
def templateCreate(request):
    return reportCreate(request, None, fromTemplate=True)

# Given a reportID, get the JSON object containing the list of associated components
@require_http_methods(['GET'])
def templateEdit(request,uuid):
    log.debug("templateEdit() called; UUID: {0}".format(uuid))
    log.debug("Found {0} available components".format(len(settings.VALID_COMPONENTS)))
    savedReport = SavedReport.get(id=uuid)
    savedReport.populateForm()

    #print(savedReport._components)
    #print(savedReport)

    return render(request,"pages/savedReportEdit.html", \
        {
            "report": savedReport,
            "reportname": savedReport.name,
            "componentsList": settings.VALID_COMPONENTS
        })


# Page Templates

@require_http_methods(['GET'])
def pageNew(request):

    pageTemplate = PageTemplate()

    response = render(
        request,
        'pages/pageTemplateNew.html',
        {
            'page': pageTemplate
        }
    )

    return response

@csrf_protect
@require_http_methods(['POST'])
def pageCreate(request):
    
    pageTemplate = PageTemplate()
    form = pageTemplate.formClass(request.POST)
    pageTemplate.updateFromForm(form)
    pageTemplate.save()
    return HttpResponse(pageTemplate.id)


@csrf_protect
def pageEdit(request, uuid):
    
    pageTemplate = PageTemplate.get(id=uuid)
    pageTemplate.populateForm()

    response = render(
        request,
        'pages/pageTemplateEdit.html',
        {
            'page': pageTemplate
        }
    )

    return response

@csrf_protect
def pageDelete(request, uuid):
    
    pageTemplate = PageTemplate.get(id=uuid)
    pageTemplate.delete()
    return HttpResponse(f'Successfully deleted page "{escape(pageTemplate.name)}"')

@csrf_protect
def pageUpdate(request, uuid):
    
    pageTemplate = PageTemplate.get(id=uuid)
    form = pageTemplate.formClass(request.POST)
    pageTemplate.updateFromForm(form)
    pageTemplate.save()
    return HttpResponse(f'Successfully updated page "{escape(pageTemplate.name)}"')

@csrf_protect
def pageClone(request, uuid):

    page = PageTemplate.get(id=uuid)
    clonedPage = page.clone()
    clonedPage.save()
    log.debug("{0}".format(clonedPage))




    return HttpResponse(clonedPage.id)




# Admin tools

@user_passes_test(lambda u: u.is_superuser)
@require_http_methods(['GET'])
def admintoolsHome(request):
    log.debug(f"adminHome called")
    return render(request,"pages/admin.html",{})


@user_passes_test(lambda u: u.is_superuser)
@require_http_methods(['GET'])
def admintoolsBackup(request):
    log.debug(f"admintoolsBackup called")
    zipfile = dbExport()
    response = HttpResponse()
    response.write(zipfile)
    response['Content-Disposition'] = 'attachment; filename={0}'.format('backup.zip')
    return response



@user_passes_test(lambda u: u.is_superuser)
@require_http_methods(['POST'])
@csrf_protect
def admintoolsRestore(request):
    log.debug(f"admintoolsRestore called")
    if request.FILES['file']:
        uploadedFile = request.FILES['file']
        resultText,resultCode = dbImport(uploadedFile)
        if resultCode == 1:
            response = HttpResponse('OK')
            response.status_code = 200
        elif resultCode == 2:
            response = HttpResponse(escape(resultText))
            response.status_code = 400
        else:
            response = HttpResponse(escape(resultText))
            response.status_code = 400
        return response  


    else:
        response = HttpResponse('Missing backup file')
        response.status_code = 400
        return response  


