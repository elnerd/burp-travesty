import hashlib

from burp import *
from burp import IBurpExtender, IScannerCheck, IRequestInfo, IScanIssue
from fuzzywuzzy import fuzz
import copy

callbacks = None  # type: IBurpExtenderCallbacks
helpers = None  # type: IExtensionHelpers




## Burp Exceptions Fix magic code
import sys, functools, inspect, traceback

def decorate_function(original_function):
    @functools.wraps(original_function)
    def decorated_function(*args, **kwargs):
        try:
            return original_function(*args, **kwargs)
        except:
            sys.stdout.write('\n\n*** PYTHON EXCEPTION\n')
            traceback.print_exc(file=sys.stdout)
            raise
    return decorated_function

def FixBurpExceptionsForClass(cls):
    for name, method in inspect.getmembers(cls, inspect.ismethod):
        setattr(cls, name, decorate_function(method))
    return cls

def FixBurpExceptions():
    for name, cls in inspect.getmembers(sys.modules['__main__'], predicate=inspect.isclass):
        FixBurpExceptionsForClass(cls)

# -- Scan Issue Skeleton

# noinspection PyClassHasNoInit
class Confidence:
    CERTAIN = "Certain"
    FIRM = "Firm"
    TENTATIVE = "Tentative"


# noinspection PyClassHasNoInit
class Severity:
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Information"
    FP = "False positive"


class IssueTypes:
    # see https://portswigger.net/kb/issues
    pass


class BaseScanIssue(IScanIssue):
    """
    Base Scan Issue to define predefined scan issues
    """
    name = "Hacker memory underrun"
    description = "The hacker forgot to update the description"
    detail = "Details details"
    issue_background = "hello"
    remediation_background = "You should fix this"
    remediation_details = "This is how you fix this"
    severity = Severity.FP
    confidence = Confidence.TENTATIVE
    issue_type = 0x08000000  # Extension generated issue - see https://portswigger.net/kb/issues
    http_messages = []
    http_service = None
    url = None

    def getHttpMessages(self):  # type: () -> List[IHttpRequestResponseWithMarkers]
        return self.http_messages

    def getIssueDetail(self):
        return self.description

    def getHttpService(self):  # type: () -> IHttpService
        return self.http_service

    def getUrl(self):
        return self.url

    def getIssueName(self):
        return self.name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.severity

    def getConfidence(self):
        return self.confidence

    def getIssueBackground(self):
        return self.issue_background

    def getRemediationBackground(self):
        return self.remediation_background


    def getRemediationDetail(self):
        return self.remediation_details

def generate_test_paths(path):
    # Check if path contains a file
    if not path.endswith("/"):
        filename = path.split("/")[-1]
        if "." in filename:
            print "stripping filename"
            path = "/".join(path.split("/")[:-1])

    parts = path.split("/")
    attack_patterns = [
        "/..",          # vanilla
        "/..;1=1",      # nginx normalized paths, but do not normalize paths with params
        "/%2e%2e",      # url encoded, know this is good
        #"/%252e%252e"  # double url encoding, remove if not good...
        #".."            # nginx alias. i.e. /dir../ - removed, generates too much noise
    ]
    attack_patterns_pathend = ["/", "%2f"]  # , "%252f", "\\"] extra that might work somewhere, but too noisy
    for i in range(len(parts), 0, -1):
        if parts[i-1] == '':
            continue
        #print "fetching baseline", "/".join(parts[0:i-1])
        #print "fetching traverse", "/".join(parts[0:i] + [".."])
        baseline_path = "/".join(parts[0:i-1]) + "/"
        print "== baseline %s" % baseline_path
        up_path = "/".join(parts[0:i])
        dummy_path = hashlib.md5(str(hash(up_path))).hexdigest()[0:6]
        for traverse in attack_patterns:
            for pathend in attack_patterns_pathend:
                yield baseline_path, up_path, up_path + traverse + pathend, up_path + "/" + dummy_path #"/".join(up_path + [traverse, pathend])

def cached_baseline(fn):
    """
    Simple cache to prevent repeating baseline requests
    HACK: This change the return signature for get_baseline
    """
    cache = dict()

    def do(http_service, request_data, attempts):
        request_info = helpers.analyzeRequest(http_service, request_data)
        url = request_info.getUrl()
        key = "%s://%s%s" % (url.getProtocol(), url.getAuthority(), url.getPath())  # scheme://host/path
        print "cached baseline key is %s" % key
        if key not in cache:
            res = fn(http_service, request_data, attempts)
            cache[key] = res # Todo, convert to Stored Requests to save memory

        is_stable, all_reqresp = cache[key]
        if len(all_reqresp) >= 2:
            fuzz_ratio = fuzz.ratio(all_reqresp[0].getResponse(), all_reqresp[1].getResponse())
        else:
            fuzz_ratio = None
        return is_stable, fuzz_ratio, helpers.analyzeResponseVariations(map(lambda reqresp: reqresp.getResponse(), all_reqresp)), all_reqresp[0]

    return do

@cached_baseline
def get_baseline(http_service, request_data, attempts=3):
    # type: (IHttpService, array, int) -> (bool, List[IHttpRequestResponse])
    """
    Repeat a request until there are no variations between the responses, or until we run out of attempts
    Returns a (is_stable, variations), where is_stable is True if we found a stable baseline. False otherwise.
    variations is a IResponseVariations object


    """

    variations = None
    all_reqresp = []
    last_variations = last_invariations = None
    this_variations = this_invariations = None

    print "== baselining with %d attempts==" % attempts
    while attempts >= 0:
        print "attempts = %d" % attempts
        reqresp = callbacks.makeHttpRequest(http_service, request_data)
        all_reqresp.append(reqresp)
        if variations is None:
            variations = helpers.analyzeResponseVariations([reqresp.getResponse()])
        else:
            variations.updateWith(reqresp.getResponse())

        this_variations = set(variations.getVariantAttributes())
        this_invarations = set(variations.getInvariantAttributes())

        print "this_variations:", this_variations
        print "this_invariations:", this_invarations

        if len(this_variations) == 0:  # no variations, found a good baseline
            print "found good baseline"
            return True, all_reqresp

        if last_variations is None and last_invariations is None:
            # First round
            last_variations = this_variations
            last_invariations = this_invarations
            attempts -= 1
            continue

        if last_variations == this_variations and last_invariations == last_variations:
            # No new variations / invariations
            print "found good baseline"
            return True, all_reqresp

        print "no baseline found in this round"
        attempts -= 1
        last_variations = this_variations
        last_invariations = this_invarations

    # Could not find a stable baseline and run out of attempts to find one
    return False, all_reqresp

def create_issue(baseHttpRequestResponse, parent_reqresp, attack_reqresp, parent_path, attack_path, base_variations, new_variations, is_base_stable):
    issue = BaseScanIssue()
    issue.name = "Path Traversal"
    issue.http_service = baseHttpRequestResponse.getHttpService()
    issue.description = """\
        It seems like %s and %s respond with two different pages.<br/>
        This indicate that the application is vulnerable to path-traversal attacks.<br/>
        <br/>
        The baseline request had the following variations: %s<br/>
        The traversal request had the following variations: %s<br/>""" % (parent_path, attack_path, base_variations, new_variations)
    issue.http_messages = [parent_reqresp, attack_reqresp]
    issue.severity = Severity.MEDIUM
    issue.confidence = Confidence.TENTATIVE

    request_info = helpers.analyzeRequest(baseHttpRequestResponse.getHttpService(), baseHttpRequestResponse.getRequest())
    issue.url = request_info.getUrl()
    return issue


class Travesty(IScannerCheck):
    def __init__(self):
        self.attack_cache = set()  # used to prevent repeated attacks

    def doActiveScan(self, baseRequestResponse, insertionPoint):  # type: (IHttpRequestResponse, IScannerInsertionPoint) -> List[IScanIssue]
        base_request = baseRequestResponse.getRequest()
        request_info = helpers.analyzeRequest(baseRequestResponse.getHttpService(), base_request)  # type: IRequestInfo

        if request_info.getMethod() != "GET":
            # Change request_method to GET
            method_insertion_point = helpers.makeScannerInsertionPoint("PATH", baseRequestResponse.getRequest(), 0, len(request_info.getMethod()))
            base_request = method_insertion_point.buildRequest(helpers.stringToBytes("GET"))
            request_info = helpers.analyzeRequest(baseRequestResponse.getHttpService(), base_request)  # update request_info as we have changed the request

        # Create a new insertion point
        request_method, request_uri, _ = request_info.getHeaders()[0].split()
        start_pos = len(request_method) + 1
        end_pos = start_pos + len(request_uri)
        insertion_point = helpers.makeScannerInsertionPoint("PATH", base_request, start_pos, end_pos)

        if "?" in request_uri:
            path = request_uri.split("?", 1)[0]
        else:
            path = request_uri

        # Attack
        for parent_path, child_path, attack_path, dummy_path in generate_test_paths(path):
            url = request_info.getUrl()
            key = "%s:%s%s" % (url.getProtocol(), url.getAuthority(), attack_path)
            if key not in self.attack_cache:
                self.attack_cache.add(key)
            else:
                # Tested before, ignore
                continue

            print "creating baseline for path:", parent_path
            parent_request_data = insertion_point.buildRequest(helpers.stringToBytes(parent_path))
            is_baseline_stable, baseline_fuzz_ratio, variations, parent_reqresp = get_baseline(baseRequestResponse.getHttpService(), parent_request_data, attempts=3)
            print "requesting path-traversal path:", attack_path
            attack_request_data = insertion_point.buildRequest(helpers.stringToBytes(attack_path))
            attack_reqresp = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), attack_request_data
            )

            base_variations = set(variations.getVariantAttributes())
            base_invariations = set(variations.getInvariantAttributes())
            print "Base Variations:", base_variations
            print "Base Invariations:", base_invariations
            parent_resp_info = helpers.analyzeResponse(parent_reqresp.getResponse())  # type: IResponseInfo
            parent_resp_body = parent_reqresp.getResponse()[parent_resp_info.getBodyOffset():]

            attack_resp_info = helpers.analyzeResponse(attack_reqresp.getResponse())  # type: IResponseInfo
            attack_resp_body = attack_reqresp.getResponse()[attack_resp_info.getBodyOffset():]


            # False Positive - Ignored variations
            ignored_variations = {u"set_cookie_names"}
            filtered_variations = base_variations - ignored_variations
            if len(base_variations - ignored_variations) == 0:
                print "FP filter: not enough variations after filtering uninteresting variations"
                continue

            # False Positive - Ignored status_codes
            ignored_status_codes = [302, 404]
            status_code = attack_resp_info.getStatusCode()
            print "STATUS CODE:", status_code, type(status_code), status_code in ignored_status_codes
            if attack_resp_info.getStatusCode() in ignored_status_codes:
                print "FP filter: ignored status codes [%d]" % (attack_resp_info.getStatusCode())
                continue


            # False positive - body is equal

            if parent_resp_body == attack_resp_body:
                print "FP filter: body is equal"
                continue

            # False positive - experimental - levenshtein distance between baseline response and attack response
            FUZZ_RATIO_MAX_INCREASE = 1.10
            if baseline_fuzz_ratio is not None:
                if fuzz.ratio(parent_reqresp.getResponse(), attack_reqresp.getResponse())/100.0 > (baseline_fuzz_ratio/100.0)*FUZZ_RATIO_MAX_INCREASE:
                    print "FP filter: levenshtein says no"
                    continue

            # False positive - check if dummy response is too similar to attack response
            print "creating fp-baseline path", dummy_path
            dummy_request_data = insertion_point.buildRequest(helpers.stringToBytes(dummy_path))
            is_dummy_stable, dummy_fuzz_ratio, dummy_variations, dummy_reqresp = get_baseline(baseRequestResponse.getHttpService(), dummy_request_data, attempts=3)

            dummy_variations.updateWith([attack_reqresp.getResponse()])
            dum_variations = set(dummy_variations.getVariantAttributes())

            if len(set(dummy_variations.getVari) - ignored_variations) == 0:
                print "FP: no variations between dummy response attack response"
                continue

            dummy_resp_info = helpers.analyzeResponse(dummy_reqresp.getResponse())
            if dummy_reqresp.getResponse()[dummy_resp_info.getBodyOffset():] == attack_resp_body:
                print "FP: dummy response and attack response body is equal"
                continue


            variations.updateWith([attack_reqresp.getResponse()])
            if is_baseline_stable:
                new_variations = set(variations.getVariantAttributes())
                if base_variations != new_variations:
                    # Found issue
                    print "Possible path-traversal found with path (stable baseline)", attack_path
                    issue = create_issue(baseRequestResponse, parent_reqresp, attack_reqresp, parent_path, attack_path, base_variations, new_variations, is_baseline_stable)
                    return [issue]
            else:
                # Remove the variations that was found in baseline from the path-traversal response
                new_variations = set(variations.getVariantAttributes())
                new_variations -= base_variations
                if len(new_variations) > 0:
                    # Found issue
                    print "Possible path-traversal found with path (unstable baseline)", attack_path
                    print "Variations:", new_variations
                    print "Base variations:", base_variations
                    issue = create_issue(baseRequestResponse, parent_reqresp, attack_reqresp, parent_path, attack_path, base_variations, new_variations, is_baseline_stable)
                    return [issue]
        return []

    def doPassiveScan(self, baseRequestResponse):  # type: (IHttpRequestResponse) -> List[IScanIssue]
        return []

    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        if existing_issue.getIssueName() == new_issue.getIssueName():
            if existing_issue.getUrl() == new_issue.getUrl():
                return -1
        return 0



class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, _callbacks):  # type: (IBurpExtenderCallbacks) -> None
        global callbacks, helpers
        callbacks = _callbacks
        helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Travesty")
        callbacks.registerScannerCheck(Travesty())
        FixBurpExceptions()