"""
Salt execution module
"""
import logging
from enum import Enum
import copy
from urllib.parse import urlencode as _urlencode
from datetime import datetime
from time import sleep

from salt.exceptions import CommandExecutionError, SaltInvocationError
from collections.abc import Mapping
from salt.exceptions import CommandExecutionError, InvalidConfigError
from salt.ext import six  # pylint: disable=3rd-party-module-not-gated
import salt.utils.http
import salt.utils.json

log = logging.getLogger(__name__)



CATALOG_HOST = "https://gacatalog.apps.rapyuta.io"
PROVISION_API_PATH = CATALOG_HOST + "/v2/service_instances"

CORE_API_HOST = "https://gaapiserver.apps.rapyuta.io"
DEVICE_API_BASE_PATH = CORE_API_HOST + "/api/device-manager/v0/"
DEVICE_API_PATH = DEVICE_API_BASE_PATH + "devices/"
DEVICE_COMMAND_API_PATH = DEVICE_API_BASE_PATH + 'cmd/'
DEVICE_METRIC_API_PATH = DEVICE_API_BASE_PATH + 'metrics/'
DEVICE_TOPIC_API_PATH = DEVICE_API_BASE_PATH + 'topics/'
DEVICE_LABEL_API_PATH = DEVICE_API_BASE_PATH + 'labels/'

class Phase(Enum):
    def __str__(self):
        return str(self.value)

    INPROGRESS = 'In progress'
    PROVISIONING = 'Provisioning'
    SUCCEEDED = 'Succeeded'
    FAILED_TO_START = 'Failed to start'
    PARTIALLY_DEPROVISIONED = 'Partially deprovisioned'
    STOPPED = 'Deployment stopped'

POSITIVE_PHASES = [
    Phase.INPROGRESS,
    Phase.PROVISIONING,
    Phase.SUCCEEDED,
]

class Status(Enum):
    def __str__(self):
        return str(self.value)

    RUNNING = 'Running'
    PENDING = 'Pending'
    ERROR = 'Error'
    UNKNOWN = 'Unknown'
    STOPPED = 'Stopped'



__virtualname__ = "rapyutaio"

def __virtual__():
    # To force a module not to load return something like:
    #   return (False, "The rapyutaio  module is not implemented yet")
    return __virtualname__



def _error(ret, err_msg):
    ret['result'] = False
    ret['comment'] = err_msg
    return ret



def _get_credentials():
    config = __salt__['config.get']('rapyutaio')
    return (config['username'], config['password'])



def _cache_token(token_data):
    return __salt__['sdb.set']("sdb://rapyutaio/auth_token", token_data)



def _request_auth_token(username, password):
    """
    Use the username (email) and password to authenticate to rapyuta.io and
    generate a new JWT auth token.

    Cache the token in the minion Salt cache so it can be
    re-used without having to re-authenticate or generate a new one
    each time we use an execution module or apply states.

    A token is valid across all the projects the user has access to.
    """
    header_dict = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }
    data = {
        "email": username,
        "password": password,
    }
    log.debug(salt.utils.json.dumps(data))
    response = salt.utils.http.query(url='https://garip.apps.rapyuta.io/user/login?type=high',
                                     header_dict=header_dict,
                                     method="POST",
                                     data=salt.utils.json.dumps(data),
                                     status=True)
    log.debug(response)

    if 'error' in response:
        raise CommandExecutionError(
            response['error']
        )

    response_body = salt.utils.json.loads(response['body'])
    response_data = response_body['data']

    return response_data



def request_auth_token(username=None, password=None):
    """
    Login to rapyuta.io using credentials provided, or
    credentials in the minion config,
    and return a new auth token

    rapyutaio:
      username: "first.last@email.com"
      password: "mypassword"
    """
    # TODO: allow multiple credential profiles and a way to select one
    if username is None or password is None:
        try:
            username, password = _get_credentials()
        except KeyError as e:
            log.exception(e)
            return None

    new_token = _request_auth_token(username, password)

    return new_token['token']



def _get_cached_token():
    """
    Returns None if:
    - sdb is not configured
    - no token has been cached
    - cached token has expired

    Otherwise returns the token
    """
    log.trace('_get_cached_token')

    # Get the cached token with its expiryAt
    try:
        cached_token = __salt__['sdb.get']('sdb://rapyutaio/auth_token', strict=True)
        log.debug(f"cached_token: {cached_token!s}")
    except SaltInvocationError:
        return None

    if cached_token is None:
        return None

    # Trim off the nanoseconds when parsing the datetime
    expiry = datetime.strptime(cached_token['expiryAt'][:19], '%Y-%m-%dT%H:%M:%S')

    if expiry >= datetime.utcnow():
        # Token is still valid
        return cached_token.get('token', None)

    return None



def _get_new_auth_token(username=None, password=None):
    """
    Requests and caches a new auth token
    """
    if username is None or password is None:
        username, password = _get_credentials()

    new_token_data = _request_auth_token(username, password)

    # Send the full response to be cached
    _cache_token(new_token_data)

    return new_token_data['token']



def _get_auth_token():
    """
    Returns cached auth token or requets a new token
    """
    auth_token = __salt__['config.get']("rapyutaio:auth_token", None)

    if auth_token is not None:
        return auth_token

    cached_token = _get_cached_token()
    if cached_token is not None:
        return cached_token

    # Request a new token
    return _get_new_auth_token()



def _header_dict(project_id, auth_token):
    """
    Create a header dict from the project ID and auth token
    """
    return {
        "accept": "application/json",
        "project": str(project_id),
        "Authorization": "Bearer " + str(auth_token),
    }



def _send_request(url, header_dict={}, method="GET", data=None, params=None):
    """
    Sends an HTTP request, parses the result, raises an exception on error
    """
    log.debug("url: %s" % url)
    log.debug("header_dict: %s" % header_dict)
    log.debug("method: %s" % method)
    log.debug("data: %s" % data)
    log.debug("params: %s" % params)

    if data is not None:
        header_dict['Content-Type'] = "application/json"

    response = salt.utils.http.query(url=url,
                                     header_dict=header_dict,
                                     method=method,
                                     data=salt.utils.json.dumps(data) if data is not None else None,
                                     params=params,
                                     status=True)
    log.debug(response)

    if 'error' in response:
        raise CommandExecutionError(
            message=response['error'],
            info={
                "status": int(response['status'])
            }
        )

    if response['body'] != '':
        return salt.utils.json.loads(response['body'])
    else:
        return {}



def _api_request(url,
                 http_method="GET",
                 header_dict={},
                 data=None,
                 params=None,
                 project_id=None,
                 auth_token=None):
    """
    Wrapper for HTTP requests to IO and handle authentication and tokens
    """
    log.debug("rapyutaio._api_request() called...")

    if project_id is None:
        project_id = __salt__['config.get']("rapyutaio:project_id")

    if not project_id:
        raise InvalidConfigError("No rapyutaio project_id found")

    if auth_token is None:
        auth_token = _get_auth_token()

    # header_dict = _header_dict(project_id, auth_token or generated_auth_token)
    header_dict = _header_dict(project_id, auth_token)

    def _send_api_request():
        return _send_request(url=url,
                             header_dict=header_dict,
                             method=http_method,
                             data=data,
                             params=params)


    # first request attempt
    try:
        return _send_api_request()
    except CommandExecutionError as e:
        if e.info['status'] == 401:
            # HTTP 401: Unauthorized
            new_auth_token = _renew_token()['token']
            header_dict = _header_dict(project_id, new_auth_token)
            return _send_api_request()
        raise e



def _deep_merge(tgt, src):
    """Deep merge tgt dict with src
    For each k,v in src: if k doesn't exist in tgt, it is deep copied from
    src to tgt. Otherwise, if v is a list, tgt[k] is replaced with
    src[k]. If v is a set, tgt[k] is updated with v, If v is a dict,
    recursively deep-update it.

    Examples:
    >>> t = {'name': 'Ferry', 'hobbies': ['programming', 'sci-fi']}
    >>> print _deep_merge(t, {'hobbies': ['gaming']})
    {'name': 'Ferry', 'hobbies': ['gaming', 'sci-fi']}
    """
    if isinstance(tgt, Mapping):
        for sk, sv in src.items():
            if sk[-1] == "+":
                merge_sublists = True
                tk = sk[:-1]
            elif sk[-1] == "-":
                replace_sublists = True
                tk = sk[:-1]
            else:
                merge_sublists = False
                replace_sublists = False
                tk = sk

            tv = tgt.get(tk, None)

            if isinstance(tv, Mapping) and isinstance(sv, Mapping):
                if sk in tgt:
                    tgt[tk] = _deep_merge(tgt[tk], sv)
                else:
                    tgt[tk] = copy.deepcopy(sv)
            elif isinstance(tv, list) and isinstance(sv, list):
                if merge_sublists:
                    tgt[tk].extend([x for x in sv if x not in tv])
                elif replace_sublists:
                    tgt[tk] = sv
                else:
                    tgt[tk] = _deep_merge(tv, sv)
            elif isinstance(tv, set) and isinstance(sv, set):
                if sk in tgt:
                    tgt[tk].update(sv.copy())
                else:
                    tgt[tk] = sv.copy()
            else:
                tgt[tk] = copy.copy(sv)
    elif isinstance(tgt, list):
        tgt_len = len(tgt)

        for idx in range(len(src)):
            if src[idx] in (None, "", [], {}):
                continue

            if idx < tgt_len:
                if isinstance(tgt[idx], (Mapping, list)) and isinstance(src[idx], (Mapping, list)):
                    tgt[idx] = _deep_merge(tgt[idx], src[idx])
                else:
                    tgt[idx] = src[idx]
            else:
                tgt.append(src[idx])
    else:
        return src

    return tgt



def _match(tgt, device):
    """
    Matches devices against a compound target string using the
    device name as the id and device labels as the grains
    """
    custom_opts = copy.copy(__opts__)

    custom_opts.update({
        "id": device['name'],
        "grains": {
            "labels": {
                label['key']: label['value'] for label in device['labels']
            },
            "config_variables": {
                var['key']: var['value'] for var in device['config_variables']
            },
            "status": device['status']
        }
    })

    matchers = salt.loader.matchers(custom_opts)

    try:
        return matchers['compound_match.match'](tgt)
    except Exception as e:
        log.exception(e)
        return False



# -----------------------------------------------------------------------------
#
# Packages
#
# -----------------------------------------------------------------------------
def get_packages(phase=(),
                 project_id=None,
                 auth_token=None):
    """
    List of package summaries in the project

    project_id

        string

    Authorization

        string

    phase

        array[string]

    salt-call --local rapyutaio.packages phase=["In progress","Succeeded"]
    """
    params = {
        'phase': phase,
    }
    url = CATALOG_HOST + "/v2/catalog?%s" % _urlencode(params, doseq=True)
    try:
        response_body = _api_request(url=url,
                                     http_method="GET",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None

    # The packages are listed under the "services" key
    return response_body['services']



def get_package(name=None,
                version=None,
                guid=None,
                project_id=None,
                auth_token=None):
    """
    Return a dict of information about a single package

    project_id

        string

    Authorization

        string

    guid

        string

    name

        string

    version

        string

    Returns:
        False: file not found
        Exception: something went wrong
        Dict: package
    """
    if guid is None:
        if name is None or version is None:
            raise SaltInvocationError(
                "Require either 'guid', or 'name' and 'version'"
            )

        #
        # Fetch a single package via its name and version
        #
        packages = get_packages(project_id=project_id,
                                auth_token=auth_token)

        # Need to accept version with and without the 'v' prefix
        if version[0] == 'v':
            version = version[1:]

        # Return the first package that matches the version
        for pkg_summary in packages:
            pkg_version = pkg_summary['metadata']['packageVersion']

            if pkg_version[0] == 'v':
                pkg_version = pkg_version[1:]

            if pkg_summary['name'] == name:
                if pkg_version == version:
                    guid = pkg_summary['id']
                    break

    if guid is None:
        return False

    #
    # Fetch a single package via its UID
    #
    url = CATALOG_HOST + "/serviceclass/status"
    params = {
        "package_uid": guid,
    }
    try:
        return _api_request(url=url,
                            http_method="GET",
                            params=params,
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None



def delete_package(name=None,
                   version=None,
                   guid=None,
                   project_id=None,
                   auth_token=None,
                   force=False):
    """
    Delete a package

    Force:
        Delete the package even if it's still in use

    Return:
        True: file deleted
        False: file not there
        Exception: could not delete
    """
    if guid is None:
        if name is None or version is None:
            raise SaltInvocationError(
                "Require either 'guid', or 'name' and 'version'"
            )

        #
        # Fetch the package UID using its name and version
        #
        package = get_package(name=name,
                              version=version,
                              project_id=project_id,
                              auth_token=auth_token)

        if package is False:
            return False

        guid = package['packageInfo']['guid']

    #
    # Send the delete request
    #
    url = CATALOG_HOST + "/serviceclass/delete"
    data = {
        "package_uid": guid,
    }
    try:
        _api_request(url=url,
                     http_method="DELETE",
                     params=data,
                     project_id=project_id,
                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    return True



def create_package(source=None,
                   manifest=None,
                   project_id=None,
                   auth_token=None):
    """
    Upload a package manifest
    """
    if manifest is None:
        if source is None:
            raise SaltInvocationError(
                "create_or_update_package requires either source or manifest"
            )

        file_name = __salt__["cp.cache_file"](source)

        if file_name is not False:
            with __utils__['files.fopen'](file_name, "r") as _f:
                file_name_part, file_extension = os.path.splitext(file_name)

                if file_extension == '.json':
                    manifest = __utils__['json.load'](_f)
                elif file_extension in ['.yaml', '.yml']:
                    manifest = __utils__['yaml.load'](_f)
                else:
                    raise SaltInvocationError(
                        "Source file must be a JSON (.json) or YAML (.yaml, .yml) file"
                    )
        else:
            raise CommandExecutionError(
                "File '{}' does not exist".format(file_name)
            )

    url = CATALOG_HOST + "/serviceclass/add"
    try:
        return _api_request(url=url,
                            http_method="POST",
                            data=manifest,
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False



# -----------------------------------------------------------------------------
#
# Networks
#
# -----------------------------------------------------------------------------
def get_networks(project_id=None,
                 auth_token=None):
    """
    Get a list of all routed networks
    """
    url = CATALOG_HOST + "/routednetwork"
    try:
        response_body = _api_request(url=url,
                                     http_method="GET",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None

    networks = [
        network
        for network
        in response_body
        if network['internalDeploymentStatus']['phase'] in list(map(str, POSITIVE_PHASES))
    ]

    return networks



def get_network(name=None,
                guid=None,
                project_id=None,
                auth_token=None):
    """
    Get an active Routed Network
    """
    if guid is None:
        if name is None:
            raise SaltInvocationError(
                "get_network needs either a valid guid or name"
            )

        networks = get_networks(project_id=project_id,
                                auth_token=auth_token)

        for network in networks:
            if network['name'] == name:
                if network['internalDeploymentStatus']['phase'] in ['In Progress', 'Succeeded', 'Provisioning']:
                    guid = network['guid']
                    break

    if guid is None:
        # We have no guid and the name didn't
        # match an existing network so we return False
        return False

    url = CATALOG_HOST + "/routednetwork/%s" % guid
    try:
        return _api_request(url=url,
                            http_method="GET",
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None



def create_network(name,
                   ros_distro,
                   runtime,
                   parameters=None,
                   project_id=None,
                   auth_token=None):
    """
    Create a new Routed Network
    """
    url = CATALOG_HOST + "/routednetwork"
    data = {
        "name": name,
        "rosDistro": ros_distro,
        "runtime": runtime,
        "parameters": parameters or {},
    }
    try:
        return _api_request(url=url,
                            http_method="POST",
                            data=data,
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None



def delete_network(name=None,
                   guid=None,
                   project_id=None,
                   auth_token=None):
    """
    """
    if name is not None:
        networks = get_networks(project_id=project_id,
                                auth_token=auth_token)

        for network in networks:
            if network['name'] == name:
                guid = network['guid']
                break

    if guid is None:
        raise CommandExecutionError(
            "delete_network needs either a valid guid or name"
        )

    url = CATALOG_HOST + "/routednetwork/%s" % guid
    try:
        _api_request(url=url,
                     http_method="DELETE",
                     project_id=project_id,
                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    return True



# -----------------------------------------------------------------------------
#
# Deployments
#
# -----------------------------------------------------------------------------
def get_deployments(package_uid=None,
                    phase=list([str(pp) for pp in POSITIVE_PHASES]),
                    project_id=None,
                    auth_token=None,):
    """
    salt-call --log-level=debug --local rapyutaio.list_deployments phase=["In progress","Succeeded"]
    """
    params = {
        'package_uid': package_uid or '',
        'phase': phase,
    }
    url = CATALOG_HOST + "/deployment/list?%s" % _urlencode(params, doseq=True)
    try:
        return _api_request(url=url,
                            http_method="GET",
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None



def get_deployment(name=None,
                   id=None,
                   project_id=None,
                   auth_token=None):
    """
    """
    if name is not None:
        deployments = get_deployments(project_id=project_id,
                                      auth_token=auth_token)

        for deployment in deployments:
            if deployment['name'] == name:
                id = deployment['deploymentId']

    if id is None:
        return None

    url = CATALOG_HOST + "/serviceinstance/%s" % id
    try:
        return _api_request(url=url,
                            http_method="GET",
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None



def create_deployment(name,
                      package_uid=None,
                      package_name=None,
                      package_version=None,
                      networks=None,
                      parameters={},
                      dependencies=[],
                      project_id=None,
                      auth_token=None):
    """
    """
    if package_uid is None:
        if package_name is None or package_version is None:
            raise SaltInvocationError(
                "create_deployment requires package_uid, or package_name and package_version"
            )

    #
    # Create provision configuration
    #
    package = get_package(name=package_name,
                          version=package_version,
                          guid=package_uid,
                          project_id=project_id,
                          auth_token=auth_token)

    if package:
        plan = package['packageInfo']['plans'][0]
    else:
        raise CommandExecutionError(
            "Could not find package '{0}'".format(package_name)
        )

    provision_configuration = {
        "accepts_incomplete": True,
        "api_version": '1.0.0',
        "context": {
            "dependentDeployments": [],
            "labels": [],
            "name": name,
        },
        "parameters": {
            "global": {},
        },
        "plan_id": plan['planId'],
        "service_id": package['packageInfo']['guid'],
        "space_guid": "spaceGuid",
        'instance_id': 'instanceId',
        'organization_guid': 'organizationGuid',
    }

    for component in plan['components']['components']:
        for internal_component in plan['internalComponents']:
            if internal_component['componentName'] == component['name']:
                component_id = internal_component['componentId']
                break

        component_parameters = {
            "component_id": component_id,
            # "bridge_params": {
            #   "alias": component['name']
            # }
        }
        for pkg_parameter in component['parameters']:
            # component_parameters[pkg_parameter['name']] = pkg_parameter.get('default', None)
            component_parameters[pkg_parameter['name']] = parameters.get(component['name'], {}).get(pkg_parameter['name'], pkg_parameter.get('default', None))

        provision_configuration['parameters'][component_id] = component_parameters

    #
    # Add routed networks
    #
    if networks is not None:
        all_routed_networks = get_networks(project_id=project_id,
                                           auth_token=auth_token)
        network_names = networks.split(",")
        network_guids = []
        for network in all_routed_networks:
            if network['name'] in network_names:
                network_guids.append({
                    "guid": network['guid']
                })

        provision_configuration['context']['routedNetworks'] = network_guids

    #
    # Dependencies
    #
    for dep_name in dependencies:
        dep_dpl = __salt__['rapyutaio.get_deployment'](name=dep_name)

        if dep_dpl is not None:
            provision_configuration['context']['dependentDeployments'].append({
                "dependentDeploymentId": dep_dpl['deploymentId']
            })

    #
    # Provision
    #
    url = PROVISION_API_PATH + "/instanceId"
    try:
        response_body = _api_request(url=url,
                                     http_method="PUT",
                                     data=provision_configuration,
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    #
    # Wait for the deployment to complete
    #
    deployment_id = response_body['operation']
    deployment_phase = str(Phase.INPROGRESS)
    while deployment_phase in list(map(str, [Phase.INPROGRESS, Phase.PROVISIONING])):
        sleep(10)

        deployment = get_deployment(id=deployment_id)
        deployment_phase = deployment['phase']

    if deployment_phase == str(Phase.SUCCEEDED):
        return deployment

    return False



def delete_deployment(name=None,
                      id=None,
                      package_uid=None,
                      plan_id=None,
                      project_id=None,
                      auth_token=None):
    """
    Response:

        {"async":false,"component_status":null}
    """
    deployment = get_deployment(name=name,
                                id=id,
                                project_id=None,
                                auth_token=None)

    if deployment is None:
        log.info(f"Deployment {name} does not exist")
        return True

    params = {
        "service_id": deployment['packageId'],
        "plan_id": deployment['planId'],
    }
    url = CATALOG_HOST + "/v2/service_instances/%s" % deployment['deploymentId']
    try:
        _api_request(url=url,
                     http_method="DELETE",
                     params=params,
                     project_id=project_id,
                     auth_token=auth_token)
        return True
    except CommandExecutionError as e:
        log.exception(e)
        return False



def get_dependencies(deployment_id,
                     project_id=None,
                     auth_token=None):
    """
    """
    url = CATALOG_HOST + "/serviceinstance/%s/dependencies" % deployment_id
    try:
        return _api_request(url=url,
                            http_method="GET",
                            project_id=project_id,
                            auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None



def get_manifest(guid,
                 project_id=None,
                 auth_token=None):
    """
    Get a manifest for a package like you would through the web interface
    """
    package = get_package(guid=guid,
                          project_id=project_id,
                          auth_token=auth_token)

    if not package:
        return None

    url = package['packageUrl']
    header_dict = {
        "accept": "application/json"
    }
    response = __utils__['http.query'](url=url,
                                       header_dict=header_dict,
                                       http_method="GET",
                                       status=True)

    if 'error' in response:
        raise CommandExecutionError(
            response['error']
        )

    return __utils__['json.loads'](response['body'])



# -----------------------------------------------------------------------------
#
# Devices
#
# -----------------------------------------------------------------------------
def get_devices(tgt=None,
                project_id=None,
                auth_token=None):
    """
    """
    url = DEVICE_API_PATH
    try:
        response_body = _api_request(url=url,
                                     http_method="GET",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None

    if tgt is not None:
        # filter the list of devices
        return [
            device
            for device
            in response_body['response']['data']
            if match(tgt, device)
        ]
    else:
        # return all devices
        return response_body['response']['data']



def get_device(name=None,
               device_id=None,
               project_id=None,
               auth_token=None):
    """
    """
    if device_id is None:
        if name is None:
            raise SaltInvocationError(
                "get_device requires device_id or name"
            )

        all_devices = get_devices(tgt=name,
                                  project_id=project_id,
                                  auth_token=auth_token)

        if all_devices in ([], None):
            return None

        device_id = all_devices[0]['uuid']

    url = DEVICE_API_PATH + device_id
    try:
        response_body = _api_request(url=url,
                                     http_method="GET",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None

    return response_body['response']['data']



# -----------------------------------------------------------------------------
#
# Commands
#
# -----------------------------------------------------------------------------
def cmd(tgt,
        cmd,
        shell=None,
        env={},
        bg=False,
        runas=None,
        cwd=None,
        project_id=None,
        auth_token=None):
    """
    Execute a command on one or more devices

    CLI Example::

        salt '*' rapyutaio.cmd \\* ls cwd=/etc/
    """

    #
    # Get devices
    #
    all_devices = get_devices(project_id=project_id, auth_token=auth_token)

    # A dict of devices to send the command, also serves as a UUID to name lookup
    device_names = {
        device['uuid']: device['name']
        for device
        in all_devices
        if match(tgt, device)
        and device['status'] == "ONLINE"
    }

    if device_names:
        # Copy only the set function args into the command dict
        command = {
            key: val
            for key, val
            in locals().items()
            if key
            in ['cmd',
                'shell',
                'env',
                'bg',
                'runas',
                'cwd']
            and val
        }
        command['device_ids'] = list(device_names.keys())

        url = DEVICE_COMMAND_API_PATH
        try:
            response_body = _api_request(url=url,
                                         http_method="POST",
                                         data=command,
                                         project_id=project_id,
                                         auth_token=auth_token)
        except CommandExecutionError as e:
            log.exception(e)
            return False

        # Response uses device UUID as key, change to device name
        return {
            device_names[uuid]: output
            for uuid, output
            in response_body['response']['data'].items()
        }

    return False


# -----------------------------------------------------------------------------
#
# Metrics
#
# -----------------------------------------------------------------------------
def get_metrics(name=None,
                device_id=None,
                project_id=None,
                auth_token=None):
    """
    """
    if device_id is None:
        if name is None:
            raise SaltInvocationError(
                "get_device requires device_id or name"
            )

        device = get_device(name=name,
                            device_id=device_id,
                            project_id=project_id,
                            auth_token=auth_token)

        device_id = device['uuid']

    url = DEVICE_METRIC_API_PATH + device_id
    try:
        response_body = _api_request(url=url,
                                     http_method="GET",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None

    return response_body['response']['data']



def add_metrics(name=None,
                device_id=None,
                metric_name=None,
                qos=None,
                project_id=None,
                auth_token=None):
    """
    """
    if device_id is None:
        if name is None:
            raise SaltInvocationError(
                "get_device requires device_id or name"
            )

        device = get_device(name=name,
                            device_id=device_id,
                            project_id=project_id,
                            auth_token=auth_token)

        device_id = device['uuid']

    if not qos.isdigit():
        try:
            qos = {
                "low": 0,
                "medium": 1,
                "high": 2
            }[qos]
        except KeyError:
            raise SaltInvocationError(
                "qos should be one of low (0), medium (1), or high (2)"
            )

    url = DEVICE_METRIC_API_PATH + device_id
    data = {
        "name": metric_name,
        "config": {
            "qos": qos,
        }
    }
    try:
        _api_request(url=url,
                     http_method="POST",
                     data=data,
                     project_id=project_id,
                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    return True



# -----------------------------------------------------------------------------
#
# Topics
#
# -----------------------------------------------------------------------------
def get_topics(name=None,
               device_id=None,
               project_id=None,
               auth_token=None):
    """
    Returns a list of topics
    """
    if device_id is None:
        if name is None:
            raise SaltInvocationError(
                "get_device requires device_id or name"
            )

        device = get_device(name=name,
                            device_id=device_id,
                            project_id=project_id,
                            auth_token=auth_token)

        device_id = device['uuid']

    url = DEVICE_METRIC_API_PATH + device_id
    try:
        response_body = _api_request(url=url,
                                     http_method="GET",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return None

    return response_body['response']['data']



# -----------------------------------------------------------------------------
#
# Labels
#
# -----------------------------------------------------------------------------
def _label_add(device_id, name, value, project_id, auth_token):
    url = DEVICE_LABEL_API_PATH + str(device_id)
    data = {
        name: value,
    }
    try:
        response_body = _api_request(url=url,
                                     http_method="POST",
                                     data=data,
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    return response_body['response']['data']



def _label_update(label_id, name, value, project_id, auth_token):
    url = DEVICE_LABEL_API_PATH + str(label_id)
    data = {
        "key": name,
        "value": value,
    }
    try:
        response_body = _api_request(url=url,
                                     http_method="PUT",
                                     data=data,
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    return response_body['response']['data']



def _label_delete(label_id, project_id, auth_token):
    url = DEVICE_LABEL_API_PATH + str(label_id)
    try:
        response_body = _api_request(url=url,
                                     http_method="DELETE",
                                     project_id=project_id,
                                     auth_token=auth_token)
    except CommandExecutionError as e:
        log.exception(e)
        return False

    return response_body['response']['data']



def label(tgt,
          name,
          value,
          project_id=None,
          auth_token=None):
    """
    Set a label on one or more devices
    """
    devices = get_devices(tgt, project_id=project_id, auth_token=auth_token)

    changes = {
        "added": [],
        "deleted": [],
        "updated": [],
    }
    for device in devices:
        device_labels = {l['key']: l for l in device['labels']}
        log.debug(device_labels)

        try:
            label = device_labels[name]
        except KeyError:
            if value != "":
                # add label
                _label_add(device['uuid'], name, value, project_id, auth_token)
                changes['added'].append(device['name'])
        else:
            if value == "":
                # delete label
                _label_delete(label['id'], project_id, auth_token)
                changes['deleted'].append(device['name'])
            elif value != device_labels[name]['value']:
                # update label
                _label_update(label['id'], name, value, project_id, auth_token)
                changes['updated'].append(device['name'])

    return {
        "label": name,
        "value": value,
        "changes": changes,
    }



def test(project_id=None, auth_token=None):
    """
    Just for testing
    """
    # return _get_cached_token()
    return _get_auth_token()
    # return _api_request(url=DEVICE_API_PATH,
    #                     http_method="GET",
    #                     project_id=project_id,
    #                     auth_token=auth_token)
