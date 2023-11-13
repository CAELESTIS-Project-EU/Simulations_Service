import logging
from rest_framework.authtoken.models import Token
from .models import Machine, Key_Gen
from accounts.views import decrypt, get_name_fqdn
import uuid
from django.utils.crypto import get_random_string
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .forms import DocumentForm
from rest_framework.exceptions import APIException
from accounts.views import start_exec, run_sim_async, deleteExecutionHTTP, get_status, stop_execution_api, restart_execution_api  # Assuming these are defined elsewhere

log = logging.getLogger(__name__)


class ConnectionFailed(APIException):
    status_code = 400
    default_detail = 'Failed to establish a connection.'
    default_code = 'connection_failed'


class MachineNotFound(APIException):
    status_code = 404
    default_detail = 'Machine not found.'
    default_code = 'machine_not_found'


class AuthenticationFailed(APIException):
    status_code = 401
    default_detail = 'Authentication credentials were not provided.'
    default_code = 'authentication_failed'



@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def run_simulation(request):
    # Establish a connection first
    try:
        connect_execution(request)
    except APIException as e:
        # If connection fails, return the error response
        return Response({"error": str(e.detail)}, status=e.status_code)

    form = DocumentForm(request.data, request.FILES)
    if form.is_valid():
        name = None
        for filename, file in request.FILES.items():
            uniqueID = uuid.uuid4()
            name = str(file)
            nameE = f"{name.split('.')[0]}_{uniqueID}.{name.split('.')[1]}"
            name = nameE
        document = form.save(commit=False)
        document.document.name = name
        document.save()

        # Extract data from request.data instead of request.POST
        numNodes = request.data.get('numNodes')
        name_sim = request.data.get('name_sim') or get_random_string(8)
        qos = request.data.get('qos')
        execTime = request.data.get('execTime')
        checkpoint_flag = request.data.get("checkpoint_flag", False)
        auto_restart = request.data.get("auto_restart", False)

        checkpoint_bool = checkpoint_flag == "on"
        auto_restart_bool = auto_restart == "on"
        if auto_restart_bool:
            checkpoint_bool = True

        eID = start_exec(numNodes, name_sim, execTime, qos, name, request, auto_restart_bool)
        log.info("eID")
        log.info(eID)
        run_simulation = run_sim_async(request, name, numNodes, name_sim, execTime, qos, checkpoint_bool,
                                       auto_restart_bool, eID)
        run_simulation.start()
        return Response({'message': 'Simulation started successfully! ', 'execution_id': eID},
                        status=status.HTTP_202_ACCEPTED)

    else:
        # Return form errors if form is not valid
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)


def connect_execution(request):
    if not request.user.is_authenticated:
        raise AuthenticationFailed()

    machine_choice = request.headers.get('MachineChoice')
    token = request.headers.get('SecToken')
    user, fqdn = get_name_fqdn(machine_choice)
    try:
        machine = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
    except Machine.DoesNotExist:
        raise MachineNotFound()

    try:
        obj = Key_Gen.objects.get(machine_id=machine.id)
        private_key = obj.private_key
        content = decrypt(private_key, token).decode()
        request.session['machine_chosen'] = machine.id
        request.session["content"] = content
    except (Key_Gen.DoesNotExist, Exception):
        raise ConnectionFailed()
    return True


@permission_classes([IsAuthenticated])
@api_view(['GET', 'PUT', 'DELETE'])
def http_execution(request, eID):
    log.info("ENTERED HERE")
    if request.method == 'GET':
        log.info("ENTERED HERE")
        return get_status_execution(request, eID)

    elif request.method == 'PUT':
        log.info("ENTERED HERE PUT")
        return execution(request, eID)

    elif request.method == 'DELETE':
        log.info("ENTERED HERE DELETE")
        return delete_execution_api(request, eID)

def delete_execution_api(request, eID):
    try:
        connect_execution(request)
    except APIException as e:
        # If connection fails, return the error response
        return Response({"error": str(e.detail)}, status=e.status_code)
    try:
        deleteExecutionHTTP(eID, request)
        return Response({'message': 'Execution deleted successfully'}, status=status.HTTP_202_ACCEPTED)
    except  ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    # Properly close the SSH connection if you opened it earlier


def get_status_execution(request, eID):
    try:
        connect_execution(request)
    except APIException as e:
        # If connection fails, return the error response
        return Response({"error": str(e.detail)}, status=e.status_code)
    try:
        res = get_status(eID, request)
        eidM = "eID: " + str(res.eID) + ","
        name = "name: " + str(res.name_sim) + ","
        jobID = "jobID: " + str(res.jobID) + ","
        user = "user: " + str(res.user) + ","
        nodes = "nodes: " + str(res.nodes) + ","
        statusE = "status: " + str(res.status) + ","
        autorestart = "autorestart: " + str(res.autorestart) + ","
        time = "time: " + str(res.time) + ";"
        jobStatus = eidM + name + jobID + user + nodes + statusE + autorestart + time
        return Response({'message': jobStatus}, status=status.HTTP_202_ACCEPTED)
    except  ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



def execution(request, eID):
    try:
        connect_execution(request)
    except APIException as e:
        # If connection fails, return the error response
        return Response({"error": str(e.detail)}, status=e.status_code)

    # Get the status from the URL query parameters
    statusExecution = request.query_params.get('status')

    # You might want to check if the desired_status is provided and valid
    if statusExecution is None:
        return Response({"error": "StatusExecution parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
    elif statusExecution == "stop":
        try:
            stop_execution_api(eID, request)
            return Response({'message': 'The execution '+str(eID)+' has been stopped!'}, status=status.HTTP_202_ACCEPTED)
        except  ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    elif statusExecution == "restart":
        try:
            restart_execution_api(eID, request)
            return Response({'message': 'The execution ' + +str(eID) + ' has been restarted!'}, status=status.HTTP_202_ACCEPTED)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    return Response({'message': 'Change of status DONE!'}, status=status.HTTP_202_ACCEPTED)
