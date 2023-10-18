import uuid
from io import StringIO
from django.shortcuts import render, redirect
from .forms import CreateUserForm, WorkFlowForm, DocumentForm, ExecutionForm, Key_Gen_Form, Machine_Form
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import yaml
import paramiko
import time
import os
import logging
from accounts.models import Execution, Key_Gen, Machine, Connection
from cryptography.fernet import Fernet
from django.db.models import Q
import threading
import random
import string
import re


log = logging.getLogger(__name__)


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)


def loginPage(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password1']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            form = login(request, user)
            messages.success(request, f' welcome {username} !!')
            return redirect('accounts:dashboard')
        else:
            form = CreateUserForm()
            return render(request, 'accounts/loginpage.html', {'form': form, 'error': True})
    else:
        form = CreateUserForm()
    return render(request, 'accounts/loginpage.html', {'form': form})


def registerPage(request):
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, f'Your account has been created. You can log in now!')
            return redirect('accounts:home')
    else:
        form = CreateUserForm()
    return render(request, 'accounts/registerpage.html', {'form': form})


@login_required
def logoutUser(request):
    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("accounts:home")


def get_random_string(length):
    # With combination of lower and upper case
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    return result_str


def checkConnection(request):
    idConn = request.session.get('idConn')
    if idConn != None:
        conn = Connection.objects.get(idConn_id=request.session["idConn"])
        if conn.status == "Disconnect":
            return False
    return True


def extract_substring(s):
    match = re.search(r'([a-zA-Z]+)\d\.', s)
    if match:
        return match.group(1)
    return None

def run_sim(request):
    if request.method == 'POST':
        checkConnBool = checkConnection(request)
        if not checkConnBool:
            machines_done = populate_executions_machines(request)
            if not machines_done:
                request.session['firstCheck'] = "no"
            request.session["checkConn"] = "Required"
            return render(request, 'accounts/executions.html',
                          {'machines': machines_done, 'checkConn': "no"})
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            name = None
            machine = request.POST.get('machineChoice')
            user = machine.split("@")[0]
            fqdn = machine.split("@")[1]
            machine_folder=extract_substring(fqdn)
            machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
            machineID = machine_found.id
            request.session['machineID'] = machineID
            request.userMachine = user
            request.fqdn = fqdn
            for filename, file in request.FILES.items():
                uniqueID = uuid.uuid4()
                name = file
                nameE = (str(name).split(".")[0]) + "_" + str(uniqueID) + "." + str(name).split(".")[1]
                name = nameE
            document = form.save(commit=False)
            document.document.name = name
            document.save()
            workflow = read_and_write(name)
            user = request.user
            #obj = Key_Gen.objects.filter(author=user, machine_id=machineID).get()
            userMachine = machine_found.user
            ssh = connection(request.session["content"], request.session["machineID"])
            request.session["connection_machine"] = machineID
            log.info("COPY START")
            workflow_name=workflow.get("workflow_type")
            # principal_folder = "/gpfs/projects/bsce81/alya/tests/TestAPIRest/users/" + userMachine + "/executions/"
            principal_folder = machine_found.wdir
            uniqueIDfolder = uuid.uuid4()
            s = "execution_" + str(uniqueIDfolder)
            if not principal_folder.endswith("/"):
                principal_folder = principal_folder + "/"
            wdirDone = principal_folder + "" + s
            cmd1 = "source /etc/profile; cd "+machine_found.installDir+"; mkdir -p " + principal_folder + "/" + s + "/workflows/; echo " + str(
                workflow) + " > " + principal_folder + "/" + s + "/workflows/" + str(
                name) + "; cd " + principal_folder + "; BACKUPDIR=$(ls -td ./*/ | head -1); echo EXECUTION_FOLDER:$BACKUPDIR;"
            log.info("COMMAND 1")
            log.info(cmd1)
            stdin, stdout, stderr = ssh.exec_command(cmd1)
            stdout = stdout.readlines()
            execution_folder = wdirDone + "/execution"
            workflow_folder = wdirDone + "/workflows"
            numNodes = request.POST.get('numNodes')
            name_sim = request.POST.get('name_sim')
            if name_sim is None:
                name_sim = get_random_string(8)
            execTime = request.POST.get('execTime')
            checkpoint_flag = request.POST.get("checkpoint_flag")
            checkpoint_bool = False
            if checkpoint_flag == "on":
                checkpoint_bool = True

            auto_restart = request.POST.get("auto_restart")
            auto_restart_bool = False
            if auto_restart == "on":
                auto_restart_bool = True

            if auto_restart_bool:
                checkpoint_bool = True
            request.session['workflow_path'] = workflow_folder
            qos = request.POST.get('qos')
            path_install_dir= machine_found.installDir
            param_machine = remove_numbers(machine_found.fqdn)
            workflow_name=str(workflow_name)
            """if checkpoint_bool:
                cmd2 = "source /etc/profile;  mkdir -p " + execution_folder + "; cp -r /gpfs/projects/bsce81/alya/tests/workflow_stable/scripts "+machine_found.installDir+";cd "+machine_found.installDir+"/scripts/"+machine_folder+"/;  sh app-checkpoint.sh " + userMachine + " " + str(
                    name) + " " + workflow_folder + " " + execution_folder + " " + numNodes + " " + execTime + " " + qos + " " + machine_found.installDir + " " + workflow_name
            else:
                cmd2 = "source /etc/profile;  mkdir -p " + execution_folder + "; cp -r /gpfs/projects/bsce81/alya/tests/workflow_stable/scripts "+machine_found.installDir+"; cd "+machine_found.installDir+"/scripts/"+machine_folder+"/; sh app.sh " + userMachine + " " + str(
                    name) + " " + workflow_folder + " " + execution_folder + " " + numNodes + " " + execTime + " " + qos + " " + machine_found.installDir + " " + workflow_name"""
            if checkpoint_bool:
                cmd2 = "source /etc/profile; cd /gpfs/projects/bsce81/alya/tests/workflow_stable/scripts/; source loadWorkflows.sh " + path_install_dir + " " + workflow_name + " "+param_machine+"; mkdir -p " + execution_folder + "; cd "+machine_found.installDir+"/scripts/"+machine_folder+"/;  source app-checkpoint.sh " + userMachine + " " + str(
                    name) + " " + workflow_folder + " " + execution_folder + " " + numNodes + " " + execTime + " " + qos + " " + machine_found.installDir
            else:
                cmd2 = "source /etc/profile; cd /gpfs/projects/bsce81/alya/tests/workflow_stable/scripts/; source loadWorkflows.sh " + path_install_dir + " " + workflow_name + " "+param_machine+"; mkdir -p " + execution_folder + "; cd "+machine_found.installDir+"/scripts/"+machine_folder+"/; source app.sh " + userMachine + " " + str(
                    name) + " " + workflow_folder + " " + execution_folder + " " + numNodes + " " + execTime + " " + qos + " " + machine_found.installDir

            log.info("COMMAND 2")
            log.info(cmd2)
            stdin, stdout, stderr = ssh.exec_command(cmd2)
            stdout = stdout.readlines()
            stderr = stderr.readlines()
            log.info(stderr)
            log.info(stdout)
            s = "Submitted batch job"
            var = ""
            while (len(stdout) == 0):
                time.sleep(1)
            if (len(stdout) > 1):
                log.info(stderr)
                log.info(stdout)
                for line in stdout:
                    if (s in line):
                        jobID = int(line.replace(s, ""))
                        var = jobID
                        request.session['jobID'] = jobID
                        form = Execution()
                        form.jobID = request.session['jobID']
                        form.user = userMachine
                        form.author = request.user
                        form.nodes = numNodes
                        form.status = "PENDING"
                        form.checkpoint = 0
                        form.time = "00:00:00"
                        form.wdir = execution_folder
                        form.workflow_path = workflow_folder
                        form.execution_time = int(execTime)
                        form.name_workflow = str(name)
                        form.qos = qos
                        form.name_sim = name_sim
                        form.autorestart = auto_restart_bool
                        form.machine=machine_found
                        form.save()
            request.session['execution_folder'] = execution_folder
            os.remove("documents/" + str(name))
            if auto_restart_bool:
                monitor_checkpoint(var, request, execTime)
            return redirect('accounts:executions')

    else:
        form = DocumentForm()
        request.session['flag'] = 'first'
        checkConnBool = checkConnection(request)
        if not checkConnBool:
            machines_done = populate_executions_machines(request)
            if not machines_done:
                request.session['firstCheck'] = "no"
            request.session["checkConn"] = "Required"
            return render(request, 'accounts/executions.html',
                          {'machines': machines_done, 'checkConn': "no"})
    return render(request, 'accounts/run_simulation.html',
                  {'form': form, 'flag': request.session['flag'], 'machines': populate_executions_machines(request)})


def results(request):
    if request.method == 'POST':
        print("")
    else:
        jobID = request.session['jobIDdone']
        ssh = connection(request.session['content'], request.session['machineID'])
        executionDone = Execution.objects.all().filter(jobID=jobID)
        stdin, stdout, stderr = ssh.exec_command(
            "sacct -j " + str(jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
        stdout = stdout.readlines()
        values = str(stdout).split()
        Execution.objects.filter(jobID=jobID).update(status=values[4], time=values[3], nodes=int(values[2]))
        execUpdate = Execution.objects.get(jobID=jobID)
    return render(request, 'accounts/results.html', {'executionsDone': execUpdate})


def render_right(request):
    checkConnBool = checkConnection(request)
    if not checkConnBool:
        machines_done = populate_executions_machines(request)
        if not machines_done:
            request.session['firstCheck'] = "no"
        request.session["checkConn"] = "Required"
        return render(request, 'accounts/executions.html',
                      {'machines': machines_done, 'checkConn': "no"})
    return


def executions(request):

    if request.method == 'POST':
        if 'resultExecution' in request.POST:
            request.session['jobIDdone'] = request.POST.get("resultExecutionValue")
            return redirect('accounts:results')
        elif 'failedExecution' in request.POST:
            request.session['jobIDfailed'] = request.POST.get("failedExecutionValue")
            return redirect('accounts:execution_failed')
        elif 'timeoutExecution' in request.POST:
            request.session['jobIDcheckpoint'] = request.POST.get("timeoutExecutionValue")
            checkpointing_noAutorestart(request.POST.get("timeoutExecutionValue"), request)
            return redirect('accounts:executions')
        elif 'stopExecution' in request.POST:
            request.session['stopExecutionValue'] = request.POST.get("stopExecutionValue")
            stopExecution(request.POST.get("stopExecutionValue"), request)
        elif 'disconnectButton' in request.POST:
            Connection.objects.filter(idConn_id=request.session["idConn"]).update(status="Disconnect")
            print("DISCONECT PHASE")
            for key in list(request.session.keys()):
                if not key.startswith("_"):  # skip keys set by the django system
                    del request.session[key]
            machines_done = populate_executions_machines(request)
            if not machines_done:
                request.session['firstCheck'] = "no"
            request.session["checkConn"] = "Required"


            return render(request, 'accounts/executions.html',
                          {'machines': machines_done, 'checkConn': "no"})
        elif 'connection' in request.POST:
            log.info("CONNECTED")
            threadUpdate = updateExecutions(request.POST.get("token"), request.POST.get('machineChoice'),
                                            request)
            user = request.POST.get('machineChoice').split("@")[0]
            fqdn = request.POST.get('machineChoice').split("@")[1]
            machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
            request.session["connection_machine"] = machine_found.id
            machineID = machine_found.id
            request.session['machineID'] = machineID
            obj = Key_Gen.objects.filter(machine_id=machineID).get()
            private_key = obj.private_key
            try:
                content = decrypt(private_key, request.POST.get("token")).decode()
                request.session["content"] = content
            except:
                print("The token is wrong!")
                return False

            threadUpdate.start()
            c = Connection()
            c.user = request.user
            c.status = "Active"
            c.save()
            request.session["idConn"] = c.idConn_id
        checkConnBool = checkConnection(request)
        if not checkConnBool:
            machines_done = populate_executions_machines(request)
            if not machines_done:
                request.session['firstCheck'] = "no"
            request.session["checkConn"] = "Required"
            return render(request, 'accounts/executions.html',
                          {'machines': machines_done, 'checkConn': "no"})
        machine_connected = Machine.objects.get(id=request.session["connection_machine"])
        executions = Execution.objects.all().filter(author=request.user,  machine=machine_connected).filter(
            Q(status="PENDING") | Q(status="RUNNING"))
        executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED", machine=machine_connected)
        executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED", machine=machine_connected)
        executionTimeout = Execution.objects.all().filter(author=request.user, status="TIMEOUT",
                                                          autorestart=False, machine=machine_connected)
        executionsCheckpoint = Execution.objects.all().filter(author=request.user, status="TIMEOUT",
                                                              autorestart=True, machine=machine_connected)
        executionsCanceled = Execution.objects.all().filter(author=request.user, status="CANCELLED+",
                                                            checkpoint="-1", machine=machine_connected)
        for execution in executionsCanceled:
            checks = Execution.objects.all().get(author=request.user, status="CANCELLED+", checkpoint=execution.jobID, machine=machine_connected)
            if checks is not None:
                execution.status = "TIMEOUT"
                execution.checkpoint = 0
                execution.save()
        """for execution in executionsDone:
            if execution.checkpoint != 0:
                e = Execution.objects.all().get(author=request.user, jobID=execution.checkpoint)
                checkpointingFinished(e, request)"""
        return render(request, 'accounts/executions.html',
                      {'executions': executions, 'executionsDone': executionsDone,
                       'executionsFailed': executionsFailed,
                       'executionsTimeout': executionTimeout, 'checkConn': "yes"})
    else:
        form = ExecutionForm()
        machines_done = populate_executions_machines(request)
        if not machines_done:
            request.session['firstCheck'] = "no"
            return render(request, 'accounts/executions.html',
                          {'firstCheck': request.session['firstCheck']})
        elif "content" not in request.session:
            request.session['firstCheck'] = "yes"
            request.session["checkConn"] = "no"
            return render(request, 'accounts/executions.html',
                          {'form': form, 'machines': machines_done,
                           'checkConn': request.session["checkConn"],
                           'firstCheck': request.session['firstCheck']})
        else:
            checkConnBool = checkConnection(request)
            if not checkConnBool:
                machines_done = populate_executions_machines(request)
                if not machines_done:
                    request.session['firstCheck'] = "no"
                request.session["checkConn"] = "Required"
                return render(request, 'accounts/executions.html',
                              {'machines': machines_done, 'checkConn': "no"})

            machine_connected = Machine.objects.get(id=request.session["connection_machine"])

            executions = Execution.objects.all().filter(author=request.user,  machine=machine_connected).filter(
                Q(status="PENDING") | Q(status="RUNNING"))
            executionsDone = Execution.objects.all().filter(author=request.user, machine=machine_connected, status="COMPLETED")
            executionsFailed = Execution.objects.all().filter(author=request.user, machine=machine_connected,status="FAILED")
            executionsCheckpoint = Execution.objects.all().filter(author=request.user, machine=machine_connected,status="TIMEOUT")
            executionTimeout = Execution.objects.all().filter(author=request.user, machine=machine_connected,status="TIMEOUT",
                                                              autorestart=False)
            executionsCanceled = Execution.objects.all().filter(author=request.user, machine=machine_connected,status="CANCELED",
                                                                checkpoint="-1")
            for execution in executionsCanceled:
                checks = Execution.objects.all().get(author=request.user, status="CANCELLED+", machine=machine_connected,
                                                     checkpoint=execution.jobID)
                if checks is not None:
                    execution.status = "TIMEOUT"
                    execution.checkpoint = 0
                    execution.save()
                checks.delete()
            """for execution in executionsDone:
                if execution.checkpoint != 0:
                    e = Execution.objects.all().get(author=request.user, jobID=execution.checkpoint)
                    checkpointingFinished(e, request)"""
            request.session["checkConn"] = "yes"
    return render(request, 'accounts/executions.html',
                  {'form': form, 'executions': executions, 'executionsDone': executionsDone,
                   'executionsFailed': executionsFailed, 'executionsTimeout': executionTimeout,
                   "checkConn": request.session["checkConn"]})


def populate_executions_machines(request):
    log.info("POPULATE EXECUTIONS")
    machines = Machine.objects.all().filter(author=request.user)
    machines_done = []
    if machines.count() != 0:
        for machine in machines:
            machines_done.append("" + str(machine.user) + "@" + machine.fqdn)
    return machines_done


class updateExecutions(threading.Thread):
    def __init__(self, token, machine, request):
        threading.Thread.__init__(self)
        self.token = token
        self.machine = machine
        self.request = request
        self.timeout = 120 * 60

    def run(self):
        timeout_start = time.time()
        log.info("PASS HERE")
        while time.time() < timeout_start + self.timeout:
            boolException = update_table(self.token, self.machine, self.request)
            if not boolException:
                break
            time.sleep(2)
        Connection.objects.filter(idConn_id=self.request.session["idConn"]).update(status="Disconnect")
        render_right(self.request)
        return



def update_table(token, machine, request):
    user = machine.split("@")[0]
    fqdn = machine.split("@")[1]
    machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
    log.info("DEBUG POINT")
    log.info(machine)
    request.session["connection_machine"] = machine_found.id
    machineID = machine_found.id
    request.session['machineID'] = machineID
    obj = Key_Gen.objects.filter(machine_id=machineID).get()
    private_key = obj.private_key
    userMachine = machine_found.user
    try:
        content = decrypt(private_key, token).decode()
        request.session["content"] = content
    except:
        print("The token is wrong!")
        return False
    ssh = connection(content, machineID )
    log.info(request.user)
    executions = Execution.objects.all().filter(author=request.user)
    log.info("EXECUTIONS")
    for executionE in executions:
        log.info(executionE)
        stdin, stdout, stderr = ssh.exec_command(
            "sacct -j " + str(executionE.jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
        stdout = stdout.readlines()
        log.info(stdout)
        values = str(stdout).split()
        Execution.objects.filter(jobID=executionE.jobID).update(status=values[4], time=values[3],
                                                                nodes=int(values[2]))
    return True




def connection(content, machineID):
    ssh = paramiko.SSHClient()
    pkey = paramiko.RSAKey.from_private_key(StringIO(content))
    machine_found = Machine.objects.get(id=machineID)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(machine_found.fqdn, username=machine_found.user, pkey=pkey)
    return ssh


def checkpointingFinished(execution, request):
    if execution.checkpoint != 0:
        e = Execution.objects.all().get(author=request.user, jobID=execution.jobID)
        return checkpointingFinished(e, request)
    else:
        Execution.objects.filter(jobID=execution.jobID).update(status="FINISHED_CHECKPOINTED")
        return


def stopExecution(jobIDstop, request):
    ssh = connection(request.session['content'], request.session['machineID'])
    command = "scancel " + jobIDstop
    stdin, stdout, stderr = ssh.exec_command(command)
    form = ExecutionForm()
    executions = Execution.objects.all().filter(author=request.user).filter(Q(status="PENDING") | Q(status="RUNNING"))
    executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED")
    executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED")
    executionTimeout = Execution.objects.all().filter(author=request.user, status="TIMEOUT", autorestart=False)
    return render(request, 'accounts/executions.html',
                  {'form': form, 'executions': executions, 'executionsDone': executionsDone,
                   'executionsFailed': executionsFailed, 'executionsTimeout': executionTimeout})


class myThread(threading.Thread):
    def __init__(self, jobID, request, time):
        threading.Thread.__init__(self)
        self.jobID = jobID
        self.request = request
        self.time = time

    def run(self):
        time.sleep(int(self.time) * 60)
        wait_timeout_new(self.jobID, self.request)
        return


def wait_timeout_new(jobID, request):
    execution = Execution.objects.get(jobID=jobID)
    if execution.status != "TIMEOUT":
        time.sleep(15)
        wait_timeout_new(jobID, request)
    else:
        checkpointing(jobIDCheckpoint=jobID, request=request)
    return


def monitor_checkpoint(jobID, request, execTime):
    thread1 = myThread(jobID, request, execTime)
    thread1.start()
    return


def checkpointing(jobIDCheckpoint, request):
    ssh = connection(request.session['content'], request.session['machineID'])
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    machine_connected = Machine.objects.get(id=request.session["connection_machine"])
    machine_folder = extract_substring(machine_connected.fqdn)
    command = "source /etc/profile; cd "+machine_connected.installDir+"/scripts/"+machine_folder+"/; sh app-checkpoint.sh " + checkpointID.user + " " + checkpointID.name_workflow + " " + checkpointID.workflow_path + " " + checkpointID.wdir + " " + str(
        checkpointID.nodes) + " " + str(checkpointID.execution_time) + " " + checkpointID.qos + " " + machine_connected.installDir
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout = stdout.readlines()
    s = "Submitted batch job"
    time = 0
    while (len(stdout) == 0):
        time.sleep(1)
    if (len(stdout) > 1):
        for line in stdout:
            if (s in line):
                jobID = int(line.replace(s, ""))
                request.session['jobID'] = jobID
                form = Execution()
                form.jobID = request.session['jobID']
                form.user = checkpointID.user
                form.author = request.user
                form.nodes = checkpointID.nodes
                form.status = "PENDING"
                form.checkpoint = jobIDCheckpoint
                form.time = "00:00:00"
                form.wdir = checkpointID.wdir
                form.workflow_path = checkpointID.workflow_path
                form.execution_time = int(checkpointID.execution_time)
                time = int(checkpointID.execution_time)
                form.name_workflow = checkpointID.name_workflow
                form.qos = checkpointID.qos
                form.name_sim = checkpointID.name_sim
                form.autorestart = checkpointID.autorestart
                form.save()
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    checkpointID.status = "CONTINUE"
    checkpointID.save()
    monitor_checkpoint(jobID=request.session['jobID'], request=request, execTime=time)
    return


def checkpointing_noAutorestart(jobIDCheckpoint, request):
    ssh = connection(request.session['content'], request.session['machineID'])
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    machine_connected = Machine.objects.get(id=request.session["connection_machine"])
    machine_folder = extract_substring(machine_connected.fqdn)
    command = "source /etc/profile; cd "+machine_connected.installDir+"/scripts/"+machine_folder+"/; sh app-checkpoint.sh " + checkpointID.user + " " + checkpointID.name_workflow + " " + checkpointID.workflow_path + " " + checkpointID.wdir + " " + str(
        checkpointID.nodes) + " " + str(checkpointID.execution_time) + " " + checkpointID.qos + " " + machine_connected.installDir
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout = stdout.readlines()
    s = "Submitted batch job"
    time = 0
    while (len(stdout) == 0):
        time.sleep(1)
    if (len(stdout) > 1):
        for line in stdout:
            if (s in line):
                jobID = int(line.replace(s, ""))
                request.session['jobID'] = jobID
                form = Execution()
                form.jobID = request.session['jobID']
                form.user = checkpointID.user
                form.author = request.user
                form.nodes = checkpointID.nodes
                form.status = "PENDING"
                form.checkpoint = jobIDCheckpoint
                form.time = "00:00:00"
                form.wdir = checkpointID.wdir
                form.workflow_path = checkpointID.workflow_path
                form.execution_time = int(checkpointID.execution_time)
                time = int(checkpointID.execution_time)
                form.name_workflow = checkpointID.name_workflow
                form.qos = checkpointID.qos
                form.name_sim = checkpointID.name_sim
                form.autorestart = checkpointID.autorestart
                form.save()
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    checkpointID.status = "CONTINUE"
    checkpointID.save()
    return


def execution_failed(request):  # used to show a page when a execution ended with a bad results
    if request.method == 'POST':
        print("")
    else:
        jobID = request.session['jobIDfailed']
        ssh = connection(request.session['content'], request.session['machineID'])
        executionDone = Execution.objects.all().filter(jobID=jobID)
        stdin, stdout, stderr = ssh.exec_command(
            "sacct -j " + str(jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
        stdout = stdout.readlines()
        values = str(stdout).split()
        Execution.objects.filter(jobID=jobID).update(status=values[4], time=values[3], nodes=int(values[2]))
        stdin, stdout, stderr = ssh.exec_command(
            "source /etc/profile; scp ")
        file = "compss-" + jobID
        executionGet = Execution.objects.get(jobID=jobID)
        pathOut = executionGet.wdir + "/" + file + ".out"
        pathErr = executionGet.wdir + "/" + file + ".err"
    return render(request, 'accounts/execution_failed.html',
                  {'executionsDone': executionGet, 'pathOut': pathOut, 'pathErr': pathErr})


def create_workflow(request):
    if request.method == 'POST':
        form = WorkFlowForm(request.POST)
        if form.is_valid():
            messages.success(request, f'Your workflow has been created. You can log in now!')
            return redirect('accounts:home')
    else:
        form = WorkFlowForm()
    return render(request, 'accounts/create_workflow.html', {'form': form})


def read_and_write(name):
    with open("documents/" + str(name)) as file:
        try:
            workflow = yaml.safe_load(file)
            return workflow
        except yaml.YAMLError as exc:
            print(exc)
    return None


def ssh_keys_result(request):
    if request.method == 'POST':
        return redirect('accounts:dashboard')
    else:
        return redirect('accounts:dashboard')


def ssh_keys_generation(request):  # method to generate the ssh keys of a specific machine
    if request.method == 'POST':
        form = Key_Gen_Form(request.POST)
        if form.is_valid():
            if 'reuse_token_button' in request.POST:  # if the user has more than 1 Machine, he can decide to use the same SSH keys and token for all its machines
                machine = request.POST.get('machineChoice')
                user = machine.split("@")[0]
                fqdn = machine.split("@")[1]
                machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
                instance = form.save(commit=False)
                instance.author = request.user
                instance.machine = machine_found
                instance.public_key = Key_Gen.objects.get(author=instance.author).public_key
                instance.private_key = Key_Gen.objects.get(author=instance.author).private_key
                instance.save()
                request.session['warning'] = "first"
                return redirect('accounts:dashboard')
            else:  # normal generation of the SSH keys
                instance = form.save(commit=False)
                instance.author = request.user
                machine = request.POST.get('machineChoice')  # it's the machine choosen by the user
                user = machine.split("@")[0]
                fqdn = machine.split("@")[1]
                request.userMachine= user
                request.fqdn= fqdn
                machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
                instance.machine = machine_found
                token = Fernet.generate_key()  # to generate a security token
                key = paramiko.RSAKey.generate(2048)  # to generate the SSH keys
                privateString = StringIO()
                key.write_private_key(privateString)
                private_key = privateString.getvalue()
                x = private_key.split("\'")
                private_key = x[0]
                log.info("LLAVE SSH")
                log.info(private_key)
                public_key = key.get_base64()
                enc_private_key = encrypt(private_key.encode(),
                                          token)  # encrypting the private SSH keys using the security token, only the user is allowed to use its SSH keys to connect to its machine
                enc_private_key = str(enc_private_key).split("\'")[1]
                x = str(token).split("\'")
                token = x[1]
                instance.public_key = public_key
                instance.private_key = enc_private_key
                if Key_Gen.objects.filter(author=instance.author, machine=instance.machine).exists():
                    if request.session['warning'] == "first":
                        if (Key_Gen.objects.filter(author=instance.author).count() > 1):
                            request.session['warning'] = "third"
                            return render(request, 'accounts/ssh_keys_generation.html',
                                          {'form': form, 'warning': request.session['warning'],
                                           'machines': populate_executions_machines(request)})
                        else:
                            request.session['warning'] = "second"
                            return render(request, 'accounts/ssh_keys_generation.html',
                                          {'form': form, 'warning': request.session['warning'],
                                           'machines': populate_executions_machines(request)})

                    if (Key_Gen.objects.filter(author=instance.author).count() > 1):
                        Key_Gen.objects.filter(author=instance.author).update(public_key=instance.public_key,
                                                                              private_key=instance.private_key)
                    else:
                        Key_Gen.objects.filter(author=instance.author, machine=instance.machine).update(
                            public_key=instance.public_key, private_key=instance.private_key)
                elif (Key_Gen.objects.filter(author=instance.author).exists()):
                    if request.session['reuse_token'] == "no":
                        request.session['reuse_token'] = "yes"
                        request.session['warning'] = "first"
                        machine = request.POST.get('machineChoice')
                        return render(request, 'accounts/ssh_keys_generation.html',
                                      {'form': form, 'warning': request.session['warning'],
                                       'reuse_token': request.session['reuse_token'],
                                       'machines': populate_executions_machines(request), 'choice': machine})
                else:
                    instance.save()
                for key in list(request.session.keys()):
                    del request.session[key]
                return render(request, 'accounts/ssh_keys_result.html', {'token': token, 'public_key': public_key})
    else:
        form = Key_Gen_Form(initial={'public_key': 123, 'private_key': 123})
        request.session['reuse_token'] = "no"
        request.session['warning'] = "first"
        if not populate_executions_machines(request):
            request.session['firstCheck'] = "yes"
        else:
            request.session['firstCheck'] = "no"
    return render(request, 'accounts/ssh_keys_generation.html',
                  {'form': form, 'warning': request.session['warning'], 'reuse_token': request.session['reuse_token'],
                   'machines': populate_executions_machines(request), 'firstCheck': request.session['firstCheck']})


def machine_definition(request):  # method to create the definition of a new Machine
    if request.method == 'POST':
        form = Machine_Form(request.POST)
        form.author = request.user
        if form.is_valid():
            instance = form.save(commit=False)
            instance.author = request.user
            instance.save()
            return render(request, 'accounts/machine_definition.html', {'form': form, 'flag': 'yes'})
    else:
        form = Machine_Form()
    return render(request, 'accounts/machine_definition.html', {'form': form})


def redefine_machine(request):  # method to redefine the details of a Machine
    if request.method == 'POST':
        form = Machine_Form(request.POST)
        request.session['noMachines'] = "yes"
        if 'chooseButton' in request.POST:
            request.session['firstPhase'] = "no"
            machine = request.POST.get('machineChoice')
            user = machine.split("@")[0]
            fqdn = machine.split("@")[1]
            machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
            machineID = machine_found.id
            request.session['machineID'] = machineID
            form = Machine_Form(
                initial={'fqdn': machine_found.fqdn, 'user': machine_found.user, 'wdir': machine_found.wdir, 'installDir': machine_found.installDir,
                         'id': machine_found.id, 'author': machine_found.author})
            return render(request, 'accounts/redefine_machine.html',
                          {'form': form, 'firstPhase': request.session['firstPhase'],
                           'noMachines': request.session['noMachines']})
        elif 'redefineButton' in request.POST:
            if (form.is_valid()):
                machine_found = Machine.objects.get(id=request.session['machineID'])
                userForm = form['user'].value()
                fqdnForm = form['fqdn'].value()
                wdirForm = form['wdir'].value()
                installDirForM= form['installDir'].value()
                Machine.objects.filter(id=request.session['machineID']).update(user=userForm, wdir=wdirForm,
                                                                               fqdn=fqdnForm, installDir=installDirForM)
                return render(request, 'accounts/redefine_machine.html',
                              {'form': form, 'firstPhase': request.session['firstPhase'], 'flag': 'yes',
                               'noMachines': request.session['noMachines']})
    else:
        form = Machine_Form()
        machines_done = populate_executions_machines(request)
        if not machines_done:
            request.session['noMachines'] = "no"
            request.session['firstPhase'] = "no"
        else:
            request.session['noMachines'] = "yes"
            request.session['firstPhase'] = "yes"
    return render(request, 'accounts/redefine_machine.html',
                  {'form': form, 'machines': machines_done, 'noMachines': request.session['noMachines'],
                   'firstPhase': request.session['firstPhase']})


def home(request):
    return render(request, 'accounts/dashboard.html')


def dashboard(request):
    return render(request, 'accounts/dashboard.html')


def load_workflow(request,path_install_dir, workflow_name):
    ssh = connection(request.session["content"], request.session["machineID"])
    log.info("MACHINE FOUND")
    machine_found = Machine.objects.get(id=request.session['machineID'])
    param_machine= remove_numbers(machine_found.fqdn)
    log.info(param_machine)
    cmd= "source /etc/profile; cd /gpfs/projects/bsce81/alya/tests/workflow_stable/scripts/; sh loadWorkflows.sh "+path_install_dir+" "+workflow_name+" "+param_machine+";"
    log.info(cmd)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout = stdout.readlines()
    stderr = stderr.readlines()
    while (len(stdout) == 0):
        time.sleep(1)
    if (len(stdout) > 1):
        log.info(stdin)
        log.info(stdout)
        log.info(stderr)
    return


def remove_numbers(input_str):
    # Split the input string by '.' to separate the hostname and domain
    parts = input_str.split('.')

    if len(parts) >= 2:
        # Take the first part as the hostname
        hostname = parts[0]

        # Remove any trailing digits from the hostname
        while hostname and hostname[-1].isdigit():
            hostname = hostname[:-1]

        return hostname
    else:
        # If there are not enough parts, return the original string
        return input_str