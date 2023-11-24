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
from accounts.models import Execution, Key_Gen, Machine
from cryptography.fernet import Fernet
from django.db.models import Q
import threading
import random
import string
import configuration as cfg
from ftplib import FTP_TLS

log = logging.getLogger(__name__)

SSH=None

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


def run_sim(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            name = None
            machine = request.POST.get('machineChoice')
            user = machine.split("@")[0]
            fqdn = machine.split("@")[1]
            machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
            machineID = machine_found.id
            request.session['machineID'] = machineID
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
            obj = Key_Gen.objects.filter(author=user, machine_id=machineID).get()
            userMachine = machine_found.user
            ssh = connection(request.session["content"], request.session["machineID"])
            # principal_folder = "/gpfs/projects/bsce81/alya/tests/TestAPIRest/users/" + userMachine + "/executions/"
            principal_folder = machine_found.wdir
            uniqueIDfolder = uuid.uuid4()
            s = "execution_" + str(uniqueIDfolder)
            if not principal_folder.endswith("/"):
                principal_folder = principal_folder + "/"
            wdirDone = principal_folder + "" + s
            cmd1 = "source /etc/profile; cd /gpfs/projects/bsce81/alya/tests/workflow_stable/; mkdir -p " + principal_folder + "/" + s + "/workflows/; echo " + str(
                workflow) + " > " + principal_folder + "/" + s + "/workflows/" + str(
                name) + "; cd " + principal_folder + "; BACKUPDIR=$(ls -td ./*/ | head -1); echo EXECUTION_FOLDER:$BACKUPDIR;"
            stdin, stdout, stderr = ssh.exec_command(cmd1)
            stdout = stdout.readlines()
            execution_folder = wdirDone + "/execution"
            workflow_folder = wdirDone + "/workflows"
            numNodes = request.POST.get('numNodes')
            name_sim = request.POST.get('name_sim')
            if name_sim is None:
                name_sim = get_random_string(8)
            execTime = request.POST.get('execTime')
            auto_restart = request.POST.get("auto_restart")
            auto_restart_bool = False
            if auto_restart == "on":
                auto_restart_bool = True
            request.session['workflow_path'] = workflow_folder
            qos = request.POST.get('qos')
            cmd2 = "source /etc/profile; mkdir -p " + execution_folder + "; cd /gpfs/projects/bsce81/alya/tests/workflow_stable/; sh app-checkpoint.sh " + userMachine + " " + str(
                name) + " " + workflow_folder + " " + execution_folder + " " + numNodes + " " + execTime + " " + qos
            stdin, stdout, stderr = ssh.exec_command(cmd2)
            stdout = stdout.readlines()
            s = "Submitted batch job"
            var = ""
            while (len(stdout) == 0):
                time.sleep(1)
            if (len(stdout) > 1):
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
                        form.save()
            request.session['execution_folder'] = execution_folder
            os.remove("documents/" + str(name))
            if auto_restart_bool:
                monitor_checkpoint(var, request, execTime)
            return redirect('accounts:executions')
    else:
        form = DocumentForm()
        request.session['flag'] = 'first'
    return render(request, 'accounts/run_simulation.html',
                  {'form': form, 'flag': request.session['flag'], 'machines': populate_executions_machines(request)})


def results(request):
    if request.method == 'POST':
        print("")
    else:
        jobID = request.session['jobIDdone']
        ssh = connection(request.session['content'], request.session['content'])
        executionDone = Execution.objects.all().filter(jobID=jobID)
        stdin, stdout, stderr = ssh.exec_command(
            "sacct -j " + str(jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
        stdout = stdout.readlines()
        values = str(stdout).split()
        Execution.objects.filter(jobID=jobID).update(status=values[4], time=values[3], nodes=int(values[2]))
        execUpdate = Execution.objects.get(jobID=jobID)
    return render(request, 'accounts/results.html', {'executionsDone': execUpdate})


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
            checkpointing(request.POST.get("timeoutExecutionValue"), request)
            return redirect('accounts:executions')
        elif 'stopExecution' in request.POST:
            request.session['stopExecutionValue'] = request.POST.get("stopExecutionValue")
            stopExecution(request.POST.get("stopExecutionValue"), request)
        elif 'disconnectButton' in request.POST:
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
            token = request.POST.get("token")
            machine = request.POST.get('machineChoice')
            user = machine.split("@")[0]
            fqdn = machine.split("@")[1]
            machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
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
        ssh = connection(request.session['content'], request.session['machineID'])
        executions = Execution.objects.all().filter(author=request.user)
        for executionE in executions:
            stdin, stdout, stderr = ssh.exec_command(
                "sacct -j " + str(executionE.jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
            stdout = stdout.readlines()
            values = str(stdout).split()
            Execution.objects.filter(jobID=executionE.jobID).update(status=values[4], time=values[3],
                                                                    nodes=int(values[2]))
        executions = Execution.objects.all().filter(author=request.user).filter(
            Q(status="PENDING") | Q(status="RUNNING"))
        executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED")
        executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED")
        executionsCheckpoint = Execution.objects.all().filter(author=request.user, status="TIMEOUT", autorestart=False)
        executionsCanceled = Execution.objects.all().filter(author=request.user, status="CANCELLED+", checkpoint="-1")
        """for execution in executionsCanceled:
            checks = Execution.objects.all().get(author=request.user, status="CANCELLED+", checkpoint=execution.jobID)
            if checks is not None:
                execution.status = "TIMEOUT"
                execution.checkpoint = 0
                execution.save()"""
        """for execution in executionsDone:
            if execution.checkpoint != 0:
                e = Execution.objects.all().get(author=request.user, jobID=execution.checkpoint)
                checkpointingFinished(e, request)"""
        return render(request, 'accounts/executions.html',
                      {'executions': executions, 'executionsDone': executionsDone, 'executionsFailed': executionsFailed,
                       'executionsCheckpoint': executionsCheckpoint, 'checkConn': "yes"})
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
            executions = Execution.objects.all().filter(author=request.user).filter(
                Q(status="PENDING") | Q(status="RUNNING"))
            executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED")
            executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED")
            executionsCheckpoint = Execution.objects.all().filter(author=request.user, status="TIMEOUT")
            executionsCanceled = Execution.objects.all().filter(author=request.user, status="CANCELED", checkpoint="-1")
            for execution in executionsCanceled:
                checks = Execution.objects.all().get(author=request.user, status="CANCELLED+",
                                                     checkpoint=execution.jobID)
                if checks is not None:
                    execution.status = "TIMEOUT"
                    execution.checkpoint = 0
                    execution.save()
                checks.delete()
            for execution in executionsDone:
                if execution.checkpoint != 0:
                    e = Execution.objects.all().get(author=request.user, jobID=execution.checkpoint)
                    checkpointingFinished(e, request)
            request.session["checkConn"] = "yes"
    return render(request, 'accounts/executions.html',
                  {'form': form, 'executions': executions, 'executionsDone': executionsDone,
                   'executionsFailed': executionsFailed, 'executionsCheckpoint': executionsCheckpoint,
                   "checkConn": request.session["checkConn"]})


def populate_executions_machines(request):
    machines = Machine.objects.all().filter(author=request.user)
    machines_done = []
    if machines.count() != 0:
        for machine in machines:
            machines_done.append("" + str(machine.user) + "@" + machine.fqdn)
    return machines_done


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
        checkpointingFinished(e, request)
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
    executionsCheckpoint = Execution.objects.all().filter(author=request.user, status="TIMEOUT", autorestart=True)
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
        ssh = connection(self.request.session['content'], self.request.session['machineID'])
        wait_timeout(self.jobID, self.request, ssh)
        return


def wait_timeout(jobID, request, ssh):
    stdin, stdout, stderr = ssh.exec_command(
        "sacct -j " + str(jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
    stdout = stdout.readlines()
    values = str(stdout).split()
    if values[4] != "TIMEOUT":
        time.sleep(15)
        wait_timeout(jobID, request, ssh)
    else:
        Execution.objects.filter(jobID=jobID).update(status=values[4], time=values[3],
                                                     nodes=int(values[2]))
        checkpointing(jobIDCheckpoint=jobID, request=request)
    return


def monitor_checkpoint(jobID, request, execTime):
    thread1 = myThread(jobID, request, execTime)
    thread1.start()
    return


def checkpointing(jobIDCheckpoint, request):
    ssh = connection(request.session['content'], request.session['machineID'])
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    command = "source /etc/profile; cd /gpfs/projects/bsce81/alya/tests/workflow_stable/; sh app-checkpoint.sh " + checkpointID.user + " " + checkpointID.name_workflow + " " + checkpointID.workflow_path + " " + checkpointID.wdir + " " + str(
        checkpointID.nodes) + " " + str(checkpointID.execution_time) + " " + checkpointID.qos
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


def execution_failed(request):
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


def ssh_keys_generation(request):
    if request.method == 'POST':
        form = Key_Gen_Form(request.POST)
        if form.is_valid():
            if 'reuse_token_button' in request.POST:
                instance = form.save(commit=False)
                instance.author = request.user
                machine = request.POST.get('machineChoice')
                user = machine.split("@")[0]
                fqdn = machine.split("@")[1]
                machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
                instance.machine = machine_found
                instance.public_key = Key_Gen.objects.get(author=instance.author).public_key
                instance.private_key = Key_Gen.objects.get(author=instance.author).private_key
                request.session['warning'] = "first"
                instance.save()
                return redirect('accounts:dashboard')
            else:
                instance = form.save(commit=False)
                instance.author = request.user
                machine = request.POST.get('machineChoice')
                user = machine.split("@")[0]
                fqdn = machine.split("@")[1]
                machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
                instance.machine = machine_found
                token = Fernet.generate_key()
                key = paramiko.RSAKey.generate(2048)
                privateString = StringIO()
                key.write_private_key(privateString)
                private_key = privateString.getvalue()
                x = private_key.split("\'")
                private_key = x[0]
                public_key = key.get_base64()
                enc_private_key = encrypt(private_key.encode(), token)
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


def machine_definition(request):
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


def redefine_machine(request):
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
                initial={'fqdn': machine_found.fqdn, 'user': machine_found.user, 'wdir': machine_found.wdir,
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
                Machine.objects.filter(id=request.session['machineID']).update(user=userForm, wdir=wdirForm,
                                                                               fqdn=fqdnForm)
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


def ftp_file_mesh():
    client = FTP_TLS()
    client.connect(host=cfg.host, port=cfg.port)
    client.login(user=cfg.user, passwd=cfg.passwd)
    client.dir()
    client.cwd(cfg.folder)
    os.makedirs("/home/ubuntu/meshs")  # create local backup directory
    os.chdir("/home/ubuntu/meshs")  # change working directory to local backup directory
    file_list = []
    client.retrlines('LIST', lambda x: file_list.append(x.split()))
    for info in file_list:
        ls_type, name = info[0], info[-1]
        if not ls_type.startswith('d'):
            with open(name, 'wb') as f:
                client.retrbinary('RETR {}'.format(f), f.write)
    client.close()

