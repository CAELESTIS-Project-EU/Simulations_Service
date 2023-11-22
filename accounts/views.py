import ftplib
import uuid
from io import StringIO
from django.shortcuts import render, redirect
from .forms import CreateUserForm, WorkFlowForm, DocumentForm, ExecutionForm, Key_Gen_Form, Machine_Form, Mesh_Form
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import yaml
import paramiko
import time
import logging
from accounts.models import Execution, Key_Gen, Machine, Connection, Mesh, userMesh
from cryptography.fernet import Fernet
from django.db.models import Q
import threading
import random
import string
import re
import os
import subprocess
import requests
import configuration as cfg
from ftplib import FTP_TLS
from rest_framework.authtoken.models import Token
from stat import S_ISDIR

log = logging.getLogger(__name__)


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(token: bytes, key: bytes) -> bytes:
    try:
        res = Fernet(key).decrypt(token)
    except Exception as e:
        log.error("Error decrypting token: %s", str(e))
        raise
    return res


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
            user = form.save()

            messages.success(request, 'Your account has been created! You can log in now!')
            return redirect('accounts:login', )  # Pass the token key as context
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


def scp_upload_code_folder(local_path, remote_path, content, machineID, branch):
    res = get_github_code(branch)  # Assuming this is part of your existing code

    ssh = paramiko.SSHClient()
    pkey = paramiko.RSAKey.from_private_key(StringIO(content))
    machine_found = Machine.objects.get(id=machineID)  # Your custom model

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(machine_found.fqdn, username=machine_found.user, pkey=pkey)
    sftp = ssh.open_sftp()

    # Check and create remote folder if it doesn't exist
    remote_dirs = remote_path.split('/')
    current_dir = ''
    for dir in remote_dirs:
        if dir:
            current_dir += '/' + dir
            try:
                sftp.stat(current_dir)
            except FileNotFoundError:
                sftp.mkdir(current_dir)

    if res:
        # Recursively upload the local folder and its contents
        for root, dirs, files in os.walk(local_path + "/" + branch):
            # Calculate the relative path from local_path to root
            relative_root = os.path.relpath(root, local_path + "/" + branch)
            # Skip the creation of the root directory itself
            if relative_root == '.':
                remote_dir = remote_path
            else:
                remote_dir = os.path.join(remote_path, relative_root)
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    sftp.mkdir(remote_dir)

            for file in files:
                local_file = os.path.join(root, file)
                remote_file = os.path.join(remote_dir, file)
                sftp.put(local_file, remote_file)

    sftp.close()
    return


def is_file_or_folder(path):
    if '.' in os.path.basename(path) and not path.endswith('.'):
        return False
    else:
        return True


def scp_upload_input_folder(local_path, remote_path, content, machineID):
    ssh = paramiko.SSHClient()
    pkey = paramiko.RSAKey.from_private_key(StringIO(content))
    machine_found = Machine.objects.get(id=machineID)  # Assuming this is your custom code

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(machine_found.fqdn, username=machine_found.user, pkey=pkey)
    sftp = ssh.open_sftp()

    # Split the remote path and create directories if they don't exist
    remote_dirs = remote_path.split('/')
    current_dir = ''
    for dir in remote_dirs:
        if dir:
            if is_file_or_folder(dir):
                current_dir += '/' + dir
                try:
                    sftp.stat(current_dir)
                except FileNotFoundError:
                    sftp.mkdir(current_dir)
    # Recursively upload the local folder and its contents
    for root, dirs, files in os.walk(local_path):
        if files:
            for file in files:
                if root == local_path:
                    file_upload(root, file, remote_path, sftp)

    for root, dirs, files in os.walk(local_path):
        for dir in dirs:
            try:
                sftp.stat(remote_path + "/" + dir)
            except FileNotFoundError:
                sftp.mkdir(remote_path + "/" + dir)
            check_folder(local_path + "/" + dir, remote_path + "/" + dir, sftp)
    sftp.close()

    return


def check_folder(local_path, remote_path, sftp):
    for root, dirs, files in os.walk(local_path, followlinks=False):
        if files:
            for file in files:
                file_upload(local_path, file, remote_path, sftp)
        if dirs:
            for dirFile in dirs:
                try:
                    sftp.stat(remote_path + "/" + dirFile)
                except FileNotFoundError:
                    sftp.mkdir(remote_path + "/" + dirFile)
                return check_folder(local_path + "/" + dirFile, remote_path + "/" + dirFile, sftp)
    return


def file_upload(root, file, remote_dir, sftp):
    local_file = os.path.join(root, file)
    remote_file = os.path.join(remote_dir, file)
    sftp.put(local_file, remote_file)
    return


def api_token(request):
    if request.method == 'POST':
        try:
            token = Token.objects.get(user=request.user)
            token.delete()
        except Token.DoesNotExist:
            log.error("Token does not exist.")

        # Create a new token
        token, created = Token.objects.get_or_create(user=request.user)

        # The render call should include the request as the first parameter
        return render(request, 'accounts/token-api.html', {'token': token.key})

    # For a GET request, just show the page without the token context
    return render(request, 'accounts/token-api.html')


def get_github_code(branch_name):
    script_path = '/var/www/API_REST/gitClone.sh'

    try:
        result = subprocess.run([script_path, branch_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check the output
        if "Repository not found. Cloning repository..." in result.stdout:
            return True
        elif "Changes detected. Pulling latest changes..." in result.stdout:
            return True
        else:
            if result.stderr:
                log.error("Error:", result.stderr)
    except subprocess.CalledProcessError as e:
        log.error(f"Script execution failed with error code {e.returncode}: {e.stderr.decode('utf-8')}")
    except FileNotFoundError:
        log.error(f"Error: The script '{script_path}' was not found.")
    return False


def get_github_repo_branches():
    repo_url = "https://github.com/CAELESTIS-Project-EU/Workflows"
    """
    Given a GitHub repository URL, this function returns a list of available branches in that repository.
    """
    # Extract the user/repo from the URL
    user_repo = repo_url.split("github.com/")[1]
    # GitHub API endpoint to get branches
    api_url = f"https://api.github.com/repos/{user_repo}/branches"

    # Make the API request
    response = requests.get(api_url)

    # Check if the response is successful
    if response.status_code == 200:
        branches = response.json()
        return [branch['name'] for branch in branches]
    else:
        return f"Error: Unable to access the GitHub repository. Status code: {response.status_code}"


def delete_github_code():
    script_path = '/var/www/API_REST/deleteCode.sh'
    try:
        subprocess.run(['bash', script_path], check=True)
    except subprocess.CalledProcessError as e:
        log.error(f"Script execution failed with error code {e.returncode}: {e.stderr.decode('utf-8')}")
    except FileNotFoundError:
        log.error(f"Error: The script '{script_path}' was not found.")
    return


def get_machine(request):
    return Machine.objects.get(id=request.session['machine_chosen']).id


def get_id_from_string(machine, author):
    user, fqdn = get_name_fqdn(machine)
    machine_found = Machine.objects.get(author=author, user=user, fqdn=fqdn)
    return machine_found.id


def get_status(eID, request):
    machine_found = Machine.objects.get(id=request.session['machine_chosen'])
    machineID = machine_found.id
    ssh = connection(request.session["content"], machineID)
    executions = Execution.objects.all().filter(author=request.user, machine=request.session['machine_chosen']).filter(
        Q(status="PENDING") | Q(status="RUNNING") | Q(status="INITIALIZING"))
    for executionE in executions:
        if executionE.jobID != 0:
            stdin, stdout, stderr = ssh.exec_command(
                "sacct -j " + str(executionE.jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
            stdout = stdout.readlines()
            values = str(stdout).split()
            Execution.objects.filter(jobID=executionE.jobID).update(status=values[4], time=values[3],
                                                                    nodes=int(values[2]))
    try:
        execution = Execution.objects.get(eID=eID)
    except:
        raise ValueError("The execution doesn't exist", 0)
    return execution


def stop_execution_api(eID, request):
    ssh = connection(request.session['content'], request.session['machine_chosen'])
    try:
        exec = Execution.objects.filter(eID=eID).get()
        if exec.eID != 0:
            command = "scancel " + str(exec.jobID)
            stdin, stdout, stderr = ssh.exec_command(command)
        Execution.objects.filter(eID=eID).update(status="CANCELLED+")
    except:
        raise ValueError("The execution doesn't exist", 0)
    return True


def restart_execution_api(eID, request):
    exec = Execution.objects.filter(eID=eID).get()
    if exec.jobID != 0:
        checkpointing_noAutorestart(exec.jobID, request)
    else:
        raise ValueError("The execution is in the initialing phase", 0)
    return


def get_name_fqdn(machine):
    user = machine.split("@")[0]
    fqdn = machine.split("@")[1]
    return user, fqdn


def wdir_folder(principal_folder):
    uniqueIDfolder = uuid.uuid4()
    nameWdir = "execution_" + str(uniqueIDfolder)
    if not principal_folder.endswith("/"):
        principal_folder = principal_folder + "/"
    wdirDone = principal_folder + "" + nameWdir
    return wdirDone, nameWdir


def ensure_local_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)


def download_folder(ftp_conn, ftp_folder_path, local_folder_path):
    ensure_local_directory_exists(local_folder_path)
    # List items in the FTP directory
    items = ftp_conn.nlst(ftp_folder_path)
    for item in items:
        local_item_path = os.path.join(local_folder_path, get_last_directory(item))
        ftp_item_path = item

        # Check if the item is a file or a folder
        if '.' in os.path.basename(item):  # Assuming files have extensions
            with open(local_item_path, 'wb') as file:
                ftp_conn.retrbinary(f'RETR {ftp_item_path}', file.write)
        else:
            download_folder(ftp_conn, ftp_item_path, local_item_path)
    return


def extract_path_and_filename(url):
    match = re.match(r'^ftp://[^/]+(/.+?)/([^/]+)$', url)
    if match:
        path = match.group(1)
        filename = match.group(2)
        return path, filename
    else:
        return None, None


def is_file_with_extension(filename):
    return '.' in filename


def get_last_directory(file_path):
    # Strip the trailing slash, if any
    if file_path.endswith('/'):
        file_path = os.path.dirname(file_path)

    # Then get the base name
    return os.path.basename(file_path)


def download_input(workflow, request, machineID):
    client = FTP_TLS()
    try:
        client.connect(host=cfg.host, port=cfg.port)
        client.login(user=cfg.user, passwd=cfg.passw)
    except ConnectionError as conn_error:
        # Handle connection-related errors
        log.error(f"Connection Error: {conn_error}")
    except TimeoutError as timeout_error:
        # Handle timeout-related errors
        log.error(f"Timeout Error: {timeout_error}")
    except Exception as e:
        # Handle other exceptions
        log.error(f"An error occurred: {e}")
    local_target_directory = '/home/ubuntu/inputFiles/'
    client.prot_p()  # Switch to secure data connection
    client.set_debuglevel(2)
    machine_found = Machine.objects.get(id=request.session['machine_chosen'])
    for key, items in workflow['input'].items():
        server = folder = None
        # Iterate through each item in the category
        for item in items:
            if 'server' in item:
                server = item['server']
            elif 'path' in item:
                folder = item['path']
        bool = True
        # After iterating through all items, check if both server and folder are found
        bool = server and folder
        if not server:
            log.error(f"YAML is not described well for {key}: missing server")
        if not folder:
            log.error(f"YAML is not described well for {key}: missing folder")
        if bool:

            path, filename = extract_path_and_filename(server)
            if is_file_with_extension(filename):
                last_dir = get_last_directory(path)
                full_path_to_check = os.path.join(local_target_directory, last_dir)
                if not os.path.exists(full_path_to_check):
                    download_folder(client, path, full_path_to_check)
                scp_upload_input_folder(full_path_to_check, os.path.join(machine_found.dataDir, last_dir),
                                        request.session['content'], machineID)
            else:
                full_path_to_check = os.path.join(local_target_directory, folder)
                if not os.path.exists(full_path_to_check):
                    ftp_folder_path = path + "/" + filename + "/"
                    local_folder_path = full_path_to_check
                    ensure_local_directory_exists(local_folder_path)
                    items = client.nlst(ftp_folder_path)
                    for item in items:
                        local_item_path = os.path.join(local_folder_path, os.path.basename(item))
                        ftp_item_path = item

                        # Check if the item is a file or a folder
                        if '.' in os.path.basename(item):  # Assuming files have extensions
                            with open(local_item_path, 'wb') as file:
                                client.retrbinary(f'RETR {ftp_item_path}', file.write)
                        else:
                            download_folder(client, ftp_item_path, local_item_path)

                scp_upload_input_folder(full_path_to_check, os.path.join(machine_found.dataDir, folder),
                                        request.session['content'], machineID)
    client.quit()
    return


class run_sim_async(threading.Thread):
    def __init__(self, request, name, numNodes, name_sim, execTime, qos, checkpoint_bool, auto_restart_bool, eID,
                 branch):
        threading.Thread.__init__(self)
        self.request = request
        self.name = name
        self.numNodes = numNodes
        self.name_sim = name_sim
        self.execTime = execTime
        self.qos = qos
        self.checkpoint_bool = checkpoint_bool
        self.auto_restart_bool = auto_restart_bool
        self.eiD = eID
        self.branch = branch

    def run(self):
        machine_found = Machine.objects.get(id=self.request.session['machine_chosen'])
        fqdn = machine_found.fqdn
        machine_folder = extract_substring(fqdn)
        workflow = read_and_write(self.name)
        userMachine = machine_found.user
        workflow_name = workflow.get("workflow_type")
        principal_folder = machine_found.wdir
        wdirPath, nameWdir = wdir_folder(principal_folder)
        cmd1 = "source /etc/profile; mkdir -p " + principal_folder + "/" + nameWdir + "/workflows/; echo " + str(
            workflow) + " > " + principal_folder + "/" + nameWdir + "/workflows/" + str(
            self.name) + "; cd " + principal_folder + "; BACKUPDIR=$(ls -td ./*/ | head -1); echo EXECUTION_FOLDER:$BACKUPDIR;"
        ssh = connection(self.request.session["content"], machine_found.id)
        stdin, stdout, stderr = ssh.exec_command(cmd1)

        execution_folder = wdirPath + "/execution"
        workflow_folder = wdirPath + "/workflows"

        alya_output_server = None
        for item in workflow.get('outputs', {}).get('alya-output', []):
            if 'server' in item:
                alya_output_server = item['server']
                break
        if alya_output_server:
            Execution.objects.filter(eID=self.eiD).update(wdir=execution_folder, workflow_path=workflow_folder,
                                                          name_workflow=workflow_name, results_ftp_path=alya_output_server)
        else:
            Execution.objects.filter(eID=self.eiD).update(wdir=execution_folder, workflow_path=workflow_folder,
                                                          name_workflow=workflow_name,
                                                          results_ftp_path=alya_output_server)
        self.request.session['workflow_path'] = workflow_folder

        path_install_dir = os.path.join(machine_found.installDir, self.branch)
        param_machine = remove_numbers(machine_found.fqdn)






        local_folder = "/home/ubuntu/installDir"
        scp_upload_code_folder(local_folder, path_install_dir, self.request.session["content"], machine_found.id,
                               self.branch)
        download_input(workflow, self.request, machine_found.id)
        if self.checkpoint_bool:
            cmd2 = "source /etc/profile;  source " + path_install_dir + "/scripts/load.sh " + path_install_dir + " " + param_machine + "; mkdir -p " + execution_folder + "; cd " + path_install_dir + "/scripts/" + machine_folder + "/;  source app-checkpoint.sh " + userMachine + " " + str(
                self.name) + " " + workflow_folder + " " + execution_folder + " " + self.numNodes + " " + self.execTime + " " + self.qos + " " + machine_found.installDir + " " + self.branch + " " + machine_found.dataDir
        else:
            cmd2 = "source /etc/profile;  source " + path_install_dir + "/scripts/load.sh " + path_install_dir + " " + param_machine + "; mkdir -p " + execution_folder + "; cd " + path_install_dir + "/scripts/" + machine_folder + "/; source app.sh " + userMachine + " " + str(
                self.name) + " " + workflow_folder + " " + execution_folder + " " + self.numNodes + " " + self.execTime + " " + self.qos + " " + machine_found.installDir + " " + self.branch + " " + machine_found.dataDir
        log.info("COMMAND")
        log.info(cmd2)
        stdin, stdout, stderr = ssh.exec_command(cmd2)
        stdout = stdout.readlines()
        stderr = stderr.readlines()
        s = "Submitted batch job"
        var = ""
        while (len(stdout) == 0):
            time.sleep(1)
        if (len(stdout) > 1):
            for line in stdout:
                if (s in line):
                    jobID = int(line.replace(s, ""))
                    Execution.objects.filter(eID=self.eiD).update(jobID=jobID, status="PENDING")
                    self.request.session['jobID'] = jobID
        self.request.session['execution_folder'] = execution_folder
        os.remove("documents/" + str(self.name))
        if self.auto_restart_bool:
            monitor_checkpoint(var, self.request, self.execTime, machine_found.id)
        return


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
            branch = request.POST.get('branchChoice')
            for filename, file in request.FILES.items():
                uniqueID = uuid.uuid4()
                nameE = (str(file).split(".")[0]) + "_" + str(uniqueID) + "." + str(file).split(".")[1]
            name = nameE
            document = form.save(commit=False)
            document.document.name = name
            document.save()
            numNodes = request.POST.get('numNodes')
            name_sim = request.POST.get('name_sim')
            qos = request.POST.get('qos')
            execTime = request.POST.get('execTime')
            checkpoint_flag = request.POST.get("checkpoint_flag")
            auto_restart = request.POST.get("auto_restart")
            if name_sim is None:
                name_sim = get_random_string(8)
            checkpoint_bool = False
            if checkpoint_flag == "on":
                checkpoint_bool = True
            auto_restart_bool = False
            if auto_restart == "on":
                auto_restart_bool = True
            if auto_restart_bool:
                checkpoint_bool = True
            eID = start_exec(numNodes, name_sim, execTime, qos, name, request, auto_restart_bool)
            run_sim = run_sim_async(request, name, numNodes, name_sim, execTime, qos, checkpoint_bool,
                                    auto_restart_bool, eID, branch)
            run_sim.start()
            return redirect('accounts:executions')

    else:
        form = DocumentForm()
        request.session['flag'] = 'first'
        branches = get_github_repo_branches()
        checkConnBool = checkConnection(request)
        if not checkConnBool:
            machines_done = populate_executions_machines(request)
            if not machines_done:
                request.session['firstCheck'] = "no"
            request.session["checkConn"] = "Required"
            return render(request, 'accounts/executions.html',
                          {'machines': machines_done, 'checkConn': "no"})
    return render(request, 'accounts/run_simulation.html',
                  {'form': form, 'flag': request.session['flag'], 'machines': populate_executions_machines(request),
                   'machine_chosen': request.session['nameConnectedMachine'], 'branches': branches})


def start_exec(numNodes, name_sim, execTime, qos, name, request, auto_restart_bool):
    machine_found = Machine.objects.get(id=request.session['machine_chosen'])
    userMachine = machine_found.user
    principal_folder = machine_found.wdir
    uID = uuid.uuid4()
    form = Execution()
    form.eID = uID
    form.jobID = 0
    form.user = userMachine
    form.author = request.user
    form.nodes = numNodes
    form.status = "INITIALIZING"
    form.checkpoint = 0
    form.time = "00:00:00"
    form.wdir = "INITIALIZING"
    form.workflow_path = "INITIALIZING"
    form.execution_time = int(execTime)
    form.name_workflow = "INITIALIZING"
    form.qos = qos
    form.name_sim = name_sim
    form.autorestart = auto_restart_bool
    form.machine = machine_found
    form.results_ftp_path = ""
    form.save()
    return uID


def results(request):
    if request.method == 'POST':
        pass
    else:
        jobID = request.session['jobIDdone']
        ssh = connection(request.session['content'], request.session['machine_chosen'])
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


def delete_parent_folder(path, ssh):
    parent_folder = os.path.dirname(path)
    command = "rm -rf " + parent_folder + "/"
    stdin, stdout, stderr = ssh.exec_command(command)
    return


def deleteExecution(eIDdelete, request):
    ssh = connection(request.session['content'], request.session['machine_chosen'])
    exec = Execution.objects.filter(eID=eIDdelete).get()
    delete_parent_folder(exec.wdir, ssh)
    if exec.eID != 0:
        command = "scancel " + str(exec.jobID)
        stdin, stdout, stderr = ssh.exec_command(command)
    Execution.objects.filter(eID=eIDdelete).delete()
    form = ExecutionForm()
    executions = Execution.objects.all().filter(author=request.user).filter(
        Q(status="PENDING") | Q(status="RUNNING") | Q(status="INITIALIZING"))
    executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED")
    executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED")
    executionTimeout = Execution.objects.all().filter(author=request.user, status="TIMEOUT", autorestart=False)
    return render(request, 'accounts/executions.html',
                  {'form': form, 'executions': executions, 'executionsDone': executionsDone,
                   'executionsFailed': executionsFailed, 'executionsTimeout': executionTimeout})


def deleteExecutionHTTP(eIDdelete, request):
    ssh = connection(request.session['content'], request.session['machine_chosen'])
    try:
        exec = Execution.objects.filter(eID=eIDdelete).get()
        delete_parent_folder(exec.wdir, ssh)
        if exec.eID != 0:
            command = "scancel " + str(exec.jobID)
            stdin, stdout, stderr = ssh.exec_command(command)
        Execution.objects.filter(eID=eIDdelete).delete()
        return
    except:
        raise ValueError("The execution doesn't exist", 0)


def ensure_ftp_directory_exists(ftp_conn, path):
    try:
        ftp_conn.cwd(path)
    except Exception as e:
        base_dir, _, folder = path.rpartition('/')
        ensure_ftp_directory_exists(ftp_conn, base_dir)
        ftp_conn.mkd(path)
        ftp_conn.cwd(path)


def upload_folder(ftp_conn, folder_path, ftp_folder_path):
    log.info("upload_folder")
    ftp_conn.dir()
    ensure_ftp_directory_exists(ftp_conn, ftp_folder_path)

    for item in os.listdir(folder_path):
        log.info("upload_folder item: "+str(item))
        local_item_path = os.path.join(folder_path, item)
        ftp_item_path = os.path.join(ftp_folder_path, item)
        log.info("local_item_path: " + str(local_item_path))
        log.info("ftp_item_path: " + str(ftp_item_path))
        if os.path.isdir(local_item_path):
            upload_folder(ftp_conn, local_item_path, ftp_item_path)
        else:
            with open(local_item_path, 'rb') as file:
                log.info("STOR "+str(ftp_item_path))
                ftp_conn.storbinary(f'STOR {ftp_item_path}', file)
    return


def get_last_subdirectory(url):
    # Split the URL by '/' and get the last element
    return url.rstrip('/').split('/')[-1]


def get_url_without_last_subdirectory(url):
    # Split the URL by '/' and remove the last element
    parts = url.split('/')[:-1]
    # Join the remaining parts back together
    return '/'.join(parts)


def download_directory(sftp, remote_dir, local_dir):
    log.info("download_directory")
    os.makedirs(local_dir, exist_ok=True)
    log.info(str(sftp.listdir_attr(remote_dir)))
    for item in sftp.listdir_attr(remote_dir):
        log.info(str(item))
        remote_item = f"{remote_dir}/{item.filename}"
        local_item = os.path.join(local_dir, item.filename)
        log.info("remote_item: "+str(remote_item))
        log.info("local_item: "+str(local_item))
        if S_ISDIR(item.st_mode):  # Check if it's a folder
            log.info("download_directory 1")
            download_directory(sftp, remote_item, local_item)
        else:  # It's a file, download it
            log.info("download_directory 2")
            sftp.get(remote_item, local_item)
    return


def copy_folder_hpc_to_service(request, service_local_path, remote_hpc_path):
    log.info("copy_folder_hpc_to_service")
    ssh = paramiko.SSHClient()
    pkey = paramiko.RSAKey.from_private_key(StringIO(request.session["content"]))
    machine_found = Machine.objects.get(id=request.session['machine_chosen'])  # Assuming this is your custom code

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(machine_found.fqdn, username=machine_found.user, pkey=pkey)
    sftp = ssh.open_sftp()
    log.info("copy_folder_hpc_to_service download_directory")
    download_directory(sftp, remote_hpc_path, service_local_path)
    sftp.close()
    ssh.close()
    return


def upload_results(request, ftp_folder_path, hpc_folder_path):
    log.info("upload_results")
    local_service_folder = os.path.join("/home/ubuntu/uploadResults", get_last_subdirectory(ftp_folder_path))
    copy_folder_hpc_to_service(request, local_service_folder, hpc_folder_path)
    client = FTP_TLS()
    client.connect(host=cfg.host, port=cfg.port)
    client.login(user=cfg.user, passwd=cfg.passw)
    client.prot_p()  # Switch to secure data connection
    log.info("upload_results upload_results")
    upload_folder(client, local_service_folder, get_url_without_last_subdirectory(ftp_folder_path))

    client.quit()
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
        elif 'deleteExecution' in request.POST:
            request.session['deleteExecutionValue'] = request.POST.get("deleteExecutionValue")
            deleteExecution(request.POST.get("deleteExecutionValue"), request)
        elif 'run_sim' in request.POST:
            request.session['machine_chosen'] = get_id_from_string(request.POST.get("machine_chosen_value"),
                                                                   request.user)
            return redirect('accounts:run_sim')

        elif 'disconnectButton' in request.POST:
            Connection.objects.filter(idConn_id=request.session["idConn"]).update(status="Disconnect")
            for key in list(request.session.keys()):
                if not key.startswith("_"):  # skip keys set by the django system
                    del request.session[key]
            machines_done = populate_executions_machines(request)
            if not machines_done:
                request.session['firstCheck'] = "no"
            request.session["checkConn"] = "Required"
            request.session['machine_chosen'] = None
            return render(request, 'accounts/executions.html',
                          {'machines': machines_done, 'checkConn': "no"})
        elif 'connection' in request.POST:
            user, fqdn = get_name_fqdn(request.POST.get('machineChoice'))
            machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
            obj = Key_Gen.objects.filter(machine_id=machine_found.id).get()
            private_key = obj.private_key
            try:
                try:
                    content = decrypt(private_key, request.POST.get("token")).decode()
                except Exception:
                    form = ExecutionForm()
                    machines_done = populate_executions_machines(request)
                    request.session['firstCheck'] = "yes"
                    request.session["checkConn"] = "no"
                    return render(request, 'accounts/executions.html',
                                  {'form': form, 'machines': machines_done,
                                   'checkConn': request.session["checkConn"],
                                   'firstCheck': request.session['firstCheck'], "errorToken": 'yes'})

            except:
                return False
            request.session["content"] = content
            request.session['machine_chosen'] = machine_found.id

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
        threadUpdate = updateExecutions(request)
        threadUpdate.start()
        machine_connected = Machine.objects.get(id=request.session["machine_chosen"])
        executions = Execution.objects.all().filter(author=request.user, machine=machine_connected).filter(
            Q(status="PENDING") | Q(status="RUNNING") | Q(status="INITIALIZING"))
        executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED",
                                                        machine=machine_connected)
        executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED",
                                                          machine=machine_connected)
        executionTimeout = Execution.objects.all().filter(author=request.user, status="TIMEOUT",
                                                          autorestart=False, machine=machine_connected)
        executionsCheckpoint = Execution.objects.all().filter(author=request.user, status="TIMEOUT",
                                                              autorestart=True, machine=machine_connected)
        executionsCanceled = Execution.objects.all().filter(author=request.user, status="CANCELLED+",
                                                            checkpoint="-1", machine=machine_connected)
        request.session['nameConnectedMachine'] = "" + machine_connected.user + "@" + machine_connected.fqdn
        for execution in executionsCanceled:
            checks = Execution.objects.all().get(author=request.user, status="CANCELLED+", checkpoint=execution.jobID,
                                                 machine=machine_connected)
            if checks is not None:
                execution.status = "TIMEOUT"
                execution.checkpoint = 0
                execution.save()
        return render(request, 'accounts/executions.html',
                      {'executions': executions, 'executionsDone': executionsDone,
                       'executionsFailed': executionsFailed,
                       'executionsTimeout': executionTimeout, 'checkConn': "yes",
                       'machine_chosen': request.session['nameConnectedMachine']})
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
                              {'machines': machines_done, 'checkConn': "no",
                               'machine_chosen': request.POST.get('machineChoice')})

            machine_connected = Machine.objects.get(id=get_machine(request))
            request.session['nameConnectedMachine'] = "" + machine_connected.user + "@" + machine_connected.fqdn
            executions = Execution.objects.all().filter(author=request.user, machine=machine_connected).filter(
                Q(status="PENDING") | Q(status="RUNNING") | Q(status="INITIALIZING"))
            executionsDone = Execution.objects.all().filter(author=request.user, machine=machine_connected,
                                                            status="COMPLETED")
            executionsFailed = Execution.objects.all().filter(author=request.user, machine=machine_connected,
                                                              status="FAILED")
            executionsCheckpoint = Execution.objects.all().filter(author=request.user, machine=machine_connected,
                                                                  status="TIMEOUT")
            executionTimeout = Execution.objects.all().filter(author=request.user, machine=machine_connected,
                                                              status="TIMEOUT",
                                                              autorestart=False)
            executionsCanceled = Execution.objects.all().filter(author=request.user, machine=machine_connected,
                                                                status="CANCELED",
                                                                checkpoint="-1")
            for execution in executionsCanceled:
                checks = Execution.objects.all().get(author=request.user, status="CANCELLED+",
                                                     machine=machine_connected,
                                                     checkpoint=execution.jobID)
                if checks is not None:
                    execution.status = "TIMEOUT"
                    execution.checkpoint = 0
                    execution.save()
                checks.delete()
            request.session["checkConn"] = "yes"
    return render(request, 'accounts/executions.html',
                  {'form': form, 'executions': executions, 'executionsDone': executionsDone,
                   'executionsFailed': executionsFailed, 'executionsTimeout': executionTimeout,
                   "checkConn": request.session["checkConn"],
                   'machine_chosen': request.session['nameConnectedMachine']})


def populate_executions_machines(request):
    machines = Machine.objects.all().filter(author=request.user)
    machines_done = []
    if machines.count() != 0:
        for machine in machines:
            machines_done.append("" + str(machine.user) + "@" + machine.fqdn)
    return machines_done


class updateExecutions(threading.Thread):
    def __init__(self, request):
        threading.Thread.__init__(self)
        self.request = request
        self.timeout = 120 * 60

    def run(self):
        timeout_start = time.time()
        while time.time() < timeout_start + self.timeout:
            boolException = update_table(self.request)
            if not boolException:
                break
            time.sleep(10)
        Connection.objects.filter(idConn_id=self.request.session["idConn"]).update(status="Disconnect")
        render_right(self.request)
        return


def update_table(request):
    log.info("update_table")
    machine_found = Machine.objects.get(id=request.session['machine_chosen'])
    machineID = machine_found.id
    ssh = connection(request.session["content"], machineID)
    executions = Execution.objects.all().filter(author=request.user, machine=request.session['machine_chosen']).filter(
        Q(status="PENDING") | Q(status="RUNNING") | Q(status="INITIALIZING"))
    for executionE in executions:
        stdin, stdout, stderr = ssh.exec_command(
            "sacct -j " + str(executionE.jobID) + " --format=jobId,user,nnodes,elapsed,state | sed -n 3,3p")
        stdout = stdout.readlines()
        values = str(stdout).split()

        if str(values[4]) == "COMPLETED" and executionE.status != "COMPLETED":
            log.info("update_table COMPLETED")
            ftp_folder_path = executionE.results_ftp_path
            results_path = "results"
            local_folder_path = os.path.join(executionE.wdir, results_path)
            upload_results(request, ftp_folder_path, local_folder_path)
        Execution.objects.filter(jobID=executionE.jobID).update(status=values[4], time=values[3],
                                                                nodes=int(values[2]))
    return True


def connection(content, machineID):
    try:
        ssh = paramiko.SSHClient()
        pkey = paramiko.RSAKey.from_private_key(StringIO(content))
        machine_found = Machine.objects.get(id=machineID)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine_found.fqdn, username=machine_found.user, pkey=pkey)
    except:
        return redirect('accounts:executions', {"errorToken": 'yes'})
    return ssh


def checkpointingFinished(execution, request):
    if execution.checkpoint != 0:
        e = Execution.objects.all().get(author=request.user, jobID=execution.jobID)
        return checkpointingFinished(e, request)
    else:
        Execution.objects.filter(jobID=execution.jobID).update(status="FINISHED_CHECKPOINTED")
        return


def stopExecution(eIDstop, request):
    ssh = connection(request.session['content'], request.session['machine_chosen'])
    exec = Execution.objects.filter(eID=eIDstop).get()
    if exec.eID != 0:
        command = "scancel " + str(exec.jobID)
        stdin, stdout, stderr = ssh.exec_command(command)
    Execution.objects.filter(eID=eIDstop).update(status="CANCELLED+")
    form = ExecutionForm()
    executions = Execution.objects.all().filter(author=request.user).filter(
        Q(status="PENDING") | Q(status="RUNNING") | Q(status="INITIALIZING"))
    executionsDone = Execution.objects.all().filter(author=request.user, status="COMPLETED")
    executionsFailed = Execution.objects.all().filter(author=request.user, status="FAILED")
    executionTimeout = Execution.objects.all().filter(author=request.user, status="TIMEOUT", autorestart=False)
    return render(request, 'accounts/executions.html',
                  {'form': form, 'executions': executions, 'executionsDone': executionsDone,
                   'executionsFailed': executionsFailed, 'executionsTimeout': executionTimeout})


class auto_restart_thread(threading.Thread):
    def __init__(self, jobID, request, time, machine_id):
        threading.Thread.__init__(self)
        self.jobID = jobID
        self.request = request
        self.time = time
        self.machine_id = machine_id

    def run(self):
        time.sleep(int(self.time) * 60)
        wait_timeout_new(self.jobID, self.request, self.machine_id)
        return


def wait_timeout_new(jobID, request, machine_id):
    execution = Execution.objects.get(jobID=jobID)
    if execution.status != "TIMEOUT":
        time.sleep(15)
        wait_timeout_new(jobID, request)
    else:
        checkpointing(jobID, request, machine_id)
    return


def monitor_checkpoint(jobID, request, execTime, machine):
    auto_restart_obj = auto_restart_thread(jobID, request, execTime, machine)
    auto_restart_obj.start()
    return


def checkpointing(jobIDCheckpoint, request, machine_id):
    ssh = connection(request.session['content'], machine_id)
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    machine_connected = Machine.objects.get(id=machine_id)
    machine_folder = extract_substring(machine_connected.fqdn)
    command = "source /etc/profile; cd " + machine_connected.installDir + "/scripts/" + machine_folder + "/; sh app-checkpoint.sh " + checkpointID.user + " " + checkpointID.name_workflow + " " + checkpointID.workflow_path + " " + checkpointID.wdir + " " + str(
        checkpointID.nodes) + " " + str(
        checkpointID.execution_time) + " " + checkpointID.qos + " " + machine_connected.installDir
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
    monitor_checkpoint(request.session['jobID'], request, time, machine_id)
    return


def checkpointing_noAutorestart(jobIDCheckpoint, request):
    ssh = connection(request.session['content'], request.session['machine_chosen'])
    checkpointID = Execution.objects.all().get(author=request.user, jobID=jobIDCheckpoint)
    machine = get_machine(request.session['machine_chosen'])
    machine_connected = Machine.objects.get(id=machine.id)
    machine_folder = extract_substring(machine_connected.fqdn)
    command = "source /etc/profile; cd " + machine_connected.installDir + "/scripts/" + machine_folder + "/; sh app-checkpoint.sh " + checkpointID.user + " " + checkpointID.name_workflow + " " + checkpointID.workflow_path + " " + checkpointID.wdir + " " + str(
        checkpointID.nodes) + " " + str(
        checkpointID.execution_time) + " " + checkpointID.qos + " " + machine_connected.installDir
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
        pass
    else:
        jobID = request.session['jobIDfailed']
        ssh = connection(request.session['content'], request.session['machine_chosen'])
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
        contentOut = None
        contentErr = None
        sftp_client = ssh.open_sftp()
        try:
            with sftp_client.open(pathOut, 'r') as file:
                contentOut = file.read()
                contentOut = contentOut.decode('utf-8')
        except FileNotFoundError:
            log.error("Output file not found.")
        try:
            with sftp_client.open(pathErr, 'r') as file:
                contentErr = file.read()
                contentErr = contentErr.decode('utf-8')
        except FileNotFoundError:
            log.error("Error file not found.")
    return render(request, 'accounts/execution_failed.html',
                  {'executionsDone': executionGet, 'pathOut': pathOut, 'pathErr': pathErr, 'contentOut': contentOut,
                   'contentErr': contentErr})


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
            log.error(exc)
    return None


def ssh_keys_result(request):
    if request.method == 'POST':
        return render('accounts/dashboard')
    else:
        return render('accounts/dashboard')


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
                request.userMachine = user
                request.fqdn = fqdn
                machine_found = Machine.objects.get(author=request.user, user=user, fqdn=fqdn)
                instance.machine = machine_found
                token = Fernet.generate_key()  # to generate a security token
                key = paramiko.RSAKey.generate(2048)  # to generate the SSH keys
                privateString = StringIO()
                key.write_private_key(privateString)
                private_key = privateString.getvalue()
                x = private_key.split("\'")
                private_key = x[0]
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
                public_key = "rsa-sha2-512 " + public_key
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
                initial={'fqdn': machine_found.fqdn, 'user': machine_found.user, 'wdir': machine_found.wdir,
                         'installDir': machine_found.installDir, 'dataDir': machine_found.dataDir,
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
                installDirForM = form['installDir'].value()
                dataDirForM = form['dataDir'].value()
                Machine.objects.filter(id=request.session['machineID']).update(user=userForm, wdir=wdirForm,
                                                                               fqdn=fqdnForm, installDir=installDirForM,
                                                                               dataDir=dataDirForM)
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


def meshes(request):
    if request.method == 'POST':
        if 'deleteMesh' in request.POST:
            request.session['deleteMeshValue'] = request.POST.get("deleteMeshValue")
            deleteMesh(request.POST.get("deleteMeshValue"), request)
        elif 'downloadMesh' in request.POST:
            request.session['downloadMeshValue'] = request.POST.get("downloadMeshValue")
            downloadMesh(request.POST.get("downloadMeshValue"), request)
        elif 'modifyMesh' in request.POST:
            request.session['modifyMeshValue'] = request.POST.get("modifyMeshValue")
            modifyMesh(request.POST.get("modifyMeshValue"), request)
        meshesAvailable = populate_meshes()
        meshesUser = populate_meshes_user(request)
        if meshesAvailable or meshesUser:
            return render(request, 'accounts/meshes.html',
                          {'MeshesAvailable': meshesAvailable, 'meshesUser': meshesUser})
        else:
            return render(request, 'accounts/meshes.html', {'firstMeshCheck': 'yes'})
    else:
        meshesAvailable = populate_meshes()
        meshesUser = populate_meshes_user(request)
        if meshesAvailable or meshesUser:
            return render(request, 'accounts/meshes.html',
                          {'MeshesAvailable': meshesAvailable, 'meshesUser': meshesUser})
        else:
            return render(request, 'accounts/meshes.html', {'firstMeshCheck': 'yes'})


def deleteMesh(idMesh, request):
    Mesh.objects.filter(mesh_id=idMesh).delete()
    return


def downloadMesh(idMesh, request):
    return render(request, 'accounts/meshes.html')


def modifyMesh(idMesh, request):
    return render(request, 'accounts/redefine_mesh.html')


def mesh_definition(request):
    if request.method == 'POST':
        form = Mesh_Form(request.POST)
        form.author = request.user
        if form.is_valid():
            instance = form.save(commit=False)
            instance.user = request.user
            instance.save()
            return render(request, 'accounts/mesh_definition.html', {'form': form, 'flag': 'yes'})
    else:
        form = Mesh_Form()
        return render(request, 'accounts/mesh_definition.html', {'form': form})


def redefine_mesh(request):
    if request.method == 'POST':
        return render(request, 'accounts/redefine_mesh.html')
    else:
        return render(request, 'accounts/redefine_mesh.html')


def populate_meshes():
    meshes = Mesh.objects.all()
    return meshes


def populate_meshes_user(request):
    meshesUser = userMesh.objects.all().filter(user=request.user)
    return meshesUser


def home(request):
    return render(request, 'accounts/dashboard.html')


def dashboard(request):
    return render(request, 'accounts/dashboard.html')


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


def upload_folder(ftp, folder_path):
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isdir(item_path):
            try:
                ftp.mkd(item)  # Try to create directory
            except Exception as e:
                print(f"Could not create directory {item}: {e}")
            ftp.cwd(item)  # Change to the directory
            upload_folder(ftp, item_path)  # Recursive call to upload folder's content
            ftp.cwd('..')  # Change back to parent directory
        else:
            with open(item_path, 'rb') as file:
                ftp.storbinary(f'STOR {item}', file)  # Upload file


def download_folder(ftp, path, local_target_directory):
    if not os.path.exists(local_target_directory):
        os.makedirs(local_target_directory)

    # Change to the target directory on FTP
    ftp.cwd(path)

    # List items in the directory
    items = ftp.nlst()

    for item in items:
        local_path = os.path.join(local_target_directory, item)
        if is_folder(ftp, item):
            # Recursive call to download folder
            download_folder(ftp, item, local_path)
        else:
            # Download file
            with open(local_path, 'wb') as f:
                ftp.retrbinary('RETR ' + item, f.write)

    # Go back to the parent directory
    ftp.cwd('..')


def is_folder(ftp, name):
    current = ftp.pwd()
    try:
        ftp.cwd(name)  # Try to change directory
        ftp.cwd(current)  # Change back to the original directory
        return True
    except ftplib.error_perm:
        return False


def custom_404_view(request, exception):
    context = {'error': 'Page not found'}
    return render(request, 'accounts/404.html', {}, status=404)


def custom_500_view(request):
    context = {'error': 'Internal server error'}
    return render(request, 'accounts/500.html', {}, status=500)


def custom_403_view(request, exception):
    context = {'error': 'Access forbidden'}
    return render(request, 'accounts/403.html', {}, status=403)


def custom_400_view(request, exception):
    context = {'error': 'Bad request'}
    return render(request, 'accounts/400.html', {}, status=400)


def csrf_failure(request, reason=""):
    context = {'error': ''}
    messages.success(request, f'CSRF verification failed. Request aborted')
    return redirect('accounts:dashboard')
