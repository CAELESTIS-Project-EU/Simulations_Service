from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import User
from django import forms
from accounts.models import Document, WorkFlow, Execution, Key_Gen, Machine, Connection, Mesh, userMesh
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox

class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)

class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ('document',)


class WorkFlowForm(forms.ModelForm):
    class Meta:
        model = WorkFlow
        fields = (
            'samplerName', 'samplerParameters', 'simulation', 'mesh', 'templateSim', 'sensitivity', 'sensitivityOutput',
            'outputs', 'numVarproblem', 'variablesSampler', 'variablesFixed')


class ExecutionForm(forms.ModelForm):
    class Meta:
        model = Execution
        fields = ('name_sim', 'jobID', 'user', 'nodes', 'status', 'time', 'wdir', 'workflow_path', 'project_name')


class Key_Gen_Form(forms.ModelForm):
    class Meta:
        model = Key_Gen
        fields = ('author', 'machine', 'public_key', 'private_key')


class Machine_Form(forms.ModelForm):
    class Meta:
        model = Machine
        fields = ('author', 'user', 'fqdn', 'wdir', 'installDir', 'dataDir')


class Connection_Form(forms.ModelForm):
    class Meta:
        model = Connection
        fields = ('user', 'status')

class Mesh_Form(forms.ModelForm):
    class Meta:
        model = Mesh
        fields = ('name','pathFTP', 'description', 'dateLastUpdate')
