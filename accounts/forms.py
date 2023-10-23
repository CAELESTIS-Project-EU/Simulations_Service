from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import User
from django import forms
from accounts.models import Document, WorkFlow, Execution, Key_Gen, Machine, Connection


class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']


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
        fields = ('name_sim', 'jobID', 'user', 'nodes', 'status', 'time', 'wdir', 'workflow_path')


class Key_Gen_Form(forms.ModelForm):
    class Meta:
        model = Key_Gen
        fields = ('author', 'machine', 'public_key', 'private_key')


class Machine_Form(forms.ModelForm):
    class Meta:
        model = Machine
        fields = ('author', 'user', 'fqdn', 'wdir', 'installDir')


class Connection_Form(forms.ModelForm):
    class Meta:
        model = Connection
        fields = ('user', 'status')
