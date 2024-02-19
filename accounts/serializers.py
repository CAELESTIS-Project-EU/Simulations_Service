from rest_framework import serializers
from .models import Document, WorkFlow, Execution, Key_Gen, Machine, Connection, Mesh, userMesh
from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password

User = get_user_model()

class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ('id', 'document', 'uploaded_at')


class WorkFlowSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkFlow
        fields = '__all__'


class ExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Execution
        fields = '__all__'


class KeyGenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Key_Gen
        fields = '__all__'


class MachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = '__all__'


class ConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Connection
        fields = '__all__'


class MeshSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mesh
        fields = '__all__'


class UserMeshSerializer(serializers.ModelSerializer):
    class Meta:
        model = userMesh
        fields = '__all__'


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label=("Username"))
    password = serializers.CharField(
        label=("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            if User.objects.filter(username=username).exists():
                user = User.objects.get(username=username)
                if not user.check_password(password):
                    raise serializers.ValidationError('Incorrect password.')
            else:
                raise serializers.ValidationError('User does not exist.')
        else:
            raise serializers.ValidationError('Must include "username" and "password".')

        attrs['user'] = user
        return attrs



class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return super(CreateUserSerializer, self).create(validated_data)
