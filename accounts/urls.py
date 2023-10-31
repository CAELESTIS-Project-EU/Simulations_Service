from django.urls import path
from . import views

app_name='accounts'

urlpatterns = [
    path('loginpage/', views.loginPage, name="loginpage"),
    path('registerpage/', views.registerPage, name="registerpage"),
    path('logout/', views.logoutUser, name="logout"),
    path('run_sim/', views.run_sim, name="run_sim"),
    path('create_workflow/', views.create_workflow, name="create_workflow"),
    path('executions/', views.executions, name="executions"),
    path('results/', views.results, name="results"),
    path('ssh_keys_result/', views.ssh_keys_result, name="ssh_keys_result"),
    path('ssh_keys_generation/', views.ssh_keys_generation, name="ssh_keys_generation"),
    path('machine_definition/', views.machine_definition, name="machine_definition"),
    path('redefine_machine/', views.redefine_machine, name="redefine_machine"),
    path('execution_failed/', views.execution_failed, name="execution_failed"),
    path('meshes/', views.meshes, name="meshes"),
    path('mesh_definition/', views.mesh_definition, name="mesh_definition"),
    path('redefine_mesh/', views.redefine_mesh, name="redefine_mesh"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('', views.home, name='home'),
]