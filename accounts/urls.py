from django.urls import path

from accounts import api_view, views

app_name = 'accounts'

api_urls = [
    path('api/run_simulation/', api_view.run_simulation, name='run_simulation'),
    path('api/delete_execution/<uuid:eID>/', api_view.delete_execution_api, name='delete_execution_api'),
    path('api/get_status_execution/<uuid:eID>/', api_view.get_status_execution, name='get_status_execution'),
    path('api/execution/<uuid:eID>/', api_view.execution, name='execution'),
]

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
    path('api_token/', views.api_token, name="api_token"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('', views.home, name='home'),
]
urlpatterns += api_urls


