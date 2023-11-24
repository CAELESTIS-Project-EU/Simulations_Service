The HPC Simulation service has been implemented using Django[3], Nginx[4], PostgreSQL[5], Gunicorn[6] and Paramiko[7] as depicted in Figure 11.  Django is a high-level Python web framework that simplifies the development of web applications by providing a robust set of tools and libraries for building dynamic web services.  Gunicorn is a Python WSGI (Web Server Gateway Interface[8]) HTTP server. It is responsible to serve Django applications by converting the HTTP request to the Django's Python code.  Nginx is a high-performance web server and reverse proxy server. In the context of serving Django applications, Nginx is typically used as a reverse proxy. Nginx acts as an intermediary between external clients and Gunicorn. The status of the service is persistently stored in the PostgreSQL, so in case of a failure in the service happens, all the pending operations can be safely recovered. Finally, Paramiko is a Python library that offers an interface for handling SSH (Secure Shell) and SFTP (Secure FTP) operations. It facilitates secure interactions with remote servers, enabling tasks such as command execution and file transfers across secure connections. The choice of Paramiko for SSH connections is driven by its capacity to programmatically establish and oversee SSH sessions, simplifying the automation of tasks, remote command execution, and secure file transfers between systems. In the present implementation, Paramiko takes on the role of executing scripts and commands by interfacing with the HPC site.

.. image:: ./images/gen_arch.png
    :align: center
    :width: 500px

.. image:: ./images/key.png
    :align: center
    :width: 500px

.. image:: ./images/img/key_decypt.png
    :align: center
    :width: 500px

.. image:: ./images/img/service_arch.png
    :align: center
    :width: 500px