Step-by-Step Guide to HPC Machine Access and Workflow Execution
===============================================================

**Initial Setup using the Graphical User Interface**
----------------------------------------------------

In this section, we illustrate how a user can utilize the graphical user interface to set up access to an HPC machine and execute workflows on it.

- **Machine Definition**: After completing the registration and login processes, users will encounter the dashboard's graphical user interface. Initially, they must define a new machine as depicted in the figure below, providing details like username, Fully Qualified Domain Name (FQDN), and paths to the working and installation directories.

  .. image:: ./images/user-guide/1.png
      :align: center
      :width: 800px

  .. image:: ./images/user-guide/2.png
      :align: center
      :width: 800px

- **SSH Key Generation**: Upon successfully defining a new machine (as shown in the figure below), users initiate the SSH key generation phase (as depicted in the figure below). This step is essential for securing access and connecting their machine to our service. Our service then automatically generates a security token and a pair of SSH keys for the machine: a public key and a private key.

  .. image:: ./images/user-guide/3.png
      :align: center
      :width: 800px

- **Receiving the Security Token and Public Key**: The service provides the user with the security token and the SSH public key (as shown in the figure below). Users then place the received public key in the "authorized_keys" file on their machine. This key acts as an identifier, ensuring only those with the corresponding private key can connect. Before storing the private key in our database, it is encrypted using the security token to prevent unauthorized use, even if someone accesses the database.

  .. image:: ./images/user-guide/4.png
      :align: center
      :width: 800px

- **Security Token Usage**: The security token is never stored permanently. Whenever the user wants to use the service to connect to their machine via SSH, they must provide the security token, as indicated in the figure below.

  .. image:: ./images/user-guide/5.png
      :align: center
      :width: 800px


**Managing and starting executions using the Graphical User Interface**
----------------------------------------------------

- **Managing Workflow Executions**: Once the SSH connection is established, users can access the executions' view (as shown in the figure below), where they can manage previous workflow executions and start new ones.

  .. image:: ./images/user-guide/6.png
      :align: center
      :width: 800px

- **Starting New Workflows**: To initiate new workflows, users need to submit a workflow description file detailing the desired workflow, along with other options like maximum execution time, number of nodes for computation, and enabling checkpointing and auto-restart. This process is depicted in the figure below.

  .. image:: ./images/user-guide/7.png
      :align: center
      :width: 800px

- **Viewing Workflow Executions**: After successful execution, new workflow executions will be listed in the workflow executions list, as depicted in the figure below.

  .. image:: ./images/user-guide/8.png
      :align: center
      :width: 800px

