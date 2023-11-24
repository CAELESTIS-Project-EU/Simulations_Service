5.5 REST API for Automating HPC Workflow Execution
==================================================

**Overview of the REST API**
----------------------------

After introducing the Web Graphical User Interface in the previous section, we now present the REST API designed for programmatic interaction with the HPC Simulation Service. This API facilitates integration with components like the Hybrid Twin Platform. Various libraries and command tools are available for interacting with this API across different programming languages and systems. Below, we describe the REST API and provide an example of its execution using the cURL command.

**API Authentication**
----------------------

- To ensure secure API transactions, JSON Web Token (JWT) is used over HTTPS.
- This is a common security standard for REST APIs.
- Users must first generate an API security access token via the Web User Interface.
- This token, encrypted with HTTPS, is checked for validity against a hashed version by the service.

**API Endpoints**
-----------------

**Run a Simulation Workflow:**
   - Method: `POST`
   - Path: `/simulations/`
   - Content-Type: `multipart/form-data`
   - Content:
     a. Mandatory:
       * `MachineChoice`: Cluster where to execute the workflow.
       * `SecToken`: Token for SSH key identification.
       * `NumNodes`: Number of nodes.
       * `ExecTime`: Maximum execution time.
     b. Optional:
       * `Branch`: Version of the workflow templates.
       * `Checkpointing`: Enabling checkpointing in execution.
       * `Autorestart`: Enabling autorestart if execution times out.
       * `QoS`: Quality of Service according to the HPC machine.
       * `Name`: Name for the workflow simulation execution.
   - Response:
     a. `message`: Success or error message.
     b. `execution_id`: Execution identifier.

**Stop a Simulation Workflow:**
   - Method: `PUT`
   - Path: `/simulations/execution/<id>/?status=stop`
   - Content-Type: `multipart/form-data`
   - Content:
     a. `MachineChoice`: Cluster for workflow execution.
     b. `SecToken`: Token for SSH key identification.
   - Response:
     a. `message`: Success or error message.

**Get Status of a Simulation Workflow:**
   - Method: `GET`
   - Path: `/simulations/execution/<id>/`
   - Content-Type: `multipart/form-data`
   - Content:
     a. `MachineChoice`: Cluster for workflow execution.
     b. `SecToken`: Token for SSH key identification.
   - Response:
     a. `eID`: Execution identifier.
     b. `Name`: Execution name.
     c. `User`: User for submission.
     d. `NumNodes`: Number of nodes used.
     e. `Status`: INITIALIZING | RUNNING | TIME_OUT | FINISHED | FAILED

**Restart a Simulation Workflow:**
   - Method: `PUT`
   - Path: `/simulations/execution/<id>/?status=restart`
   - Content-Type: `multipart/form-data`
   - Content:
     a. `MachineChoice`: Cluster for workflow execution.
     b. `SecToken`: Token for SSH key identification.
   - Response:
     c. `message`: Success or error message.

**Delete a Simulation Workflow:**
   - Method: `DELETE`
   - Path: `/simulations/execution/<id>`
   - Content-Type: `multipart/form-data`
   - Content:
     a. `MachineChoice`: Cluster for workflow execution.
     b. `SecToken`: Token for SSH key identification.
   - Response:
     c. `message`: Success or error message.

