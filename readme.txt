----------------------------------------- FAST Protocol Server and Client ------------------------------------------------
-------- Hossam Mabed ----------
-------- May 4, 2020  ----------
------ AIT-Budapest Inc. -------


---------------------------------------------------- Overview -----------------------------------------------------------------

Thank you for choong File Asynchronous Secure Transfer (FAST), your one-stop solution for all your remote file handling needs!

In this repo, you will find the following:
- In the ./design directory, you can find the Markdown, LaTeX, and PDF format of the design documents
        for the first version of the FAST protocols
- In the ./implementation directory, you can find all the scripts necessary to run the FAST Protocol services
        (more details on that later)
- In the root directory, the changelog.pdf provides the major design changes and additions that this implementation
        provides, in comparison with the original design document, found in ./design
    


---------------------------------------------------- Installation -----------------------------------------------------------------

To start using FAST, please run the installation script by navigating to the implementation direction
and running the installation script, or by typing into your terminal:

cd implementation && ./install.sh

on your terminal window. This will install all the Python modules you need to use the FAST client and server.
To manually install them: you will need the following Python modules:
- PyCryptodome
- ast
- termcolor
- colorama

Furthermore, make sure your Python has the following modules:
- os
- re 
- shutil
- getpass
- shlex

------------------------------------------------------- Running ------------------------------------------------------------------


To start using the server and client after installation, simply navigate to the implementation directory and run the run.sh script!
You can do so by typing into your termina:

cd implementation && ./run.sh

Or if you are already in the implementation directory:

./run.sh

Alternatively, you may choose to run the service (or part of it) manually.
After you have successfully installed, you need to run the network simulator, to allow server and client to communicate.
Afterwards, you need to run the server script. Then, you can start the client and start communicating with the server freely!

The network module is in ./implementation/netsim, the server module is in ./implementation/server
and the client is in ./implementation/client. You can run the Python scripts there yourself!
Alternatively, you can also use the run_network.sh, run_server.sh, or run_client.sh scripts, also located in the
implementation directory, to run just the network, server, or client, respectively.


-------------------------------------------------------- Contact Us! ----------------------------------------------------------------


Thank you for choosing FAST! We hope you have a great experience.

For any feedback or suggestions, please email the administrator at:
Hossam Mabed
h_mabed@college.harvard.edu


