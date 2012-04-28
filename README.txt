================================================================================
| ELEC5616 Assignment                                                          |
|------------------------------------------------------------------------------|
| Joshua Spence (308216350)                                                    |
| Ahmad Al Mutawa (312003919)                                                  |
| James Moutafidis (???)                                                       |
================================================================================

--------------------------------------------------------------------------------
EXECUTABLES
--------------------------------------------------------------------------------
There are three executables resulting from the StealthNet package. These are as
follows:

- Client
    A StealthNet client instance. This is a GUI application that allows users to
    chat and share files.
- Server
    A StealthNet server instance. This is a command-line application that is 
    used to co-ordinate StealthNet clients.
- Proxy
    A StealthNet proxy instance. In its default form, this application is a 
    transparent layer (man-in-the-middle) that transparently relays messages
    between clients and servers. The proxy can additionally be used to simulate
    various security attacks.

--------------------------------------------------------------------------------
INSTRUCTIONS
--------------------------------------------------------------------------------
To build:
	From the root project directory, execute the command `ant default'. To build
	documentation and create TAR archives as well, execute the command 
	

To run:
	To execute a client application execute the command `ant run_client'. 
	Alternatively, run the script `run.sh --client [--debug] [extra arguments]'.
	
	To execute a server application execute the command `ant run_server'.
	Alternatively, run the script `run.sh --server [--debug] [extra arguments]'.
	
	To execute a proxy application execute the command `ant run_proxy'.
    Alternatively, run the script `run.sh --proxy [--debug] [extra arguments]'.
	
	Alternatively, the command `ant run' will execute a single proxy appliation,
	a single server application and two client applications.