ELEC5616 Assignment
===================

Introduction
------------
A secure communications program written for the unit of study ELEC5616 (Computer
and Network Security) at the University of Sydney.

Authors
-------
- Joshua Spence (308216350)
- James Moutafidis (420105464)


Overview
--------
There are four executables resulting from the StealthNet package. These are as
follows:

- *Client:* A StealthNet client instance. This is a GUI application that allows
  users to chat and share files.
- *Server:*  A StealthNet server instance. This is a command-line application
  that is used to co-ordinate StealthNet clients.
- *Proxy:* A StealthNet proxy instance. In its default form, this application is
  a transparent layer (man-in-the-middle) that transparently relays messages
  between clients and servers. The proxy can additionally be used to simulate
  various security attacks.
- *Bank:* A StealthNet bank instance. This is a command-line application to
  co-ordinate StealthNet payments.

Instructions
------------

### Building
From the root project directory, execute the command `ant default`. To build
documentation and create TAR archives as well, execute the command `ant all`.

### Executing
To execute a bank application, run the script
`./run.sh --bank [--debug] [extra arguments]`.

To execute a client application, run the script
`./run.sh --client [--debug] [extra arguments]`.

To execute a server application, run the script
`run.sh --server [--debug] [extra arguments]`.

To execute a proxy application, run the script
`run.sh --proxy [--debug] [extra arguments]`.
