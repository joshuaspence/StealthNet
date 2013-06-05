ELEC5616 Assignment
===================

Introduction
------------
A secure communications program written for the unit of study
[ELEC5616 (Computer and Network Security)][elec5616] at the
[University of Sydney][usyd].

Authors
-------
- Joshua Spence (308216350)
- James Moutafidis (420105464)

License
-------
Released under the [MIT License][mit]. See [LICENSE.md](LICENSE.md) for more
details.

Overview
--------
There are four executables resulting from the StealthNet package. These are as
follows:

- *Client:* A StealthNet client instance. This is a GUI application that allows
  users to chat and share files.
- *Server:* A StealthNet server instance. This is a command-line application
  that is used to co-ordinate StealthNet clients.
- *Proxy:* A StealthNet proxy instance. In its default form, this application
  is a transparent layer (man-in-the-middle) that transparently relays messages
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
To execute a bank application, run the script:

    ./run.sh --bank [--debug] [extra arguments]

To execute a client application, run the script:

    ./run.sh --client [--debug] [extra arguments]

To execute a server application, run the script
    run.sh --server [--debug] [extra arguments]

To execute a proxy application, run the script

    run.sh --proxy [--debug] [extra arguments]


[elec5616]: <http://sydney.edu.au/courses/uos/ELEC5616/computer-and-network-security>
[mit]: <http://opensource.org/licenses/MIT>
[usyd]: <http://sydney.edu.au>
