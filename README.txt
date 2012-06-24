================================================================================
| ELEC5616 Assignment                                                          |
|------------------------------------------------------------------------------|
| Joshua Spence (308216350)                                                    |
| James Moutafidis (420105464)                                                 |
================================================================================

--------------------------------------------------------------------------------
LICENSE
--------------------------------------------------------------------------------
This program is free software: you can redistribute it and/or modify it under 
the terms of the GNU General Public License as published by the Free Software 
Foundation, either version 3 of the License, or (at your option) any later 
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY 
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
this program. If not, see <http://www.gnu.org/licenses/>.

--------------------------------------------------------------------------------
EXECUTABLES
--------------------------------------------------------------------------------
There are four executables resulting from the StealthNet package. These are as
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
- Bank
	A StealthNet bank instance. This is a command-line application to 
	co-ordinate StealthNet payments.

--------------------------------------------------------------------------------
INSTRUCTIONS
--------------------------------------------------------------------------------
To build:
	From the root project directory, execute the command `ant default'. To build
	documentation and create TAR archives as well, execute the command 
	`ant all'.

To run:
	To execute a bank application, run the script
	`run.sh --proxy [--debug] [extra arguments]'.

	To execute a client application, run the script 
	`run.sh --client [--debug] [extra arguments]'.
	
	To execute a server application, run the script 
	`run.sh --server [--debug] [extra arguments]'.
	
	To execute a proxy application, run the script 
	`run.sh --proxy [--debug] [extra arguments]'.
