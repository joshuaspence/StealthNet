================================================================================
| ELEC5616 Assignment                                                          |
|------------------------------------------------------------------------------|
| Joshua Spence (308216350)                                                    |
| Ahmad Al Mutawa                                                              |
================================================================================

--------------------------------------------------------------------------------
INSTRUCTIONS
--------------------------------------------------------------------------------
To build:
	From the root project directory, execute the command `ant all'.

To run:
	To execute a client application execute the command `ant run_client'. 
	Alternatively, run the script `run_client.sh'.
	
	To execute a server application execute the command `ant run_server'.
	Alternatively, run the script `run_client.sh'. Alternatively, the command 
	`ant run' will execute a single server application and two client 
	applications.
	
--------------------------------------------------------------------------------
SECURITY
--------------------------------------------------------------------------------
1.  AUTHENTICATION.
    My idea for authentication is as follows. Note that in order for this to  
    work, the client must be able to trust the identity of the server upon 
    initial connection.
    
    For connections between a client and the server:
    1) When a StealthNet server is created, a unique public-private key pair are
       created.
    2) When a StealthNet client is created, a unique public-private key pair are
       created.
    3) When the client makes the initial connection with the server, the client 
       sends the server both the user ID, and the its public key.
    4) The server acknowledges the client's connection, and sends back its own 
       public key.
    5) Whenever a client sends a message to the server, it signs the message 
       with its own private key. The server can then verify the message using
       the client's public key.
    6) Whenever the server sends a message to a client, it signs the message
       using its own private key. The client can then verify the message using
       the server's public key.
    
    For connections between two clients:
    1)  When a StealthNet client is created, a unique public-private key pair are
       created.
    2) ??
    
    Note that the initial key exchanges (steps 3 and 4) must be performed over a
    secure channel. This could prove to be difficult.
    
    Authentication is implemented in the `StealthNetIdentity' class. Public and
    private key details are to be stored within the `StealthNetComms' class,
    and messages should be signed/verified as they pass through this layer. Note
    that servers/clients need only have one public/private key pair, it is not
    necessary to provide a unique key pair for each communication.

2.  CONFIDENTIALITY
    We will use a block cipher in order to encrypt and decrypt messages. 
    Messages should be encrypted (and decrypted) at the packet level so that
    higher layers do not need to know about the encryption. Confidentiality is 
    implemented in the `StealthNetEncryption' class.
    
    The IV and key must be derived from key exchange in Authentication method.
    
    1) ???

3.  INTEGRITY
    Basically, we need a hash of the message that we are able to transmit with  
    the message itself. If, at the other end of the communication, the message 
    doesn't produce the same hash value, then the message must've been altered.
    
    I am not sure, however, of how we can ensure that the hash/checksum value 
    itself isn't altered. This will require some thought.
    
    This security mechanism will be associated with a `StealthNetComms' 
    instance.
    
    1) Whenever a message is to be sent, the message is hashed and the hash 
       value is prepended/appended to the message itself.
    2) Whenever a message is received, the message received is hashed and 
       compared to the received hash value. If the hash values differ, then the 
       message is discarded. 

4.  PREVENTING REPLAY
    We will have to look into proven methods on how to do this, but I did have a 
    thought of a method that may work...
    
    Basically, the client and server needs to share a seed for a pseudo-random 
    number generator. They must initially share this seed over a secure channel. 
    Now, in oder to prevent replay attacks, all that the server needs to do is 
    only accept messages with the expected sequence number (the next generated 
    pseudo-random number). Since the client and server are both able to 
    calculate the next sequence number, any legitimate client should be able to 
    generate the next expected sequence number and prepend it to a message. The
    pseudo-random number generator is implemented in the `StealthNetPRNG' class.
    
    The implementation of this security mechanism should be included in the 
    `StealthNetComms' class, so that legitimate users are not able to replay 
    messages from other legitimate users.
    
    1) When connecting to the server initially, the server sends the client a 
       seed value for a pseudo-random number generator.
    2) Whenever one entity (client/server) wants to send a message to another 
       entity, the sender first calculates the next sequence number produced by 
       the pseudo-random number generator and prepends/appends it to the 
       message.
    3) Whenever the receiving entity receives a message from a sender, it checks
       the sequence number contained in the message and compares it to the real 
       sequence number that is generated using the pseudo-random number 
       generator. If the sequence numbers do not match then the message is 
       discarded.
    4) Whenever a legitimate sequence number is received, the next expected 
       sequence number should be incremented, and the sender of the legitimate
       message should be notified of this increment.
     
     Note that it is crucial that the exchange of the seed value is performed 
     over a secure channel, otherwise an attacker could also know the seed value
     and generate valid sequence numbers. This will require some extra though.