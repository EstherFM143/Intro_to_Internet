# Intro_to_Internet
The coursework for the programming course is to create a program that communicates with a server using TCP and UDP protocols. It consists of a compulsory basic part and optional additional parts.
Connecting to the server: The server the implementation is talking to can be found at 195.148.20.105, port 10000.
The basic part and additional parts are implemented according to coursework.txt.
Further instructions of the assignment can be seen in instruction.pdf

Basic Part.
The basic part of the coursework involves the following steps:
TCP Communication: The program sends a message to the server using the TCP protocol.
UDP Communication: The program parses the message received from the TCP communication to extract the UDP port and its own ID.
Word List Handling: The program sends a message to the UDP port of the server and receives a list of words.
Word Order Translation: The program translates the order of the words and sends the modified list back to the server.
Repetition: This process is repeated until the server indicates that it has run out of messages.

Additional Parts
The additional parts of the coursework are optional and include the following features:
Encryption: Messages are encrypted before being sent to the server.
Parity: Messages include parity bits for error detection.
Multipart Messages: Messages can be split into multiple parts and reassembled upon receipt.
