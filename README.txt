Welcome to the prototype implementation of the Semaphore client

Simply run client_node to connect to the network.
It will create a 'Client' folder that stores node data (Mac: in home directory, Linux: in local directory) 

In the GUI:
Write a message then click the "broadcast" button to broadcast
Click on a previous message to reply
Broadcast "!mint" to mint a new alias
Broadcast "!nym <your_new_nym>" to update your alias nym

Or, if you want to run the source:

Requires Python3.10 environment with plyvel, ecdsa, and PyQt6 installed
You can install the necessary modules by running 'pip install -r requirements.txt'
If pip has trouble installing plyvel, you can try a conda environment

To run the client, run node.py

By default the sequencer will run on localhost on port 5000
To change the defaults, edit params.json
The sequencer private key is set by default. To change the private key, delete sequencer_db and it will atomatically reset on startup
SEQUENCER_PUBKEY must be updated in params.json if the sequencer private key is updated
Use the "pubkey" command to get the sequencer pubkey

The client will automatically connect to the sequencer on startup

In the Terminal:
Use the "mint" command to create reqeust a new alias
Use the "key" command to update the alias' pubkey/privkey
Use the "nym" command to update the alias' human-readable screen NamedTuple
Use the "bc" command to send a broadcast

Use the "toggle_show" command to toggle if new broadcasts are printed for both sequencer and client
Enabled by default for client
Disable by default for sequencer

Watch out for bugs!
