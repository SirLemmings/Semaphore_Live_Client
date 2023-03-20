import json

ALIAS_LENGTH = 4
PUBKEY_LENGTH = 64
SIG_LENGTH = 64
NYM_MAX_LENGTH = 32
HEADER_LENGTH = 4
EPOCH_TIME = 1
SLACK_EPOCHS = 2
FORWARD_SLACK_EPOCHS = 1
SYNC_EPOCHS = 1
DB_INT_LENGTH = 4
RESET = 0
SEQUENCER_IP = "34.125.143.162"
SEQUENCER_PORT = 5000
SEQUENCER_PUBKEY = "61c3d4dc3ffc55b902b0111093fd49673c2b7a54f4fc668b00c51d277fe264c4a4f6b87aae7062382c5f8ce2f5ea9436e2c98548e553382328ddcb982d4b87d4"

DELAY = FORWARD_SLACK_EPOCHS+1+SLACK_EPOCHS+SYNC_EPOCHS
MAX_MESSAGE_LENGTH = 255-ALIAS_LENGTH*2-DB_INT_LENGTH
PARENT_LENGTH = ALIAS_LENGTH+DB_INT_LENGTH