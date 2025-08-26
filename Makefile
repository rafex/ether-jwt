# Set the directory for this project so make deploy need not receive PROJECT_DIR
PROJECT_DIR         := ether-jwt
PROJECT_GROUP_ID    := dev.rafex.ether.jwt
PROJECT_ARTIFACT_ID := ether-jwt

# Include shared build logic
include ../build-helpers/common.mk
include ../build-helpers/git.mk