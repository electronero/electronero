#!/usr/bin/env bash
apt-get install build-essential cmake pkg-config libboost-all-dev libzmq-dev libssl-dev libzmq3-dev libsodium-dev libunbound-dev libminiupnpc-dev libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev libgtest-dev doxygen graphviz
echo "Dependencies installation complete"
make
echo "Electronero Ubuntu Build process complete"
