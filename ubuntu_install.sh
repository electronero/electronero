#!/usr/bin/env bash
apt-get install build-essential cmake pkg-config libboost-all-de libzmq3-dev libssl-dev libsodium-dev libunbound-dev libminiupnpc-dev libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev libgtest-dev doxygen graphviz
echo "Dependencies installation complete"
make
echo "Electronero Ubuntu Build process complete"
