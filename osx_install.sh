#!/usr/bin/env bash
brew install gcc@5 cmake pkg-config boost@1.59 boost git openssl@1.1 zmqpp zmq unbound jmuncaster/header-only/cppzmq libsodium miniupnpc libunwind-headers xz readline ldns expat doxygen graphviz
echo "Dependencies installation complete"
make
echo "Electronero Mac Build process complete"
