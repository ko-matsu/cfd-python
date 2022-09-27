FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends cmake git python3-pip build-essential libssl-dev libffi-dev python3-dev

WORKDIR /workspace
