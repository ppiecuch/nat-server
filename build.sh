#!/bin/bash

set -e

version="latest"
docker build -t nat_server:$version .
