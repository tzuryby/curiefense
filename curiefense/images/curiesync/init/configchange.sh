#!/bin/sh

# K8s mode, notify localhost
curl -X POST "http://localhost:8998" -H "Content-Type: application/json" -d "$1"