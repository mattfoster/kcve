#!/bin/bash

# Exit on error
set -e

# Build all commands
for cmd in cmd/*; do
    if [ -d "$cmd" ]; then
        echo "Building $cmd..."
        go build "./$cmd"
    fi
done

echo "Build complete!" 
