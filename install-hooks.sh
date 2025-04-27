#!/bin/bash
cp .githooks/* .git/hooks/
chmod +x .git/hooks/*
echo "Git hooks installed successfully."
