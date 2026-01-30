#!/bin/bash
set -e

# Usage: ./run_patch_crasher.sh <COMMIT_HASH> [IMAGE_PATH]

COMMIT="$1"
IMAGE="${2:-disk.raw}"

if [ -z "$COMMIT" ]; then
    echo "Usage: $0 <commit_hash> [path_to_linux_image]"
    echo "Example: $0 cd8ae32e4e4652db55bce6b9c79267d8946765a9 ./bullseye.img"
    exit 1
fi
CONFIG_FILE="dashboard/config/linux/upstream-apparmor-kasan-base.config"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found: $CONFIG_FILE"
    exit 1
fi

# Read config content and create JSON input using Python
python3 -c "
import json
import os
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = f.read()

    data = {
        'PatchCommit': '$COMMIT',
        'Syzkaller': os.getcwd(),
        'Image': os.path.abspath('$IMAGE'),
        'Type': 'qemu',
        'VM': {
            'count': 1,
            'cpu': 2,
            'mem': 4096
        },
        'KernelConfig': config,
        'SyzkallerCommit': 'master',
        'ReproOpts': '',
        'ReproSyz': '',
        'CodesearchToolBin': os.path.join(os.getcwd(), 'bin', 'syz-codesearch')
    }

    with open('patch_crasher_input.json', 'w') as f:
        json.dump(data, f, indent=4)
    print('Successfully created patch_crasher_input.json')

except Exception as e:
    print(f'Error creating JSON: {e}')
    sys.exit(1)
"

echo ""
echo "To run the patch-crasher flow, execute:"
echo "go run ./tools/syz-aflow -workflow=patch-crasher -input=patch_crasher_input.json -workdir=workdir"
