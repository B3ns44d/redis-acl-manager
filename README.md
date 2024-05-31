# Redis ACL Manager

Redis ACL Manager is a tool for managing Redis Access Control Lists (ACLs) using Redis Sentinel. It provides a
convenient way to create and manage ACL users in a Redis cluster configured with Sentinel.

## Features

- Create new ACL users with customizable permissions.
- Manage ACL users in a Redis cluster.
- Support for connecting to Redis cluster with Sentinel.
- Sync ACL across Redis nodes

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/B3ns44d/redis-acl-manager.git
   cd redis-acl-manager
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Configuration File

Create a JSON configuration file with the following structure:

```json
{
  "REDIS_PORT": 6379,
  "REDIS_MASTER": "mymaster",
  "REDIS_ADMIN_PASSWORD": "admin_password",
  "REDIS_ADMIN_USER": "admin_user",
  "USERNAME": "test_user",
  "ACL_SETTINGS": {
    "enabled": true,
    "nopass": false,
    "passwords": [
      "+pass1",
      "+pass2"
    ],
    "commands": [
      "+SET",
      "+GET"
    ],
    "keys": [
      "key1",
      "key2"
    ],
    "channels": [
      "channel1",
      "channel2"
    ]
  },
  "REDIS_AGENT_NODE_0": "server001.hostname.com",
  "REDIS_AGENT_NODE_1": "server002.hostname.com",
  "REDIS_AGENT_NODE_2": "server003.hostname.com"
}
```

### Command-line Arguments

- `--config`: Path to the JSON configuration file.
- `--log_level`: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).

### Example Usage

```bash
python redis_acl_manager/main.py --config config.json
```

