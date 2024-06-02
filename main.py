import argparse
import json
import logging
import sys
from typing import List, Tuple, Any

import redis.sentinel
from pydantic import BaseModel, ValidationError, field_validator
from retrying import retry


class ACLConfig(BaseModel):
    enabled: bool
    nopass: bool = False
    passwords: List[str]
    commands: List[str]
    keys: List[str]
    channels: List[str]


class RedisConfig(BaseModel):
    REDIS_PORT: int
    REDIS_MASTER: str
    REDIS_ADMIN_PASSWORD: str
    REDIS_ADMIN_USER: str
    USERNAME: str
    ACL_SETTINGS: ACLConfig
    REDIS_NODES: List[str]

    @field_validator('REDIS_PORT')
    def port_must_be_valid(cls, v):
        if not (0 < v < 65536):
            raise ValueError('Port must be between 1 and 65535')
        return v


class RedisACLManager:
    def __init__(self, sentinel_hosts: List[Tuple[str, int]], sentinel_port: int, master_name: str, username: str,
                 admin_password: str, admin_username: str, acl_config: dict,
                 ssl_ca_certs: str = "/etc/redis/redis.crt"):
        self.sentinel_hosts = sentinel_hosts
        self.sentinel_port = sentinel_port
        self.master_name = master_name
        self.username = username
        self.admin_password = admin_password
        self.admin_username = admin_username
        self.acl_config = acl_config
        self.ssl_ca_certs = ssl_ca_certs

    @retry(stop_max_attempt_number=5, wait_exponential_multiplier=1000, wait_exponential_max=10000)
    def connect_sentinel(self):
        logging.info("Connecting to Redis Sentinel...")
        sentinel = redis.sentinel.Sentinel(self.sentinel_hosts,
                                           sentinel_kwargs={'password': self.admin_password,
                                                            'username': self.admin_username, 'ssl': True,
                                                            'ssl_ca_certs': self.ssl_ca_certs, 'ssl_cert_reqs': None,
                                                            'ssl_certfile': None, 'ssl_keyfile': None,
                                                            'ssl_check_hostname': False, 'socket_connect_timeout': 0.5})
        master = sentinel.discover_master(self.master_name)
        logging.info(f"Discovered master node: {master}")

        slaves = sentinel.discover_slaves(self.master_name)
        logging.info(f"Discovered slave nodes: {slaves}")

        slave_connections = [
            redis.StrictRedis(host=slave[0], port=slave[1], password=self.admin_password, username=self.admin_username,
                              ssl=True, ssl_ca_certs=self.ssl_ca_certs) for slave in slaves]
        logging.info("Connected to master and slave nodes.")

        return sentinel.master_for(self.master_name, socket_timeout=1, username=self.admin_username,
                                   password=self.admin_password, ssl=True,
                                   ssl_ca_certs=self.ssl_ca_certs), slave_connections, master, slaves

    @retry(stop_max_attempt_number=5, wait_exponential_multiplier=1000, wait_exponential_max=10000)
    def create_acl_user(self):
        logging.info(f"Creating ACL user: {self.username}")
        master, slaves, master_info, slave_info = self.connect_sentinel()
        acl_settings = self.acl_config

        acl_params = {'username': self.username, 'enabled': acl_settings.get('enabled', False),
                      'nopass': acl_settings.get('nopass', False), 'passwords': acl_settings.get('passwords', []),
                      'commands': acl_settings.get('commands', []), 'keys': acl_settings.get('keys', []),
                      'channels': acl_settings.get('channels', []), 'reset_channels': True}

        try:
            logging.info(f"Applying ACLs on master node: {master_info[0]}:{master_info[1]}")
            master.acl_setuser(**acl_params)
            master.acl_save()

            for i, slave in enumerate(slaves):
                logging.info(f"Applying ACLs on slave node: {slave_info[i][0]}:{slave_info[i][1]}")
                slave.acl_setuser(**acl_params)
                slave.acl_save()

            user_data = {"REDIS_USER": self.username, "REDIS_PASSWORD": ",".join(acl_settings.get("passwords", []))}
            logging.info("ACL user created successfully.")
            print(json.dumps(user_data))
        except redis.exceptions.ResponseError as e:
            logging.error(f"Redis command execution failed: {e}")
            raise

    @retry(stop_max_attempt_number=5, wait_exponential_multiplier=1000, wait_exponential_max=10000)
    def delete_acl_user(self):
        logging.info(f"Deleting ACL user: {self.username}")
        master, slaves, master_info, slave_info = self.connect_sentinel()
        try:
            logging.info(f"Deleting ACL user on master node: {master_info[0]}:{master_info[1]}")
            master.acl_deluser(self.username)

            for i, slave in enumerate(slaves):
                logging.info(f"Deleting ACL user on slave node: {slave_info[i][0]}:{slave_info[i][1]}")
                slave.acl_deluser(self.username)

            logging.info("ACL user deleted successfully.")
            print(json.dumps({"message": f"Deleted ACL user: {self.username}"}))
        except redis.exceptions.ResponseError as e:
            logging.error(f"Redis command execution failed: {e}")
            raise

    def get_acl_user(self, username: str):
        master, slaves, master_info, slave_info = self.connect_sentinel()
        user_acl = {}

        try:
            logging.info(f"Retrieving ACL user '{username}' from master node: {master_info[0]}:{master_info[1]}")
            user_acl['master'] = master.acl_getuser(username)
        except redis.exceptions.ResponseError as e:
            logging.error(f"Failed to retrieve ACL user '{username}' from master node: {e}")
            user_acl['master'] = str(e)

        for i, slave in enumerate(slaves):
            try:
                logging.info(
                    f"Retrieving ACL user '{username}' from slave node {i}: {slave_info[i][0]}:{slave_info[i][1]}")
                user_acl[f'slave_{i}'] = slave.acl_getuser(username)
            except redis.exceptions.ResponseError as e:
                logging.error(f"Failed to retrieve ACL user '{username}' from slave node {i}: {e}")
                user_acl[f'slave_{i}'] = str(e)

        return user_acl


def load_config(config_path: str) -> RedisConfig:
    try:
        with open(config_path, 'r') as f:
            config_data: dict[str, Any] = json.load(f)
        if 'REDIS_NODES' in config_data:
            config_data['REDIS_NODES'] = config_data['REDIS_NODES'].split(',')
        else:
            raise ValueError("REDIS_NODES key is missing in the configuration file.")
        return RedisConfig(**config_data)
    except FileNotFoundError:
        logging.error(f"Configuration file {config_path} not found.")
        raise


def main():
    parser = argparse.ArgumentParser(description='Manage ACL user for Redis instance')
    parser.add_argument('--config', help='Path to the configuration file', required=True)
    parser.add_argument('--operation', default='CREATE', choices=['CREATE', 'DELETE', 'GET'],
                        help='Operation type: "CREATE" to create a new ACL user (default), '
                             '"DELETE" to delete an existing ACL user, '
                             '"GET" to get ACL user details from all nodes')
    parser.add_argument('--log_level', default='DEBUG', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Log level')
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        config = load_config(args.config)

        redis_port = config.REDIS_PORT
        master_name = config.REDIS_MASTER
        admin_password = config.REDIS_ADMIN_PASSWORD
        admin_username = config.REDIS_ADMIN_USER
        username = config.USERNAME
        acl_settings = config.ACL_SETTINGS.model_dump()
        sentinel_nodes = [(node, redis_port) for node in config.REDIS_NODES]
        acl_manager = RedisACLManager(sentinel_port=redis_port, master_name=master_name, admin_password=admin_password,
                                      admin_username=admin_username, username=username, acl_config=acl_settings,
                                      sentinel_hosts=sentinel_nodes)

        if args.operation == 'CREATE':
            acl_manager.create_acl_user()
        elif args.operation == 'DELETE':
            acl_manager.delete_acl_user()
        elif args.operation == 'GET':
            user_acl = acl_manager.get_acl_user(username)
            for node, acl in user_acl.items():
                if isinstance(acl, dict):
                    logging.info(f"ACL details for user '{username}' on node {node}:")
                    for key, value in acl.items():
                        logging.info(f"{key}: {value}")
                else:
                    logging.error(f"Error retrieving ACL details for user '{username}' on node {node}: {acl}")
        else:
            logging.error("Invalid operation. Please use 'CREATE', 'DELETE', or 'GET'.")
            sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON configuration: {e}")
        sys.exit(1)
    except ValidationError as e:
        logging.error(f"Configuration validation error: {e}")
        sys.exit(1)
    except redis.exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
