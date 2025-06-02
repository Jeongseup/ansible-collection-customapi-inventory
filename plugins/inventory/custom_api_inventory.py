# plugins/inventory/custom_api_inventory.py
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT

from __future__ import annotations


PLUGIN_NAME = 'custom_api_inventory'


DOCUMENTATION = f'''
    name: {PLUGIN_NAME}
    plugin_type: inventory
    short_description: Custom Ansible inventory plugin to fetch data from an API
    description:
        - This plugin fetches inventory data from a specified custom API.
        - It parses the JSON output and populates Ansible's inventory.
    options:
      plugin:
        description: Name of the plugin.
        required: True
        choices: ['{PLUGIN_NAME}']
      api_url:
        description: The URL of the custom API endpoint.
        required: True
        env:
          - name: ANSIBLE_CUSTOM_API_URL
        ini:
          - section: custom_api_inventory
            key: api_url
      api_token:
        description: The authentication token for the custom API.
        required: False
        secret: True
        env:
          - name: ANSIBLE_CUSTOM_API_TOKEN
        ini:
          - section: custom_api_inventory
            key: api_token
      use_ssl_verify:
        description: Whether to verify SSL certificates for the API request.
        type: bool
        default: True # 기본값은 True로 설정
      timeout:
        description: Request timeout in seconds.
        type: int
        default: 10 # 기본 타임아웃 10초
'''

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.errors import AnsibleError, AnsibleParserError
import requests
import json


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = PLUGIN_NAME # 전역 변수 PLUGIN_NAME 사용

    def __init__(self):
        super(InventoryModule, self).__init__()

    def verify_file(self, path):
        super(InventoryModule, self).verify_file(path)
        self.display.vvv(f"Verify_file checking path: {path}")
        if path.endswith(('.customapi.yml', '.customapi.yaml')):
            return True
        return False
    
    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        # self.display는 BaseInventoryPlugin에 의해 이미 설정되어 있습니다.
        self.display.v(f"Custom API Inventory plugin '{self.NAME}' parsing inventory source: {path}")
        config_data = self._read_config_data(path)
        # set _options from config data
        self._consume_options(config_data)

        try:
            raw_data = self._fetch_data_from_api()
        except AnsibleError as e:
            raise AnsibleParserError(f"Failed to fetch or parse data from API: {e}")

        if not raw_data:
            raise AnsibleParserError("API returned no data or the data was empty after fetching.")

        self._populate_inventory(raw_data)
        self.display.v(f"Finished parsing inventory source: {path}")
    def _fetch_data_from_api(self):
        api_url = self.get_option('api_url')
        api_token = self.get_option('api_token')
        # DOCUMENTATION에 정의된 기본값을 사용하도록 get_option 호출
        verify_ssl = self.get_option('use_ssl_verify')
        timeout = self.get_option('timeout')

        self.display.debug(f"DEBUG: api_url from get_option is: '{api_url}'") # display는 BaseInventoryPlugin에 이미 있음

        if not api_url: # 이 검사는 get_option이 None을 반환할 경우를 대비
            raise AnsibleParserError(
                "API URL is not configured correctly. It's a required option."
            )

        headers = {'Accept': 'application/json'}
        if api_token:
            headers['Authorization'] = f'Bearer {api_token}'

        self.display.vvv(f"Fetching inventory data from API: {api_url}")
        self.display.vvv(f"Using SSL verification: {verify_ssl}, Timeout: {timeout}s")
        if api_token:
            self.display.vvv("API token provided.")
        else:
            self.display.vvv("No API token provided.")

        try:
            response = requests.get(api_url, headers=headers, timeout=timeout, verify=verify_ssl)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_message = f"HTTP Error from API ({api_url}): {e.response.status_code} {e.response.reason}"
            try:
                error_detail = e.response.json()
                error_message += f" - Detail: {error_detail}"
            except json.JSONDecodeError:
                error_message += f" - Content: {e.response.text[:200]}"
            raise AnsibleError(error_message) from e
        except requests.exceptions.ConnectionError as e:
            raise AnsibleError(f"Connection error while trying to reach API at {api_url}: {e}") from e
        except requests.exceptions.Timeout as e:
            raise AnsibleError(f"Timeout while trying to reach API at {api_url} (timeout: {timeout}s): {e}") from e
        except requests.exceptions.RequestException as e:
            raise AnsibleError(f"Error fetching data from API at {api_url}: {e}") from e
        except json.JSONDecodeError as e:
            response_text_snippet = response.text[:200] if hasattr(response, 'text') else "No response body"
            raise AnsibleError(f"Failed to parse JSON response from API at {api_url}. Error: {e}. Response snippet: {response_text_snippet}") from e

    def _populate_inventory(self, data):
        # ... (이 부분은 이전 코드와 동일하게 유지, self.display 사용) ...
        if not isinstance(data, dict):
            raise AnsibleParserError("API response, while valid JSON, was not a dictionary (object).")
        self.display.vvv("Populating inventory from processed API data.")
        meta = data.get('_meta', {})
        hostvars_data = meta.get('hostvars', {})
        if not hostvars_data:
            self.display.v("No 'hostvars' found in API response's '_meta' section. No host-specific variables will be set from _meta.")
        for hostname, Hvars in hostvars_data.items():
            self.inventory.add_host(hostname)
            for var_name, var_value in Hvars.items():
                self.inventory.set_variable(hostname, var_name, var_value)
            self.display.vvv(f"Added host '{hostname}' with vars from _meta.")
        groups_data = data.get('groups', {})
        if not groups_data:
            self.display.v("No 'groups' section found in API response. Hosts will only be in 'all' and 'ungrouped' unless otherwise defined.")
        all_group_info = data.get('all', {})
        all_children = all_group_info.get('children', [])
        if all_children:
            for child_group_name in all_children:
                self.inventory.add_group(child_group_name)
                self.inventory.add_child('all', child_group_name)
                self.display.vvv(f"Ensured group '{child_group_name}' exists and is a child of 'all'.")
        for group_name, group_info in groups_data.items():
            if not isinstance(group_info, dict):
                self.display.warning(f"Skipping invalid group data for '{group_name}': not a dictionary.")
                continue
            self.inventory.add_group(group_name)
            self.display.vvv(f"Processing group: '{group_name}'")
            if 'hosts' in group_info:
                for hostname_in_group in group_info['hosts']:
                    self.inventory.add_host(hostname_in_group, group=group_name)
                    self.display.vvv(f"Added host '{hostname_in_group}' to group '{group_name}'.")
            if 'vars' in group_info:
                for var_name, var_value in group_info['vars'].items():
                    self.inventory.set_variable(group_name, var_name, var_value)
                    self.display.vvv(f"Set var '{var_name}' for group '{group_name}'.")
            if 'children' in group_info:
                for child_group_name in group_info['children']:
                    self.inventory.add_group(child_group_name)
                    self.inventory.add_child(group_name, child_group_name)
                    self.display.vvv(f"Added child group '{child_group_name}' to group '{group_name}'.")


