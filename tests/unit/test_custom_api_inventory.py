# tests/unit/test_custom_api_inventory.py
import pytest
from unittest.mock import MagicMock # pytest-mock의 mocker fixture와 함께 사용 가능
from plugins.inventory.custom_api_inventory import InventoryModule, AnsibleError 

# 테스트에 사용될 모의 API 응답 데이터
# 플러그인 파일에서 가져온 MOCK_API_RESPONSE를 여기에 정의합니다.
MOCK_API_SUCCESS_RESPONSE = {
    "_meta": {
        "hostvars": {
            "cosmos-validator-01-prod-eu": {
                "ansible_host": "10.0.1.10", "ansible_user": "ubuntu", "ansible_port": 22,
                "csp": "AWS", "node_role": "cosmos_validator", "server_location": "eu-central-1",
                "custom_labels": {"blockchain_type": "cosmos", "environment": "production", "project": "alpha"}
            },
            "monitoring-util-01-fsn": {
                "ansible_host": "10.0.0.7", "ansible_user": "root", "ansible_port": 22,
                "csp": "Hetzner", "node_role": "utility_monitoring", "server_location": "fsn1-dc14",
                "custom_labels": {"datacenter": "hel1", "environment": "ops", "tool": "monitoring_stack"}
            }
        }
    },
    "all": { # 'all' 그룹의 자식 그룹들 명시
        "children": [
            "ungrouped", "csp_aws", "csp_hetzner", "role_cosmos_validator", "role_utility_monitoring",
            "label_environment_production", "label_environment_ops" # 예시 레이블 그룹
        ]
    },
    "groups": {
        "csp_aws": {"hosts": ["cosmos-validator-01-prod-eu"], "vars": {"aws_region_specific_var": "value1"}},
        "csp_hetzner": {"hosts": ["monitoring-util-01-fsn"]},
        "role_cosmos_validator": {"hosts": ["cosmos-validator-01-prod-eu"]},
        "role_utility_monitoring": {"hosts": ["monitoring-util-01-fsn"]},
        "label_environment_production": {"hosts": ["cosmos-validator-01-prod-eu"]},
        "label_environment_ops": {"hosts": ["monitoring-util-01-fsn"]},
        "some_parent_group": { # 그룹 계층 구조 테스트용
            "children": ["csp_aws"],
            "vars": {"parent_var": "parent_value"}
        },
        "ungrouped": {"hosts": []} # API가 명시적으로 ungrouped 호스트를 제공할 수도 있음
    }
}

MOCK_API_EMPTY_RESPONSE = {
    "_meta": {"hostvars": {}}, "all": {"children": ["ungrouped"]}, "groups": {"ungrouped": {"hosts": []}}
}

MOCK_API_NO_GROUPS_RESPONSE = {
    "_meta": {
        "hostvars": {
            "host_only_node": {"ansible_host": "10.0.0.99", "service": "standalone"}
        }
    },
    "all": {"children": ["ungrouped"]},
    # groups 섹션이 아예 없을 수 있음
}

REQUESTS_GET_PATH = 'plugins.inventory.custom_api_inventory.requests.get'

@pytest.fixture
def inventory_plugin(mocker):
    """Setup an instance of the InventoryModule with mocked Ansible internal objects."""
    plugin = InventoryModule()
    plugin.inventory = mocker.MagicMock() # Ansible Inventory 객체 모킹
    plugin.display = mocker.MagicMock()   # Ansible Display 객체 모킹

    # self.get_option 모킹 (옵션 값을 반환하도록 설정)
    def mock_get_option(option_name):
        options = {
            'api_url': 'http://fakeapi.com/inventory',
            'api_token': 'fake_token_123',
            'use_ssl_verify': False,
            'timeout': 5,
            'cache': False # 테스트 시 캐시 비활성화 또는 별도 테스트
        }
        return options.get(option_name, plugin._OPTIONS_DEFAULTS.get(option_name)) # DOCUMENTATION의 기본값 처리
    plugin.get_option = MagicMock(side_effect=mock_get_option)
    
    # _OPTIONS_DEFAULTS는 BaseInventoryPlugin에 없으므로, 플러그인에 추가하거나
    # get_option 모킹 시 기본값을 직접 처리해야 합니다.
    # 여기서는 DOCUMENTATION의 default 값을 플러그인이 내부적으로 가지고 있다고 가정하거나,
    # get_option 모킹 시 모든 필수/선택 옵션에 대한 반환값을 명시합니다.
    # 간단하게 하기 위해, 테스트에 필요한 옵션만 mock_get_option에서 반환하도록 합니다.
    # 플러그인 DOCUMENTATION에 use_ssl_verify와 timeout의 default가 정의되어 있으므로,
    # self.get_option이 이를 반영해야 합니다.
    # BaseInventoryPlugin.get_option은 이 기본값을 자동으로 처리해줍니다.
    # 따라서, side_effect에서 기본값을 명시적으로 처리할 필요는 없을 수 있습니다.
    # 여기서는 명시적으로 처리하는 형태로 두겠습니다.
    plugin._OPTIONS_DEFAULTS = { # 테스트를 위해 임시로 설정 (원래는 BaseInventoryPlugin이 처리)
        'use_ssl_verify': True,
        'timeout': 10
    }
    # 실제로는 BaseInventoryPlugin이 DOCUMENTATION을 파싱하여 기본값을 self.get_option에 반영합니다.
    # 유닛 테스트 시에는 이 부분을 모킹으로 제어하는 것이 일반적입니다.

    return plugin

class TestCustomApiInventoryPlugin:

    def test_verify_file_valid(self, inventory_plugin):
        """Test verify_file with a valid file path."""
        assert inventory_plugin.verify_file('inventory.customapi.yml') is True
        assert inventory_plugin.verify_file('inventory.customapi.yaml') is True

    def test_verify_file_invalid(self, inventory_plugin):
        """Test verify_file with an invalid file path."""
        assert inventory_plugin.verify_file('inventory.txt') is False

    def test_populate_inventory_all_features(self, inventory_plugin):
        """Test _populate_inventory with a full API response."""
        inventory_plugin._populate_inventory(MOCK_API_SUCCESS_RESPONSE)

        # Host verifications
        inventory_plugin.inventory.add_host.assert_any_call("cosmos-validator-01-prod-eu")
        inventory_plugin.inventory.set_variable.assert_any_call(
            "cosmos-validator-01-prod-eu", "ansible_host", "10.0.1.10"
        )
        inventory_plugin.inventory.set_variable.assert_any_call(
            "cosmos-validator-01-prod-eu", "custom_labels", 
            {"blockchain_type": "cosmos", "environment": "production", "project": "alpha"}
        )
        inventory_plugin.inventory.add_host.assert_any_call("monitoring-util-01-fsn")

        # Group verifications
        inventory_plugin.inventory.add_group.assert_any_call("csp_aws")
        inventory_plugin.inventory.set_variable.assert_any_call("csp_aws", "aws_region_specific_var", "value1")
        inventory_plugin.inventory.add_host.assert_any_call("cosmos-validator-01-prod-eu", group="csp_aws")

        inventory_plugin.inventory.add_group.assert_any_call("some_parent_group")
        inventory_plugin.inventory.set_variable.assert_any_call("some_parent_group", "parent_var", "parent_value")
        inventory_plugin.inventory.add_child.assert_any_call("some_parent_group", "csp_aws")

        # 'all' group children
        for child_group in MOCK_API_SUCCESS_RESPONSE["all"]["children"]:
            inventory_plugin.inventory.add_group.assert_any_call(child_group) # 그룹 생성 확인
            inventory_plugin.inventory.add_child.assert_any_call("all", child_group)

    def test_populate_inventory_empty_response(self, inventory_plugin):
        """Test _populate_inventory with an empty but valid API response."""
        inventory_plugin._populate_inventory(MOCK_API_EMPTY_RESPONSE)
        inventory_plugin.inventory.add_host.assert_not_called() # 호스트가 없으므로
        inventory_plugin.inventory.add_group.assert_any_call("ungrouped")
        inventory_plugin.inventory.add_child.assert_any_call("all", "ungrouped")

    def test_populate_inventory_no_groups_section(self, inventory_plugin):
        """Test _populate_inventory when API response has no 'groups' section."""
        inventory_plugin._populate_inventory(MOCK_API_NO_GROUPS_RESPONSE)
        inventory_plugin.inventory.add_host.assert_called_once_with("host_only_node")
        inventory_plugin.inventory.set_variable.assert_any_call("host_only_node", "ansible_host", "10.0.0.99")
        # 'groups' 섹션이 없으므로, 명시적인 그룹 추가/설정 호출은 'all', 'ungrouped' 외에는 적어야 함
        # (호스트 추가 시 자동으로 'all', 'ungrouped'에 들어갈 수 있음)

    def test_fetch_data_successful(self, inventory_plugin, mocker):
        """Test _fetch_data_from_api on successful API call."""
        mock_response = mocker.MagicMock() 
        mock_response.json.return_value = {"data": "success"}
        mock_response.raise_for_status = mocker.MagicMock()
        
        # mocker.patch를 사용하여 requests.get을 모킹
        mock_requests_get = mocker.patch(REQUESTS_GET_PATH, return_value=mock_response)

        # get_option이 특정 값을 반환하도록 재설정 (픽스처의 기본 설정을 오버라이드)
        inventory_plugin.get_option.side_effect = lambda name: {
            'api_url': 'http://test.com/api', 'api_token': 'test_token',
            'use_ssl_verify': True, 'timeout': 15
        }.get(name, True) # 기본값 True (use_ssl_verify의 경우)

        data = inventory_plugin._fetch_data_from_api()

        mock_requests_get.assert_called_once_with(
            'http://test.com/api',
            headers={'Accept': 'application/json', 'Authorization': 'Bearer test_token'},
            timeout=15,
            verify=True
        )
        assert data == {"data": "success"}

    def test_fetch_data_http_error(self, inventory_plugin, mocker): # <--- mocker를 인자로 받음
        """Test _fetch_data_from_api on HTTP error."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 401
        mock_response.reason = "Unauthorized"
        mock_response.text = '{"error": "Invalid token"}'
        mock_response.json.return_value = {"error": "Invalid token"}
        
        import requests # requests.exceptions.HTTPError를 위해 임포트
        http_error = requests.exceptions.HTTPError(response=mock_response)
        mock_response.raise_for_status = mocker.MagicMock(side_effect=http_error)
        
        mock_requests_get = mocker.patch(REQUESTS_GET_PATH, return_value=mock_response)
        
        inventory_plugin.get_option.side_effect = lambda name: {
            'api_url': 'http://test.com/api', 'api_token': 'invalid_token',
            'use_ssl_verify': True, 'timeout': 10
        }.get(name, True)

        with pytest.raises(AnsibleError, match=r"HTTP Error from API .* 401 Unauthorized .* Detail: {'error': 'Invalid token'}"):
            inventory_plugin._fetch_data_from_api()

    def test_parse_method_overall_success(self, inventory_plugin, mocker): # <--- mocker를 인자로 받음
        """Test the main parse method for a successful run."""
        mock_http_response = mocker.MagicMock()
        mock_http_response.json.return_value = MOCK_API_SUCCESS_RESPONSE # 테스트용 목 데이터 사용
        mock_http_response.raise_for_status = mocker.MagicMock()
        
        mock_requests_get = mocker.patch(REQUESTS_GET_PATH, return_value=mock_http_response)

        # parse 메소드 실행에 필요한 Ansible 내부 객체들 모킹
        mock_ansible_inventory_obj = inventory_plugin.inventory # fixture에서 이미 모킹됨
        mock_loader_obj = mocker.MagicMock()
        dummy_path = 'dummy_inventory_config.customapi.yml'

        # parse 실행
        inventory_plugin.parse(mock_ansible_inventory_obj, mock_loader_obj, dummy_path, cache=False)

        api_url = inventory_plugin.get_option('api_url')
        api_token = inventory_plugin.get_option('api_token')
        timeout = inventory_plugin.get_option('timeout')
        verify_ssl = inventory_plugin.get_option('use_ssl_verify')
        
        expected_headers = {'Accept': 'application/json'}
        if api_token: # api_token이 None이 아닐 경우에만 헤더에 추가
            expected_headers['Authorization'] = f'Bearer {api_token}'

        mock_requests_get.assert_called_once_with(
            api_url, # inventory_plugin.get_option을 통해 설정된 URL 사용
            headers=expected_headers,
            timeout=timeout, # inventory_plugin.get_option을 통해 설정된 timeout 사용
            verify=verify_ssl # inventory_plugin.get_option을 통해 설정된 use_ssl_verify 사용
        )
        
        inventory_plugin.inventory.add_host.assert_any_call("cosmos-validator-01-prod-eu")
        inventory_plugin.inventory.add_group.assert_any_call("csp_aws")

    # ... (다른 테스트 케이스들도 mocker를 인자로 받도록 수정) ...