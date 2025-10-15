import json
import os

class ConfigManager:
    def __init__(self):
        self.config_file = self.get_config_path()

    def get_config_path(self):
        """获取配置文件路径"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(current_dir, 'settings.json')

    def load_config(self):
        """加载配置"""
        default_config = {
            'udp_mode': False,
            'enable_upnp': False,
            'verbose': False,
            'exit_on_change': False,
            'stun_server': '',
            'keep_alive': '',
            'bind_interface': '',
            'bind_port': '',
            'forward_method': '',
            'target_address': '',
            'target_port': '',
            'keep_retrying': False,
            'script_path': ''
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # 合并配置，确保新字段有默认值
                    for key, value in default_config.items():
                        if key not in loaded_config:
                            loaded_config[key] = value
                    return loaded_config
        except Exception:
            pass

        return default_config.copy()

    def save_config(self, config):
        """保存配置"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
