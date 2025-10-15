import json
import os
import sys
from pathlib import Path

class ConfigManager:
    def __init__(self):
        self.config_file = self.get_config_path()

    def get_config_path(self):
        """获取配置文件路径"""
        # 判断是否是打包后的exe
        if getattr(sys, 'frozen', False):
            # 打包后的exe，使用用户数据目录
            if os.name == 'nt':  # Windows
                app_data_dir = Path(os.environ.get('APPDATA', ''))
                config_dir = app_data_dir / 'NatterGUI'
            else:  # Linux/Mac
                home_dir = Path.home()
                config_dir = home_dir / '.config' / 'natter-gui'
        else:
            # 开发环境，使用当前目录
            current_dir = Path(__file__).parent
            config_dir = current_dir

        # 确保配置目录存在
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # 返回配置文件完整路径
        return str(config_dir / 'settings.json')

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
            # 确保配置目录存在（双重保险）
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
                
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False
