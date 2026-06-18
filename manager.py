
import os
import json
import sys

def get_app_data_dir():
    """
    Returns the absolute path to the system-specific local app data folder.
    e.g., C:\\Users\\<Username>\\AppData\\Local\\SamparkKranti on Windows.
    """
    if sys.platform == "win32":
        base_dir = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    elif sys.platform == "darwin":
        base_dir = os.path.expanduser("~/Library/Application Support")
    else:
        base_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        
    app_dir = os.path.join(base_dir, "SamparkKranti")
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

class ConfigManager:
    def __init__(self):
        # Resolve config directory within the system AppData folder
        base_app_dir = get_app_data_dir()
        config_name = os.environ.get("NEXUS_CONFIG_DIR", "config")
        
        # If NEXUS_CONFIG_DIR is an absolute path, respect it; otherwise, locate within AppData
        if os.path.isabs(config_name):
            self.config_dir = config_name
        else:
            self.config_dir = os.path.join(base_app_dir, config_name)
            
        os.makedirs(self.config_dir, exist_ok=True)
        self.settings_path = os.path.join(self.config_dir, 'settings.json')
        self.profile_path = os.path.join(self.config_dir, 'profile.json')

        self.default_settings = {
            "theme": "dark",
            "window_width": 1280,
            "window_height": 800,
            "window_x": None,
            "window_y": None,
            "notifications_enabled": True,
            "sound_enabled": True,
            "auto_download_photos": True,
            "auto_download_documents": True
        }

        # Initial blank profile forces onboarding modal on first app launch
        self.default_profile = {
            "name": "",
            "username": "",
            "avatar_letter": "S",
            "avatar_color": "#6366f1",
            "bio": "Ready for decentralized connections.",
            "status": "online"
        }

    def load_settings(self):
        if not os.path.exists(self.settings_path):
            self.save_settings(self.default_settings)
            return self.default_settings
        try:
            with open(self.settings_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return self.default_settings

    def save_settings(self, settings):
        try:
            with open(self.settings_path, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4)
            return True
        except Exception:
            return False

    def update_setting(self, key, value):
        settings = self.load_settings()
        settings[key] = value
        self.save_settings(settings)

    def load_profile(self):
        if not os.path.exists(self.profile_path):
            self.save_profile(self.default_profile)
            return self.default_profile
        try:
            with open(self.profile_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return self.default_profile

    def save_profile(self, profile):
        try:
            with open(self.profile_path, 'w', encoding='utf-8') as f:
                json.dump(profile, f, indent=4)
            return True
        except Exception:
            return False