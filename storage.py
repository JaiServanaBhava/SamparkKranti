import os
import shutil
import sys

def get_app_data_dir() -> str:
    """
    Returns the absolute path to the system-specific local app data folder.
    e.g., C:\\Users\\<Username>\\AppData\\Local\\SamparkKranti on Windows.
    Creates the directory if it does not exist.
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


class StorageEngine:
    def __init__(self, base_dir="storage"):
        # Resolve storage directory relative to system AppData if it is not an absolute path
        if os.path.isabs(base_dir):
            self.base_dir = base_dir
        else:
            self.base_dir = os.path.join(get_app_data_dir(), base_dir)
            
        self.categories = ["images", "videos", "audio", "documents"]
        self._init_folders()

    def _init_folders(self):
        for cat in self.categories:
            os.makedirs(os.path.join(self.base_dir, cat), exist_ok=True)

    def determine_category(self, file_extension):
        ext = file_extension.lower().lstrip('.')
        mapping = {
            'images': ['jpg', 'jpeg', 'png', 'webp', 'gif'],
            'videos': ['mp4', 'mkv', 'mov', 'webm'],
            'audio': ['mp3', 'wav', 'ogg', 'm4a'],
            'documents': ['pdf', 'docx', 'xlsx', 'pptx', 'txt', 'zip']
        }
        for cat, extensions in mapping.items():
            if ext in extensions:
                return cat
        return 'documents'

    def save_file(self, source_path):
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source asset not found: {source_path}")
            
        filename = os.path.basename(source_path)
        ext = os.path.splitext(filename)[1]
        category = self.determine_category(ext)
        
        dest_dir = os.path.join(self.base_dir, category)
        dest_path = os.path.join(dest_dir, filename)

        # Handle file name collisions gracefully
        counter = 1
        name, extension = os.path.splitext(filename)
        while os.path.exists(dest_path):
            dest_path = os.path.join(dest_dir, f"{name}_{counter}{extension}")
            counter += 1

        shutil.copy2(source_path, dest_path)
        return {
            "file_name": os.path.basename(dest_path),
            "file_path": os.path.abspath(dest_path),
            "file_type": category,
            "file_size": os.path.getsize(dest_path)
        }

    def get_storage_metrics(self, db_path="messenger.db"):
        # Resolve database path relative to AppData if not specified as an absolute path
        if not os.path.isabs(db_path):
            db_path = os.path.join(get_app_data_dir(), db_path)

        metrics = {cat: 0 for cat in self.categories}
        metrics["database"] = os.path.getsize(db_path) if os.path.exists(db_path) else 0
        
        for cat in self.categories:
            folder = os.path.join(self.base_dir, cat)
            for root, dirs, files in os.walk(folder):
                metrics[cat] += sum(os.path.getsize(os.path.join(root, name)) for name in files)
                
        metrics["total"] = sum(metrics.values())
        return metrics