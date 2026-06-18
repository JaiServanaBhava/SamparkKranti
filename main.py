

import os
import sys
import logging
import argparse

# Parse args early
parser = argparse.ArgumentParser(description="Sampark Kranti DHT Messenger")
parser.add_argument("--port",      type=int,   default=7777,    help="TCP listen port")
parser.add_argument("--debug",     action="store_true",          help="Enable pywebview DevTools")
parser.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                    help="Logging verbosity")
args, _unknown = parser.parse_known_args()

# Logging
logging.basicConfig(
    level=getattr(logging, args.log_level),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sampark.main")

try:
    import webview
    WEBVIEW_AVAILABLE = True
except ImportError:
    WEBVIEW_AVAILABLE = False
    logger.warning("pywebview not found. Headless mode run activated.")

from manager  import ConfigManager
from bridge   import APIBridge


def _find_frontend() -> str:
    candidates = [
        os.path.join(os.path.dirname(__file__), "index.html"),
        os.path.join(os.path.dirname(__file__), "frontend", "index.html"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    raise FileNotFoundError(
        "index.html not found. Check root directory."
    )


def main():
    logger.info("Initializing Sampark Kranti…")

    config = ConfigManager()

    # API Bridge Initializer
    bridge = APIBridge(config, logger)

    if not WEBVIEW_AVAILABLE:
        logger.info("Sampark Kranti running in headless background mode.")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Termination hook accepted.")
        return

    try:
        html_path = _find_frontend()
    except FileNotFoundError as e:
        logger.critical(str(e))
        sys.exit(1)

    window = webview.create_window(
        title   = "Sampark Kranti",  # Window title stays exactly "Sampark Kranti"
        url     = f"file://{html_path}",
        js_api  = bridge,
        width   = config.load_settings().get("window_width",  1280),
        height  = config.load_settings().get("window_height", 800),
        x       = config.load_settings().get("window_x"),
        y       = config.load_settings().get("window_y"),
        resizable        = True,
        text_select      = True,
        confirm_close    = False,
        background_color = "#0f0f0f",
    )

    bridge.set_window(window)

    def _on_closing():
        try:
            settings = config.load_settings()
            settings["window_width"]  = window.width
            settings["window_height"] = window.height
            settings["window_x"]      = window.x
            settings["window_y"]      = window.y
            config.save_settings(settings)
        except Exception:
            pass

    window.events.closing += _on_closing

    logger.info(f"Opening Sampark Kranti → {html_path}")
    webview.start(debug=args.debug, private_mode=False)


if __name__ == "__main__":
    main()