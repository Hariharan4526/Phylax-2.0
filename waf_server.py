"""
Phylax WAF Engine Startup
Runs WAF HTTP handler on configured host/port.
"""

from config import config, logger
from src.waf_engine import WAFEngine
from src.http_handler import WAFHTTPHandler


def create_waf_engine() -> WAFEngine:
    """Create WAF engine with configured model artifacts."""
    return WAFEngine(
        model_path=config.MODEL_PATH,
        scaler_path=config.SCALER_PATH,
        feature_names_path=config.FEATURES_PATH,
    )


def main():
    """Start WAF API server."""
    logger.info("Starting WAF server")
    engine = create_waf_engine()
    handler = WAFHTTPHandler(engine)
    handler.run(host=config.WAF_HOST, port=config.WAF_PORT, debug=config.DEBUG)


if __name__ == "__main__":
    main()
