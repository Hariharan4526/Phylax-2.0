# config.py - Configuration management for Phylax-2.0
# Uses environment variables with sensible defaults

import os
import logging
from pathlib import Path

# Get project root directory
PROJECT_ROOT = Path(__file__).parent

class Config:
    """Base configuration"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'phylax-2026-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    TESTING = False
    
    # Server Configuration
    WAF_HOST = os.getenv('WAF_HOST', '0.0.0.0')
    WAF_PORT = int(os.getenv('WAF_PORT', 5000))
    DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', 5001))
    
    # Database Configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///dashboard.db')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Model Configuration
    MODEL_PATH = os.getenv('MODEL_PATH', str(PROJECT_ROOT / 'models' / 'gb_model.pkl'))
    SCALER_PATH = os.getenv('SCALER_PATH', str(PROJECT_ROOT / 'models' / 'scaler.pkl'))
    FEATURES_PATH = os.getenv('FEATURES_PATH', str(PROJECT_ROOT / 'models' / 'feature_names.json'))
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', str(PROJECT_ROOT / 'logs' / 'phylax.log'))
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # WAF Configuration
    WAF_URL = os.getenv('WAF_URL', 'http://localhost:5000')
    ML_THRESHOLD = float(os.getenv('ML_THRESHOLD', '0.5'))
    ANOMALY_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', '0.7'))
    MAX_PAYLOAD_SIZE = int(os.getenv('MAX_PAYLOAD_SIZE', '10485760'))  # 10 MB
    
    # Request Configuration
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '10'))
    RETRIES = int(os.getenv('RETRIES', '3'))
    RETRY_DELAY = float(os.getenv('RETRY_DELAY', '0.5'))
    
    # API Configuration
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = DEBUG
    
    @staticmethod
    def init_logging():
        """Initialize logging configuration"""
        # Create logs directory if it doesn't exist
        log_dir = Path(Config.LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=Config.LOG_LEVEL,
            format=Config.LOG_FORMAT,
            handlers=[
                logging.FileHandler(Config.LOG_FILE),
                logging.StreamHandler()
            ]
        )
        
        return logging.getLogger(__name__)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY')  # Must be set in production
    
    @classmethod
    def validate(cls):
        """Validate production configuration"""
        if not os.getenv('SECRET_KEY'):
            raise ValueError("SECRET_KEY must be set in production environment")
        return cls

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    DATABASE_URL = 'sqlite:///:memory:'
    SQLALCHEMY_DATABASE_URI = DATABASE_URL

# Configuration factory
def get_config():
    """Get configuration based on environment"""
    env = os.getenv('ENVIRONMENT', 'development').lower()
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    config_class = configs.get(env, DevelopmentConfig)
    
    if env == 'production':
        config_class.validate()
    
    return config_class

# Initialize and export
config = get_config()
logger = config.init_logging()