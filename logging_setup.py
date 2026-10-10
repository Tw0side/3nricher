import logging
import sys


from config import Config

def setup_logging(level: str | None = None) -> logging.Logger:
	"""
	
	Configure the root logger and retunr the 3nricher logger.
	
	 Args:
        level: Optional override ("DEBUG", "INFO", "WARNING", "ERROR").
               If None, uses Config.LOG_LEVEL.

    	Returns:
        The `3nricher` logger instance.
    	"""
	
	log_level_name = (level or Config.LOG_LEVEL).upper()
	log_level = getattr(logging, log_level_name, logging.INFO)
	
	
	logging.basicConfig(
		level=log_level,
		format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
		datefmt="%Y-%m-%dT%H:%M:%S%z",
		stream=sys.stderr,
		force=True,
	)

	logging.getLogger("urllib3").setLevel(logging.WARNING)
	logging.getLogger("requests").setLevel(logging.WARNING)
	logging.getLogger("charset_normalizer").setLevel(logging.WARNING)
	
	return logging.getLogger("3nricher")
