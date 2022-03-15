import sys
import logging

logger = logging.getLogger('rawhttpget')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s\t %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
