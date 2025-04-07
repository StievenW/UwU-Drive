from waitress import serve
from app import app
import logging
import multiprocessing
import os
import signal
import sys
from datetime import datetime

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('waitress')

def calculate_threads():
    """Calculate optimal threads for low-end hardware"""
    cpu_count = multiprocessing.cpu_count()
    
    if HAVE_PSUTIL:
        # If psutil available, use memory info
        memory = psutil.virtual_memory()
        total_mem_gb = memory.total / (1024 * 1024 * 1024)
        
        # Conservative thread calculation for low memory
        # Allocate ~100MB per thread
        mem_threads = int((total_mem_gb * 1024) / 100)
        
        # Use minimum of CPU-based or memory-based thread count
        thread_count = min(
            cpu_count * 4,  # 4 threads per core
            mem_threads,    # Memory-based thread limit
            32             # Hard maximum for stability
        )
    else:
        # Simple calculation without psutil
        # Use 4 threads per core, max 32
        thread_count = min(cpu_count * 4, 32)
    
    # Ensure minimum of 4 threads
    return max(4, thread_count)

def signal_handler(sig, frame):
    """Handle shutdown gracefully"""
    logger.info("Shutting down server...")
    sys.exit(0)

def monitor_resources():
    """Log resource usage"""
    if HAVE_PSUTIL:
        process = psutil.Process()
        mem = process.memory_info()
        cpu = process.cpu_percent()
        logger.info(f"Memory usage: {mem.rss/1024/1024:.1f}MB, CPU: {cpu}%")

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create logs directory if not exists
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Setup logging with rotation
    log_file = f"logs/server_{datetime.now().strftime('%Y%m%d')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    threads = calculate_threads()
    logger.info(f"Starting server with {threads} threads")
    
    try:
        # Configure Waitress with adjusted chunk settings
        serve(
            app,
            host='0.0.0.0',
            port=5000,
            threads=threads,
            url_scheme='https',
            ident='UwU Drive Storage',
            
            # Adjusted for 9.99MB chunks
            max_request_body_size=10*1024*1024,    # 10MB per request
            cleanup_interval=60,                    # 1 min cleanup
            channel_timeout=300,                    # 5 min timeout
            connection_limit=100,                   # Stable connections
            
            # Optimized buffer sizes for 9.99MB chunks
            send_bytes=32768,                      # 32KB send chunks
            outbuf_overflow=20971520,              # 20MB outbuf
            inbuf_overflow=20971520,               # 20MB inbuf
            max_request_header_size=262144,        # 256KB headers
            
            # Basic settings
            asyncore_use_poll=True,
            expose_tracebacks=False,
            url_prefix='',
            
            # Network settings
            ipv4=True,
            ipv6=False,
            clear_untrusted_proxy_headers=True,
            trusted_proxy='*',
            
            # Moderate backlog
            backlog=1024
        )
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1)
