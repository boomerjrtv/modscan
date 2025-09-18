import aiohttp
import logging

logger = logging.getLogger(__name__)

def get_request_mutator_trace_config():
    """
    Returns an aiohttp.TraceConfig object with request mutation hooks.

    This configuration can be passed to an aiohttp.ClientSession to intercept
    and modify requests before they are sent.
    """
    
    async def mutate_request(session, trace_config_ctx, params):
        """
        This is the signal handler that acts as our interceptor.
        It modifies the request parameters in-place.
        """
        try:
            # --- MUTATOR PIPELINE --- #
            # This is where we will add more advanced mutators in the future.
            
            # 1. Proof-of-Concept Mutator: Add a custom header.
            params.headers['X-Gemini-Scan'] = 'true'
            # Reduce noise: trace at DEBUG level, not INFO
            logger.debug(f"Request to {params.url} mutated: Added X-Gemini-Scan header.")
            
        except Exception as e:
            logger.error(f"Error in request mutator middleware: {e}")

    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_start.append(mutate_request)
    
    return trace_config
