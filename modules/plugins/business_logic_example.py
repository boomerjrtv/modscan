"""
Example of a business logic plugin.
"""

def run(url, session):
    """
    This function is called by the vulnerability scanner.
    It should return a list of VulnerabilityFinding objects.
    """
    # In a real plugin, you would perform some checks here.
    # For this example, we'll just return an empty list.
    return []
