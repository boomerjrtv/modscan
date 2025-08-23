#!/usr/bin/env python3
"""
Dynamic API schema generator for frontend-backend consistency
Prevents hardcoded frontend logic by automatically generating schema
"""

import sqlite3
import json
from typing import Dict, List, Any
from asset_manager import AssetManager

class APISchemaGenerator:
    """Generates dynamic API schema from database structure"""
    
    def __init__(self, db_path: str = "lean_recon.db"):
        self.db_path = db_path
        self.asset_manager = AssetManager()
    
    def get_table_schema(self, table_name: str) -> Dict[str, Any]:
        """Get schema information for a table"""
        with self.asset_manager._get_db() as db:
            cursor = db.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            schema = {
                "table": table_name,
                "columns": [],
                "types": {},
                "nullable": {},
                "defaults": {}
            }
            
            for col_info in columns:
                col_name = col_info[1]
                col_type = col_info[2]
                not_null = col_info[3]
                default_val = col_info[4]
                
                schema["columns"].append(col_name)
                schema["types"][col_name] = col_type
                schema["nullable"][col_name] = not not_null
                schema["defaults"][col_name] = default_val
            
            return schema
    
    def get_assets_display_config(self) -> Dict[str, Any]:
        """Generate display configuration for assets table"""
        schema = self.get_table_schema("assets")
        
        # Define which columns to show and their display properties
        display_config = {
            "visible_columns": [],
            "column_labels": {},
            "column_types": {},
            "sortable": {},
            "filterable": {},
            "searchable": []
        }
        
        # Column configurations
        column_configs = {
            "id": {"label": "ID", "visible": False, "sortable": True},
            "url": {"label": "URL", "visible": True, "sortable": True, "filterable": True, "searchable": True},
            "host": {"label": "Host", "visible": True, "sortable": True, "filterable": True, "searchable": True},
            "status_code": {"label": "Status", "visible": True, "sortable": True, "filterable": True},
            "response_time": {"label": "Time (ms)", "visible": True, "sortable": True},
            "content_length": {"label": "Size", "visible": True, "sortable": True},
            "title": {"label": "Title", "visible": True, "sortable": False, "searchable": True},
            "tech_stack": {"label": "Technology", "visible": True, "sortable": False, "filterable": True, "searchable": True},
            "screenshot_path": {"label": "Screenshot", "visible": True, "sortable": False},
            "discovery_method": {"label": "Method", "visible": True, "sortable": True, "filterable": True},
            "discovered_at": {"label": "Discovered", "visible": True, "sortable": True},
            "last_scanned": {"label": "Last Scan", "visible": True, "sortable": True}
        }
        
        # Build configuration based on actual database schema
        for col_name in schema["columns"]:
            if col_name in column_configs:
                config = column_configs[col_name]
                
                if config.get("visible", False):
                    display_config["visible_columns"].append(col_name)
                
                display_config["column_labels"][col_name] = config.get("label", col_name.title())
                display_config["column_types"][col_name] = schema["types"][col_name]
                display_config["sortable"][col_name] = config.get("sortable", False)
                display_config["filterable"][col_name] = config.get("filterable", False)
                
                if config.get("searchable", False):
                    display_config["searchable"].append(col_name)
        
        return display_config
    
    def get_available_domains(self) -> List[str]:
        """Get list of available domains for authentication"""
        with self.asset_manager._get_db() as db:
            cursor = db.execute("SELECT DISTINCT host FROM assets WHERE host IS NOT NULL ORDER BY host")
            domains = [row[0] for row in cursor.fetchall()]
            return domains
    
    def get_api_endpoints(self) -> Dict[str, Any]:
        """Generate API endpoint documentation"""
        return {
            "endpoints": {
                "/api/assets": {
                    "methods": ["GET"],
                    "description": "Get assets list with filtering",
                    "parameters": {
                        "search": "string - Search term for URL, title, tech_stack",
                        "status": "integer - Filter by status code",
                        "host": "string - Filter by host",
                        "method": "string - Filter by discovery method"
                    }
                },
                "/api/domains": {
                    "methods": ["GET"],
                    "description": "Get available domains for authentication"
                },
                "/api/schema": {
                    "methods": ["GET"],
                    "description": "Get dynamic schema configuration"
                }
            }
        }
    
    def generate_frontend_config(self) -> Dict[str, Any]:
        """Generate complete frontend configuration"""
        return {
            "assets": self.get_assets_display_config(),
            "domains": self.get_available_domains(),
            "api": self.get_api_endpoints(),
            "version": "1.0",
            "timestamp": "2025-01-19"
        }

def main():
    """Generate and print schema configuration"""
    generator = APISchemaGenerator()
    config = generator.generate_frontend_config()
    print(json.dumps(config, indent=2))

if __name__ == "__main__":
    main()