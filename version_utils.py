#!/usr/bin/env python3
"""
caseScope Version Management Utilities
Copyright 2025 Justin Dube
"""

import json
import os
from pathlib import Path

class VersionManager:
    def __init__(self, config_path=None):
        if config_path is None:
            # Try to find version.json in the same directory as this script
            script_dir = Path(__file__).parent
            config_path = script_dir / "version.json"
        
        self.config_path = Path(config_path)
        self._version_data = None
    
    def load_version(self):
        """Load version data from JSON file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    self._version_data = json.load(f)
            else:
                # Fallback version if file doesn't exist
                self._version_data = {
                    "version": "7.0.0",
                    "release_date": "2025-09-24",
                    "description": "Default version",
                    "build": "development"
                }
        except Exception as e:
            print(f"Error loading version: {e}")
            self._version_data = {
                "version": "7.0.0",
                "release_date": "2025-09-24", 
                "description": "Error loading version",
                "build": "development"
            }
        
        return self._version_data
    
    def get_version(self):
        """Get the current version string (always fresh)"""
        self.load_version()  # Always reload to get latest version
        return self._version_data.get("version", "7.0.0")
    
    def get_full_version_info(self):
        """Get complete version information (always fresh)"""
        self.load_version()  # Always reload to get latest version
        return self._version_data
    
    def update_version(self, new_version, description=None):
        """Update version in the JSON file"""
        if self._version_data is None:
            self.load_version()
        
        self._version_data["version"] = new_version
        if description:
            self._version_data["description"] = description
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._version_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error updating version: {e}")
            return False

# Global version manager instance
version_manager = VersionManager()

def get_version():
    """Convenience function to get current version"""
    return version_manager.get_version()

def get_version_info():
    """Convenience function to get full version info"""
    return version_manager.get_full_version_info()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "get":
            print(get_version())
        elif sys.argv[1] == "info":
            info = get_version_info()
            print(f"Version: {info['version']}")
            print(f"Release Date: {info['release_date']}")
            print(f"Description: {info['description']}")
            print(f"Build: {info['build']}")
        elif sys.argv[1] == "set" and len(sys.argv) > 2:
            new_version = sys.argv[2]
            description = sys.argv[3] if len(sys.argv) > 3 else None
            if version_manager.update_version(new_version, description):
                print(f"Version updated to {new_version}")
            else:
                print("Failed to update version")
                sys.exit(1)
        else:
            print("Usage: python version_utils.py [get|info|set <version> [description]]")
    else:
        print(get_version())
