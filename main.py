import os
import sys

# Add current directory to path so all sibling modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Fix #1: Streamlit executes this file as a plain module — NOT as __main__.
# Calling show_dashboard() MUST happen at module top-level (not inside an
# if __name__ == "__main__" guard), otherwise streamlit run main.py is a no-op.
from display import show_dashboard
show_dashboard()
