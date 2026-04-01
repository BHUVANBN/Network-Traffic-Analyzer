import os
import sys

# Add current directory to path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Run the display module directly
if __name__ == "__main__":
    from display import show_dashboard
    show_dashboard()
