"""
PALE
Just a cli project dedicated to my pale.
Created by: Om Joshi 
Github: https://github.com/iamomjoshi
repo: https://github.com/iamomjoshi/pale
"""

class Colors:
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Bright colors
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_MAGENTA = '\033[1;95m'
    BRIGHT_CYAN = '\033[1;96m'
    BRIGHT_WHITE = '\033[1;97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    END = '\033[0m'

def print_banner():
    """Print the application banner with creator info."""
    banner = f"""
{Colors.BRIGHT_CYAN}██████╗  █████╗ ██╗     ███████╗{Colors.END}
{Colors.BRIGHT_CYAN}██╔══██╗██╔══██╗██║     ██╔════╝{Colors.END}
{Colors.BRIGHT_BLUE}██████╔╝███████║██║     █████╗  {Colors.END}
{Colors.BLUE}██╔═══╝ ██╔══██║██║     ██╔══╝  {Colors.END}
{Colors.BRIGHT_MAGENTA}██║     ██║  ██║███████╗███████╗{Colors.END}
{Colors.MAGENTA}╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝{Colors.END}

{Colors.BRIGHT_GREEN} {Colors.BRIGHT_CYAN}PALE{Colors.END} {Colors.BRIGHT_GREEN}– Advanced CLI Security Utility{Colors.END}
{Colors.BRIGHT_YELLOW} Created by: {Colors.BRIGHT_CYAN}Om Joshi{Colors.END} {Colors.BRIGHT_YELLOW}| Modern Security Framework{Colors.END}
{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
"""

    print(banner)

def print_success(message: str):
    """Print success message with styling."""
    print(f"{Colors.BRIGHT_GREEN} {message}{Colors.END}")

def print_error(message: str):
    """Print error message with styling."""
    print(f"{Colors.BRIGHT_RED} {message}{Colors.END}")

def print_warning(message: str):
    """Print warning message with styling."""
    print(f"{Colors.BRIGHT_YELLOW}  {message}{Colors.END}")

def print_info(message: str):
    """Print info message with styling."""
    print(f"{Colors.BRIGHT_CYAN}  {message}{Colors.END}")

if __name__ == "__main__":
    try:
        print_banner()
    except KeyboardInterrupt:
        print_info(f"\n{Colors.BRIGHT_YELLOW} Goodbye! Stay secure!{Colors.END}")
    except Exception as e:
        print_error(f"An error occurred: {e}")