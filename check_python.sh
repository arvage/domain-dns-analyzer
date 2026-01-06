# First, check what Python versions are actually available
echo "Checking installed Python versions:"
ls -la /usr/bin/python* 2>/dev/null | grep -E "python3\.[0-9]+" || echo "Using which command..."
which python3.10 python3.11 python3.12 2>/dev/null || echo "Limited Python versions found"

# Check if deadsnakes PPA is available (for newer Python versions)
echo ""
echo "To install Python 3.12 on Ubuntu, run these commands:"
echo "sudo apt update"
echo "sudo apt install -y software-properties-common"
echo "sudo add-apt-repository -y ppa:deadsnakes/ppa"
echo "sudo apt update"
echo "sudo apt install -y python3.12 python3.12-venv python3.12-dev"
