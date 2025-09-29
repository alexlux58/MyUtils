#!/bin/bash

# Enhanced Security Reconnaissance Framework - Test Runner
# This script runs the test suite with different configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to setup virtual environment
setup_venv() {
    print_status "Setting up virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install pytest pytest-asyncio pytest-mock
}

# Function to run unit tests
run_unit_tests() {
    print_status "Running unit tests..."
    pytest tests/ -m "unit" -v --tb=short
}

# Function to run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    pytest tests/ -m "integration" -v --tb=short
}

# Function to run all tests
run_all_tests() {
    print_status "Running all tests..."
    pytest tests/ -v --tb=short
}

# Function to run tests with coverage
run_tests_with_coverage() {
    print_status "Running tests with coverage..."
    pip install pytest-cov
    pytest tests/ --cov=src --cov-report=html --cov-report=term-missing
}

# Function to run specific test file
run_test_file() {
    local test_file="$1"
    if [ -f "tests/${test_file}" ]; then
        print_status "Running test file: ${test_file}"
        pytest "tests/${test_file}" -v --tb=short
    else
        print_error "Test file not found: tests/${test_file}"
        exit 1
    fi
}

# Function to run tests with specific marker
run_tests_by_marker() {
    local marker="$1"
    print_status "Running tests with marker: ${marker}"
    pytest tests/ -m "${marker}" -v --tb=short
}

# Function to run linting
run_linting() {
    print_status "Running linting..."
    
    if command_exists flake8; then
        flake8 src/ tests/ --max-line-length=120 --ignore=E203,W503
    else
        print_warning "flake8 not found, skipping linting"
    fi
    
    if command_exists black; then
        black --check src/ tests/
    else
        print_warning "black not found, skipping code formatting check"
    fi
}

# Function to run security checks
run_security_checks() {
    print_status "Running security checks..."
    
    if command_exists bandit; then
        bandit -r src/ -f json -o security_report.json
        print_success "Security report generated: security_report.json"
    else
        print_warning "bandit not found, skipping security checks"
    fi
}

# Function to clean up
cleanup() {
    print_status "Cleaning up..."
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
}

# Function to show help
show_help() {
    echo "Enhanced Security Reconnaissance Framework - Test Runner"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  unit              Run unit tests only"
    echo "  integration       Run integration tests only"
    echo "  all               Run all tests (default)"
    echo "  coverage          Run tests with coverage report"
    echo "  file <filename>   Run specific test file"
    echo "  marker <marker>   Run tests with specific marker"
    echo "  lint              Run linting checks"
    echo "  security          Run security checks"
    echo "  clean             Clean up temporary files"
    echo "  setup             Setup virtual environment"
    echo "  help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 unit                    # Run unit tests"
    echo "  $0 coverage               # Run tests with coverage"
    echo "  $0 file test_engine.py    # Run specific test file"
    echo "  $0 marker slow            # Run slow tests"
    echo "  $0 lint                   # Run linting"
}

# Main script logic
main() {
    # Check if Python 3 is available
    if ! command_exists python3; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check if pip is available
    if ! command_exists pip; then
        print_error "pip is required but not installed"
        exit 1
    fi
    
    # Parse command line arguments
    case "${1:-all}" in
        "unit")
            setup_venv
            run_unit_tests
            ;;
        "integration")
            setup_venv
            run_integration_tests
            ;;
        "all")
            setup_venv
            run_all_tests
            ;;
        "coverage")
            setup_venv
            run_tests_with_coverage
            ;;
        "file")
            if [ -z "$2" ]; then
                print_error "Please specify a test file"
                exit 1
            fi
            setup_venv
            run_test_file "$2"
            ;;
        "marker")
            if [ -z "$2" ]; then
                print_error "Please specify a marker"
                exit 1
            fi
            setup_venv
            run_tests_by_marker "$2"
            ;;
        "lint")
            setup_venv
            run_linting
            ;;
        "security")
            setup_venv
            run_security_checks
            ;;
        "clean")
            cleanup
            print_success "Cleanup completed"
            ;;
        "setup")
            setup_venv
            print_success "Setup completed"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
