#!/bin/bash
# mac_restore.sh - Restore Mac backup created by mac_backup.sh
# Usage: ./mac_restore.sh [backup_file_or_directory]

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}📦${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [backup_file_or_directory]"
    echo ""
    echo "Examples:"
    echo "  $0                                    # List available backups and prompt for selection"
    echo "  $0 MacBackup_20241201.tar.gz         # Restore from specific backup file"
    echo "  $0 ~/MacBackup_20241201              # Restore from extracted backup directory"
    echo ""
    echo "Available backups in current directory:"
    ls -la MacBackup_*.tar.gz 2>/dev/null || echo "  No backup files found"
    echo ""
    echo "Available backups in home directory:"
    ls -la ~/MacBackup_*.tar.gz 2>/dev/null || echo "  No backup files found"
}

# Function to extract backup if it's a tar.gz file
extract_backup() {
    local backup_path="$1"
    local extract_dir="/tmp/mac_restore_$$"
    
    if [[ "$backup_path" == *.tar.gz ]]; then
        print_status "Extracting backup archive..."
        mkdir -p "$extract_dir"
        tar -xzf "$backup_path" -C "$extract_dir"
        echo "$extract_dir/$(basename "$backup_path" .tar.gz)"
    else
        echo "$backup_path"
    fi
}

# Function to restore Homebrew packages
restore_homebrew() {
    local backup_dir="$1"
    local brewfile="$backup_dir/Brewfile"
    
    if [[ -f "$brewfile" ]]; then
        print_status "Restoring Homebrew packages..."
        if command -v brew &>/dev/null; then
            brew bundle install --file="$brewfile"
            print_success "Homebrew packages restored"
        else
            print_warning "Homebrew not found. Please install Homebrew first:"
            echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        fi
    else
        print_warning "Brewfile not found in backup"
    fi
}

# Function to restore dotfiles
restore_dotfiles() {
    local backup_dir="$1"
    
    print_status "Restoring dotfiles..."
    
    # List of dotfiles to restore
    local dotfiles=(".zshrc" ".bash_profile" ".bashrc" ".gitconfig" ".vimrc" ".mender-clirc")
    
    for dotfile in "${dotfiles[@]}"; do
        if [[ -f "$backup_dir/$dotfile" ]]; then
            if [[ -f "$HOME/$dotfile" ]]; then
                print_warning "Backing up existing $dotfile to ${dotfile}.backup"
                cp "$HOME/$dotfile" "$HOME/${dotfile}.backup"
            fi
            cp "$backup_dir/$dotfile" "$HOME/"
            print_success "Restored $dotfile"
        fi
    done
}

# Function to restore SSH keys
restore_ssh() {
    local backup_dir="$1"
    local ssh_backup="$backup_dir/ssh"
    
    if [[ -d "$ssh_backup" ]]; then
        print_status "Restoring SSH keys..."
        if [[ -d "$HOME/.ssh" ]]; then
            print_warning "Backing up existing .ssh directory to .ssh.backup"
            cp -r "$HOME/.ssh" "$HOME/.ssh.backup"
        fi
        mkdir -p "$HOME/.ssh"
        cp -r "$ssh_backup"/* "$HOME/.ssh/"
        chmod 700 "$HOME/.ssh"
        chmod 600 "$HOME/.ssh/id_*" 2>/dev/null || true
        chmod 644 "$HOME/.ssh/id_*.pub" 2>/dev/null || true
        print_success "SSH keys restored"
    else
        print_warning "SSH backup not found"
    fi
}

# Function to restore AWS config
restore_aws() {
    local backup_dir="$1"
    local aws_backup="$backup_dir/aws"
    
    if [[ -d "$aws_backup" ]]; then
        print_status "Restoring AWS configuration..."
        if [[ -d "$HOME/.aws" ]]; then
            print_warning "Backing up existing .aws directory to .aws.backup"
            cp -r "$HOME/.aws" "$HOME/.aws.backup"
        fi
        mkdir -p "$HOME/.aws"
        cp -r "$aws_backup"/* "$HOME/.aws/"
        print_success "AWS configuration restored"
    else
        print_warning "AWS backup not found"
    fi
}

# Function to restore system preferences
restore_preferences() {
    local backup_dir="$1"
    local prefs_backup="$backup_dir/preferences"
    
    if [[ -d "$prefs_backup" ]]; then
        print_status "Restoring system preferences..."
        if [[ -d "$HOME/Library/Preferences" ]]; then
            print_warning "Backing up existing Preferences to Preferences.backup"
            cp -r "$HOME/Library/Preferences" "$HOME/Library/Preferences.backup"
        fi
        cp -r "$prefs_backup/Preferences" "$HOME/Library/"
        print_success "System preferences restored"
    else
        print_warning "Preferences backup not found"
    fi
}

# Function to restore application support
restore_app_support() {
    local backup_dir="$1"
    local appsupport_backup="$backup_dir/appsupport"
    
    if [[ -d "$appsupport_backup" ]]; then
        print_status "Restoring application support data..."
        if [[ -d "$HOME/Library/Application Support" ]]; then
            print_warning "Backing up existing Application Support to Application Support.backup"
            cp -r "$HOME/Library/Application Support" "$HOME/Library/Application Support.backup"
        fi
        cp -r "$appsupport_backup/Application Support" "$HOME/Library/"
        print_success "Application support data restored"
    else
        print_warning "Application support backup not found"
    fi
}

# Function to restore LaunchAgents
restore_launchagents() {
    local backup_dir="$1"
    local launchagents_backup="$backup_dir/launchagents"
    
    if [[ -d "$launchagents_backup" ]]; then
        print_status "Restoring LaunchAgents..."
        if [[ -d "$HOME/Library/LaunchAgents" ]]; then
            print_warning "Backing up existing LaunchAgents to LaunchAgents.backup"
            cp -r "$HOME/Library/LaunchAgents" "$HOME/Library/LaunchAgents.backup"
        fi
        cp -r "$launchagents_backup/LaunchAgents" "$HOME/Library/"
        print_success "LaunchAgents restored"
    else
        print_warning "LaunchAgents backup not found"
    fi
}

# Function to show applications list
show_applications() {
    local backup_dir="$1"
    local apps_list="$backup_dir/applications_list.txt"
    
    if [[ -f "$apps_list" ]]; then
        print_status "Applications that were installed on the original system:"
        echo "----------------------------------------"
        cat "$apps_list"
        echo "----------------------------------------"
        print_warning "You may need to manually install these applications"
    else
        print_warning "Applications list not found in backup"
    fi
}

# Main restore function
restore_backup() {
    local backup_path="$1"
    
    if [[ ! -e "$backup_path" ]]; then
        print_error "Backup path does not exist: $backup_path"
        exit 1
    fi
    
    print_status "Starting restore from: $backup_path"
    
    # Extract backup if it's an archive
    local backup_dir
    backup_dir=$(extract_backup "$backup_path")
    
    if [[ ! -d "$backup_dir" ]]; then
        print_error "Invalid backup directory: $backup_dir"
        exit 1
    fi
    
    print_status "Backup directory: $backup_dir"
    
    # Confirm before proceeding
    echo ""
    print_warning "This will restore configuration files and may overwrite existing ones."
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Restore cancelled"
        exit 0
    fi
    
    # Perform restores
    restore_homebrew "$backup_dir"
    restore_dotfiles "$backup_dir"
    restore_ssh "$backup_dir"
    restore_aws "$backup_dir"
    restore_preferences "$backup_dir"
    restore_app_support "$backup_dir"
    restore_launchagents "$backup_dir"
    show_applications "$backup_dir"
    
    print_success "Restore completed!"
    print_status "You may need to:"
    echo "  - Restart your terminal or run 'source ~/.zshrc'"
    echo "  - Restart applications to pick up new preferences"
    echo "  - Manually install applications from the list above"
    echo "  - Restart your system for some preferences to take effect"
}

# Main script logic
main() {
    if [[ $# -eq 0 ]]; then
        # No arguments provided, show available backups
        show_usage
        exit 0
    fi
    
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_usage
        exit 0
    fi
    
    # Restore from provided backup
    restore_backup "$1"
}

# Run main function
main "$@"
