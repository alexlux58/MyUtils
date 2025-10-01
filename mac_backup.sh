#!/bin/bash
# backup_mac.sh - Backup apps & configs for migration

BACKUP_DATE=$(date +%Y%m%d)
BACKUP_NAME="MacBackup_${BACKUP_DATE}"
BACKUP_DIR="$HOME/$BACKUP_NAME"
ARCHIVE_NAME="$BACKUP_NAME.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "📦 Backing up Homebrew packages..."
if command -v brew &>/dev/null; then
  brew bundle dump --file="$BACKUP_DIR/Brewfile" --force
else
  echo "Homebrew not found, skipping..."
fi

echo "📦 Backing up applications list..."
ls /Applications > "$BACKUP_DIR/applications_list.txt"

echo "📦 Backing up dotfiles..."
cp -v ~/.zshrc ~/.bash_profile ~/.bashrc ~/.gitconfig ~/.vimrc 2>/dev/null "$BACKUP_DIR/" || true

echo "📦 Backing up SSH keys..."
mkdir -p "$BACKUP_DIR/ssh"
cp -rv ~/.ssh/* "$BACKUP_DIR/ssh/" 2>/dev/null || true

echo "📦 Backing up AWS configs..."
mkdir -p "$BACKUP_DIR/aws"
cp -rv ~/.aws/* "$BACKUP_DIR/aws/" 2>/dev/null || true

echo "📦 Backing up Mender CLI config..."
cp -v ~/.mender-clirc "$BACKUP_DIR/" 2>/dev/null || true

echo "📦 Backing up system preferences..."
mkdir -p "$BACKUP_DIR/preferences"
cp -rv ~/Library/Preferences "$BACKUP_DIR/preferences/" 2>/dev/null || true

echo "📦 Backing up application support..."
mkdir -p "$BACKUP_DIR/appsupport"
cp -rv ~/Library/Application\ Support "$BACKUP_DIR/appsupport/" 2>/dev/null || true

echo "📦 Backing up LaunchAgents..."
mkdir -p "$BACKUP_DIR/launchagents"
cp -rv ~/Library/LaunchAgents "$BACKUP_DIR/launchagents/" 2>/dev/null || true

echo "📦 Compressing everything..."
tar -czf "$HOME/$ARCHIVE_NAME" -C "$HOME" "$(basename "$BACKUP_DIR")"

# Make a copy into WorkNotes
WORKNOTES_DIR="$HOME/Documents/WorkNotes"
if [ -d "$WORKNOTES_DIR" ]; then
  cp "$HOME/$ARCHIVE_NAME" "$WORKNOTES_DIR/"
  echo "✅ Copy placed in $WORKNOTES_DIR/$ARCHIVE_NAME"
else
  echo "⚠️ WorkNotes folder not found at $WORKNOTES_DIR"
fi

echo "✅ Backup complete: $HOME/$ARCHIVE_NAME"
