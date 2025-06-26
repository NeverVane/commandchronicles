# Public Mirror Management Guide

This guide explains how to create and maintain a clean public mirror of the CommandChronicles CLI project for GitHub release, keeping development files private while sharing the essential codebase with the community.

## Overview

The CommandChronicles CLI project uses a **dual-repository approach**:

- **Private Development Repository**: Contains all development files, implementation plans, task configurations, debug logs, and work-in-progress documentation
- **Public Mirror Repository**: Contains only the essential files needed for users to build, use, and contribute to the project

## Why Use a Public Mirror?

✅ **Clean Public Face**: Users see only polished, essential files  
✅ **Privacy**: Keep implementation plans, personal notes, and development mess private  
✅ **Security**: Avoid accidentally exposing sensitive development information  
✅ **Professional Presentation**: Maintain a clean, focused public repository  
✅ **Selective Sharing**: Choose exactly what the community sees  

## Quick Start

### 1. Initial Setup

Create your public mirror for the first time:

```bash
# Run from your private repository root
./scripts/sync-public-mirror.sh --init-git ~/commandchronicles-cli-public
```

This will:
- Copy essential files to `~/commandchronicles-cli-public`
- Initialize a git repository
- Create an initial commit

### 2. Create GitHub Repository

1. Go to GitHub and create a new **public** repository named `commandchronicles-cli`
2. Don't initialize with README (we already have one)

### 3. Push to GitHub

```bash
cd ~/commandchronicles-cli-public
git remote add origin https://github.com/yourusername/commandchronicles-cli.git
git branch -M main
git push -u origin main
```

### 4. Update the Mirror

Whenever you want to sync changes from development to public:

```bash
# From your private repository
./scripts/sync-public-mirror.sh ~/commandchronicles-cli-public
cd ~/commandchronicles-cli-public
git add .
git commit -m "Sync from development repository"
git push
```

## What Gets Included vs Excluded

### ✅ Included in Public Mirror

| Category | Files/Directories | Purpose |
|----------|------------------|---------|
| **Source Code** | `main.go`, `internal/`, `pkg/` | Core application code |
| **Build Config** | `go.mod`, `go.sum`, `Makefile` | Build and dependency management |
| **Documentation** | `README.md` | User-facing documentation |
| **Scripts** | `scripts/install.sh`, `scripts/build-release.sh` | User installation and build scripts |
| **Configuration** | `.env.example`, `.gitignore` | Configuration templates |
| **CI/CD** | `.github/` | GitHub Actions workflows |
| **Tests** | `test/` | Test suites for contributors |
| **User Docs** | Selected files from `docs/` | User-relevant documentation |

### ❌ Excluded from Public Mirror

| Category | Files/Directories | Reason |
|----------|------------------|--------|
| **Dev Plans** | `*PLAN*.md`, `*SUMMARY*.md`, `*ANALYSIS*.md` | Internal development strategy |
| **Dev Config** | `.taskmasterconfig` | Task management configuration |
| **Logs** | `debug.log`, `*.log` | Debug and development logs |
| **Build Artifacts** | `ccr`, `commandchronicles-cli`, `build/` | Generated binaries |
| **Dev Docs** | `SERVER_DOCS/`, `SYNC-IMPLEMENTATION-PLAN/` | Internal documentation |
| **Decision Docs** | `TUI-BEHAVIOR-DECISION.md`, etc. | Development decisions |
| **Empty Dirs** | `test-scripts/` | Unused development directories |

## Advanced Usage

### Preview Changes (Dry Run)

See what would be copied without actually copying:

```bash
./scripts/sync-public-mirror.sh --dry-run --verbose
```

### Force Overwrite

Overwrite existing target directory:

```bash
./scripts/sync-public-mirror.sh --force ~/commandchronicles-cli-public
```

### Custom Target Directory

Sync to a specific location:

```bash
./scripts/sync-public-mirror.sh /path/to/my/public/repo
```

## Recommended Workflow

### For Major Releases

1. **Complete development work** in private repository
2. **Test thoroughly** - ensure everything builds and works
3. **Update public documentation** (README.md, etc.)
4. **Sync to public mirror**:
   ```bash
   ./scripts/sync-public-mirror.sh ~/commandchronicles-cli-public
   ```
5. **Review changes** in public repository
6. **Commit and push**:
   ```bash
   cd ~/commandchronicles-cli-public
   git add .
   git commit -m "Release v1.2.3: Add new features and bug fixes"
   git tag v1.2.3
   git push origin main --tags
   ```
7. **Create GitHub release** using the tag

### For Bug Fixes

1. **Fix bug** in private repository
2. **Test fix** thoroughly
3. **Quick sync**:
   ```bash
   ./scripts/sync-public-mirror.sh ~/commandchronicles-cli-public
   cd ~/commandchronicles-cli-public
   git add .
   git commit -m "Fix: Resolve issue with command parsing"
   git push
   ```

### For Documentation Updates

1. **Update README.md** or other user docs in private repo
2. **Sync immediately**:
   ```bash
   ./scripts/sync-public-mirror.sh ~/commandchronicles-cli-public
   cd ~/commandchronicles-cli-public
   git add .
   git commit -m "docs: Update installation instructions"
   git push
   ```

## File Management Best Practices

### In Your Private Repository

- ✅ Keep all development files here
- ✅ Use descriptive commit messages
- ✅ Document implementation decisions
- ✅ Store personal notes and task configurations
- ❌ Don't worry about keeping it clean - it's private!

### In Your Public Repository

- ✅ Keep commits focused and meaningful
- ✅ Use conventional commit messages
- ✅ Tag releases properly
- ✅ Maintain clean history
- ❌ Never manually edit files here - always sync from private repo

## Troubleshooting

### Script Issues

**Permission denied when running script:**
```bash
chmod +x scripts/sync-public-mirror.sh
```

**rsync not found:**
```bash
# macOS
brew install rsync

# Ubuntu/Debian
sudo apt-get install rsync

# CentOS/RHEL
sudo yum install rsync
```

### Git Issues

**Diverged histories:**
If your public repo gets out of sync, force push (use with caution):
```bash
cd ~/commandchronicles-cli-public
git push --force-with-lease
```

**Accidentally committed development files:**
Reset to the last clean state and re-sync:
```bash
cd ~/commandchronicles-cli-public
git reset --hard HEAD~1  # Go back one commit
# Then re-run sync script
```

## Automation Options

### GitHub Actions (Advanced)

You can automate the sync process using GitHub Actions. Create `.github/workflows/sync-public.yml` in your **private** repository:

```yaml
name: Sync Public Mirror
on:
  push:
    branches: [main]
    tags: ['v*']
  workflow_dispatch:

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Sync to public repository
        env:
          PUBLIC_REPO_TOKEN: ${{ secrets.PUBLIC_REPO_TOKEN }}
        run: |
          # Your automation script here
          # This is advanced - implement only if needed
```

### Shell Aliases

Add to your `.bashrc` or `.zshrc`:

```bash
alias sync-public='cd /path/to/private/repo && ./scripts/sync-public-mirror.sh ~/commandchronicles-cli-public'
alias publish-public='cd ~/commandchronicles-cli-public && git add . && git commit -m "Sync from development" && git push'
```

## Security Considerations

- ✅ **Always review** changes before pushing to public
- ✅ **Use dry-run** mode when uncertain
- ✅ **Keep sensitive data** in private repo only
- ✅ **Regularly audit** public repository for accidental leaks
- ❌ **Never store** API keys, passwords, or tokens in either repository

## Maintenance Schedule

### Weekly
- Review what's been added to private repo
- Sync any user-facing changes

### Before Releases
- Full sync and review
- Test build process in public mirror
- Update version tags

### Monthly
- Audit public repository for any issues
- Clean up any accidentally committed files
- Review and update this guide as needed

## Getting Help

If you encounter issues with the sync process:

1. **Check the script output** - it provides detailed logging
2. **Use `--verbose` flag** for more detailed information
3. **Try `--dry-run`** first to preview changes
4. **Review excluded files** - make sure nothing important is being filtered out

## Summary

The public mirror approach gives you the best of both worlds: complete freedom in your private development environment while maintaining a professional, clean public face for your project. The sync script handles all the complexity, so you can focus on building great software.

Remember: **Always sync from private → public, never the reverse!**