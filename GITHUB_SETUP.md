# GitHub Setup Guide

Quick guide to push your Domain Analyzer project to GitHub.

## Step 1: Create GitHub Repository

1. Go to [GitHub](https://github.com/arvage)
2. Click the **+** icon (top right) → **New repository**
3. Fill in:
   - **Repository name:** `domain-dns-analyzer`
   - **Description:** `Domain DNS Analyzer - Security-hardened tool for analyzing domain DNS records, DMARC, SPF, and technical contacts. By Utopia Tech.`
   - **Visibility:** Choose Public or Private
   - ⚠️ **DO NOT** initialize with README, .gitignore, or license (we already have these)
4. Click **Create repository**

## Step 2: Connect Local Repository to GitHub

After creating the repository, run these commands in your project directory:

```powershell
# Add remote repository (replace with your actual repo URL)
git remote add origin https://github.com/arvage/domain-dns-analyzer.git

# Verify remote was added
git remote -v

# Push to GitHub (first time)
git push -u origin master
```

If prompted for credentials, you'll need to use a **Personal Access Token** instead of your password.

## Step 3: Create Personal Access Token (if needed)

1. Go to **GitHub** → **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
2. Click **Generate new token (classic)**
3. Give it a name: "Domain Analyzer Deployment"
4. Select scopes: Check **repo** (all sub-items)
5. Click **Generate token**
6. **COPY THE TOKEN** - you won't see it again!
7. Use this token as your password when pushing

## Step 4: Verify Upload

After pushing, refresh your GitHub repository page. You should see all your files uploaded!

## Future Updates

To push changes after making updates:

```powershell
# Stage all changes
git add .

# Commit with message
git commit -m "Description of changes"

# Push to GitHub
git push
```

## Repository URL

Your repository will be at:
```
https://github.com/arvage/domain-dns-analyzer
```

## Update Installation Documentation

The INSTALLATION.md already references this repository. Users can clone with:

```bash
git clone https://github.com/arvage/domain-dns-analyzer.git
```

## Optional: Add Repository Topics

On GitHub, click **About** (gear icon) → Add topics:
- `dns-analyzer`
- `domain-tools`
- `dmarc-checker`
- `python`
- `fastapi`
- `security`
- `devops`
- `utopia-tech`

This helps others discover your tool!

---

**Need help?** Contact support@utopiats.com
