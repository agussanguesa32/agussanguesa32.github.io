# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a personal cybersecurity blog built with Jekyll using the Chirpy theme. The site documents projects, progress, and lessons learned from platforms like Hack The Box and other practical exercises. It's hosted on GitHub Pages at https://agussanguesa32.github.io.

## Technology Stack

- **Jekyll** (static site generator)
- **Chirpy Theme** (~> 7.2.4) - Feature-rich Jekyll theme
- **Ruby** (3.3 in CI/CD)
- **html-proofer** - For testing site integrity

## Development Commands

### Local Development
```bash
# Install dependencies
bundle install

# Serve site locally (development mode)
bundle exec jekyll s -l

# Serve site with live reload and custom host
bash tools/run.sh -H 0.0.0.0

# Serve site in production mode
bash tools/run.sh --production
```

### Building and Testing
```bash
# Build site for production
JEKYLL_ENV=production bundle exec jekyll b -d "_site"

# Build and test site (includes HTML validation)
bash tools/test.sh

# Test site with htmlproofer (after building)
bundle exec htmlproofer _site --disable-external --ignore-urls "/^http:\/\/127.0.0.1/,/^http:\/\/0.0.0.0/,/^http:\/\/localhost/"
```

## Site Architecture

### Directory Structure
- **_posts/** - Blog posts in markdown format with YAML frontmatter
- **_tabs/** - Static pages (About, Archives, Categories, Tags)
- **_plugins/** - Jekyll plugins (e.g., posts-lastmod-hook.rb for last modified dates)
- **_data/** - YAML data files (contact.yml, share.yml)
- **assets/** - Static assets (images, CSS, JS)
- **_site/** - Generated site output (excluded from git)
- **tools/** - Development and build scripts

### Content Management

**Blog Posts** follow the naming convention: `YYYY-MM-DD-post-title.md` in `_posts/`

Required frontmatter:
```yaml
---
title: "Post Title"
date: YYYY-MM-DD
categories: [Category1, Category2]
tags: [tag1, tag2, tag3]
image: /assets/img/posts/YYYY-MM-DD-post-title/image.jpg
---
```

### Configuration

**_config.yml** contains:
- Site metadata (title, tagline, description)
- Author information (name, email, social links)
- Theme settings (timezone, language, PWA settings)
- Jekyll configuration (pagination, kramdown, collections)
- Analytics and comment system configuration (currently disabled)

**Important settings:**
- Timezone: `America/Argentina/Buenos_Aires`
- Language: `en`
- Pagination: 10 posts per page
- PWA enabled with offline cache

### Deployment

Deployment is automated via GitHub Actions (`.github/workflows/pages-deploy.yml`):
1. Triggers on push to `main` or `master` branches
2. Sets up Ruby 3.3 and installs dependencies
3. Builds site with Jekyll in production mode
4. Tests site with htmlproofer (disables external link checking)
5. Deploys to GitHub Pages

The workflow can also be triggered manually via the Actions tab.

### Theme Customization

This repository uses the Chirpy Starter approach where critical theme files are copied locally:
- Theme gem provides layouts, includes, sass, and assets
- Local overrides in `_config.yml`, `_plugins/`, `_tabs/`, and `index.html`
- Use `bundle info --path jekyll-theme-chirpy` to locate theme gem files if deeper customization is needed

### Post Images

Post images should be stored in `/assets/img/posts/YYYY-MM-DD-post-title/` directory and referenced in frontmatter as:
```yaml
image: /assets/img/posts/YYYY-MM-DD-post-title/image.jpg
```

### Working with Tabs

Tabs (static pages) in `_tabs/` use:
```yaml
---
layout: page
permalink: /title/
---
```

The `order` field in frontmatter controls tab ordering in navigation.
