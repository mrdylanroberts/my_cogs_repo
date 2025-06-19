# 📚 Cybersecurity Glossary Cog

A comprehensive cybersecurity glossary cog for Red-DiscordBot that provides an interactive, paginated interface for browsing cybersecurity terms and definitions. Features user contributions, moderation system, and advanced search capabilities.

## ✨ Features

### 🔍 **Interactive Browsing**
- Paginated glossary display with Discord UI buttons
- Alphabetical sorting of all terms
- Search functionality with partial matching
- Clean embed formatting with term highlighting

### 👥 **User Contributions**
- Users can submit new terms and definitions
- Moderation queue for pending submissions
- Configurable auto-approval for trusted roles
- Contributor role system for verified users

### 🛡️ **Moderation System**
- Approve/reject pending term submissions
- Remove existing terms from glossary
- Moderator role configuration
- Automatic notifications for new submissions

### 📊 **Management Tools**
- Statistics and analytics
- Export glossary as JSON
- Configurable settings per guild
- Bulk operations support

## 🚀 Installation

1. **Add the cog repository:**
   ```
   !repo add my_cogs_repo <repository_url>
   ```

2. **Install the glossary cog:**
   ```
   !cog install my_cogs_repo glossary
   ```

3. **Load the cog:**
   ```
   !load glossary
   ```

## 📖 Usage

### Basic Commands

#### `!glossary` or `!gloss`
Display the main glossary with pagination controls.

#### `!glossary search <term>`
Search for specific terms in the glossary.
```
!glossary search encryption
!glossary search "sql injection"
```

#### `!glossary add "<term>" <definition>`
Add a new term to the glossary.
```
!glossary add "Zero Trust" A security model that requires verification for every user and device
!glossary add "SIEM" Security Information and Event Management system
```

#### `!glossary stats`
View glossary statistics and recent activity.

### Moderation Commands
*(Requires `Manage Messages` permission)*

#### `!glossary pending`
View all pending term submissions awaiting approval.

#### `!glossary approve <term>`
Approve a pending term submission.
```
!glossary approve "API Gateway"
```

#### `!glossary reject <term>`
Reject a pending term submission.
```
!glossary reject "Invalid Term"
```

#### `!glossary remove <term>`
Remove an existing term from the glossary.
```
!glossary remove "Outdated Term"
```

#### `!glossary export`
Export the entire glossary as a JSON file.

### Administrative Commands
*(Requires `Administrator` permission)*

#### `!glossary config`
View available configuration options.

#### Configuration Options:
- **Auto-approval:** `!glossary config autoapprove <true/false>`
- **Moderator roles:** `!glossary config modroles <add/remove> <@role>`
- **Contributor roles:** `!glossary config controles <add/remove> <@role>`
- **Terms per page:** `!glossary config perpage <1-20>`

## 🎯 Default Terms

The cog comes pre-loaded with essential cybersecurity terms:

- **API** - Application Programming Interface
- **Botnet** - Network of compromised computers
- **CSRF** - Cross-Site Request Forgery
- **DDoS** - Distributed Denial of Service
- **Encryption** - Data protection through coding
- **Firewall** - Network security system
- **Honeypot** - Decoy security system
- **IDS** - Intrusion Detection System
- **Malware** - Malicious software
- **Phishing** - Social engineering attack
- **Ransomware** - File-encrypting malware
- **SQL Injection** - Database attack method
- **Two-Factor Authentication** - Multi-step verification
- **VPN** - Virtual Private Network
- **Zero-Day** - Unknown vulnerability

## 🔧 Configuration

### Role-Based Permissions

1. **Moderator Roles:** Can approve/reject submissions and manage terms
2. **Contributor Roles:** Can add terms without moderation (if configured)
3. **Regular Users:** Can view glossary and submit terms for review

### Settings

- **Auto-approval:** Bypass moderation for all submissions
- **Max definition length:** Limit definition character count (default: 1000)
- **Terms per page:** Control pagination size (default: 10)

## 🎨 UI Features

### Interactive Buttons
- **◀️ Previous:** Navigate to previous page
- **▶️ Next:** Navigate to next page
- **🔍 Search:** Quick search reminder

### Embed Styling
- Color-coded embeds for different states
- Truncated definitions for clean display
- Author attribution for submissions
- Timestamp tracking for moderation

## 📝 Examples

### Adding a New Term
```
User: !glossary add "OSINT" Open Source Intelligence gathering from publicly available sources

Bot: ⏳ Term Submitted for Review
**OSINT** has been submitted and is awaiting moderator approval.

Definition: Open Source Intelligence gathering from publicly available sources
```

### Searching Terms
```
User: !glossary search malware

Bot: [Displays paginated results with all terms containing "malware"]
```

### Moderator Approval
```
Moderator: !glossary approve OSINT

Bot: ✅ Term Approved
**OSINT** has been approved and added to the glossary!

Definition: Open Source Intelligence gathering from publicly available sources
Originally submitted by UserName
```

## 🛠️ Technical Details

### Dependencies
- Red-DiscordBot 3.5+
- discord.py 2.0+
- Python 3.8+

### Data Storage
- Uses Red's Config system for persistent storage
- Guild-specific term storage
- JSON export capability
- Automatic backup through Red's data management

### Performance
- Efficient pagination with Discord UI
- Lazy loading for large glossaries
- Optimized search algorithms
- Memory-efficient term storage

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows Red-DiscordBot standards
- New features include appropriate documentation
- Test thoroughly before submitting
- Follow existing code style and patterns

## 📄 License

This cog is released under the same license as Red-DiscordBot.

## 🆘 Support

For issues, feature requests, or questions:
1. Check existing documentation
2. Search for similar issues
3. Create a detailed issue report
4. Include bot logs if applicable

---

**Made with ❤️ for the cybersecurity community**