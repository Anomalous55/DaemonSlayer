# 🛡️ DaemonSlayer

**DaemonSlayer** is a command-line security tool that scans installed packages on your Linux system and cross-references them against the OpenSourceMalware threat database to detect malicious software, compromised dependencies, and backdoors. OpenSourceMalware tracks threats across a broad range of asset types, helping you identify malicious resources across the open-source supply chain.

##  Features
* **Cross-Distribution Support:** Automatically detects and scans packages across Debian/Ubuntu (`dpkg`), RHEL/Fedora (`rpm`), and Arch Linux (`pacman`).
* **Targeted Package Checking:** Check a specific package by name, ecosystem, and version without scanning the entire system.
* **Smart Local Caching:** Protects your 2,000 requests/day API quota by caching known safe/malicious package states locally. Only queries the API for new or upgraded packages.
* **Interactive Terminal UI:** Built with `rich` to provide animated progress bars, color-coded threat tables, and an interactive cache management menu.
* **Pipeline Ready:** Easily export scan results to a structured JSON file for CI/CD integrations or SIEM workflows.

##  Prerequisites
* **Python 3.7+**
* An **OpenSourceMalware API Key**. You can get one for free by signing in with GitHub at [opensourcemalware.com](https://opensourcemalware.com).

Install the required Python libraries:
`pip install requests rich`

##  Installation & Setup
1. Clone this repository or download `daemonslayer.py`.
2. Open `daemonslayer.py` in your text editor.
3. Replace the placeholder API key at the top of the file with your actual OpenSourceMalware key:
   `API_KEY = "YOUR_API_KEY_HERE"`

##  Usage

DaemonSlayer is operated entirely via command-line flags.

**Run a Full System Scan:**
Scans all installed packages and renders a color-coded table of any threats found.
`python daemonslayer.py --scan`

**Check a Single Specific Package:**
Target a single package without scanning the entire system. You can optionally specify the ecosystem and version.
`python daemonslayer.py --package requests --ecosystem deb --version 2.31.0`

**Export Results to JSON:**
Runs a system scan and silently exports the threat report to a file for use in other security tools.
`python daemonslayer.py --scan --export report.json`

**Manage the Local Cache:**
Opens an interactive Terminal UI menu to view cache statistics, wipe the entire cache to force a fresh scan, or selectively clear only "safe" packages.
`python daemonslayer.py --manage-cache`

**View Help Menu:**
`python daemonslayer.py --help`

##  How the Cache Works
A typical Linux installation has between 1,500 and 3,000 packages. To avoid hitting the free-tier API rate limits (2,000 requests per day), DaemonSlayer stores the scan result of every package inside `pkg_scan_cache.json`. 

On subsequent runs, DaemonSlayer will instantly load results from the cache and **only** query the API for newly installed packages, or packages that have been upgraded to a different version. 

## ⚠️ Disclaimer
DaemonSlayer relies on third-party threat intelligence databases. While it is an excellent layer of defense-in-depth, no single tool catches 100% of malware. Always maintain standard security practices on your system.
