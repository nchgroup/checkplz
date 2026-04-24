# checkplz

**checkplz** is an Rust adaptation of the populars **[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)** & **[GoCheck](https://github.com/gatariee/gocheck)** tools, designed to scan files for potential threats while leveraging AMSI (Antimalware Scan Interface) and Windows Defender. By isolating malicious content with precision and providing comprehensive analysis, checkplz offers an enhanced and efficient file scanning experience.

## Contributing

Mod by Vay3t (original: https://github.com/BlackSnufkin/CheckPlz)

## Key Features
- **AMSI Integration:** Perform accurate buffer scans for threat detection.
- **Binary Search Threat Isolation:** Precisely locate the section of a file causing detection.
- **Hex Dump Analysis:** Visualize malicious content with a detailed hexadecimal and ASCII dump.
- **Debugging Support:** Enable verbose output for deeper insights.
- **Customizable Output:** Choose between raw or colorful, human-friendly terminal outputs.

## How It Works

1. **AMSI Scanning**:
   - Initializes an AMSI context.
   - Scans the file content and buffers for threats.
   - If a threat is detected, performs a binary search to isolate the malicious segment.

2. **Windows Defender Scanning**:
   - Invokes `MpCmdRun.exe` to scan the file.
   - Analyzes the output for threat detection.
   - Performs a binary search if a threat is found.

3. **Binary Search**:
   - Recursively scans segments of the file to locate malicious content.
   - Produces detailed logs and results.


## Installation
1. Clone the repository
2. Compile the project:
   ```bash
   cargo build --release
   ```
3. The executable will be available at `target/release/checkplz.exe`.

## Usage Instructions
Run checkplz with the desired options:

```bash
Usage: checkplz.exe [OPTIONS]

Options:
  -f, --file <FILE>  Path to the file to scan
  -d, --debug        Enable debug mode
  -a, --amsi         Use AMSI scan
  -m, --msdefender   Use Windows Defender scan
  -r, --raw          Raw output without ANSI colors
  -u, --url <URL>    URL to download and scan the binary
  -h, --help         Print help
  -V, --version      Print version
```

### Example Commands
- Scan a file using AMSI:
  ```bash
  checkplz.exe --file malicious.exe --amsi
  ```

- Scan a file with Windows Defender:
  ```bash
  checkplz.exe --file suspicious.exe --msdefender
  ```

- Perform a scan using both AMSI and Windows Defender with debug output enabled:
  ```bash
  checkplz.exe --file unknown.exe --amsi --msdefender --debug
  ```

- Perform a scan with raw output formatting:
  ```bash
  checkplz.exe --file unknown.exe --amsi --raw
  ```

- Scan a file from a URL:
  ```bash
  checkplz.exe --url https://example.com/malicious.exe --amsi
  ```

## Output Overview
- **Scan Results:** Displays detection status, potential malicious offsets, and the time taken for scanning.
- **Hex Dump Analysis:** Detailed views of the suspicious sections, highlighting malicious bytes.
![Screenshot 2024-12-27 163057](https://github.com/user-attachments/assets/b8101d33-c4a4-4fc5-85f7-f1b1b6313dde)
