# ParamHunter

A Burp Suite extension that automatically discovers hidden and undocumented HTTP parameters on every endpoint observed during browsing. Built with the modern Montoya API, it works on both Community Edition and Professional.

## What It Does

ParamHunter passively monitors your HTTP traffic and, for each unique endpoint it sees, launches a background fuzzing campaign to find parameters the application accepts but does not advertise. When a hidden parameter is confirmed, the finding is logged to the UI, printed to the extension console, and (on Professional) reported as a Burp Issue.

## How It Works

1. **Traffic Interception**: Every in scope HTTP request/response pair is captured passively through Burp's HTTP handler. The extension never blocks or modifies your browsing traffic.

2. **Endpoint Deduplication**: Each endpoint is identified by its method, host, and path. An endpoint is only fuzzed once per session to avoid redundant work.

3. **Parameter Injection**: A wordlist of 680+ common parameter names is tested against the endpoint. The fuzzer detects the content type of the original request and injects parameters in the appropriate format:
   - GET requests: query string parameters
   - POST with form data: URL encoded form fields
   - POST with JSON: new keys in the JSON body
   - POST with XML: new XML nodes

4. **Batch Testing**: Parameters are sent in batches of 15 to reduce the number of requests. Each batch response is compared against a calibrated baseline using six detection signals:
   - HTTP status code changes
   - Structural token level diff exceeding the calibrated noise floor
   - Response body length differences exceeding the measured jitter
   - New JSON keys appearing in the response
   - Redirect location header changes
   - Parameter name reflection in the response body

5. **Dynamic Content Handling**: Before fuzzing begins, the original request is sent three times. The responses are normalized (timestamps, CSRF tokens, UUIDs, hex nonces, base64 blobs, and clock values are all replaced with stable placeholders) and then tokenized. The maximum token level diff across the three samples establishes a noise floor, and the maximum body length variance establishes a jitter baseline. Fuzz responses must exceed these measured thresholds to trigger a finding, which eliminates false positives from pages with rotating tokens or embedded clocks.

6. **Binary Search Isolation**: When a batch triggers a difference, the batch is recursively split in half and retested to isolate exactly which parameter caused the change. Each candidate is then confirmed with an individual request.

6. **Rate Limit Handling**: If the server responds with HTTP 429 and includes a Retry-After header, ParamHunter will automatically pause for the specified duration and resume fuzzing. If no header is present, it uses exponential backoff. You can also manually pause or cancel fuzzing at any time from the UI.

## Installation

### Build from Source

Requires Java 17 or later.

```
cd ParamHunter
./gradlew build
```

The compiled extension JAR will be at `build/libs/ParamHunter-1.0.0.jar`.

### Load into Burp Suite

1. Open Burp Suite (Community or Professional)
2. Go to Extensions > Installed > Add
3. Select "Java" as the extension type
4. Browse to `ParamHunter-1.0.0.jar`
5. Click Next

A new tab called "ParamHunter" will appear in the Burp UI.

## Community and Professional Compatibility

The extension detects which edition of Burp Suite is running at startup. On Community Edition, all findings are displayed in the UI table and printed to the extension output. On Professional, findings are additionally reported as Burp Issues in the site map. The detected edition is shown in the stats bar at the bottom of the ParamHunter tab.

## User Interface

The ParamHunter tab contains the following sections.

### Status Toggle

An enable/disable button that controls whether the extension actively processes new traffic and launches fuzzing tasks.

### Wordlist Controls

Displays the current wordlist size. The "Load Custom Wordlist" button opens a file chooser for loading a plain text file with one parameter name per line. Custom wordlists are merged with the built in default and deduplicated. The "Reset to Default" button reverts to the original 680+ parameter wordlist.

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Threads | 5 | Number of concurrent fuzzing threads (1 to 20) |
| Delay (ms) | 200 | Milliseconds to wait between batch requests |
| Only fuzz in scope targets | On | Restricts fuzzing to targets in your Burp scope |
| Skip endpoints already fuzzed | On | Prevents re fuzzing endpoints seen earlier in the session |

### Findings Table

A table with columns for Timestamp, Host, Endpoint, Method, Discovered Parameter, and Evidence. Right clicking a row provides two options:

- **Send to Repeater**: Opens the confirming request/response in Burp Repeater
- **Copy as curl**: Copies a curl command for the request to the clipboard

### Action Buttons

- **Export Findings (CSV)**: Saves all findings to a CSV file
- **Clear Findings**: Removes all findings from the table and resets stats
- **Pause Fuzzing**: Temporarily stops all fuzzing tasks. Resume by toggling the Pause button again.
- **Cancel Fuzzing**: Immediately stops all fuzzing tasks and cancels any in-progress brute force operations.

### Stats Bar

Displays running totals for endpoints fuzzed, parameters tested, total findings, and the detected Burp edition mode.

## Context Menu

Right clicking any request in Burp's Proxy History or other tools shows a "Send to ParamHunter" option. This manually queues the selected request for fuzzing regardless of whether the extension has already seen that endpoint.

## Wordlist

The built in wordlist contains 680+ parameter names covering common patterns across web applications, including authentication tokens, pagination controls, debug flags, API keys, redirect URLs, format selectors, CRUD operations, search and filter parameters, and many more. Lines starting with `#` are treated as comments and blank lines are ignored.

## Architecture

| File | Purpose |
|------|---------|
| ParamHunterExtension.java | Entry point implementing BurpExtension, wires all components |
| HttpTrafficHandler.java | Passive HTTP handler that captures in scope traffic |
| FuzzingEngine.java | Core fuzzing logic with batch testing and binary search |
| WordlistManager.java | Loads, merges, and filters parameter wordlists |
| EndpointRegistry.java | Tracks which endpoints have been fuzzed |
| ResponseDiffer.java | Compares baseline and fuzz responses across six signals |
| BodyNormalizer.java | Strips dynamic content (timestamps, tokens, UUIDs) with pre compiled regex |
| BaselineProfile.java | Immutable calibration snapshot with pre tokenized baseline and noise floor |
| FindingsManager.java | Stores findings and creates Burp Issues on Professional |
| CapabilityChecker.java | Detects Community vs Professional at runtime |
| ParamHunterContextMenu.java | Adds "Send to ParamHunter" to right click menus |
| ui/ParamHunterTab.java | Swing based UI tab with controls and findings display |
| ui/FindingsTable.java | Table model backing the findings JTable |

https://github.com/user-attachments/assets/3268a118-3e77-42b3-95c2-7eae8ba5a4b1

https://github.com/user-attachments/assets/26bb02c4-7d5d-4947-ad26-aabadc97aa4f

https://github.com/user-attachments/assets/744abf7f-a9bd-43f5-87b4-caba63706902

https://github.com/user-attachments/assets/574328cc-bc9d-41cc-91ce-1d422a0fb84a

https://github.com/user-attachments/assets/b3b76fca-9a6a-4796-a147-7c8a41b3edfd

## Technical Details

- All fuzzing HTTP requests are sent through Burp's own HTTP client so they appear in Proxy history and respect upstream proxy settings
- The fuzzing thread pool is configurable and cleanly shuts down when the extension is unloaded
- Known parameters from the original request are automatically excluded from the wordlist before fuzzing
- All data is stored in memory only with no disk writes unless you explicitly export findings
- The extension can be safely loaded and unloaded without restarting Burp

## License

This project is provided as is for security testing and research purposes. Use responsibly and only against systems you have authorization to test.

## New Features (March 2026)

- **Pause Fuzzing**: You can pause brute forcing at any time using the new Pause button in the UI. Fuzzing will wait until resumed.
- **Cancel Fuzzing**: The Cancel button immediately stops all brute force tasks.
- **Smart Rate Limit Handling**: If the server responds with HTTP 429 and provides a Retry-After header, ParamHunter will automatically wait the specified time and resume fuzzing where it left off.

---
