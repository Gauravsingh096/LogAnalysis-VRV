﻿# LogAnalysis-VRV

# Log Analyzer Script

A Python script to analyze web server logs, extract key information, and save results to a CSV file. The script identifies suspicious activities, frequently accessed endpoints, and requests per IP address.

---

## Features

- **IP Address Analysis**:
  - Counts requests per IP address.
- **Most Accessed Endpoint**:
  - Finds the most frequently accessed endpoint in the logs.
- **Suspicious Activity Detection**:
  - Identifies IPs with failed login attempts exceeding a defined threshold.
- **CSV Export**:
  - Saves analysis results to a structured CSV file.

---

## Requirements

- Python 3.x
- Required modules:
  - `re` (Standard library, no installation required)
  - `collections.Counter` (Standard library, no installation required)
  - `csv` (Standard library, no installation required)

---

## Installation

1. Clone or download this repository:
   ```bash
 git clone https://github.com/your-username/log-analyzer.git](https://github.com/Gauravsingh096/LogAnalysis-VRV
 cd log-analyzer
   ```
2. ```
   python main.py
   ```
##License
This project is open-source and available under the MIT License.




