# Cloud-Integrated Zero-Day Threat Research and Countermeasure System

## Objective
Simulate zero-day vulnerability environments and build a proactive, AI-driven vulnerability monitoring and defense platform across Azure, AWS, and pfSense CE.

## Project Structure
- **1_Zero_Day_Emulation**: Vulnerable containers, syscall test cases
- **2_Suricata_Custom_Rules**: Inline IDS rules for exploit/C2 detection
- **3_YARA_Rules_and_Patches**: Pattern-based malware signatures + secure binary patches
- **4_Ghidra_Syscall_Extractor**: Plugin to analyze syscall flow in malware binaries
- **5_Rust_Syscall_Hook**: Kernel-level syscall logger for behavioral tracing
- **6_AFL_Fuzzing_AWS_CodeBuild**: Fuzzing CI pipeline with AFL++
- **7_ML_Triage_Engine**: Python ML model to classify fuzzed artifacts
- **8_Vulnerability_Lifecycle_Report**: End-to-end zero-day management writeup
- **9_RealTime_Forensics**: Upload memory dumps, Volatility3 output here
- **10_Cloud_Defense_Orchestration**: Upload cloud detection screenshots here

## Notes
This project simulates a full zero-day discovery and mitigation lifecycle with realistic tooling and defenses, supporting multi-cloud deployments and local pfSense integration.
