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

## Screenshots

![image](https://github.com/user-attachments/assets/e7e17198-a6af-480e-bcf3-38e168172759)

![image](https://github.com/user-attachments/assets/fa2c0444-aaf1-4dd9-a62a-dba4af484b2c)

![image](https://github.com/user-attachments/assets/cc65ea74-3d0f-40ac-b4cd-c68cc2d4895f)

![image](https://github.com/user-attachments/assets/27d1acc2-2185-4160-b5dd-672efd1476eb)

![image](https://github.com/user-attachments/assets/8c7b1fe1-02ce-48b1-9a1f-d6c2ae9fc0fa)

![image](https://github.com/user-attachments/assets/9e7d018c-ff43-42f2-9693-019a59379813)

![image](https://github.com/user-attachments/assets/fe29a257-8989-4ad1-88b6-85f8a25f2c00)

![image](https://github.com/user-attachments/assets/11152437-c6ae-4776-9c51-97b8e9670f4b)

![image](https://github.com/user-attachments/assets/227c3a78-8549-4ff7-8f18-889b74ff7d7e)
