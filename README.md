# ELF Disassembler 
| 2025 Stealien On-site Training (Reverse Engineering) Assignment

## Overview
This project is a simple tool that parses an ELF file, extracts the `.text` section, and disassembles its machine code into assembly instructions.

## Features
- Parse ELF headers and section tables
- Retrieve start address and size of the `.text` section
- Disassemble using the Capstone engine

## Requirements
- [Capstone](https://www.capstone-engine.org/) library
```
pip install capstone
```

## Example
![image](https://github.com/user-attachments/assets/40db35d1-c5b9-4a7f-b0e6-65e1e30f52d2)
![image](https://github.com/user-attachments/assets/75780985-7c47-47cf-80b4-c69e51152c3f)

