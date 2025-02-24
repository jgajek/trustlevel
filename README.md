# TrustLevel

## Description
Command-line tool to display the hidden Process Trust Label constraints that are not shown in the normal Windows security descriptor DACL views. The constraints, if present, specify the maximal permissions that can be granted to a security principal unless their process token meets the required trust level. This mechanism can be used to protect securable objects from owners, administrators, and the system account unless they are accessed from a protected process.


## Installation
1. Clone the repository:
    
2. Open the project in Visual Studio 2022.
3. Build the project using the provided solution file (`trustlevel.sln`).

## Usage
Run the executable with the following options:

Examples:
- To get the trust level of a file:
    `trustlevel.exe -f "C:\Windows\System32\cmd.exe"`
    
- To get the trust level of a registry key:
    `trustlevel.exe -r "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"`
