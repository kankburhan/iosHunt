# Ghidra Headless Script for Vulnerability Scanning
# Usage: analyzeHeadless <project_path> <project_name> -import <binary> -postScript ghidra_vuln.py <output_json_path>

import ghidra.app.script.GhidraScript
import ghidra.program.model.symbol
import ghidra.program.model.listing
import json
import sys

# List of potentially vulnerable functions to check
VULN_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "gets", "system", "popen", 
    "memcpy", "memmove", "strncpy", "strncat", "snprintf",
    "CC_MD5", "CC_SHA1", "kSecAttrAccessibleAlways"
]

findings = []

def get_function_at(address):
    func = currentProgram.getFunctionManager().getFunctionContaining(address)
    if func:
        return func.getName()
    return "unknown_function"

def run_scan():
    print("[*] Starting Vulnerability Scan...")
    
    # Get the symbol table
    symbolTable = currentProgram.getSymbolTable()
    
    for vuln_func in VULN_FUNCTIONS:
        # Find the external function symbol
        # We look for "vuln_func" or "_vuln_func" (common in Mach-O)
        symbols = list(symbolTable.getSymbols(vuln_func)) + list(symbolTable.getSymbols("_" + vuln_func))
        
        for sym in symbols:
            # Get references to this symbol
            refs = getReferencesTo(sym.getAddress())
            
            for ref in refs:
                ref_addr = ref.getFromAddress()
                
                # Check if it's a call
                # In strict static analysis, we might just look at all xrefs
                
                calling_func = get_function_at(ref_addr)
                
                finding = {
                    "vulnerability": vuln_func,
                    "address": ref_addr.toString(),
                    "caller": calling_func,
                    "description": "Call to potentially unsafe function " + vuln_func
                }
                findings.append(finding)
                print("[!] Found usage of {} at {} in {}".format(vuln_func, ref_addr, calling_func))

    # Output to JSON
    # The last argument to the script usually is the output file
    args = getScriptArgs()
    if len(args) > 0:
        output_file = args[0]
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=4)
        print("[+] Report saved to " + output_file)
    else:
        print("[-] No output file specified in script args.")

if __name__ == '__main__':
    run_scan()
