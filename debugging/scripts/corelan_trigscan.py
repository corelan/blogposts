#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
corelan_trigscan.py

Corelan Consulting bv
www.corelan-training.com
www.corelan-certified.com
www.corelan.be

(c) 2026 Corelan Consulting bv. All rights reserved.


LICENSE TERMS

This software is provided for educational, research, and professional use.

Permission is granted to use, study, and modify this code under the following conditions:

1. Commercial Use Allowed
   This software may be used in commercial environments (e.g. companies,
   consulting, penetration testing, research), provided it is not sold or
   otherwise commercialized as a product.

2. No Commercial Redistribution
   You may not sell, license, sublicense, bundle, or otherwise distribute this
   software (or derivatives of it) as part of a commercial offering without
   explicit prior written permission from Corelan Consulting bv.

3. Attribution Required
   Any use, modification, or redistribution of this software must include clear
   attribution to Corelan Consulting bv as the original author.

4. Copyleft Requirement
   If you modify this software and distribute it, you must:
     - Make the modified source code publicly available
     - Retain this license header in full
     - Clearly document your changes

5. No Warranty
   This software is provided "as is", without warranty of any kind, express or
   implied, including but not limited to the warranties of merchantability,
   fitness for a particular purpose, and noninfringement.

6. Limitation of Liability
   In no event shall Corelan Consulting bv be liable for any claim, damages, or
   other liability arising from, out of, or in connection with the software or
   the use or other dealings in the software.

By using this software, you agree to these terms.


Attach to a 32-bit or 64-bit process on Windows using Frida, scan a given
module for math-heavy FP/SSE/AVX routines (good candidates for sin/cos/tan
etc.), and emit WinDbg-compatible breakpoints.

Usage (example):

    python corelan_trigscan.py -p MyApp.exe -m MyApp.exe

Options:

    -p / --process      Process name or PID (e.g. MyApp.exe or 1234)
    -m / --module       Module name to scan (e.g. MyApp.exe or a DLL).
                        If omitted, the process main image module will be used.
    --min-density       Minimum relevant-insn density (default: 0.6)
    --min-relevant      Minimum number of relevant instructions (default: 40)
    --min-total         Minimum total instructions in function+helpers (default: 40)
    --min-trig          Minimum trig-count (trig column) (default: 0)
    --min-icall         Minimum indirect call count (default: 0)
    --max-helper-insns  Max instructions to scan in each helper block (default: 256)
    --max-func-insns    Max instructions to scan in main function (default: 4096)
    --limit-bp          Maximum number of printed/emitted breakpoints (default: 1000)
    --splitsize         Number of breakpoints per numbered .bps file (default: 500)
    --check-offset      Optional offset within module to sanity-check (hex or dec).
"""

import sys
import argparse
import frida
import glob
import os
import re
from textwrap import dedent
from datetime import datetime


AGENT_SOURCE = dedent(r"""
'use strict';

// Formatting helpers -------------------------------------------------------

function fmtOffsetHex(val) {
    let n;

    if (typeof val === 'string') {
        const s = val.toLowerCase().startsWith('0x') ? val : ('0x' + val);
        n = parseInt(s, 16);
    } else {
        n = Number(val);
    }

    if (!isFinite(n) || isNaN(n)) {
        return "0x????????";
    }

    let s = n.toString(16);
    while (s.length < 8) s = "0" + s;
    return "0x" + s;
}

function fmtModAddr(modname, val) {
    return modname + "+" + fmtOffsetHex(val);
}

function fmtHex(val) {
    return "0x" + val.toString(16);
}

// Simple agent-side progress logger
function agentLog(msg) {
    send(msg);
}

// Emit a message every X functions to avoid flooding
const PROGRESS_INTERVAL = 200;
let funcCounter = 0;

// Arch info (used in multiple places)
const ARCH = Process.arch;     // "ia32", "x64", ...
const IS_X64 = (ARCH === 'x64');

const TRIG_MNEMS = {
    'fsin': true,
    'fcos': true,
    'fptan': true,
    'fyl2x': true,
    'fyl2xp1': true,
    'f2xm1': true,
    'fscale': true,
    'ftan': true
};

// Extra SSE signals common in libm-style trig implementations
const TRIG_SSE_MNEMS = {
    'sqrtsd': true,
    'sqrtss': true,
    'sqrtps': true,
    'sqrtpd': true,
    'psrlq':  true,
    'pinsrw': true
};

const INT_FP_MNEMS = {
    'fist': true,
    'fistp': true,
    'fisttp': true,
    'ficom': true,
    'ficomp': true,
    'fidiv': true,
    'fidivr': true,
    'fimul': true,
    'fisub': true,
    'fisubr': true,
    'fiadd': true
};

function isFpInstruction(mnem) {
    if (!mnem) return false;
    mnem = mnem.toLowerCase();
    if (mnem[0] !== 'f') return false;
    if (INT_FP_MNEMS[mnem]) return false;
    return true;
}

function isSseInstruction(insn) {
    const mnemRaw = insn.mnemonic.toLowerCase();
    const opStr = (insn.opStr || '').toLowerCase();

    if (opStr.indexOf('xmm') !== -1 ||
        opStr.indexOf('ymm') !== -1 ||
        opStr.indexOf('zmm') !== -1)
        return true;

    let mnem = mnemRaw;
    if (mnem.startsWith('v') && mnem.length > 1) {
        mnem = mnem.substring(1);
    }

    if (mnem.endsWith('ps') || mnem.endsWith('pd') ||
        mnem.endsWith('ss') || mnem.endsWith('sd'))
        return true;

    if (mnem === 'xorpd' || mnem === 'xorps' ||
        mnem === 'andpd' || mnem === 'andps' ||
        mnem === 'orpd'  || mnem === 'orps'  ||
        mnem === 'sqrtsd' || mnem === 'sqrtss' ||
        mnem === 'sqrtps' || mnem === 'sqrtpd')
        return true;

    return false;
}

function isRelevantInstruction(insn) {
    const mRaw = insn.mnemonic.toLowerCase();
    if (TRIG_MNEMS[mRaw])
        return true;
    if (isFpInstruction(mRaw))
        return true;
    if (isSseInstruction(insn))
        return true;
    return false;
}

function isTrigInstruction(insn) {
    const mRaw = insn.mnemonic.toLowerCase();

    if (TRIG_MNEMS[mRaw])
        return true;
    if (TRIG_SSE_MNEMS[mRaw])
        return true;

    if (mRaw.startsWith('v') && mRaw.length > 1) {
        const bare = mRaw.substring(1);
        if (TRIG_SSE_MNEMS[bare])
            return true;
    }

    return false;
}

function inModuleRange(addr, moduleBase, moduleEnd) {
    return addr.compare(moduleBase) >= 0 && addr.compare(moduleEnd) < 0;
}

function analyzeBlock(startPtr, moduleBase, moduleEnd, maxInsns) {
    let cur = startPtr;
    let total = 0;
    let relevant = 0;
    let trig = 0;
    let indirectCalls = 0;

    try {
        while (inModuleRange(cur, moduleBase, moduleEnd) && total < maxInsns) {
            const insn = Instruction.parse(cur);
            total++;

            if (isRelevantInstruction(insn)) {
                relevant++;
                if (isTrigInstruction(insn))
                    trig++;
            }

            const m = insn.mnemonic.toLowerCase();

            if (m === 'call' && insn.operands && insn.operands.length > 0) {
                const op0 = insn.operands[0];
                if (op0.type !== 'imm') {
                    indirectCalls++;
                }
            }

            if (m.startsWith('ret')) {
                break;
            }

            cur = insn.next;
        }
    } catch (e) {
        // Parsing failed, just stop this block
    }

    return {
        total: total,
        relevant: relevant,
        trig: trig,
        indirectCalls: indirectCalls
    };
}

function analyzeFunction(startPtr, moduleBase, moduleEnd, maxFuncInsns, maxHelperInsns) {
    let cur = startPtr;
    let total = 0;
    let relevant = 0;
    let trig = 0;
    let indirectCalls = 0;

    const visitedHelpers = {};
    const helperCache = {};

    try {
        while (inModuleRange(cur, moduleBase, moduleEnd) && total < maxFuncInsns) {
            if (total !== 0 && (total % 2000) === 0) {
                const offPtr = cur.sub(moduleBase);
                let offVal = 0;
                try {
                    offVal = offPtr.toUInt32();
                } catch (e) {
                    offVal = parseInt(offPtr.toString(), 16);
                }
                send("... still analyzing @" + fmtOffsetHex(offVal));
            }

            const insn = Instruction.parse(cur);
            total++;

            if (isRelevantInstruction(insn)) {
                relevant++;
                if (isTrigInstruction(insn))
                    trig++;
            }

            const m = insn.mnemonic.toLowerCase();

            try {
                if (m === 'call' && insn.operands && insn.operands.length > 0) {
                    const op0 = insn.operands[0];

                    if (op0.type === 'imm') {
                        const target = ptr(op0.value);
                        if (inModuleRange(target, moduleBase, moduleEnd)) {
                            const key = target.toString();
                            if (!visitedHelpers[key]) {
                                visitedHelpers[key] = true;

                                let hStats = helperCache[key];
                                if (!hStats) {
                                    hStats = analyzeBlock(target, moduleBase, moduleEnd, maxHelperInsns);
                                    helperCache[key] = hStats;
                                }

                                total         += hStats.total;
                                relevant      += hStats.relevant;
                                trig          += hStats.trig;
                                indirectCalls += hStats.indirectCalls;
                            }
                        }
                    } else {
                        indirectCalls++;
                    }
                }
            } catch (e) {
                // ignore helper analysis failures
            }

            if (m.startsWith('ret')) {
                break;
            }

            cur = insn.next;
        }
    } catch (e) {
        // Abort this function on any disasm failure
    }

    return {
        total: total,
        relevant: relevant,
        trig: trig,
        indirectCalls: indirectCalls
    };
}

function getX64PrologSpecs() {
    return [
        {
            name: 'fp64',
            pattern: '55 48 89 E5',
            validate: function (funcStart) {
                try {
                    const i1 = Instruction.parse(funcStart);
                    const i2 = Instruction.parse(i1.next);
                    return (
                        i1.mnemonic.toLowerCase() === 'push' &&
                        i1.opStr.toLowerCase() === 'rbp' &&
                        i2.mnemonic.toLowerCase() === 'mov' &&
                        i2.opStr.toLowerCase() === 'rbp, rsp'
                    );
                } catch (e) {
                    return false;
                }
            }
        },
        {
            name: 'shadow64',
            pattern: '48 83 EC 28',
            validate: function (funcStart) {
                try {
                    const i1 = Instruction.parse(funcStart);
                    return (
                        i1.mnemonic.toLowerCase() === 'sub' &&
                        i1.opStr.toLowerCase().startsWith('rsp,')
                    );
                } catch (e) {
                    return false;
                }
            }
        }
    ];
}

function getPrologSpecs() {
    if (!IS_X64) {
        return [
            {
                name: 'fp32',
                pattern: '55 8B EC',
                validate: function (funcStart) {
                    try {
                        const i1 = Instruction.parse(funcStart);
                        const i2 = Instruction.parse(i1.next);
                        return (
                            i1.mnemonic.toLowerCase() === 'push' &&
                            i1.opStr.toLowerCase() === 'ebp' &&
                            i2.mnemonic.toLowerCase() === 'mov' &&
                            i2.opStr.toLowerCase() === 'ebp, esp'
                        );
                    } catch (e) {
                        return false;
                    }
                }
            }
        ];
    }
    return getX64PrologSpecs();
}

function analyzeSpecificOffset(moduleName, offsetStr, maxHelperInsns, maxFuncInsns) {
    let offsetVal = 0;

    try {
        if (typeof offsetStr === 'string') {
            const s = offsetStr.toLowerCase().startsWith('0x') ? offsetStr : ('0x' + offsetStr);
            offsetVal = parseInt(s, 16);
        } else {
            offsetVal = Number(offsetStr);
        }
    } catch (e) {
        return {
            location: moduleName + "+<invalid>",
            offset: "<invalid>",
            module_base: "<unavailable>",
            module_end: "<unavailable>",
            module_size: 0,
            absolute_address: "<unavailable>",
            offset_in_range: false,
            prolog_match: false,
            prolog_mode: null,
            first_insn: "<unavailable>",
            second_insn: "<unavailable>",
            total: 0,
            relevant: 0,
            density: 0.0,
            trig: 0,
            indirect_calls: 0,
            error: "failed to parse offset"
        };
    }

    if (!isFinite(offsetVal) || isNaN(offsetVal)) {
        return {
            location: moduleName + "+<invalid>",
            offset: "<invalid>",
            module_base: "<unavailable>",
            module_end: "<unavailable>",
            module_size: 0,
            absolute_address: "<unavailable>",
            offset_in_range: false,
            prolog_match: false,
            prolog_mode: null,
            first_insn: "<unavailable>",
            second_insn: "<unavailable>",
            total: 0,
            relevant: 0,
            density: 0.0,
            trig: 0,
            indirect_calls: 0,
            error: "offset is not a valid number"
        };
    }

    let mod;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        return {
            location: moduleName + "+" + fmtOffsetHex(offsetVal),
            offset: fmtOffsetHex(offsetVal),
            module_base: "<module lookup failed>",
            module_end: "<module lookup failed>",
            module_size: 0,
            absolute_address: "<unavailable>",
            offset_in_range: false,
            prolog_match: false,
            prolog_mode: null,
            first_insn: "<unavailable>",
            second_insn: "<unavailable>",
            total: 0,
            relevant: 0,
            density: 0.0,
            trig: 0,
            indirect_calls: 0,
            error: "Process.getModuleByName failed: " + String(e)
        };
    }

    const moduleBase = mod.base;
    const moduleEnd = mod.base.add(mod.size);
    const funcStart = moduleBase.add(ptr(offsetVal));

    const result = {
        location: fmtModAddr(moduleName, offsetVal),
        offset: fmtOffsetHex(offsetVal),
        module_base: moduleBase.toString(),
        module_end: moduleEnd.toString(),
        module_size: Number(mod.size),
        absolute_address: funcStart.toString(),
        offset_in_range: inModuleRange(funcStart, moduleBase, moduleEnd),
        prolog_match: false,
        prolog_mode: null,
        first_insn: "<unavailable>",
        second_insn: "<unavailable>",
        total: 0,
        relevant: 0,
        density: 0.0,
        trig: 0,
        indirect_calls: 0,
        error: null
    };

    try {
        const i1 = Instruction.parse(funcStart);
        result.first_insn = i1.address.toString() + "  " + i1.mnemonic + " " + (i1.opStr || "");

        try {
            const i2 = Instruction.parse(i1.next);
            result.second_insn = i2.address.toString() + "  " + i2.mnemonic + " " + (i2.opStr || "");
        } catch (e) {
            result.second_insn = "<parse failed>";
        }
    } catch (e) {
        result.first_insn = "<parse failed>";
        result.second_insn = "<parse failed>";
    }

    if (!result.offset_in_range) {
        result.error = "offset outside module range";
        return result;
    }

    const prologSpecs = getPrologSpecs();
    for (let i = 0; i < prologSpecs.length; i++) {
        const spec = prologSpecs[i];
        try {
            if (spec.validate(funcStart)) {
                result.prolog_match = true;
                result.prolog_mode = spec.name;
                break;
            }
        } catch (e) {
        }
    }

    try {
        const stats = analyzeFunction(funcStart, moduleBase, moduleEnd, maxFuncInsns, maxHelperInsns);
        result.total = stats.total;
        result.relevant = stats.relevant;
        result.trig = stats.trig;
        result.indirect_calls = stats.indirectCalls;
        if (stats.total > 0) {
            result.density = stats.relevant / stats.total;
        }
    } catch (e) {
        result.error = "analyzeFunction failed: " + String(e);
    }

    return result;
}

rpc.exports = {
    getarch: function () {
        return ARCH;
    },

    getmainmodule: function () {
        try {
            const mods = Process.enumerateModules();
            if (mods.length > 0) {
                return mods[0].name;
            }
        } catch (e) {
        }
        return null;
    },

    hasmodule: function (moduleName) {
        try {
            Process.getModuleByName(moduleName);
            return true;
        } catch (e) {
            return false;
        }
    },

    checkoffset: function (moduleName, offsetStr, maxHelperInsns, maxFuncInsns) {
        return analyzeSpecificOffset(moduleName, offsetStr, maxHelperInsns, maxFuncInsns);
    },

    scanmodule: function (moduleName, minDensity, minRelevant, minTotal, minTrig, minIcall, maxHelperInsns, maxFuncInsns) {
        const results = [];

        const mod = Process.getModuleByName(moduleName);
        const moduleBase = mod.base;
        const moduleEnd  = mod.base.add(mod.size);
        const moduleSizePtr = moduleEnd.sub(moduleBase);
        let moduleSize = 0;
        try {
            moduleSize = moduleSizePtr.toUInt32();
        } catch (e) {
            moduleSize = parseInt(moduleSizePtr.toString(), 16);
        }

        agentLog(
            "Module " + moduleName +
            " size=" + fmtHex(moduleSize) +
            " arch=" + ARCH
        );

        const ranges = mod.enumerateRanges('r-x');

        const prologSpecs = getPrologSpecs();
        if (IS_X64) {
            agentLog("x64 prolog scan modes: " + prologSpecs.map(function (p) { return p.name; }).join(", "));
        }

        let totalRxSize = 0;
        ranges.forEach(function (range) {
            totalRxSize += Number(range.size);
        });

        const seenFuncs = {};
        let candidateCount = 0;
        let prologCount = 0;
        let analyzedCount = 0;
        let processedBytes = 0;

        ranges.forEach(function (range) {
            try {
                const rangeBase = range.base;
                const rangeSize = Number(range.size);

                const rStartPtr = rangeBase.sub(moduleBase);
                const rEndPtr   = rangeBase.add(rangeSize).sub(moduleBase);
                let rStart = 0, rEnd = 0;
                try {
                    rStart = rStartPtr.toUInt32();
                    rEnd   = rEndPtr.toUInt32();
                } catch (e) {
                    rStart = parseInt(rStartPtr.toString(), 16);
                    rEnd   = parseInt(rEndPtr.toString(), 16);
                }

                let pctRangeStart = 0.0;
                if (totalRxSize > 0) {
                    pctRangeStart = (processedBytes / totalRxSize) * 100.0;
                }

                agentLog(
                    "Scanning range " +
                    fmtModAddr(moduleName, rStart) + " - " +
                    fmtModAddr(moduleName, rEnd) +
                    " (approx " + pctRangeStart.toFixed(2) + "%)"
                );

                prologSpecs.forEach(function (spec) {
                    let matches = [];
                    try {
                        matches = Memory.scanSync(rangeBase, range.size, spec.pattern);
                    } catch (e) {
                        matches = [];
                    }

                    matches.forEach(function (match) {
                        const funcStart = match.address;

                        const key = funcStart.toString();
                        if (seenFuncs[key])
                            return;
                        seenFuncs[key] = true;

                        prologCount++;

                        const offPtr = funcStart.sub(moduleBase);
                        let offVal = 0;
                        try {
                            offVal = offPtr.toUInt32();
                        } catch (e) {
                            offVal = parseInt(offPtr.toString(), 16);
                        }

                        funcCounter++;
                        if (funcCounter % PROGRESS_INTERVAL === 0) {
                            let offInRange = 0;
                            try {
                                offInRange = funcStart.sub(rangeBase).toUInt32();
                            } catch (e) {
                                offInRange = parseInt(funcStart.sub(rangeBase).toString(), 16);
                            }
                            if (offInRange < 0) offInRange = 0;
                            if (offInRange > rangeSize) offInRange = rangeSize;

                            let pct = 0.0;
                            if (totalRxSize > 0) {
                                pct = ((processedBytes + offInRange) / totalRxSize) * 100.0;
                            }

                            agentLog(
                                "Progress " + pct.toFixed(2) +
                                "% — analyzing function @ " +
                                fmtModAddr(moduleName, offVal) +
                                " [" + spec.name + "]"
                            );
                        }

                        let okProlog = false;
                        try {
                            okProlog = spec.validate(funcStart);
                        } catch (e) {
                            okProlog = false;
                        }

                        if (!okProlog)
                            return;

                        const stats = analyzeFunction(funcStart, moduleBase, moduleEnd, maxFuncInsns, maxHelperInsns);
                        analyzedCount++;

                        const total         = stats.total;
                        const relevant      = stats.relevant;
                        const trig          = stats.trig;
                        const indirectCalls = stats.indirectCalls;

                        if (total <= 0)
                            return;

                        const density = relevant / total;

                        if (total >= minTotal &&
                            relevant >= minRelevant &&
                            density >= minDensity &&
                            trig >= minTrig &&
                            indirectCalls >= minIcall) {

                            const offsetVal = offVal;

                            candidateCount++;
                            agentLog(
                                "FOUND " +
                                fmtModAddr(moduleName, offsetVal) +
                                " dens=" + density.toFixed(3) +
                                " rel=" + relevant +
                                " total=" + total +
                                " trig=" + trig +
                                " icalls=" + indirectCalls +
                                " mode=" + spec.name +
                                " (candidates=" + candidateCount + ")"
                            );

                            results.push({
                                start: fmtModAddr(moduleName, offsetVal),
                                offset: fmtOffsetHex(offsetVal),
                                total: total,
                                relevant: relevant,
                                density: density,
                                trig: trig,
                                indirect_calls: indirectCalls,
                                prolog_mode: spec.name
                            });
                        }
                    });
                });

                processedBytes += rangeSize;
            } catch (e) {
                // Ignore range-level failures
            }
        });

        results.sort(function (a, b) {
            if (b.trig !== a.trig)
                return b.trig - a.trig;
            if (b.density !== a.density)
                return b.density - a.density;
            if (b.relevant !== a.relevant)
                return b.relevant - a.relevant;
            return b.indirect_calls - a.indirect_calls;
        });

        agentLog(
            "scanmodule complete. Candidates: " + results.length +
            " (prologs=" + prologCount +
            ", analyzed=" + analyzedCount + ")"
        );

        return results;
    }
};
""")


def parse_args():
    ap = argparse.ArgumentParser(
        description="Scan a module in a running process for FP/SSE/AVX-heavy routines (sin/cos/tan candidates) using Frida."
    )
    ap.add_argument("-p", "--process", required=True,
                    help="Process name or PID to attach to (e.g. MyApp.exe or 1234)")
    ap.add_argument("-m", "--module", required=False, default=None,
                    help="Module name to scan (e.g. MyApp.exe or a DLL). "
                         "If omitted, the process main image module will be used.")
    ap.add_argument("--min-density", type=float, default=0.6,
                    help="Minimum relevant instruction density (default: 0.6)")
    ap.add_argument("--min-relevant", type=int, default=40,
                    help="Minimum number of relevant instructions (default: 40)")
    ap.add_argument("--min-total", type=int, default=40,
                    help="Minimum total instructions in function+helpers (default: 40)")
    ap.add_argument("--min-trig", type=int, default=0,
                    help="Minimum trig-count (trig column) (default: 0)")
    ap.add_argument("--min-icall", type=int, default=0,
                    help="Minimum indirect call count (default: 0)")
    ap.add_argument("--max-helper-insns", type=int, default=256,
                    help="Maximum instructions to scan in each helper block (default: 256)")
    ap.add_argument("--max-func-insns", type=int, default=4096,
                    help="Maximum instructions to scan in main function (default: 4096)")
    ap.add_argument("--limit-bp", type=str, default="1000",
                    help="Limit number of printed/emitted breakpoints (default: 1000). Use 0, * or all for no limit.")
    ap.add_argument("--splitsize", type=int, default=500,
                    help="Number of breakpoints per numbered .bps file (default: 500)")
    ap.add_argument("--check-offset", type=str, default=None,
                    help="Optional offset within module to sanity-check (hex or dec, e.g. 0x02278f10).")
    return ap.parse_args()


def parse_limit_bp(value: str):
    """
    Parse --limit-bp.

    Supported:
      - integer > 0 : apply that limit
      - 0, *, all   : unlimited

    Returns:
      None for unlimited, or positive int
    """
    s = str(value).strip().lower()
    if s in ("0", "*", "all"):
        return None

    n = int(s, 10)
    if n < 0:
        raise ValueError("limit-bp must be >= 0, or one of: 0, *, all")
    if n == 0:
        return None
    return n


def parse_offset_string(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    if any(c in "abcdef" for c in s):
        return int(s, 16)
    return int(s, 10)


def sanitize_folder_name(name: str) -> str:
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    sanitized = sanitized.strip().rstrip(". ")
    return sanitized or "corelan_trigscan_output"


def create_and_load_script(session, on_message):
    script = session.create_script(AGENT_SOURCE)
    script.on("message", on_message)
    script.load()
    return script


def attach_to_process(process_spec, requested_module=None):
    """
    Attach to a process by PID or by name.

    If process_spec is a PID, attach directly.
    If process_spec is a name and requested_module is supplied, try matching
    processes until one is found where that module is loaded.

    Returns:
        (session, script, attached_pid, attached_name, is_pid_input)

    Exits on failure.
    """
    device = frida.get_local_device()

    def on_message(message, data):
        if message["type"] == "send":
            print(f"[AGENT] {message['payload']}")
        elif message["type"] == "error":
            print("[AGENT][ERROR]", message.get("description", ""), file=sys.stderr)
            if "stack" in message:
                print(message["stack"], file=sys.stderr)
        else:
            print("[AGENT]", message, file=sys.stderr)

    is_pid = process_spec.isdigit()
    if is_pid:
        pid = int(process_spec)
        try:
            session = device.attach(pid)
            script = create_and_load_script(session, on_message)
        except frida.ProcessNotFoundError:
            print(f"[!] Process with PID {pid} not found.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Failed to attach to PID {pid}: {e}")
            sys.exit(1)

        if requested_module:
            try:
                has_mod = script.exports_sync.hasmodule(requested_module)
            except Exception as e:
                print(f"[!] Failed to test module '{requested_module}' in PID {pid}: {e}")
                try:
                    session.detach()
                except Exception:
                    pass
                sys.exit(1)

            if not has_mod:
                print(f"[!] Attached to PID {pid}, but module '{requested_module}' is not loaded in that process.")
                try:
                    session.detach()
                except Exception:
                    pass
                sys.exit(1)

        return session, script, pid, None, True

    try:
        matches = [
            proc for proc in device.enumerate_processes()
            if proc.name.lower() == process_spec.lower()
        ]
    except Exception as e:
        print(f"[!] Failed to enumerate processes: {e}")
        sys.exit(1)

    if not matches:
        print(f"[!] Process '{process_spec}' not found.")
        sys.exit(1)

    if requested_module:
        print(f"[+] Found {len(matches)} process(es) named '{process_spec}'. Looking for one with module '{requested_module}' loaded...")
    else:
        print(f"[+] Found {len(matches)} process(es) named '{process_spec}'. Trying to attach...")

    for proc in matches:
        session = None
        script = None
        try:
            print(f"[+] Trying PID {proc.pid} ({proc.name})...")
            session = device.attach(proc.pid)
            script = create_and_load_script(session, on_message)

            if requested_module:
                try:
                    has_mod = script.exports_sync.hasmodule(requested_module)
                except Exception as e:
                    print(f"[!] Could not test module '{requested_module}' in PID {proc.pid}: {e}")
                    try:
                        session.detach()
                    except Exception:
                        pass
                    continue

                if not has_mod:
                    print(f"[!] PID {proc.pid} does not have module '{requested_module}' loaded. Trying next process...")
                    try:
                        session.detach()
                    except Exception:
                        pass
                    continue

            print(f"[+] Successfully attached to PID {proc.pid} ({proc.name}).")
            return session, script, proc.pid, proc.name, False

        except Exception as e:
            print(f"[!] Could not attach to PID {proc.pid} ({proc.name}): {e}")
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass

    if requested_module:
        print(f"[!] Failed to find any process named '{process_spec}' with module '{requested_module}' loaded.")
    else:
        print(f"[!] Failed to attach to any process named '{process_spec}'.")
    sys.exit(1)


def main():
    args = parse_args()

    try:
        bp_limit = parse_limit_bp(args.limit_bp)
    except Exception as e:
        print(f"[!] Invalid --limit-bp value '{args.limit_bp}': {e}", file=sys.stderr)
        sys.exit(1)

    if args.splitsize <= 0:
        print(f"[!] Invalid --splitsize value '{args.splitsize}': must be > 0", file=sys.stderr)
        sys.exit(1)

    if args.min_icall < 0:
        print(f"[!] Invalid --min-icall value '{args.min_icall}': must be >= 0", file=sys.stderr)
        sys.exit(1)

    process_spec = args.process
    module_name = args.module

    is_pid_input = process_spec.isdigit()
    pid_input = int(process_spec) if is_pid_input else None

    check_offset_val = None
    if args.check_offset:
        try:
            check_offset_val = parse_offset_string(args.check_offset)
        except Exception as e:
            print(f"[!] Invalid --check-offset value '{args.check_offset}': {e}", file=sys.stderr)
            sys.exit(1)

    print("[+] Configuration:")
    if is_pid_input:
        print(f"    Process (PID)       : {pid_input}")
    else:
        print(f"    Process (name)      : {process_spec}")
    if module_name is not None:
        print(f"    Module              : {module_name}")
    else:
        print(f"    Module              : (auto: main module)")
    print(f"    Min density         : {args.min_density}")
    print(f"    Min relevant        : {args.min_relevant}")
    print(f"    Min total           : {args.min_total}")
    print(f"    Min trig (min-trig) : {args.min_trig}")
    print(f"    Min icall           : {args.min_icall}")
    print(f"    Max helper insns    : {args.max_helper_insns}")
    print(f"    Max function insns  : {args.max_func_insns}")
    print(f"    Limit breakpoints   : {'unlimited' if bp_limit is None else bp_limit}")
    print(f"    Split size          : {args.splitsize}")
    if check_offset_val is not None:
        print(f"    Check offset        : 0x{check_offset_val:08x}")
    else:
        print("    Check offset        : (none)")
    print("")

    session, script, pid, attached_name, is_pid = attach_to_process(process_spec, requested_module=module_name)

    try:
        arch = script.exports_sync.getarch()
    except Exception as e:
        print(f"[!] Failed to query target architecture: {e}", file=sys.stderr)
        try:
            session.detach()
        except Exception:
            pass
        sys.exit(1)

    if module_name is None:
        try:
            main_mod = script.exports_sync.getmainmodule()
        except Exception as e:
            print(f"[!] Failed to query main module name: {e}", file=sys.stderr)
            try:
                session.detach()
            except Exception:
                pass
            sys.exit(1)

        if not main_mod:
            print("[!] Could not determine main module name; please specify --module explicitly.")
            try:
                session.detach()
            except Exception:
                pass
            sys.exit(1)

        module_name = main_mod
        print(f"[+] No module specified. Using main module: {module_name}")

        try:
            has_mod = script.exports_sync.hasmodule(module_name)
        except Exception as e:
            print(f"[!] Failed to verify main module '{module_name}': {e}", file=sys.stderr)
            try:
                session.detach()
            except Exception:
                pass
            sys.exit(1)

        if not has_mod:
            print(f"[!] Resolved main module '{module_name}', but it is not present in the attached process.")
            try:
                session.detach()
            except Exception:
                pass
            sys.exit(1)

    is_x64 = (arch == "x64")

    if is_pid:
        print(f"[+] Attached to process PID {pid} (arch={arch}).")
    else:
        print(f"[+] Attached to process '{process_spec}' via PID {pid} (arch={arch}).")

    print(f"[+] Scanning module '{module_name}' for FP/SSE/AVX-heavy routines...")

    try:
        results = script.exports_sync.scanmodule(
            module_name,
            float(args.min_density),
            int(args.min_relevant),
            int(args.min_total),
            int(args.min_trig),
            int(args.min_icall),
            int(args.max_helper_insns),
            int(args.max_func_insns),
        )
    except Exception as e:
        print(f"[!] RPC error from agent: {e}", file=sys.stderr)
        try:
            session.detach()
        except Exception:
            pass
        sys.exit(1)

    checked_entry = None
    checked_bp_cmd = None
    checked_bp_index = None    
    if check_offset_val is not None:
        for r in results:
            offset_val = int(r["offset"], 16)
            if offset_val == check_offset_val:
                checked_entry = r
                break

    specific_check = None
    if check_offset_val is not None:
        try:
            print(f"[+] Requesting direct analysis for {module_name}+0x{check_offset_val:08x}")
            specific_check = script.exports_sync.checkoffset(
                module_name,
                f"0x{check_offset_val:x}",
                int(args.max_helper_insns),
                int(args.max_func_insns),
            )
            print(f"[+] Raw checkoffset response keys: {sorted(specific_check.keys())}")
        except Exception as e:
            specific_check = {
                "offset": f"0x{check_offset_val:08x}",
                "location": f"{module_name}+0x{check_offset_val:08x}",
                "error": f"RPC checkoffset failed: {e}",
            }

    try:
        session.detach()
    except Exception:
        pass

    if not results:
        print("[*] No candidates found that meet the thresholds.")
    else:
        results.sort(
            key=lambda r: (
                -r["trig"],
                -r["density"],
                -r["relevant"],
                -r.get("indirect_calls", 0),
            )
        )

    bp_results = results if bp_limit is None else results[:bp_limit]

    total_candidates = len(results)
    shown_text = "all" if bp_limit is None else str(bp_limit)
    print(f"[+] Found {total_candidates} candidate functions.\n")

    if check_offset_val is not None:
        print(f"[+] Sanity check for offset {module_name}+0x{check_offset_val:08x}: ", end="")
        if checked_entry:
            print("FOUND among candidates.")
            print(
                f"    density={checked_entry['density']:.3f}, "
                f"relevant={checked_entry['relevant']}, "
                f"total={checked_entry['total']}, "
                f"trig={checked_entry['trig']}, "
                f"indirect_calls={checked_entry.get('indirect_calls', 0)}, "
                f"prolog={checked_entry.get('prolog_mode', '?')}"
            )
        else:
            print("NOT found among candidates (may be below current thresholds).")

        if specific_check is not None:
            print("[+] Direct analysis of requested offset:")
            print(f"    location        : {specific_check.get('location', '?')}")
            print(f"    module base     : {specific_check.get('module_base', '?')}")
            print(f"    module end      : {specific_check.get('module_end', '?')}")
            print(f"    module size     : 0x{int(specific_check.get('module_size', 0)):x}")
            print(f"    absolute addr   : {specific_check.get('absolute_address', '?')}")
            print(f"    in range        : {specific_check.get('offset_in_range')}")
            print(f"    first insn      : {specific_check.get('first_insn', '?')}")
            print(f"    second insn     : {specific_check.get('second_insn', '?')}")
            print(f"    prolog match    : {specific_check.get('prolog_match')}")
            print(f"    prolog mode     : {specific_check.get('prolog_mode')}")
            print(f"    density         : {specific_check.get('density', 0.0):.3f}")
            print(f"    relevant        : {specific_check.get('relevant', 0)}")
            print(f"    total           : {specific_check.get('total', 0)}")
            print(f"    trig            : {specific_check.get('trig', 0)}")
            print(f"    indirect calls  : {specific_check.get('indirect_calls', 0)}")
            if specific_check.get("error"):
                print(f"    error           : {specific_check['error']}")

    output_dir = sanitize_folder_name(module_name)
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"[!] Failed to create output directory '{output_dir}': {e}", file=sys.stderr)
        return

    log_path = os.path.join(output_dir, "corelan_trigscan.log")
    bp_path = os.path.join(output_dir, "corelan_trigscan.bps")

    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("corelan_trigscan log\n")
            f.write("=====================\n")
            f.write(f"Timestamp          : {datetime.now().isoformat(timespec='seconds')}\n")
            if is_pid:
                f.write(f"Process            : PID {pid}\n")
            else:
                f.write(f"Process            : {process_spec}\n")
            f.write(f"Module             : {module_name}\n")
            f.write(f"Arch               : {arch}\n")
            f.write(f"Min density        : {args.min_density}\n")
            f.write(f"Min relevant       : {args.min_relevant}\n")
            f.write(f"Min total          : {args.min_total}\n")
            f.write(f"Min trig (min-trig): {args.min_trig}\n")
            f.write(f"Min icall          : {args.min_icall}\n")
            f.write(f"Max helper insns   : {args.max_helper_insns}\n")
            f.write(f"Max function insns : {args.max_func_insns}\n")
            f.write(f"Breakpoint limit   : {'unlimited' if bp_limit is None else bp_limit}\n")
            f.write(f"Split size         : {args.splitsize}\n")
            f.write(f"Output directory   : {output_dir}\n")
            f.write(f"Breakpoint file    : {bp_path}\n")
            f.write(f"Total candidates   : {total_candidates}\n")
            f.write("Sort order         : trig desc, density desc, relevant desc, indirect_calls desc\n")

            if check_offset_val is not None:
                f.write(f"Check offset       : 0x{check_offset_val:08x}\n")
                if checked_entry:
                    f.write("Check offset result: FOUND among candidates\n")
                    f.write(f"  density          : {checked_entry['density']:.3f}\n")
                    f.write(f"  relevant         : {checked_entry['relevant']}\n")
                    f.write(f"  total            : {checked_entry['total']}\n")
                    f.write(f"  trig             : {checked_entry['trig']}\n")
                    f.write(f"  indirect_calls   : {checked_entry.get('indirect_calls', 0)}\n")
                    f.write(f"  prolog_mode      : {checked_entry.get('prolog_mode', '?')}\n")
                else:
                    f.write("Check offset result: NOT found among candidates "
                            "(possibly filtered by thresholds)\n")

                f.write("\n")
                f.write("# Direct analysis for requested --check-offset\n")
                if specific_check is None:
                    f.write("No direct offset analysis data available.\n")
                else:
                    f.write(f"location           : {specific_check.get('location', '?')}\n")
                    f.write(f"offset             : {specific_check.get('offset', '?')}\n")
                    f.write(f"module_base        : {specific_check.get('module_base', '?')}\n")
                    f.write(f"module_end         : {specific_check.get('module_end', '?')}\n")
                    f.write(f"module_size        : 0x{int(specific_check.get('module_size', 0)):x}\n")
                    f.write(f"absolute_address   : {specific_check.get('absolute_address', '?')}\n")
                    f.write(f"offset_in_range    : {specific_check.get('offset_in_range')}\n")
                    f.write(f"first_insn         : {specific_check.get('first_insn', '?')}\n")
                    f.write(f"second_insn        : {specific_check.get('second_insn', '?')}\n")
                    f.write(f"prolog_match       : {specific_check.get('prolog_match')}\n")
                    f.write(f"prolog_mode        : {specific_check.get('prolog_mode')}\n")
                    f.write(f"density            : {specific_check.get('density', 0.0):.3f}\n")
                    f.write(f"relevant           : {specific_check.get('relevant', 0)}\n")
                    f.write(f"total              : {specific_check.get('total', 0)}\n")
                    f.write(f"trig               : {specific_check.get('trig', 0)}\n")
                    f.write(f"indirect_calls     : {specific_check.get('indirect_calls', 0)}\n")
                    if specific_check.get("error"):
                        f.write(f"error              : {specific_check.get('error')}\n")

            f.write("\n")
            f.write("# Candidate list (see sort order above)\n")
            f.write("# idx  location                  density   relevant   total   trig   icalls   prolog\n")

            for idx, r in enumerate(results, start=1):
                offset_val = int(r["offset"], 16)
                offset_fmt = f"0x{offset_val:08x}"
                location = f"{module_name}+{offset_fmt}"
                density = r["density"]
                relevant = r["relevant"]
                total = r["total"]
                trig = r["trig"]
                indirect_calls = r.get("indirect_calls", 0)
                prolog_mode = r.get("prolog_mode", "?")
                f.write(
                    f"{idx:4d}  {location:24s}  {density:7.3f}   {relevant:8d}   "
                    f"{total:5d}   {trig:4d}   {indirect_calls:6d}   {prolog_mode}\n"
                )

    except Exception as e:
        print(f"[!] Failed to write log file '{log_path}': {e}", file=sys.stderr)
        return

    # Build all breakpoint commands once
    bp_cmds = []
    bpid = 1000
    for idx, r in enumerate(bp_results, start=1):
        offset_val = int(r["offset"], 16)
        offset_fmt = f"0x{offset_val:08x}"
        density = r["density"]
        relevant = r["relevant"]
        total = r["total"]
        trig = r["trig"]
        indirect_calls = r.get("indirect_calls", 0)
        prolog_mode = r.get("prolog_mode", "?")
        prefix = f"{module_name}+{offset_fmt}"
        bp_cmd = (
            f"bp{bpid} {module_name}+{offset_fmt} "
            f"\".printf /D \\\"----- <b>{prefix} bp{bpid} hit</b> "
            f"dens={density:.3f} rel={relevant} tot={total} trig={trig} "
            f"icalls={indirect_calls} prolog={prolog_mode} ----- "
            f"<link cmd=\\\\\\\"bd {bpid}\\\\\\\">[disable]</link>\\\\n\\\"; gc\""
        )
        bp_cmds.append(bp_cmd)
        bpid += 1

        if check_offset_val is not None and offset_val == check_offset_val:
            checked_bp_cmd = bp_cmd
            checked_bp_index = idx

    # Remove all existing corelan_trigscan*.bps files in output dir
    try:
        for old_bp in glob.glob(os.path.join(output_dir, "corelan_trigscan*.bps")):
            try:
                os.remove(old_bp)
            except Exception as e:
                print(f"[!] Failed to remove old breakpoint file '{old_bp}': {e}", file=sys.stderr)
                return
    except Exception as e:
        print(f"[!] Failed to enumerate old breakpoint files in '{output_dir}': {e}", file=sys.stderr)
        return

    # Write master breakpoint file
    try:
        with open(bp_path, "w", encoding="utf-8") as bf:
            for bp_cmd in bp_cmds:
                bf.write(bp_cmd + "\n")
    except Exception as e:
        print(f"[!] Failed to write breakpoint file '{bp_path}': {e}", file=sys.stderr)
        return

    # Write numbered chunk files using --splitsize
    chunk_size = args.splitsize
    chunk_files = []

    try:
        for chunk_index, start in enumerate(range(0, len(bp_cmds), chunk_size), start=1):
            chunk = bp_cmds[start:start + chunk_size]
            chunk_path = os.path.join(output_dir, f"corelan_trigscan_{chunk_index:04d}.bps")
            with open(chunk_path, "w", encoding="utf-8") as cf:
                for bp_cmd in chunk:
                    cf.write(bp_cmd + "\n")
            chunk_files.append(chunk_path)
    except Exception as e:
        print(f"[!] Failed to write chunked breakpoint files: {e}", file=sys.stderr)
        return
    
    checked_chunk_file = None
    if check_offset_val is not None and checked_entry is not None and checked_bp_index is not None:
        chunk_number = ((checked_bp_index - 1) // chunk_size) + 1
        checked_chunk_file = os.path.join(output_dir, f"corelan_trigscan_{chunk_number:04d}.bps")    

    print(f"\n[+] Output directory         : '{output_dir}'")
    print(f"[+] Full analysis written to : '{log_path}'")
    print(f"[+] Breakpoints written to   : '{bp_path}'")
    if chunk_files:
        print(f"[+] Wrote {len(chunk_files)} numbered breakpoint file(s):")
        print(f"    first: {chunk_files[0]}")
        print(f"    last : {chunk_files[-1]}")
    else:
        print("[+] No numbered breakpoint files were created (no breakpoints emitted).")

    if check_offset_val is not None and checked_entry is not None:
        if checked_chunk_file is not None:
            print(f"[+] Function at offset written to  : '{checked_chunk_file}'")
        else:
            print("[+] Checked offset was found among candidates, but no numbered breakpoint file could be resolved.")

    print("[+] Done.")


if __name__ == "__main__":
    main()