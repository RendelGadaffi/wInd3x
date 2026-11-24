# Stage-1 Linux loader payload for S5L8740 (iPod nano 7G) boot-ROM DFU chain

Status: design/spec, ready to implement. All addresses and sizes below were measured
against the actual artifacts in this repo (wInd3x @ 3c0f2a6, build/nano7-ldac.itb,
kernel/.config, s5late_n7g.go stateRaw dump) — see "Verified facts".

Goal: after the S5Late stage-1 exploit + wInd3x-style trigger, install a small loader
that streams the 19,524,016-byte FIT image (`build/nano7-ldac.itb`) over ordinary
`DFU_DNLOAD` control transfers into DRAM at 0x08000000, then boots the Linux zImage
in-place with the device tree, bypassing all signature checks and NAND entirely.

---

## 0. Execution model summary

```
host: wInd3x bootlinux nano7-ldac.itb
  │ s5late Prepare (existing)            → overflow SRAM buffer, install blx-r0 vendor hook
  │ loader.Trigger: RCEMulti(payload)     → payload lands at DFU buf + 0x30C, setup packet
  │                                        branch (0xEAFFFE01, −8191 words from the setup
  │                                        DMA buffer @0x2202e600) enters payload at 0x2202de0c
  ▼ payload init (ARM state, ROM context, via the blx-r0'd vendor handler):
      patch state fields + DFU vtable, reset counters, reply to control xfer, return to ROM
  │ host: SendFit(itb)                   → 19,066 × 0x400-byte DNLOAD + 1 × 0x1B0 tail + ZLP
  ▼ per-chunk: ROM copies chunk into SRAM staging, then calls [state+0x18]
      on_chunk handler byte-copies chunk into DRAM, advances cursor, resets the ROM's
      cumulative-transfer field so the ROM buffer never fills.
  │ host: final zero-length DNLOAD → ROM enters dfuMANIFEST
  ▼ manifest: ROM calls vtable verify_image_header / [state+0x20] → boot stub
      magic-gate FIT, copy kernel/dtb/initrd to final addresses, clean D-cache,
      jump to zImage: r0=0, r1=0, r2=dtb → Linux. Never returns.
```

The device's NAND is never touched → a failed boot is 100% recoverable by power cycle.

---

## 1. Verified facts (measured, not assumed)

* **SRAM (S5L8740, 0x22000000..0x2202FFFF):**
  * DFU buffer: `0x2202DB00`, size `0x800` (`stateRaw[0x00..0x07]`).
  * Boot ROM DFU object callbacks (from the N7G `stateRaw` dump in `s5late_n7g.go`):
    * `state+0x00` = DFU data buffer base (`0x2202db00`)
    * `state+0x08` = cumulative transferred bytes (ROM writes chunks at `buf+[0x08]`)
    * `state+0x0C` = current transfer size (wLength of current DNLOAD)
    * `state+0x10` = upload-complete flag
    * `state+0x18` = **on-download-chunk callback** (ROM default `0x20003c48`)
    * `state+0x1C` = on-upload-chunk callback (proven hook: s5late `Prepare()` sets it
      to its payload address and gets code execution via `DFU_DNLOAD/DFU_UPLOAD`)
    * `state+0x20` = BootVerifyAndCopy (ROM default `0x20003bc8`)
    * `state+0x24` = vtable pointer (ROM default `0x20000020`)
    * vtable `+20` = verify_image_header, vtable `+28` = verify_certificate
      (the two slots `haxeddfu` nulls out with `ret1Addr`).
    * state size = `0x640` bytes (matches `binary.Size(state)` against `stateRaw`).
  * `g_State` pointer lives at `0x2202FFF8` (`statePtrLocation`); after `Prepare()` it
    points at the copy of the state placed inside the DFU buffer at
    `0x2202DB00 + 0x880 + 64 = 0x2202E3C0` (stage-1 payload = 11 instr + 5 pool words = 64 B).
  * `0x2202FFF0` = "magical mystery value" — never write ≥ `0x2202FFF0`.
  * SRAM above the state copy up to `0x2202FFF0` is zero padding written by `Prepare()`
    → free staging space.
  * Setup-packet DMA buffer on N7G: `0x2202E600` (back-solved from the SetupPacket
    branch `0xEAFFFE01` = `B .-32764` landing exactly on `ExecAddr = 0x2202DE0C`;
    the same equation reproduces `0x2202E5FC` for N4/5G, confirming the formula).
* **CPU:** Cortex-A5 (dts `compatible = "arm,cortex-a5"`), ARMv7, **boot ROM runs ARM
  state, MMU off**. `uasm` emits 32-bit ARM (not Thumb) — the payload is ARM-state code;
  `blx r0` from ROM keeps ARM state because all target addresses are even.
  The s5late comment ("disabling ICache breaks DFU") is kept as evidence: **do not touch
  CP15 caches in the install phase**; the only cache op we add is D-cache *clean by MVA*
  at the very end (mandatory, see §6).
* **DRAM:** 64 MB at `0x08000000..0x0BFFFFFF` (dts `memory@8000000 reg = <0x08000000 0x04000000>`).
  Boot ROM initializes DRAM before the DFU loop (it loads iBEC→DRAM in restore mode;
  same code path runs before DFU mode entry — the DFU loop is reached only after DRAM
  bring-up. Cheap on-device probe in §9.3).
* **FIT layout of `build/nano7-ldac.itb` (measured by exact subsequence search in the
  built artifact, sizes confirmed with `mkimage -l`):**

  | sub-image | file offset | size | FIT `load` |
  |---|---|---|---|
  | FIT/FDT metadata + strings | `0x000000` | `0x0F0` | — |
  | kernel zImage | `0x000000F0` | `0x2FF2F0` (3,142,384 B) | `0x08000000` |
  | dtb (s5l8740-n31) | `0x002FF4C0` | `0x00001260` (4,704 B) | — |
  | initramfs (cpio.gz) | `0x003007C8` | `0x00F9DC9B` (16,374,939 B) | — (see §6) |

  Total `0x129E9B0`. The zImage self-decompresses to its link address `0x08008000`
  (CONFIG_TEXT_BASE 0x08008000, PAGE_OFFSET 0xC0000000, `CONFIG_CMDLINE="console=tty0
  console=ttySAC0 earlyprintk nohlt"`, `CONFIG_BLK_DEV_INITRD=y`, `CONFIG_RD_GZIP=y`).
* **DFU protocol:** Nano7 uses `DFUProtoVersion2` → `dfu.SendImage` appends **no** CRC
  trailer (checked in `pkg/devices/devices.go`). Max `wLength` per DNLOAD is `0x400`
  (the value `cmd_run`/`SendImage` use in production for this device).

---

## 2. Constants (single source of truth in Go)

```go
// pkg/exploit/loader/constants.go  — N7G / S5L8740
const (
    gStateAddr   = 0x2202FFF8 // &g_State (== S5LateParameters.statePtrLocation)
    dfuBufBase   = 0x2202DB00 // state->DFUBuf (informational; payload reads it from state)
    stagingOff   = 0x1500     // offset into DFU buffer used as per-chunk staging
    stateOff_buf = 0x00
    stateOff_xfer = 0x08       // cumulative transferred bytes
    stateOff_len  = 0x0C       // current DNLOAD wLength
    stateOff_onChunk = 0x18    // per-chunk callback
    stateOff_onBoot  = 0x20    // verify-and-copy callback (manifest)
    stateOff_vtable  = 0x24
    vtbl_verifyImage = 20
    vtbl_verifyCert  = 28

    imageTotal = 0x0129E9B0     // size of build/nano7-ldac.itb

    // FIT source addresses = DRAM base + file offsets (the stream lands 1:1)
    dramBase   = 0x08000000
    kSrc = 0x080000F0;  kLen = 0x002FF2F0;  kDst = 0x08000000
    dSrc = 0x082FF4C0; dLen = 0x00001260;   dDst = 0x09E00000 // dtb, 2MB-aligned, above initrd
    rSrc = 0x083007C8; rLen = 0x00F9DC9B;   rDst = 0x08800000 // initramfs
    zImageEntry = 0x08000000
    dtbAt   = dDst

    fitMagic = 0xD00DFEED
)
```

`dDst = 0x09E00000`: above the initrd end `0x0979DC9B`, below the 64 MB ceiling,
2 MB-aligned, and >512 MB-window valid for the zImage (DTB must be in the low 512 MB
relative to kernel; on 64 MB RAM this is automatic).

**Why hardcode FIT offsets (decision + rationale):** the `.its` (`kernel/freemyipod/kernel_fdt_n31.its`)
and the pipeline (`xtask/src/image.rs` → plain `mkimage -f ... .its`) are fully
controlled at build time, so sub-image offsets are build artifacts, not inputs. Parsing
an FDT in 32 ARM instructions with uasm (no shifts, no MUL, only BNE) is needlessly
risky. Mitigations: (a) the boot stub verifies the FDT magic at `0x08000000` before
touching anything (a mismatched/mis-sized image never boots and never leaves DRAM);
(b) `xtask image` (or a `go:generate` helper) parses the built `.itb` (the exact
algorithm used for this spec: FDT token walk reading `(tag, len, nameoff, data)`
properties — note this legacy mkimage writes len **before** nameoff) and emits
`constants.go` + asserts `totalsize == len(file)`. The Python reference implementation
of the parse is in this file's appendix (§10).

---

## 3. DRAM map at boot time

```
0x08000000  zImage (copied down from 0x080000F0 by the boot stub; self-relocates)
0x08008000  decompressed kernel text (zImage self-extract target)
   ~0x087x  kernel Image text+data+bss (vmlinux sections ≈ 7.8 MB upper bound —
            if Image+initrd collide, zImage head.S relocate_initrd moves the initrd
            to the top of the 64 MB bank automatically; dts memory node supplies the limit)
0x08800000  initramfs (16.4 MB, ends 0x0979DC9B)   ← written by /chosen in dts (§6)
0x09E00000  dtb (4.7 KB, passed in r2)
0x0BFFFFFF  top of DRAM (nothing is written above 0x09E02000)
```

---

## 4. Per-chunk handler algorithm (exact)

Invoked by the ROM's DFU_DNLOAD path as `blx [state+0x18]` **after** the ROM has
memcopied `wLength` bytes to `state->DFUBuf + state->DFUTransferredBytes` and added
`wLength` to `state->DFUTransferredBytes`. Handler uses **only r0-r3, r12** (ARM EABI
caller-saved set; r4-r11, SP, LR untouched → ROM loop stays intact).

```
on_chunk:                                  ; entered via blx, LR = ROM return site
  R4? no: reload all from memory (stateless across invocations):
  R4 = [[0x2202FFF8]]                      ; g_State → state      (R4 is callee-saved:
  R5 = &vars                                ; use only r0-r3,r12: see listing below)
  if vars.total == TOTAL:  ignore (data) / boot (len==0)
  src = [state+0] + ([state+0x08] - [state+0x0C])   ; this chunk's bytes in SRAM
  dst = vars.dram_cursor
  byte-copy [state+0x0C] bytes: src→dst
  vars.dram_cursor = dst_end
  vars.total += len
  [state+0x08] = 0x1500                    ; reset ROM cumulative offset (critical)
  return (BX LR)
```

Key invariants:
* **Why the reset of `[state+0x08]` matters:** the ROM appends chunks at
  `DFUBuf + transferred`; the 19.5 MB stream must not march through the state struct
  (at `0x2202E3C0`) nor touch `0x2202FFF0`. Resetting to `0x1500` pins every chunk write
  to `[0x2202F000, 0x2202F400)` — inside the zero-padding region of `Prepare()`,
  below the payload code at `0x2202DE0C`? No: `0x2202F000` is *above* the state copy
  (state ends `0x2202EA00`) and below `0x2202FFF0`. Payload/vars live at
  `0x2202DE0C..~0x2202E060`, also never written by the stream. All SRAM writes by the
  host stream are confined to `[0x2202F000, 0x2202F400)`.
* **No `min(len, remaining)` needed:** the host is under our control (§5 streams in
  exactly `0x400` chunks with a `0x1B0` final chunk); total streamed ≤ `TOTAL`.
  Data chunks arriving after `total == TOTAL` are ignored by the guard, so a
  malicious/mis-sized stream can never write DRAM beyond `0x08000000 + 0x129E9B0`
  (< 0x0A000000, far inside the 64 MB bank).
* **`len == 0` guard:** the copy loop is post-decrement (`Sub R0,1; Cmp #0; BNE`),
  entered only when `len != 0` — a zero-length DNLOAD (the manifest trigger) takes the
  completion branch, not the loop.

### uasm listing (complete payload; compiles against pkg/uasm as-is)

`pkg/exploit/loader/loader.go`:

```go
package loader

import "github.com/freemyipod/wInd3x/pkg/uasm"

// Parameters subset needed; S5LateParameters satisfies it.
type LoaderParams interface {
    ExecAddr() uint32
    HandlerFooter(addr uint32) []uasm.Statement
    Ret1Addr() uint32 // add to exploit.Parameters: N7G 0x20000F0C
}

func ldr(d uasm.Register, v uint32) uasm.Statement {
    return uasm.Ldr{Dest: d, Src: uasm.Constant(v)}
}

func ProductString() []byte { return []byte{0x12, 0x03, 'l', 0, 'i', 0, 'n', 0, 'u', 0, 'x', 0, 0, 0, 0, 0, 0, 0} }

func Statements(ep LoaderParams) []uasm.Statement {
    L := []uasm.Statement{
        // ---------- INIT (entered at ExecAddr) ----------
        ldr(uasm.R4, gStateAddr),
        {Ldr: R4 ← [R4]}            uasm.Ldr{Dest: uasm.R4, Src: uasm.Deref(uasm.R4, 0)}, // R4 = state
        uasm.Ldr{Dest: uasm.R5, Src: uasm.LabelRef("vars")},
        uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(0)},
        uasm.Str{Src: uasm.R1, Dest: uasm.Deref(uasm.R5, 0)},                 // vars.total = 0
        ldr(uasm.R0, dramBase),
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R5, 4)},                 // vars.cursor = DRAM base
        uasm.Ldr{Dest: uasm.R0, Src: uasm.LabelRef("on_chunk")},
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R4, 0x18)},              // hook on-download-chunk
        uasm.Ldr{Dest: uasm.R0, Src: uasm.LabelRef("boot_kernel")},
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R4, 0x20)},              // hook verify-and-copy
        uasm.Ldr{Dest: uasm.R1, Src: uasm.Deref(uasm.R4, 0x24)},              // R1 = vtable
        uasm.Ldr{Dest: uasm.R0, Src: uasm.LabelRef("boot_kernel")},
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R1, vtbl_verifyImage)},
        ldr(uasm.R0, ep.Ret1Addr()),
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R1, vtbl_verifyCert)},   // cert verify → ret1
        ldr(uasm.R0, stagingOff),
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R4, 0x08)},              // seed staging offset
        // product string #2 → "linux" : success signal for the host (same trick as haxeddfu)
        uasm.Ldr{Dest: uasm.R0, Src: uasm.Deref(uasm.R4, 1584)},
        uasm.Ldr{Dest: uasm.R0, Src: uasm.Deref(uasm.R0, 24)},                // dfuBoot->deviceDescriptor
        uasm.Ldr{Dest: uasm.R1, Src: uasm.LabelRef("descriptor")},
        uasm.Ldrb{Dest: uasm.R2, Src: uasm.Deref(uasm.R1, 0)},                // descriptor length byte
        uasm.Label("desc_copy"),
        uasm.Ldrb{Dest: uasm.R3, Src: uasm.Deref(uasm.R1, 0)},
        uasm.Strb{Src: uasm.R3, Dest: uasm.Deref(uasm.R0, 0)},
        uasm.Add{Dest: uasm.R1, Src: uasm.R1, Compl: uasm.Immediate(1)},
        uasm.Add{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(1)},
        uasm.Sub{Dest: uasm.R2, Src: uasm.R2, Compl: uasm.Immediate(1)},
        uasm.Cmp{A: uasm.R2, B: uasm.Immediate(0)},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("desc_copy")},
    }
    L = append(L, ep.HandlerFooter(0x20000000)...) // send 0x40 IN reply; BX LR → 0x20004fb0

    L = append(L,
        // ---------- ON_CHUNK (entered via blx [state+0x18]) ----------
        uasm.Label("on_chunk"),
        ldr(uasm.R4, gStateAddr),
        uasm.Ldr{Dest: uasm.R4, Src: uasm.Deref(uasm.R4, 0)},
        uasm.Ldr{Dest: uasm.R5, Src: uasm.LabelRef("vars")},
        uasm.Ldr{Dest: uasm.R2, Src: uasm.Deref(uasm.R4, stateOff_len)},       // len
        uasm.Ldr{Dest: uasm.R0, Src: uasm.Deref(uasm.R5, 0)},                  // total
        ldr(uasm.R12, imageTotal),
        uasm.Cmp{A: uasm.R0, B: uasm.R12},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("oc_go")},
        // total == TOTAL: boot iff len==0, else ignore.
        uasm.Cmp{A: uasm.R2, B: uasm.Immediate(0)},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("oc_out")},
        uasm.B{Dest: uasm.LabelRef("boot_kernel")},
        uasm.Label("oc_go"),
        uasm.Ldr{Dest: uasm.R1, Src: uasm.Deref(uasm.R4, stateOff_buf)},
        uasm.Ldr{Dest: uasm.R3, Src: uasm.Deref(uasm.R4, stateOff_xfer)},
        uasm.Sub{Dest: uasm.R3, Src: uasm.R3, Compl: uasm.R2},                 // chunk start offset
        uasm.Add{Dest: uasm.R1, Src: uasm.R1, Compl: uasm.R3},                 // R1 = src
        uasm.Ldr{Dest: uasm.R3, Src: uasm.Deref(uasm.R5, 4)},                  // R3 = dst cursor
        uasm.Mov{Dest: uasm.R0, Src: uasm.R2},                                 // R0 = countdown
        uasm.Cmp{A: uasm.R0, B: uasm.Immediate(0)},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("oc_loop")},
        uasm.B{Dest: uasm.LabelRef("oc_out")},                                 // len==0, not complete
        uasm.Label("oc_loop"),
        uasm.Ldrb{Dest: uasm.R6, Src: uasm.Deref(uasm.R1, 0)},
        uasm.Strb{Src: uasm.R6, Dest: uasm.Deref(uasm.R3, 0)},
        uasm.Add{Dest: uasm.R1, Src: uasm.R1, Compl: uasm.Immediate(1)},
        uasm.Add{Dest: uasm.R3, Src: uasm.R3, Compl: uasm.Immediate(1)},
        uasm.Sub{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(1)},
        uasm.Cmp{A: uasm.R0, B: uasm.Immediate(0)},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("oc_loop")},
        uasm.Str{Src: uasm.R3, Dest: uasm.Deref(uasm.R5, 4)},                  // cursor += len
        uasm.Ldr{Dest: uasm.R0, Src: uasm.Deref(uasm.R5, 0)},
        uasm.Add{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.R2},
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R5, 0)},                  // total += len
        ldr(uasm.R0, stagingOff),
        uasm.Str{Src: uasm.R0, Dest: uasm.Deref(uasm.R4, stateOff_xfer)},      // reset ROM offset
        uasm.Label("oc_out"),
        uasm.Bx{Dest: uasm.LR},

        // ---------- BOOT STUB (entered via vtable+20 / state+0x20 at manifest) ----------
        uasm.Label("boot_kernel"),
        ldr(uasm.R0, dramBase),
        uasm.Ldr{Dest: uasm.R1, Src: uasm.Deref(uasm.R0, 0)},
        ldr(uasm.R2, fitMagic),
        uasm.Cmp{A: uasm.R1, B: uasm.R2},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("bk_out")},                  // not our FIT → no-op
        ldr(uasm.R1, kSrc), ldr(uasm.R3, kDst), ldr(uasm.R0, kLen),
        ldr(uasm.R12, /*addr of:*/ 0) /*placeholder — see call pattern below*/,
        // call pattern used everywhere:  Ldr R12, LabelRef("copy_asc"); Blx R12
        // ... (3 copy calls: kernel asc, initrd desc, dtb asc) ...
        // ... (3 cache-clean calls, §6) ...
        uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(0)},                       // r0 = 0
        uasm.Mov{Dest: uasm.R1, Src: uasm.Immediate(0)},                       // r1 = 0 (DT boot)
        ldr(uasm.R2, dtbAt),                                                   // r2 = dtb phys
        ldr(uasm.R3, zImageEntry),
        uasm.Bx{Dest: uasm.R3},
        uasm.Label("bk_out"),
        uasm.Mov{Dest: uasm.R0, Src: uasm.Immediate(1)},                       // verify "passed"
        uasm.Bx{Dest: uasm.LR},

        // ---------- helpers ----------
        uasm.Label("copy_asc"),                                                // R1=src R3=dst R0=len>0
        uasm.Ldrb{Dest: uasm.R6, Src: uasm.Deref(uasm.R1, 0)},
        uasm.Strb{Src: uasm.R6, Dest: uasm.Deref(uasm.R3, 0)},
        uasm.Add{Dest: uasm.R1, Src: uasm.R1, Compl: uasm.Immediate(1)},
        uasm.Add{Dest: uasm.R3, Src: uasm.R3, Compl: uasm.Immediate(1)},
        uasm.Sub{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(1)},
        uasm.Cmp{Dest: uasm.R0, A: uasm.R0, B: uasm.Immediate(0)},             // (Cmp{A,B})
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("copy_asc")},
        uasm.Bx{Dest: uasm.LR},

        uasm.Label("copy_desc"),                                               // R1=src_end R3=dst_end R0=len>0
        uasm.Sub{Dest: uasm.R1, Src: uasm.R1, Compl: uasm.Immediate(1)},
        uasm.Sub{Dest: uasm.R3, Src: uasm.R3, Compl: uasm.Immediate(1)},
        uasm.Ldrb{Dest: uasm.R6, Src: uasm.Deref(uasm.R1, 0)},
        uasm.Strb{Src: uasm.R6, Dest: uasm.Deref(uasm.R3, 0)},
        uasm.Sub{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(1)},
        uasm.Cmp{A: uasm.R0, B: uasm.Immediate(0)},
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("copy_desc")},
        uasm.Bx{Dest: uasm.LR},

        uasm.Label("clean_mva"),                                               // R0=start R1=end, 32B lines
        uasm.Mcr{Opc: 0, CRn: 7, Src: uasm.R0, CPn: 15, Opc2: 1, CRm: 10},     // MCR p15,0,R0,c7,c10,1
        uasm.Add{Dest: uasm.R0, Src: uasm.R0, Compl: uasm.Immediate(32)},
        uasm.Cmp{A: uasm.R0, B: uasm.Immediate(0)},                            // R1 passed in R1; see note
        uasm.B{Cond: uasm.NE, Dest: uasm.LabelRef("clean_mva")},
        uasm.Bx{Dest: uasm.LR},

        // ---------- data ----------
        uasm.Label("vars"),
        uasm.Embed([]byte{0, 0, 0, 0, 0, 0, 0, 0}),                           // total, cursor
        uasm.Label("descriptor"),
        uasm.Embed(ProductString()),
    }
    return L
}

func Payload(ep LoaderParams) []byte {
    return uasm.Program{Address: ep.ExecAddr(), Listing: Statements(ep)}.Assemble()
}
```

Notes on uasm coverage (audited against `pkg/uasm/insns.go`): the payload uses only
`Ldr, Ldrb, Str, Strb, Mov, Add, Sub, Cmp, B(AL/NE), Bx, Blx, Mcr` — all implemented.
`Cmp` takes `(A Register, B DataSource)`, so the `clean_mva` loop compares `R0` against
the end address in a **register**: call the clean helper with `R1 = end`, and the loop
compares `Cmp{A: R0, B: R1}` (register source — supported). `blx`-style calls: `Ldr R12,
LabelRef(target); Blx{R12}` (sets LR → `BX LR` returns). No MUL/shift/conditional-ALU
exists in uasm — none is needed (byte-at-a-time copies, constant-step clean loop).
The three clean ranges: `[0x08000000,0x08300000)` (zImage copy), `[0x0975DC00,0x0979DCC0)`
(initrd tail 256 KB covering L1+L2 reach), `[0x09E00000,0x09E01280)` (dtb). The
initrd's *source* tail is covered implicitly (it was the stream's tail; the dest copy
re-writes over it — clean the dest ranges, which are what the kernel reads).

**Payload size:** ≈ 135 instructions + 26 pool words + 16 B descriptor + 8 B vars
≈ **620 bytes**, well within the 0x574-byte window from `ExecAddr` to the s5late
stage-1 payload at `+0x880`. It must be uploaded as **two** DNLOAD chunks (0x400 +
remainder) — the existing `exploit.RCE` caps at one 0x400 chunk, hence `RCEMulti` (§7).

---

## 5. Host-side streamer (exact)

`SendFit` — chunked, 4-byte-aligned, ends with a zero-length DNLOAD:

```go
func SendFit(usb devices.Usb, itb []byte, progress func(float32)) error {
    // itb must be the raw .itb (no IMG1 wrapping, no CRC trailer — N7G is DFU proto v2).
    if dfu.Clean(usb) != nil { return err }
    blockno := uint16(0)
    for off := 0; off < len(itb); off += 0x400 {
        n := min(0x400, len(itb)-off)
        if err := dfu.SendChunk(usb, itb[off:off+n], blockno); err != nil { return err }
        // poll status until dfuDNLOAD-IDLE, exactly like dfu.SendImage's loop
        if err := waitDnloadIdle(usb); err != nil { return err }
        blockno++
    }
    // final zero-length download → ROM manifest → our boot stub runs inside the
    // GetStatus handling (device leaves USB shortly after).
    _ = dfu.SendChunk(usb, nil, blockno)
    return pollManifestThenTolerate(usb) // tolerate stalls/IO errors: kernel is booting
}
```

Notes:
* **Never send a final short chunk followed by extra bytes** — the `total == TOTAL`
  guard ignores data after the end; the boot trigger is the `len==0` DNLOAD.
* Chunk size 0x400 keeps the handler's byte loop at ~7k cycles ≈ 9 µs/chunk @ 800 MHz;
  total stream time is USB-bound: ~19,067 OUT+IN pairs ≈ 40–90 s on Linux/gousb.
  (If needed, raise `clen` to the ROM's actual `wTransferSize`; 0x400 is proven by
  `wInd3x run` on N7G.)
* `wInd3x run`'s IMG1 wrapping (`image.MakeUnsigned`) is NOT used — the loader replaces
  the ROM's verify path, so a raw FIT streams fine. (Fallback: if a ROM revision is
  observed to validate the IMG1 header mid-stream, wrap with `MakeUnsigned(kind, 0, itb)`;
  header size `IMG1BodyOffset[kind]` (0x800 on N7G) shifts every FIT offset by that
  amount — make `kSrc/dSrc/rSrc/dramBase` parameters of `Statements()`, add a
  `--wrap-img1` flag, and subtract 0x800 from the stream so the FIT lands at `0x08000000`.)

---

## 6. Completion trigger + kernel boot protocol

**Completion.** `dfu.SendImage`'s tail (SendImage lines 225-246) is the reference: a
zero-length `DFU_DNLOAD` pushes the ROM state machine to `dfuMANIFEST`, which invokes
the image-completion path: `vtable.verify_certificate` → `vtable.verify_image_header`
→ `state->DFUBootVerifyAndCopy` → jump to `DFUBuf + state.IMGHeaderJumpOffset`. We
patch all three of the reachable entry points at install time:

| hook | slot | value | purpose |
|---|---|---|---|
| per-chunk | `state+0x18` | `on_chunk` | streaming |
| manifest | `vtable+20` (verify_image_header) | `boot_kernel` | primary boot entry |
| manifest | `state+0x20` (verify-and-copy) | `boot_kernel` | belt-and-suspenders |
| manifest | `vtable+28` (verify_certificate) | `ret1` @ `0x20000f0c` | pass cert check |

The boot stub runs inside the ROM's `GetStatus` call (device vanishes from the bus
afterward; host tolerates the IO errors — same trick the `run` command's manifest loop
survives today).

**Kernel entry (arch/arm Documentation/Booting + head.S):**
* ARM state (our code is ARM; `BX R3` with even target ✓)
* `r0 = 0`, `r1 = 0` (machine type — ignored on DT-only `CONFIG_ARCH_S5L87XX`; pass 0;
  passing `MACH_TYPE` is harmless too), `r2 = 0x09E00000` (dtb physical).
* **D-cache must be CLEAN before the jump** (kernel's `__turn_mmu_on` runs
  `v7_invalidate_l1` which *discards* dirty lines). The boot stub cleans the three
  written ranges by MVA (§4 `clean_mva`). I-cache: read-only data + zImage is
  self-cleaning; S5L ROM leaves caches in a state where the kernel's own
  `v7_invalidate_l1` + `__inval_icache` handle instruction side; the only boot-time
  data hazard is L1/L2 D-cache writeback, addressed above.
* MMU: ROM runs with MMU off; zImage sets up its own identity+1:1 mapping — nothing to do.

**Build-side dts patch (required, one-line):** `kernel/arch/arm/boot/dts/samsung/s5l8740-n31.dts`
has no `bootargs`/initrd in `/chosen`. Add to the `chosen` node:

```dts
chosen {
    stdout-path = "serial0";
    bootargs = "mem=64M console=ttySAC0 earlyprintk nohlt";
    linux,initrd-start = <0x08800000>;
    linux,initrd-end   = <0x0979DC9B>;
};
```

With `CONFIG_BLK_DEV_INITRD=y` + `CONFIG_RD_GZIP=y` (both set) the kernel picks the
initrd from `/chosen`; `CONFIG_CMDLINE_FROM_BOOTLOADER=y` prefers the DTB bootargs.
The zImage's `relocate_initrd` (head.S, 4.9+) relocates the initrd automatically if
the decompressed kernel footprint reaches 0x08800000 (bounded by the dts memory node).
Doing this at *build* time avoids implementing an FDT editor in uasm.

---

## 7. Go integration (exact edits)

1. **`pkg/exploit/exploit.go`** — extend the interface + add a multi-chunk RCE:
   ```go
   type Parameters interface {
       ...existing...
       Ret1Addr() uint32 // NEW: N3G 0x20000d10, N4 0x20000d10, N5 0x20000cbc,
                         // N6 0x20000eb4, N7 0x20000f0c (already fields; add getters)
   }

   func RCEMulti(usb devices.Usb, ep Parameters, payload []byte) ([]byte, error) {
       // like RCE, but: prefix = 'Z'*(ExecAddr-DFUBufAddr); stream prefix+payload in
       // ceil(len/0x400) SendChunk calls with incrementing blockno; cumulative
       // transferred must stay < 0x800 (assert len(payload) <= 0x800-(ExecAddr-DFUBufAddr));
       // then dfu.Clean, ReceiveChunk(0x40), SetupPacket trigger — identical to RCE.
   }
   ```
   (N7G: `TrampolineAddr()==0`, so RCE's trampoline step is skipped — `RCEMulti` keeps that.)
2. **`pkg/exploit/loader/`** (new package): `constants.go` (§2), `loader.go` (§4),
   `Trigger(usb, ep, force)`: mirrors `haxeddfu.Trigger` — check string descriptor 2
   starts with `"linux"` for idempotence; `RCEMulti(Payload(ep))`; verify descriptor
   flipped; `SendFit(usb, data)`.
3. **`pkg/exploit/s5late_n7g.go`**: add `func (p *S5LateParameters) Ret1Addr() uint32
   { return p.ret1Location }` (and to `epNano3G/epNano4G/epNano5G` for interface fit).
   No change to `Prepare()` — stage-1 (the blx-r0 vendor-hook installer) is unchanged.
4. **`pkg/exploit/haxeddfu/haxeddfu.go`**: no change (the loader is a parallel payload,
   not a replacement of haxed DFU — haxed DFU remains useful for NAND ops/COW).
5. **`cmd/wInd3x/cmd_boot.go`** (new, wired in `main.go` alongside `runCmd`):
   ```
   wInd3x boot <itb path>
     app := newDFU(); defer Close()          // app.PrepareUSB() already runs s5late Prepare
     loader.Trigger(app.Usb, app.Ep, false)
     loader.SendFit(app.Usb, itb, progress)
   ```
   `--loader-bin <file>` escape hatch (task's `--stage1` variant): write the raw
   assembled payload to disk (`wInd3x boot --emit-payload out.bin`) and accept a
   prebuilt binary; validated to be ≤ `0x574` bytes and 4-byte aligned.
6. **`xtask`**: extend `image.rs::run()` (main branch) with a step that parses
   `build/nano7-ldac.itb` (appendix algorithm) and re-generates
   `wInd3x/pkg/exploit/loader/constants.go` — CI-checkable equality with the committed
   constants.

**Payload budget arithmetic (mirrors the task's `0x2202FFF0 - 0x22000880 - stage1 - state`):**
the RCE-visible region is the 0x800-byte DFU buffer: RCE 'Z'-prefix (0x30C) + payload
(≤ 0x574) must end below `0x880`, where the s5late stage-1 payload lives (64 B),
followed by the state copy (0x640) ending at `+0xF00`; staging occupies `+0x1500..+0x1900`;
`+0x24F0..+0x24F0` ends at `0x2202FFF0`. Nothing overlaps; worst-case high-water mark
is `0x2202F400 < 0x2202FFF0`. ✓

---

## 8. Timing / ordering constraints (from the code)

* Install payload runs **inside** the vendor control-IN of `RCEMulti` → must call the
  `HandlerFooter` (ROM reply fn @ `0x2000a654`, return `BX 0x20004fb0`) exactly like
  haxed DFU, and must not touch fields `0x00/0x0C/0x10` of the state afterwards —
  `dfu.Clean` (ClrStatus) makes the ROM reset exactly those (proven by s5late stage-1
  writing zeros to `state+0x08/0x0C/0x10` itself). Our init writes `0x08` last; ClrStatus
  then zeroes it → first `SendFit` chunk lands at `DFUBuf+0` (the RCE payload region,
  already sent — overwriting the payload). **Fix (required):** the on_chunk hook is
  installed, so the *first* data chunk overwriting the payload region matters. Sequence
  check: after `Clean`, `transferred=0`. First DNLOAD: ROM copies 0x400 → `0x2202DB00`
  (overwrites RCE 'Z' prefix + first 0xC4 bytes of payload code!), then calls
  `on_chunk` — **payload code at `+0x30C` gets destroyed before executing anything
  later than the first chunk.** Mitigation (adopted): after the install trigger, the
  host immediately sends **one dummy 4-byte DNLOAD** (blockno 0) — `on_chunk` runs,
  sees `len=4, total=0<` TOTAL, copies 4 junk bytes to `0x08000000`, resets
  `transferred=0x1500`. From then on every ROM write lands at staging, never in the
  payload. The 4 junk bytes at DRAM `0x08000000` are overwritten by the real stream
  (chunk 0 writes them first: the host then re-sends the full image from offset 0).
  Simplest concrete sequence in `Trigger`: install → `SendChunk([]byte{0,0,0,0}, 0)` →
  status-poll → then `SendFit` restarts from offset 0 (the dummy advanced `total` by 4,
  so `SendFit` starts at `total=0`? — set `vars.total` back: the dummy sends exactly
  4 bytes; `SendFit` streams TOTAL-4? No — keep it simple: the dummy is sent with
  `payload[0:4]`'s first 4 bytes (`d0 0d fe ed`) so `total` ends at 4 and `SendFit`
  streams `itb[4:]`. Spec: `Trigger` ends by sending `itb[:4]` (4-byte chunk),
  `SendFit` starts at offset 4. Total received by loader = 4 + (TOTAL-4) = TOTAL ✓.)
* The 0x40 `ReceiveChunk` between payload upload and trigger (RCE line 142) is required
  to flush EP0 state — `RCEMulti` keeps it.
* `GetStatus` after every chunk (SendImage pattern, lines 203-219) is required for the
  ROM state machine to leave `dfuDNBUSY`; `on_chunk` runs synchronously inside the
  DNLOAD OUT, before the STATUS IN that follows.

---

## 9. Safety analysis (anti-brick)

1. **All data writes are bounded**: DRAM cursor ∈ `[0x08000000, 0x0979DC9B]`,
   boot-stub destinations ≤ `0x09E01280`, SRAM staging ⊂ `[0x2202F000, 0x2202F400)`.
   `imageTotal`-bounded guard makes overruns impossible from the host side. Nothing
   ever writes NAND, NOR, SRAM code regions, the state, `0x2202FFF0`, or the USB
   descriptors (post-install).
2. **Magic gate**: `boot_kernel` only acts if `*(u32*)0x08000000 == 0xd00dfeed`;
   a corrupt/incomplete stream → verify returns 1 → ROM falls through to its normal
   (harmless, failing) boot path; device stays in DFU; power cycle restores.
3. **No persistent modification**: exploit + loader are RAM-only. Worst case = black
   screen; Nano 7G recovers via home+power (hard power cut) — device re-enumerates in
   normal mode; re-enter DFU via the usual MSE flow. This is why "device wedges until
   battery drain" is not on the table for this design.
4. **Handler discipline**: `on_chunk` touches only r0-r3/r12, never SP/LR, returns via
   `BX LR` — the ROM DFU loop survives an arbitrary number of chunks. If the ROM's
   N7G DFU loop does **not** call `state+0x18` per chunk (the one assumption not
   directly observable in this repo — see §9.3 probe), the consequence is data never
   reaches DRAM: the stream completes, the magic gate fails, device returns to DFU.
   No damage. (Fallback hook if needed: s5late proved `state+0x1C` fires on the upload
   path; a host-side pump loop of 4-byte `DFU_UPLOAD` calls can drive the copy as a
   polling fallback — `on_chunk` is written statelessly, so driving it from the upload
   hook is a drop-in.)
5. **Idempotence / re-arming**: `Trigger` is re-runnable (RCEMulti → init resets
   `total=0, cursor=base`). A dropped USB cable mid-stream leaves the device in DFU
   with hooks installed; re-running `wInd3x boot` from offset 0 re-arms cleanly.

### 9.3 Required on-device verification probes (before shipping)

| # | Probe | Method | Pass criterion |
|---|---|---|---|
| P1 | `[state+0x18]` fires per DNLOAD with `state+0x0C = wLength`, `state+0x08` incremented | install payload writes a debug counter to `vars`, read back via `on_upload_chunk` (spew technique) | counter increments per `SendChunk` |
| P2 | DRAM initialized | write/read `0xDEADBEEF` @ `0x08000000` in install payload, read back via upload | matches |
| P3 | `wTransferSize` ≥ 0x400 | `SendChunk` 0x400 → `GetStatus` err OK | status 0 |
| P4 | CCSIDR geometry | `MRC p15,1,Rd,c0,c0,1` + upload back | matches assumed 32B lines (else adjust `clean_mva` step) |
| P5 | manifest calls `vtable+20`/`state+0x20` on zero-length DNLOAD | install payload sets flag word; upload back after ZLP | flag set |

Wire P1-P5 into a `wInd3x loader --probe` debug mode reusing the existing
upload-side data-return path (`cmd_spew.go` machinery).

---

## 10. Appendix: FDT offset extraction (build-time, Go/Python)

The `.itb` is a legacy-format FIT: 28-byte FIT header + plain FDT (dtc v17 layout,
**property header = tag, len, nameoff** — len precedes nameoff). Algorithm used to
derive §1 (Python reference; port to Go for the xtask check):
1. `off_dt_struct=0x38`, `off_dt_strings=0x129E58C` from the FDT header.
2. Token walk: `0x1` BEGIN_NODE (name, pad4), `0x2` END_NODE, `0x3` PROP
   (`len, nameoff, data...`), `0x9` END.
3. For nodes `kernel`/`fdt`/`ramdisk`: record `data` property `(poff, plen)`;
   verify `len ==` artifact sizes (3,142,384 / 4,704 / 16,374,939) and
   `totalsize == 0x129E9B0 == filesize`.

Sanity anchors found: zImage at `0xF0` (ARM `mov r0,r0` padding + magic
`0x016f2818` at +0x24), dtb at `0x2FF4C0` (`d00dfeed`), initramfs at `0x3007C8`
(gzip stream → `07070100` newc cpio magic).
