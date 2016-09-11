;;; capstone-binding.el --- interaction with capstone-core bindings  -*- lexical-binding: t; -*-

;; Copyright (C) 2016  Bas Alberts

;; Author: Bas Alberts <bas@collarchoke.org>
;; Keywords: convenience

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;;; Code:

(require 'cl)
(require 'capstone-core)

;; arch constants
(require 'capstone-arm-const)
(require 'capstone-arm64-const)
(require 'capstone-mips-const)
(require 'capstone-ppc-const)
(require 'capstone-sparc-const)
(require 'capstone-sysz-const)
(require 'capstone-x86-const)
(require 'capstone-xcore-const)

;; Capstone C interface

;; API version
(defconst capstone-CS_API_MAJOR 3)
(defconst capstone-CS_API_MINOR 0)

;; architectures
(defconst capstone-CS_ARCH_ARM 0)
(defconst capstone-CS_ARCH_ARM64 1)
(defconst capstone-CS_ARCH_MIPS 2)
(defconst capstone-CS_ARCH_X86 3)
(defconst capstone-CS_ARCH_PPC 4)
(defconst capstone-CS_ARCH_SPARC 5)
(defconst capstone-CS_ARCH_SYSZ 6)
(defconst capstone-CS_ARCH_XCORE 7)
(defconst capstone-CS_ARCH_MAX 8)
(defconst capstone-CS_ARCH_ALL #xFFFF)

;; disasm mode
(defconst capstone-CS_MODE_LITTLE_ENDIAN 0)            ; little-endian mode (default mode)
(defconst capstone-CS_MODE_ARM 0)                      ; ARM mode
(defconst capstone-CS_MODE_16 (lsh 1 1))               ; 16-bit mode (for X86)
(defconst capstone-CS_MODE_32 (lsh 1 2))               ; 32-bit mode (for X86)
(defconst capstone-CS_MODE_64 (lsh 1 3))               ; 64-bit mode (for X86, PPC)
(defconst capstone-CS_MODE_THUMB (lsh 1 4))            ; ARM's Thumb mode, including Thumb-2
(defconst capstone-CS_MODE_MCLASS (lsh 1 5))           ; ARM's Cortex-M series
(defconst capstone-CS_MODE_V8 (lsh 1 6))               ; ARMv8 A32 encodings for ARM
(defconst capstone-CS_MODE_MICRO (lsh 1 4))            ; MicroMips mode (MIPS architecture)
(defconst capstone-CS_MODE_MIPS3 (lsh 1 5))            ; Mips III ISA
(defconst capstone-CS_MODE_MIPS32R6 (lsh 1 6))         ; Mips32r6 ISA
(defconst capstone-CS_MODE_MIPSGP64 (lsh 1 7))         ; General Purpose Registers are 64-bit wide (MIPS arch)
(defconst capstone-CS_MODE_V9 (lsh 1 4))               ; Sparc V9 mode (for Sparc)
(defconst capstone-CS_MODE_BIG_ENDIAN (lsh 1 31))      ; big-endian mode
(defconst capstone-CS_MODE_MIPS32 capstone-CS_MODE_32) ; Mips32 ISA
(defconst capstone-CS_MODE_MIPS64 capstone-CS_MODE_64) ; Mips64 ISA

;; Capstone option type
(defconst capstone-CS_OPT_SYNTAX 1)         ; Intel X86 asm syntax (CS_ARCH_X86 arch)
(defconst capstone-CS_OPT_DETAIL 2)         ; Break down instruction structure into details
(defconst capstone-CS_OPT_MODE 3)           ; Change engine's mode at run-time
(defconst capstone-CS_OPT_MEM 4)            ; Change engine's mode at run-time
(defconst capstone-CS_OPT_SKIPDATA 5)       ; Skip data when disassembling
(defconst capstone-CS_OPT_SKIPDATA_SETUP 6) ; Setup user-defined function for SKIPDATA option

;; Capstone option value
(defconst capstone-CS_OPT_OFF 0) ; Turn OFF an option - default option of CS_OPT_DETAIL
(defconst capstone-CS_OPT_ON 3)  ; Turn ON an option (CS_OPT_DETAIL)

;; Common instruction operand types - to be consistent across all architectures.
(defconst capstone-CS_OP_INVALID 0)
(defconst capstone-CS_OP_REG 1)
(defconst capstone-CS_OP_IMM 2)
(defconst capstone-CS_OP_MEM 3)
(defconst capstone-CS_OP_FP 4)

;; Common instruction groups - to be consistent across all architectures.
(defconst capstone-CS_GRP_INVALID 0) ; uninitialized/invalid group.
(defconst capstone-CS_GRP_JUMP 1)    ; all jump instructions (conditional+direct+indirect jumps)
(defconst capstone-CS_GRP_CALL 2)    ; all call instructions
(defconst capstone-CS_GRP_RET 3)     ; all return instructions
(defconst capstone-CS_GRP_INT 4)     ; all interrupt instructions (int+syscall)
(defconst capstone-CS_GRP_IRET 5)    ; all interrupt return instructions

;; Capstone syntax value
(defconst capstone-CS_OPT_SYNTAX_DEFAULT   0) ; Default assembly syntax of all platforms (CS_OPT_SYNTAX)
(defconst capstone-CS_OPT_SYNTAX_INTEL     1) ; Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
(defconst capstone-CS_OPT_SYNTAX_ATT       2) ; ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
(defconst capstone-CS_OPT_SYNTAX_NOREGNAME 3) ; Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)

;; Capstone error type
(defconst capstone-CS_ERR_OK 0)         ; No error: everything was fine
(defconst capstone-CS_ERR_MEM 1)        ; Out-Of-Memory error: cs_open(), cs_disasm()
(defconst capstone-CS_ERR_ARCH 2)       ; Unsupported architecture: cs_open()
(defconst capstone-CS_ERR_HANDLE 3)     ; Invalid handle: cs_op_count(), cs_op_index()
(defconst capstone-CS_ERR_CSH 4)        ; Invalid csh argument: cs_close(), cs_errno(), cs_option()
(defconst capstone-CS_ERR_MODE 5)       ; Invalid/unsupported mode: cs_open()
(defconst capstone-CS_ERR_OPTION 6)     ; Invalid/unsupported option: cs_option()
(defconst capstone-CS_ERR_DETAIL 7)     ; Invalid/unsupported option: cs_option()
(defconst capstone-CS_ERR_MEMSETUP 8)
(defconst capstone-CS_ERR_VERSION 9)    ; Unsupported version (bindings)
(defconst capstone-CS_ERR_DIET 10)      ; Information irrelevant in diet engine
(defconst capstone-CS_ERR_SKIPDATA 11)  ; Access irrelevant data for "data" instruction in SKIPDATA mode
(defconst capstone-CS_ERR_X86_ATT 12)   ; X86 AT&T syntax is unsupported (opt-out at compile time)
(defconst capstone-CS_ERR_X86_INTEL 13) ; X86 Intel syntax is unsupported (opt-out at compile time)

;; query id for cs_support()
(defconst capstone-CS_SUPPORT_DIET (+ capstone-CS_ARCH_ALL 1))
(defconst capstone-CS_SUPPORT_X86_REDUCE (+ capstone-CS_ARCH_ALL 2))

;;; wrapper functions around the capstone-core exposed api

;; NOTE: capstone handles are actual pointer values ... so if you provide
;; invalid handle values to any of these APIs, you _WILL_ segfault

;; capstone errors for testing against
(defconst capstone-errors `(,capstone-CS_ERR_OK
                            ,capstone-CS_ERR_MEM
                            ,capstone-CS_ERR_ARCH
                            ,capstone-CS_ERR_HANDLE
                            ,capstone-CS_ERR_CSH
                            ,capstone-CS_ERR_MODE
                            ,capstone-CS_ERR_OPTION
                            ,capstone-CS_ERR_DETAIL
                            ,capstone-CS_ERR_MEMSETUP
                            ,capstone-CS_ERR_VERSION
                            ,capstone-CS_ERR_DIET
                            ,capstone-CS_ERR_SKIPDATA
                            ,capstone-CS_ERR_X86_ATT
                            ,capstone-CS_ERR_X86_INTEL))

(defun capstone-version ()
  "Return the major and minor version of capstone in a list"
  (let ((version (capstone--cs-version)))
    ;; version is an integer of (major << 8 | minor)
    (list (lsh version -8) (logand #xff version))))

(defun capstone-support (query)
  "Check if arch id in QUERY is supported, returns t or nil"
  (assert (integerp query))
  (let ((ret (capstone--cs-support query)))
    (if (= ret 0)
        nil
      t)))

(defun capstone-errno (handle)
  "Return last error number for capstone instance HANDLE"
  (assert (integerp handle))
  (capstone--cs-errno handle))

(defun capstone-strerror (code)
  "Return the error string for a given error code, or nil"
  (assert (integerp code))
  (capstone--cs-strerror code))

(defun capstone-last-error (handle)
  "Return last error string for capstone instance HANDLE"
  (assert (integerp handle))
  (capstone-strerror (capstone-errno handle)))

(defun capstone-open (arch mode)
  "Initiate a capstone instance for ARCH in MODE, returns handle value or nil"
  (assert (integerp arch))
  (assert (integerp mode))
  (let ((handle (capstone--cs-open arch mode)))
    (cond ((member handle capstone-errors)
           (message "capstone-open failed, error: %s" (capstone-strerror handle))
           nil)
          ;; passed all checks, we have a handle
          (t
           handle))))

(defun capstone-close (handle)
  "Close capstone instance HANDLE, returns t or nil"
  (assert (integerp handle))
  (assert (not (member handle capstone-errors)))
  (let ((ret (capstone--cs-close handle)))
    (if (= ret capstone-CS_ERR_OK)
        t
      (progn
        (message "capstone-close failed, error: %s" (capstone-strerror ret))
        nil))))

;; capstone-CS_OPT_DETAIL is not handled in the backend, so turning it on is moot
(defun capstone-option (handle type value)
  "Set option of TYPE and VALUE for capstone instance HANDLE, returns t or nil"
  (assert (integerp handle))
  (assert (integerp type))
  (assert (integerp value))
  (let ((ret (capstone--cs-option handle type value)))
    (if (= ret capstone-CS_ERR_OK)
        t
      (progn
        (message "capstone-option failed, error: %s" (capstone-strerror ret))
        nil))))

;; not supporting detail api yet
(cl-defstruct struct-capstone-insn
  id       ; integer, instruction id
  address  ; integer, address of instruction
  size     ; integer, size of instruction
  bytes    ; list of uint8_t integers, size bytes of machine bytes
  mnemonic ; string, ascii text of instruction mnemonic
  op_str   ; string, ascii text of instruction operands
  )

(defun capstone-insn (insn)
  "Turn a list form insn into a struct form insn"
  (assert (listp insn))
  (destructuring-bind (id address size bytes mnemonic op_str) insn
    (make-struct-capstone-insn
     :id id
     :address address
     :size size
     :bytes bytes
     :mnemonic mnemonic
     :op_str op_str)))

;; raw is just a vector of uint8_t integers
(defun capstone-disasm (handle code address count)
  "Using capstone instance HANDLE, disassemble the uint8_t integer vector CODE at base ADDRESS for COUNT instructions (0 for all), returns a list of capstone-insn structs"
  (assert (integerp handle))
  (assert (vectorp code))
  (assert (integerp address))
  (assert (integerp count))
  (capstone--cs-disasm handle code address count))

(defun capstone-reg-name (handle reg_id)
  "Using capstone instance HANDLE, return name of register REG_ID in a string"
  (assert (integerp handle))
  (assert (integerp reg_id))
  (capstone--cs-reg-name handle reg_id))

(defun capstone-insn-name (handle insn_id)
  "Using capstone instance HANDLE, return name of instruction INSN_ID in a string"
  (assert (integerp handle))
  (assert (integerp insn_id))
  (capstone--cs-insn-name handle insn_id))

(defun capstone-group-name (handle group_id)
  "Using capstone instance HANDLE, return name of a group GROUP_ID that an instruction can belong to, in a string"
  (assert (integerp handle))
  (assert (integerp group_id))
  (capstone--cs-group-name handle group_id))

(defun capstone-open-arch (arch mode)
  ;; open a capstone handle for ARCH in MODE
  (assert (symbolp arch))
  (when mode
    (assert (integerp mode)))
  (let ((mode (or mode capstone-CS_MODE_LITTLE_ENDIAN))) ; default mode
    (ecase arch
      (:x86
       (capstone-open
        capstone-CS_ARCH_X86
        mode))
      (:arm
       (capstone-open
        capstone-CS_ARCH_ARM
        mode))
      (:arm64
       (capstone-open
        capstone-CS_ARCH_ARM64
        mode))
      (:sparc
       (capstone-open
        capstone-CS_ARCH_SPARC
        mode))
      (:ppc
       (capstone-open
        capstone-CS_ARCH_PPC
        mode))
      (:xcore
       (capstone-open
        capstone-CS_ARCH_XCORE
        mode))
      (:sysz
       (capstone-open
        capstone-CS_ARCH_SYSZ
        mode))
      (:mips
       (capstone-open
        capstone-CS_ARCH_MIPS
        mode)))))

(provide 'capstone-binding)
