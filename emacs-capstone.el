;;; emacs-capstone.el --- elisp API for the capstone dissassembler (https://www.capstone-engine.org)  -*- lexical-binding: t; -*-

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

;; Constants ported from the capstone Python bindings
;; which were written by Nyugen Anh Quynnh <aquynh@gmail.com>

;; TODO: implement the cs detail API

;;; Code

(require 'capstone-disasm) ; this pulls in everything we need

;;; demo functions

(defun capstone-example-use ()
  "Just a little demo function to show the API in use"
  (let ((disas (capstone-disasm-x86 [ #xcc #xc3 #xcc ] #xdeadc0de 0)))
    (dolist (insn disas)
      (let* ((insn (capstone-insn insn)) ; transform to struct form
             (mnemonic (struct-capstone-insn-mnemonic insn))
             (operands (struct-capstone-insn-op_str insn))
             (address (struct-capstone-insn-address insn)))
        (message "capstone disassembled: 0x%x: %s %s" address mnemonic operands)))
    disas))

;;; test/dev functions

(defun capstone--test-exposed-api ()
  "Internal testing function just for my dev convenience"
  (let ((handle (capstone-open
                 capstone-CS_ARCH_X86
                 capstone-CS_MODE_LITTLE_ENDIAN)))
    (capstone-option handle capstone-CS_OPT_SKIPDATA capstone-CS_OPT_ON)
    (capstone-option handle capstone-CS_OPT_SKIPDATA capstone-CS_OPT_OFF)
    (message "capstone last known error: %s" (capstone-last-error handle))
    (message "capstone disas: %s" (capstone-disasm handle [ #xcc #xc3 #xcc ] #xdeadbeef 0))
    (message "capstone reg name: %s" (capstone-reg-name handle capstone-X86_REG_EAX))
    (message "capstone insn name: %s" (capstone-insn-name handle capstone-X86_INS_ADD))
    (message "capstone group name: %s" (capstone-group-name handle capstone-X86_GRP_JUMP))
    (capstone-close handle)))

(provide 'emacs-capstone)
