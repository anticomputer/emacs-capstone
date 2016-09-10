;;; elisp capstone API for the capstone-core emacs25 module
;;;
;;; Constants ported from the capstone Python bindings
;;; which were written by Nguyen Anh Quynnh <aquynh@gmail.com>
;;;
;;; see `capstone-example-use' for a concise example of usage
;;;
;;; bas@collarchoke.org, 09/04/2016
;;;
;;; TODO: implement the cs detail API for more in depth code analysis support

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
