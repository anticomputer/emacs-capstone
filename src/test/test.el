;;; this runs some basic first-pass tests on the capstone-core module
(require 'ert)
(require 'emacs-capstone)

(defvar test-capstone-errors `(,capstone-CS_ERR_OK
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

(ert-deftest test-capstone-core-x86 ()
  "should return a valid handle"
  (let ((handle (capstone--cs-open capstone-CS_ARCH_X86
                                   capstone-CS_MODE_LITTLE_ENDIAN)))
    (should (and
             ;; test version
             (numberp (capstone--cs-version))

             ;; test support of CS_ARCH_X86
             (numberp (capstone--cs-support capstone-CS_ARCH_X86))

             ;; test handle opened without error
             (not (member handle test-capstone-errors))

             ;; test getting detailed error descriptions
             (stringp (capstone--cs-strerror capstone-CS_ERR_MEM))

             ;; test setting an option
             (member (capstone--cs-option handle
                                          capstone-CS_OPT_SYNTAX
                                          capstone-CS_OPT_ON)
                     test-capstone-errors)

             ;; test getting a reg name
             (stringp (capstone--cs-reg-name handle capstone-X86_REG_EAX))

             ;; test getting an instruction name
             (stringp (capstone--cs-insn-name handle capstone-X86_INS_ADD))

             ;; test getting a group name
             (stringp (capstone--cs-group-name handle capstone-X86_GRP_JUMP))

             ;; test disassembling something
             (listp (capstone--cs-disasm handle
                                         [ #xcc #xc3 ]
                                         #xdeadbeef
                                         2))

             ;; Test closing the handle
             (= capstone-CS_ERR_OK (capstone--cs-close handle)))

            )))
