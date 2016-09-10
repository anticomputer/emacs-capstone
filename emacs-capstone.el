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

(require 'capstone-binding) ; the core binding api
(require 'capstone-buffer)  ; file and buffer backend
(require 'capstone-binfmt)  ; binfmt parsing backend

;;; our main disasm functions

(defmacro* capstone-with-disasm ((disas-sym code start count arch mode keep-handle)
                                 &body body)
  "A macro to provide a generic interface to all supported archs, BODY will have available ,DISAS-SYM for the list of disassembled opcodes in CODE at START address for COUNT number of ARCH in MODE instructions (0 for all), if you want to use a specific handle supply it in KEEP-HANDLE, otherwise set to nil and a handle will be provided for you"

  ;; use uninterned local symbols so we don't collide with anything used in BODY scope obarray
  (let ((handle (gensym "handle"))
        (disas (gensym "disas")))

    ;; 11:15, restate my assumptions
    `(assert (symbolp disas-sym))
    `(assert (vectorp code))
    `(assert (integerp start))
    `(assert (integerp count))
    `(assert (symbolp arch))
    `(assert (integerp mode))
    `(when keep-handle
       (assert (integerp keep-handle)))

    `(let* ((,handle (or ,keep-handle (capstone-open-arch ,arch ,mode)))
            (,disas (if ,handle
                        (capstone-disasm ,handle ,code ,start ,count)
                      nil)))
       ;; handle fail or no results
       (if (not ,disas)
           (progn
             (if ,handle
                 (progn
                   (message "capstone-disasm %s (no results), last error: %s"
                            ,arch (capstone-last-error ,handle))
                   (unless ,keep-handle
                     (capstone-close ,handle)))
               (message "capstoned-disasm %s failed, invalid handle"))
             nil)
         (progn
           (unless ,keep-handle
             (capstone-close ,handle))
           (let ((,disas-sym ,disas))
             ,@body))) ; keep last eval of BODY as result eval
       )))

(defun capstone-disasm-buffer (input-buffer arch mode start &optional output-buffer)
  "disasm buffer INPUT-BUFFER as ARCH in MODE instructions at START address, optionally output results OUTPUT-BUFFER"
  (assert (bufferp input-buffer))
  (assert (symbolp arch))
  (when mode
    (assert (integerp mode)))
  (assert (integerp start))
  (when output-buffer
    (assert (bufferp output-buffer)))

  (with-current-buffer input-buffer
    ;; XXX: fill this out for all archs
    (let* ((max-opcode-width (ecase arch (:x86 15)))
           (keep-handle (capstone-open-arch arch mode))
           (offset 0)
           (align-size max-opcode-width))
      (while (< offset (point-max))
        (let* ((bytes-left (- (point-max) (+ offset (point-min))))
               (max-opcode-width
                (if (< bytes-left max-opcode-width)
                    bytes-left
                  max-opcode-width))
               (code (capstone-vector-from-buffer
                      input-buffer offset
                      max-opcode-width)))
          ;; disassemble for 1 instruction at a time
          (let* ((insn (capstone-with-disasm
                        (disas
                         (capstone-vector-from-buffer
                          input-buffer
                          offset max-opcode-width)
                         start
                         1
                         arch
                         mode
                         keep-handle)
                        ;; BODY start
                        (if disas
                            (let* ((insn (capstone-insn (car disas))))
                              insn)
                          nil)
                        ;; BODY end
                        )))
            ;; outside of macro ... should prolly make an extract macro too
            (if insn
                (let* ((size (struct-capstone-insn-size insn))
                       (mnemonic (struct-capstone-insn-mnemonic insn))
                       (operands (struct-capstone-insn-op_str insn))
                       (address (struct-capstone-insn-address insn))
                       (bytes (struct-capstone-insn-bytes insn)))
                  (when output-buffer
                    (capstone-insert-buffer-line
                     ;; XXX: this will be replaced with proper formatting in the major mode
                     (format "0x%.8x: %s %s %s"
                             address
                             (concat (mapconcat #'(lambda (x) (format "%.2x" x)) bytes " ")
                                     (make-string (* (- align-size size) 3) ?\ ))
                             mnemonic
                             operands)
                     output-buffer))
                  (setq offset (+ offset size))
                  (setq start (+ start size)))
              (setq offset (point-max)))
            )))
      (capstone-close keep-handle))))

(defun capstone-disasm-file (file fmt arch &optional start mode)
  "Disassemble a binary opcode FILE of ARCH at START address in MODE (optional: default little endian)"
  (assert (and (stringp file) (file-exists-p file)))
  (assert (symbolp arch))
  (assert (symbolp fmt))
  (when start
    (assert (integerp start)))
  (when mode
    (assert (integerp mode)))
  (let* ((start (or start 0))
         (processed-section-list nil) ; processed sections go into here
         (section-list (ecase fmt (:raw (capstone-parse-raw file))))) ; add supported formats
    (dolist (section section-list)
      (let* ((label (struct-capstone-binfmt-section-label section))
             (base (struct-capstone-binfmt-section-base section))
             (size (struct-capstone-binfmt-section-size section))
             (raw-buffer (struct-capstone-binfmt-section-raw section))
             (notes (struct-capstone-binfmt-section-notes section))
             (asm-buffer (capstone-create-output-buffer (format "*%s-asm*" label)))
             ;; use section provide address only if no user override
             (start (if (= start 0) base start)))
        (capstone-disasm-buffer raw-buffer arch mode start asm-buffer)
        (with-current-buffer asm-buffer
          (goto-char (point-min)))
        (switch-to-buffer asm-buffer)
        (setq processed-section-list
              (cons (make-struct-capstone-binfmt-section
                     :label label
                     :base start ; relocate section as per user spec if needed
                     :size size
                     :raw raw-buffer
                     :asm asm-buffer
                     :notes notes) processed-section-list))
        ))
    ;; return a list of completed sections for further handling
    processed-section-list))

;;; convenience wrappers, these are subject to change ...

(defun capstone-disasm-file-x86 (file fmt &optional start)
  (interactive "fPath to raw binary:\niStart address for listing: ")
  (capstone-disasm-file file fmt :x86 start))

(defun capstone-disasm-x86 (code start count)
  (capstone-with-disasm (disas            ; bind results to this symbol for BODY
                         code start count ; main args
                         :x86 nil         ; default mode is little endian
                         nil)             ; open/close handle automagically
                        ;; BODY
                        disas             ; eval through to raw results in BODY
                        ))

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
