;;; capstone-disasm.el --- emacs-capstone main disasm API  -*- lexical-binding: t; -*-

;; Copyright (C) 2016  Bas Alberts

;; Author: Bas Alberts <bas@mokusatsu.org>
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

;;

;;; Code:

(require 'capstone-binding) ; the core binding api
(require 'capstone-buffer)  ; file and buffer backend
(require 'capstone-binfmt)  ; binfmt parsing backend

;;; our main disasm functions
(require 'cl)

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
               (message "capstone-disasm %s failed, invalid handle" ,arch))
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
          (let ((insn (capstone-with-disasm
                       (disas
                        code
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

(defun capstone-disasm-file (file fmt arch &optional start mode toggle-hexl)
  "Disassemble a binary opcode FILE of ARCH at START address in MODE (optional: default little endian)"
  (assert (and (stringp file) (file-exists-p file)))
  (assert (symbolp arch))
  (assert (symbolp fmt))
  (when start
    (assert (integerp start)))
  (when mode
    (assert (integerp mode)))
  (let* ((start (or start 0))
         (processed-sections
          (capstone-with-sections
           (sections file fmt)
           ;; BODY ... walk the pulled sections and disassemble as required
           (let ((i 0))
             (dolist (section sections)
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
                 (setf (nth i sections) (make-struct-capstone-binfmt-section
                                         :label label
                                         :base start ; relocate section as per user spec if needed
                                         :size size
                                         :raw raw-buffer
                                         :asm asm-buffer
                                         :notes notes)))
               (setq i (+ i 1)))
             sections)))) ;; eval through to our now processed sections
    ;; do any further processing on the sections here
    (when toggle-hexl
      (dolist (section processed-sections)
        (let ((raw (struct-capstone-binfmt-section-raw section)))
          (capstone-toggle-hexl raw))))
    ))

;;; convenience wrappers, these are subject to change ...

(defun capstone-disasm-file-x86 (file fmt start)
  (interactive "fPath to raw binary: \nSbinary fmt (e.g. :raw): \nxStart address for listing (0 for binfmt parsing based): ")
  (capstone-disasm-file file fmt :x86 start))

(defun capstone-disasm-x86 (code start count)
  (capstone-with-disasm (disas            ; bind results to this symbol for BODY
                         code start count ; main args
                         :x86 nil         ; default mode is little endian
                         nil)             ; open/close handle automagically
                        ;; BODY
                        disas             ; eval through to raw results in BODY
                        ))

(provide 'capstone-disasm)
