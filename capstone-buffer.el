;;; capstone-buffer.el --- emacs-capstone file and buffer handling  -*- lexical-binding: t; -*-

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

;; file and buffer handling

;;; Code:

(require 'cl)

(defun capstone-file-to-vector (file)
  "Transform a _SMALL_ binary FILE into a vector of bytes"
  (assert (stringp file))
  (with-temp-buffer
    (set-buffer-multibyte nil) ; make sure we're a unibyte buffer
    (insert-file-contents-literally file)
    (goto-char (point-min))
    ;; allocate a vector of buffer-size bytes and populate it
    (let ((byte-vec (make-vector (buffer-size) 0))
          (i 0))
      (while (not (eobp))
        (let* ((byte (char-after)))
          (aset byte-vec i byte)
          (forward-char 1)
          (setq i (+ i 1))))
      byte-vec)))

(defun capstone-file-to-buffer (file &optional buffer-name)
  "Load a _LARGE_ binary FILE into a unibyte buffer"
  (assert (stringp file))
  (let ((buffer (generate-new-buffer (generate-new-buffer-name (or buffer-name file)))))
    (with-current-buffer buffer
      (set-buffer-multibyte nil)
      (insert-file-contents-literally file)
      (goto-char (point-min)))
    buffer))

(defun capstone-vector-from-buffer (buffer offset count &optional filter)
  "Return COUNT bytes from BUFFER starting at OFFSET from (point-min) as a vector"
  (assert (bufferp buffer))
  (assert (integerp offset))
  (assert (integerp count))
  (when filter
    (assert (functionp filter)))
  (with-current-buffer buffer
    (let ((filter-buffer-substring-function
           (or filter ; default filter just returns the raw string
               #'(lambda (start end &optional delete)
                   (buffer-substring start end))))
          (offset (+ offset (point-min))))
      (if (> offset (point-max))
          (progn
            (message "capstone-vector-from-buffer, error: offset set beyond (point-max)")
            nil)
        (vconcat (filter-buffer-substring offset (+ offset count)))))))

(defun capstone-create-output-buffer (buffer-name)
  "Create an output buffer of BUFFER-NAME"
  (assert (stringp buffer-name))
  (let ((buffer (get-buffer-create (generate-new-buffer-name buffer-name))))
    (unless buffer
      (message "capstone-create-output-buffer failed (%s)" buffer-name))
    buffer))

;; XXX: come up with some columned/aligned formatting scheme for this
(defun capstone-insert-buffer-line (line buffer)
  "Insert LINE into BUFFER, appends newline"
  (assert (stringp line))
  (assert (bufferp buffer))
  (with-current-buffer buffer
    (goto-char (point-max))
    (setq buffer-read-only nil)
    (insert (format "%s\n" line))
    (setq buffer-read-only t)))

(defun capstone-toggle-hexl (buffer)
  "Toggle a buffer to/from hexl mode"
  (assert (bufferp buffer))
  (with-current-buffer buffer
    (cl-letf (((symbol-function 'yes-or-no-p) #'(lambda (p) t))
              ((symbol-function 'y-or-n-p) #'(lambda (p) t)))
      (hexl-mode))))

(provide 'capstone-buffer)
