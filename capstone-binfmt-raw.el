;;; capstone-binfmt-raw.el --- emacs-capstone raw binfmt  -*- lexical-binding: t; -*-

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

;; this is the simplest binfmt example

;;; Code:

(require 'capstone-binfmt-common)

(defun capstone-pull-sections-raw (file)
  "Return a list of capstone sections for raw binary FILE"
  (let* ((section-list nil)
         (section-count 0)
         (output-name (file-name-nondirectory file))
         (buffer-name (format "*%s-raw*" output-name))
         (raw-buffer (capstone-file-to-buffer
                      file
                      buffer-name)))
    (setq section-list
          (cons (make-struct-capstone-binfmt-section
                 :label (format "%s-section%d" output-name section-count)
                 :base 0
                 :size (with-current-buffer raw-buffer (- (point-max) (point-min)))
                 :raw raw-buffer
                 :notes (format "raw binary section (src: %s)" file)) section-list))
    section-list))

(provide 'capstone-binfmt-raw)
