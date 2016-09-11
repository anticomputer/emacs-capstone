;;; capstone-binfmt-common.el --- emacs-capstone binfmt support  -*- lexical-binding: t; -*-

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

;;

;;; Code:
(require 'cl)
(require 'capstone-buffer)

;; a binfmt parser should return a list of the following structs for each section
(cl-defstruct struct-capstone-binfmt-section
  label ; section name
  base  ; section base address
  size  ; section size
  raw   ; raw backend buffer
  asm   ; disasm buffer
  notes ; notes bro
  )

(provide 'capstone-binfmt-common)
