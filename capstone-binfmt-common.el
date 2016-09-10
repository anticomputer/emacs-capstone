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
