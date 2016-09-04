# emacs-capstone

This is a set of elisp bindings for the capstone dissassembly library[1].
Provided because I think emacs has everything it needs to be a decent
ASM navigation platform. This relies on the new native module support
in emacs version 25.

## Dependencies

Tested with capstone 3.0.4, install the libcapstone library on your system
and make sure you run `ldconfig` after install so it can be found by the
linker.

Your emacs25 needs to be built with module support, `configure --with-modules`

## Building

Edit the Makefile to match your environment and run `make`, this will also run
a series of tests to ensure everything is working as epxected.

## Installing

### Step one

Build the module, then add the emacs-capstone directory to your emacs load path.

### Step two

```lisp 
(require 'emacs-capstone) 
```

### Step three 

Off you go.

## Example

```lisp
(defun capstone-example-use ()
  "Just a little demo function to show the API in use"
  (let ((disas (capstone-disasm-x86 [ #xcc #xc3 #xcc #x2b #x4f #x52 ] #xdeadc0de 0)))
    (dolist (insn disas)
      (setq insn (capstone-insn insn)) ; transform to struct for convenience
      (let ((mnemonic (struct-capstone-insn-mnemonic insn))
            (operands (struct-capstone-insn-op_str insn))
            (address (struct-capstone-insn-address insn)))
        (message "capstone disassembled: 0x%x: %s %s" address mnemonic operands)))
    disas))
```

```
*** Welcome to IELM ***  Type (describe-mode) for help.
ELISP> (require 'emacs-capstone)
emacs-capstone
ELISP> (capstone-example-use)
((224 3735929054 1
      (204)
      "int3" "")
 (149 3735929055 1
      (195)
      "ret" "")
 (224 3735929056 1
      (204)
      "int3" "")
 (326 3735929057 3
      (43 79 82)
      "sub" "ecx, dword ptr [rdi + 0x52]"))

ELISP>
...
capstone disassembled: 0xdeadc0de: int3 
capstone disassembled: 0xdeadc0df: ret 
capstone disassembled: 0xdeadc0e0: int3 
capstone disassembled: 0xdeadc0e1: sub ecx, dword ptr [rdi + 0x52]
...
```

## TODO

emacs-capstone does not support the capstone detail API yet, because I didn't need
it as of time of writing. I'll throw it in at some near point in the future. 

## References

[1] capstone-engine.org
