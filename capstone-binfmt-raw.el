;;; the simplest binfmt

(require 'capstone-binfmt-common)

(defun capstone-parse-raw (file)
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
